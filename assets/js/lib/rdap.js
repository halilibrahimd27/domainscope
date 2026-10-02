/**
 * rdap.js — RDAP (RFC 9082/9083) lookups for domains and IP addresses.
 *
 * Server discovery uses the IANA bootstrap registry (RFC 9224):
 *   https://data.iana.org/rdap/dns.json, ipv4.json, ipv6.json  (ACAO *, verified 2026-09-23)
 * The files are cached in-module (per fetch implementation, 24 h). Domain
 * lookups use the longest matching bootstrap label suffix and prefer https
 * service URLs; https://rdap.org/ (ACAO *, redirects to the authoritative
 * server) is the fallback when the bootstrap file or the registry cannot be
 * reached.
 *
 * Facts verified live on 2026-09-23 (they shape the logic below):
 *  - .tr (and .de, .jp, .io, .az …) have NO entry in the IANA bootstrap and
 *    rdap.org answers 404 "No RDAP service is available for this resource" →
 *    `unsupportedTld: true`, no request is made when the bootstrap is loaded.
 *  - 432 of 591 bootstrap servers send Access-Control-Allow-Origin (all big
 *    gTLD/ccTLD registries do: Verisign .com/.net, PIR .org, Google .dev/.app,
 *    Nominet .uk …). Some registries (e.g. .tw, .na, a few brand TLDs) do not;
 *    browsers then fail with a network TypeError, reported as `error`.
 *  - All five RIRs (ARIN, RIPE, APNIC, LACNIC→registro.br, AFRINIC) send ACAO.
 *
 * Verified live on 2026-10-02 (the domain portfolio, lib/portfolio.js):
 *  - .io, .sh, .ac and .me are still missing from the bootstrap, but their registry operator's
 *    server (Identity Digital, which the bootstrap names for .ai) answers them with ACAO `*`:
 *    {@link RDAP_OVERRIDES} sends them there instead of calling them "no RDAP".
 *  - rdap.org is the fallback only, at most one request a second ({@link RDAP_ORG_INTERVAL_MS},
 *    shared by every lookup of the page). Its 429 carries no CORS header, so a browser sees a
 *    network TypeError: after such an answer (or a readable 429 of its own) it is left alone for
 *    {@link RDAP_ORG_COOLDOWN_MS}, so a list of domains does not prolong its rate limit. A lookup
 *    waiting for its turn when that happens is not sent. rdap.org redirects to the registry: a 429
 *    whose final URL is the registry's is the registry's limit, and an unreadable answer after the
 *    registry itself gave none is most likely the registry's again — neither pauses rdap.org.
 *  - Registries rate-limit too: rdap.sidn.nl answered three concurrent requests 200, 429, 429. So
 *    one request is in flight per registry server at a time, and a registry's 429 is waited out
 *    (its Retry-After, else {@link RDAP_REGISTRY_RETRY_MS} doubled each time) and asked again, at
 *    most {@link RDAP_REGISTRY_429_RETRIES} times, never through rdap.org (it would only forward to
 *    the same registry).
 *  - An {@link RDAP_OVERRIDES} server answers 404 for a TLD it does not serve as well as for a
 *    domain not registered (rdap.identitydigital.services does for google.de): its 404 is not
 *    conclusive, never "not registered".
 *
 * DOM-free; runs in browsers and Node 22.
 */

import {
  fetchJson, retry, defaultShouldRetry, errorKind, throwIfAborted, abortReasonToError, HttpError, sleep
} from './util.js';
import { normalizeHostname, isPublicSuffix } from './domain.js';
import { normalizeIP, parseIP, parseCidr, isPrivateIP, formatIP } from './netinfo.js';
import { noteRequest } from './egresslog.js';

/** IANA RDAP bootstrap files (RFC 9224). */
export const IANA_BOOTSTRAP = Object.freeze({
  dns: 'https://data.iana.org/rdap/dns.json',
  ipv4: 'https://data.iana.org/rdap/ipv4.json',
  ipv6: 'https://data.iana.org/rdap/ipv6.json'
});

/** Redirecting RDAP aggregator used as the fallback. */
export const RDAP_ORG = 'https://rdap.org/';

/** rdap.org is asked at most once per this many milliseconds (every lookup of the page together). */
export const RDAP_ORG_INTERVAL_MS = 1000;
/** After an unreadable answer (a browser's view of its 429) or a 429, rdap.org is not asked for this long. */
export const RDAP_ORG_COOLDOWN_MS = 60000;
const RDAP_ORG_HOST = 'rdap.org';

/** A registry server's 429 without a Retry-After: it is asked again after this long, doubled each time. */
export const RDAP_REGISTRY_RETRY_MS = 2000;
/** A registry server's 429: the request is asked again at most this many times. */
export const RDAP_REGISTRY_429_RETRIES = 3;
/** A Retry-After longer than this is not waited out: the lookup fails as rate limited. */
export const RDAP_REGISTRY_WAIT_MAX_MS = 60000;

/**
 * Registry RDAP servers of TLDs the IANA bootstrap does not list yet (verified 2026-10-02: each
 * answers its TLD with ACAO `*`). Used only when the bootstrap names no server for the TLD.
 * @type {Readonly<Record<string, string>>}
 */
export const RDAP_OVERRIDES = Object.freeze({
  io: 'https://rdap.identitydigital.services/rdap/',
  sh: 'https://rdap.identitydigital.services/rdap/',
  ac: 'https://rdap.identitydigital.services/rdap/',
  me: 'https://rdap.identitydigital.services/rdap/'
});

const BOOTSTRAP_TTL_MS = 24 * 60 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 15000;
const ACCEPT = 'application/rdap+json, application/json;q=0.9';

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Registry-level registrable domain: eTLD+1 using ICANN suffixes only (the
 * registry holds `github.io`, not `user.github.io`). Returns null for bare
 * public suffixes (`com.tr`) and invalid input.
 * @param {string} host
 * @returns {string|null}
 */
export function registryDomain(host) {
  const h = normalizeHostname(String(host ?? '').replace(/^\*\./, ''));
  if (!h || isPublicSuffix(h, { includePrivate: false })) return null;
  const labels = h.split('.');
  for (let i = 0; i < labels.length - 1; i += 1) {
    if (isPublicSuffix(labels.slice(i + 1).join('.'), { includePrivate: false })) {
      return labels.slice(i).join('.');
    }
  }
  return null;
}

function isAbort(err) {
  return errorKind(err) === 'abort';
}

function describe(err) {
  if (!err) return 'Unknown error';
  if (err instanceof HttpError) return /not conclusive/.test(err.message) ? err.message : `HTTP ${err.status}${err.statusText ? ` ${err.statusText}` : ''}`;
  if (err instanceof TypeError) return `Network error (the RDAP server may not allow browser access): ${err.message}`;
  return String(err.message || err);
}

/** Wait for `promise`, rejecting early when `signal` aborts. */
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
 * Parse an RDAP date. Values without a zone designator are taken as UTC.
 * @param {unknown} v
 * @returns {Date|null}
 */
function parseDate(v) {
  if (typeof v !== 'string' || !v.trim()) return null;
  let s = v.trim();
  if (/T\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) s += 'Z';
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : new Date(t);
}

/** Ensure a trailing '/' on a bootstrap base URL (RFC 9224 §3 says they end with '/', not all do). */
function withSlash(base) {
  return base.endsWith('/') ? base : `${base}/`;
}

/**
 * Order a service's URLs: https first; an http-only service is tried as
 * https (browsers on GitHub Pages block http as mixed content).
 */
function serviceCandidates(urls) {
  const list = (Array.isArray(urls) ? urls : []).filter((u) => typeof u === 'string' && /^https?:\/\//i.test(u));
  const https = list.filter((u) => /^https:/i.test(u));
  const out = https.length ? https : list.map((u) => u.replace(/^http:/i, 'https:'));
  return [...new Set(out.map(withSlash))];
}

/* ------------------------------------------------------------------------ */
/* Bootstrap                                                                */
/* ------------------------------------------------------------------------ */

let bootstrapCaches = new WeakMap(); // fetchImpl → Map(kind → { promise, at })
let rdapOrgGates = new WeakMap(); // fetchImpl → { next, coolUntil }
let registryGates = new WeakMap(); // fetchImpl → Map(host → { tail, coolUntil })

/** Drop the cached IANA bootstrap files and the pacing of rdap.org and the registries (all fetch implementations). */
export function clearRdapCache() {
  bootstrapCaches = new WeakMap();
  rdapOrgGates = new WeakMap();
  registryGates = new WeakMap();
}

/** Host name of a URL (lower case), '' when it is none. */
function hostOf(url) {
  try {
    return new URL(String(url)).host.toLowerCase();
  } catch {
    return '';
  }
}

/** rdap.org was paused while a request waited for its turn: the request is not sent. */
class RdapOrgPausedError extends Error {
  constructor() {
    super('rdap.org is paused after its rate limit: not asked');
    this.name = 'RdapOrgPausedError';
  }
}

/** One registry server's pacing for one fetch implementation: a queue of one request at a time, and its 429 wait. */
function registryGate(fetchImpl, host) {
  const key = typeof fetchImpl === 'function' ? fetchImpl : registryGate;
  let hosts = registryGates.get(key);
  if (!hosts) {
    hosts = new Map();
    registryGates.set(key, hosts);
  }
  let gate = hosts.get(host);
  if (!gate) {
    gate = { tail: Promise.resolve(), coolUntil: 0 };
    hosts.set(host, gate);
  }
  return gate;
}

/**
 * Wait for a registry server's turn: one request in flight per server, after its 429 wait.
 * Resolves with the function that frees the server for the next request (call it once done).
 */
async function registryTurn(gate, signal) {
  const prev = gate.tail;
  let release;
  const mine = new Promise((resolve) => {
    release = resolve;
  });
  gate.tail = prev.then(() => mine);
  try {
    await withSignal(prev, signal);
    const wait = gate.coolUntil - Date.now();
    if (wait > 0) await sleep(wait, signal);
  } catch (err) {
    release();
    throw err;
  }
  return release;
}

/** Wait a registry server out after its 429: its Retry-After, else `baseMs` (the caller doubles it). */
function registryCoolDown(fetchImpl, host, err, baseMs) {
  const wait = Number.isFinite(err && err.retryAfterMs) ? err.retryAfterMs : baseMs;
  const gate = registryGate(fetchImpl, host);
  gate.coolUntil = Math.max(gate.coolUntil, Date.now() + wait);
  return wait;
}

/** rdap.org's pacing for one fetch implementation (the page has one: every lookup shares it). */
function rdapOrgGate(fetchImpl) {
  const key = typeof fetchImpl === 'function' ? fetchImpl : rdapOrgGate;
  let gate = rdapOrgGates.get(key);
  if (!gate) {
    gate = { next: 0, coolUntil: 0 };
    rdapOrgGates.set(key, gate);
  }
  return gate;
}

/**
 * Wait for rdap.org's next slot: requests go out at least `intervalMs` apart, in call order. A
 * request whose turn comes while rdap.org is paused is not sent (RdapOrgPausedError).
 */
async function rdapOrgTurn(gate, intervalMs, signal) {
  if (gate.coolUntil > Date.now()) throw new RdapOrgPausedError();
  const now = Date.now();
  const at = Math.max(now, gate.next);
  gate.next = at + Math.max(0, intervalMs);
  if (at > now) await sleep(at - now, signal);
  if (gate.coolUntil > Date.now()) throw new RdapOrgPausedError();
}

/**
 * After rdap.org's answer. Its own 429 (the final URL is rdap.org's) pauses it for
 * RDAP_ORG_COOLDOWN_MS (or its Retry-After when longer); a 429 behind its redirect is the
 * registry's: that server is waited out instead. A TypeError — in a browser rdap.org's 429 carries
 * no CORS header, so it cannot be told from a network error — pauses it only when the registry
 * itself answered readably this lookup (else it is most likely the registry's failure again).
 * Returns the error to report (a TypeError says what it may be).
 */
function noteRdapOrgFailure(gate, err, opts) {
  if (err instanceof HttpError && err.status === 429) {
    const host = hostOf(err.url);
    if (host && host !== RDAP_ORG_HOST) {
      registryCoolDown(opts.fetchImpl, host, err, opts.registryRetryMs);
      return err;
    }
    gate.coolUntil = Date.now() + Math.max(opts.rdapOrgCooldownMs, Number.isFinite(err.retryAfterMs) ? err.retryAfterMs : 0);
    return err;
  }
  if (!(err instanceof TypeError) || opts.registryUnreadable) return err;
  gate.coolUntil = Date.now() + opts.rdapOrgCooldownMs;
  return new TypeError(`rdap.org gave no readable answer (its rate limit, HTTP 429, carries no CORS header): ${err.message}`);
}

/**
 * Parse an IANA bootstrap file into `[{ entries: string[], urls: string[] }]`.
 * @param {object} json
 * @returns {Array<{ entries: string[], urls: string[] }>}
 * @throws {SyntaxError} when the structure is not a bootstrap file
 */
export function parseBootstrap(json) {
  if (!json || !Array.isArray(json.services)) throw new SyntaxError('Invalid RDAP bootstrap file');
  const out = [];
  for (const svc of json.services) {
    if (!Array.isArray(svc) || !Array.isArray(svc[0]) || !Array.isArray(svc[1])) continue;
    const entries = svc[0].filter((e) => typeof e === 'string').map((e) => e.trim().toLowerCase().replace(/\.$/, ''));
    const urls = svc[1].filter((u) => typeof u === 'string');
    if (entries.length && urls.length) out.push({ entries, urls });
  }
  return out;
}

async function loadBootstrap(kind, { fetchImpl, signal, timeoutMs }) {
  const key = typeof fetchImpl === 'function' ? fetchImpl : loadBootstrap;
  let cache = bootstrapCaches.get(key);
  if (!cache) {
    cache = new Map();
    bootstrapCaches.set(key, cache);
  }
  let entry = cache.get(kind);
  if (entry && Date.now() - entry.at > BOOTSTRAP_TTL_MS) {
    cache.delete(kind);
    entry = null;
  }
  if (!entry) {
    // Deliberately not tied to the caller's signal: concurrent callers share
    // it and later lookups reuse it. Only the timeout bounds it.
    const promise = retry(
      () => fetchJson(IANA_BOOTSTRAP[kind], { fetchImpl, timeoutMs, headers: { accept: 'application/json' } }),
      { retries: 1, baseDelayMs: 300, maxDelayMs: 3000 }
    ).then(parseBootstrap);
    const created = { promise, at: Date.now() };
    entry = created;
    cache.set(kind, created);
    promise.catch(() => {
      if (cache.get(kind) === created) cache.delete(kind);
    });
  }
  return withSignal(entry.promise, signal);
}

/**
 * Find the RDAP base URLs for a domain: longest matching label suffix.
 * @param {Array<{ entries: string[], urls: string[] }>} services parsed dns.json
 * @param {string} name lowercase ASCII domain
 * @returns {{ entry: string, urls: string[] }|null}
 */
export function findDomainService(services, name) {
  const labels = String(name).toLowerCase().replace(/\.$/, '').split('.');
  for (let i = 0; i < labels.length; i += 1) {
    const suffix = labels.slice(i).join('.');
    for (const svc of services) {
      if (svc.entries.includes(suffix)) return { entry: suffix, urls: serviceCandidates(svc.urls) };
    }
  }
  return null;
}

/**
 * Find the RDAP base URLs for an IP: longest matching prefix.
 * @param {Array<{ entries: string[], urls: string[] }>} services parsed ipv4.json / ipv6.json
 * @param {string} ip
 * @returns {{ entry: string, urls: string[] }|null}
 */
export function findIpService(services, ip) {
  const addr = parseIP(ip);
  if (!addr) return null;
  let best = null;
  for (const svc of services) {
    for (const entry of svc.entries) {
      const cidr = parseCidr(entry);
      if (!cidr || cidr.version !== addr.version) continue;
      const bits = cidr.version === 4 ? 32 : 128;
      const mask = cidr.prefix === 0 ? 0n : ((1n << BigInt(bits)) - 1n) ^ ((1n << BigInt(bits - cidr.prefix)) - 1n);
      if ((addr.value & mask) !== cidr.network) continue;
      if (!best || cidr.prefix > best.prefix) best = { prefix: cidr.prefix, entry, urls: serviceCandidates(svc.urls) };
    }
  }
  return best ? { entry: best.entry, urls: best.urls } : null;
}

/* ------------------------------------------------------------------------ */
/* jCard / entity helpers                                                   */
/* ------------------------------------------------------------------------ */

/** Values of a jCard property (e.g. 'fn', 'email', 'org', 'kind'). */
function vcardValues(entity, prop) {
  const arr = entity && Array.isArray(entity.vcardArray) ? entity.vcardArray[1] : null;
  if (!Array.isArray(arr)) return [];
  const out = [];
  for (const p of arr) {
    if (!Array.isArray(p) || String(p[0]).toLowerCase() !== prop) continue;
    const v = p[3];
    const s = Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()).join(' ') : v;
    if (typeof s === 'string' && s.trim()) out.push(s.trim());
  }
  return out;
}

function hasRole(entity, role) {
  return !!entity && Array.isArray(entity.roles) && entity.roles.some((r) => String(r).toLowerCase() === role);
}

/** Depth-first entity search (top-level entities first). */
function findEntity(entities, pred, depth = 0) {
  if (!Array.isArray(entities) || depth > 4) return null;
  for (const e of entities) if (e && typeof e === 'object' && pred(e)) return e;
  for (const e of entities) {
    const hit = e && typeof e === 'object' ? findEntity(e.entities, pred, depth + 1) : null;
    if (hit) return hit;
  }
  return null;
}

function entityName(entity) {
  if (!entity) return null;
  return vcardValues(entity, 'fn')[0] || vcardValues(entity, 'org')[0] || null;
}

function abuseEmail(entities) {
  const abuse = findEntity(entities, (e) => hasRole(e, 'abuse') && vcardValues(e, 'email').length > 0);
  return abuse ? vcardValues(abuse, 'email')[0] : null;
}

function eventDates(events) {
  const out = {};
  for (const ev of Array.isArray(events) ? events : []) {
    if (!ev || typeof ev !== 'object') continue;
    const action = String(ev.eventAction || '').trim().toLowerCase();
    const date = parseDate(ev.eventDate);
    if (action && date && !(action in out)) out[action] = date;
  }
  return out;
}

function selfLink(json) {
  const links = Array.isArray(json?.links) ? json.links : [];
  const self = links.find((l) => l && l.rel === 'self' && typeof l.href === 'string');
  return self ? self.href : null;
}

/* ------------------------------------------------------------------------ */
/* Domain                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Extract the useful fields of an RDAP domain object.
 * @param {object} json RDAP response (objectClassName 'domain')
 * @returns {{ ldhName: string|null, handle: string|null, registrar: string|null, registrarIanaId: string|null,
 *   registrarUrl: string|null, abuseEmail: string|null, created: Date|null, updated: Date|null, expires: Date|null,
 *   status: string[], nameservers: string[], dnssecSigned: boolean|null, selfUrl: string|null }}
 * @throws {SyntaxError} when `json` is not an object
 */
export function parseRdapDomain(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw new SyntaxError('RDAP response is not an object');
  const events = eventDates(json.events);
  const registrar = findEntity(json.entities, (e) => hasRole(e, 'registrar'));
  let ianaId = null;
  if (registrar && Array.isArray(registrar.publicIds)) {
    const pid = registrar.publicIds.find((p) => p && /iana\s*registrar\s*id/i.test(String(p.type || '')));
    if (pid && pid.identifier !== undefined && pid.identifier !== null && String(pid.identifier).trim()) {
      ianaId = String(pid.identifier).trim();
    }
  }
  let registrarUrl = null;
  if (registrar) {
    const about = (Array.isArray(registrar.links) ? registrar.links : [])
      .find((l) => l && l.rel === 'about' && typeof l.href === 'string' && /^https?:/i.test(l.href));
    registrarUrl = about ? about.href : (vcardValues(registrar, 'url')[0] || null);
  }
  const ns = [];
  for (const n of Array.isArray(json.nameservers) ? json.nameservers : []) {
    const raw = n && (n.ldhName || n.unicodeName);
    const host = typeof raw === 'string' ? normalizeHostname(raw) : null;
    if (host && !ns.includes(host)) ns.push(host);
  }
  let dnssecSigned = null;
  const sd = json.secureDNS;
  if (sd && typeof sd === 'object') {
    if (typeof sd.delegationSigned === 'boolean') dnssecSigned = sd.delegationSigned;
    else if ((Array.isArray(sd.dsData) && sd.dsData.length) || (Array.isArray(sd.keyData) && sd.keyData.length)) dnssecSigned = true;
  }
  return {
    ldhName: typeof json.ldhName === 'string' ? json.ldhName.toLowerCase().replace(/\.$/, '') : null,
    handle: typeof json.handle === 'string' ? json.handle : null,
    registrar: entityName(registrar) || (registrar && typeof registrar.handle === 'string' ? registrar.handle : null),
    registrarIanaId: ianaId,
    registrarUrl,
    abuseEmail: abuseEmail(json.entities),
    created: events.registration || null,
    updated: events['last changed'] || events['last update'] || null,
    expires: events.expiration || events['registrar expiration'] || null,
    status: (Array.isArray(json.status) ? json.status : [])
      .filter((s) => typeof s === 'string' && s.trim()).map((s) => s.trim().toLowerCase()),
    nameservers: ns,
    dnssecSigned,
    selfUrl: selfLink(json)
  };
}

function domainResult(domain) {
  return {
    ok: false,
    domain,
    registrar: null,
    registrarIanaId: null,
    created: null,
    updated: null,
    expires: null,
    status: [],
    nameservers: [],
    dnssecSigned: null,
    rdapServer: null,
    unsupportedTld: false,
    error: null,
    // extensions
    errorKind: null,
    notFound: false,
    input: domain,
    tld: null,
    url: null,
    handle: null,
    registrarUrl: null,
    abuseEmail: null,
    // a failed lookup (`error` set): the last HTTP status, the Retry-After when readable, when it failed (ms)
    httpStatus: null,
    retryAfterMs: null,
    failedAt: null
  };
}

/** The failure fields of a lookup that got no answer (lib/sourcestatus.js words them). */
function failureFields(err) {
  return {
    error: describe(err),
    errorKind: errorKind(err),
    httpStatus: err instanceof HttpError ? err.status : null,
    retryAfterMs: err && Number.isFinite(err.retryAfterMs) ? err.retryAfterMs : null,
    failedAt: Date.now()
  };
}

async function fetchRdap(url, { fetchImpl, signal, timeoutMs, gate = null, intervalMs = RDAP_ORG_INTERVAL_MS }) {
  // About › What this page sent: this host is a registry's RDAP server (the bootstrap named it, or
  // it is rdap.org, whose redirect takes the note along) — not a host whose path merely looks like one.
  noteRequest(url, 'rdap');
  return retry(
    async () => {
      // rdap.org (the fallback): one request a second at most, every attempt in turn.
      if (gate) await rdapOrgTurn(gate, intervalMs, signal);
      return fetchJson(url, { fetchImpl, signal, timeoutMs, headers: { accept: ACCEPT } });
    },
    // Retry timeouts / 5xx once; never 4xx (404 = not found is an answer) and not network
    // TypeErrors, which in browsers are almost always a missing CORS header (the rdap.org fallback
    // is the second attempt). A 429 is not retried here: a registry's is waited out by its queue
    // (askRegistry), rdap.org's pauses it.
    {
      retries: 1, signal, baseDelayMs: 400, maxDelayMs: 4000,
      shouldRetry: (err) => !(err instanceof TypeError) && !(err instanceof HttpError && err.status === 429) && defaultShouldRetry(err)
    }
  );
}

/**
 * Ask a registry server: one request in flight per server; its 429 is waited out (Retry-After, else
 * `registryRetryMs` doubled each time) and the same request asked again first — the requests
 * queued behind it wait —, at most `registry429Retries` times; then the 429 is the answer (rate
 * limited).
 */
async function askRegistry(url, opts) {
  const host = hostOf(url);
  const gate = registryGate(opts.fetchImpl, host);
  const release = await registryTurn(gate, opts.signal);
  try {
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await fetchRdap(url, opts);
      } catch (err) {
        if (isAbort(err) || !(err instanceof HttpError && err.status === 429)) throw err;
        const wait = registryCoolDown(opts.fetchImpl, host, err, opts.registryRetryMs * 2 ** attempt);
        if (attempt >= opts.registry429Retries || wait > opts.registryWaitMaxMs) throw err;
        await sleep(wait, opts.signal);
      }
    }
  } finally {
    release();
  }
}

/**
 * Ask one RDAP base URL (a registry's, or rdap.org paced and paused by its gate).
 * @returns {Promise<object>} the JSON; rejects like fetchRdap, or with the error noteRdapOrgFailure reports
 */
async function askRdap(base, url, opts) {
  if (base !== RDAP_ORG) return askRegistry(url, opts);
  const gate = rdapOrgGate(opts.fetchImpl);
  try {
    return await fetchRdap(url, { ...opts, gate, intervalMs: opts.rdapOrgIntervalMs });
  } catch (err) {
    if (isAbort(err) || err instanceof RdapOrgPausedError) throw err;
    throw noteRdapOrgFailure(gate, err, opts);
  }
}

/** Is rdap.org paused after an unreadable answer or a 429 (for this fetch implementation)? */
function rdapOrgPaused(fetchImpl) {
  return rdapOrgGate(fetchImpl).coolUntil > Date.now();
}

function isNoServiceBody(err) {
  return err instanceof HttpError && err.status === 404 && /no rdap service/i.test(err.body || '');
}

/**
 * Registration data for a domain via RDAP. The registry-level domain is
 * queried (`www.example.com.tr` → `example.com.tr`; ICANN suffixes only).
 *
 * Never rejects except with AbortError when `signal` aborts. Outcomes:
 *  - ok: true with the parsed fields;
 *  - unsupportedTld: true when the TLD has no RDAP service (e.g. .tr);
 *  - notFound: true (extension) when the registry answers 404 (not registered);
 *  - otherwise `error` / `errorKind` (network, CORS, timeout, http, parse).
 *
 * A TLD the bootstrap does not list but {@link RDAP_OVERRIDES} does goes to that registry server
 * (also when the bootstrap cannot be read); its 404 is not conclusive (a failure, never notFound).
 * One request is in flight per registry server, and its 429 is waited out and asked again, never
 * through rdap.org. rdap.org, the fallback, is paced to {@link RDAP_ORG_INTERVAL_MS} and paused
 * after its own 429 or an unreadable answer (`rdapOrgPaused` in the result when it was skipped
 * for that).
 *
 * @param {string} domain
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, fallback?: boolean,
 *   rdapOrgIntervalMs?: number, rdapOrgCooldownMs?: number, registryRetryMs?: number,
 *   registry429Retries?: number, registryWaitMaxMs?: number }} [opts]
 *   Extensions: timeoutMs (per request), fallback (false = never use rdap.org), rdapOrgIntervalMs /
 *   rdapOrgCooldownMs (rdap.org's pacing and pause), registryRetryMs / registry429Retries /
 *   registryWaitMaxMs (a registry's 429; tests).
 * @returns {Promise<{ ok: boolean, domain: string, registrar: string|null, registrarIanaId: string|null,
 *   created: Date|null, updated: Date|null, expires: Date|null, status: string[], nameservers: string[],
 *   dnssecSigned: boolean|null, rdapServer: string|null, unsupportedTld: boolean, error: string|null,
 *   errorKind: string|null, notFound: boolean, input: string, tld: string|null, url: string|null,
 *   handle: string|null, registrarUrl: string|null, abuseEmail: string|null,
 *   httpStatus: number|null, retryAfterMs: number|null, failedAt: number|null }>}
 *   Extensions for a lookup that got no answer (`error` without notFound / unsupportedTld): the last
 *   HTTP status, the service's Retry-After when readable and when it failed (ms since the epoch).
 */
export async function rdapDomain(domain, {
  fetchImpl = globalThis.fetch, signal, timeoutMs = DEFAULT_TIMEOUT_MS, fallback = true,
  rdapOrgIntervalMs = RDAP_ORG_INTERVAL_MS, rdapOrgCooldownMs = RDAP_ORG_COOLDOWN_MS,
  registryRetryMs = RDAP_REGISTRY_RETRY_MS, registry429Retries = RDAP_REGISTRY_429_RETRIES, registryWaitMaxMs = RDAP_REGISTRY_WAIT_MAX_MS
} = {}) {
  throwIfAborted(signal);
  const host = normalizeHostname(typeof domain === 'string' ? domain.replace(/^\*\./, '') : '');
  const input = host || String(domain ?? '');
  const name = host ? registryDomain(host) : null;
  if (!name) {
    const out = domainResult(input);
    out.error = host ? 'Not a registrable domain (public suffix)' : 'Invalid domain name';
    out.errorKind = 'invalid';
    return out;
  }
  const out = domainResult(name);
  out.input = input;
  out.tld = name.slice(name.lastIndexOf('.') + 1);
  const opts = { fetchImpl, signal, timeoutMs, rdapOrgIntervalMs, rdapOrgCooldownMs, registryRetryMs, registry429Retries, registryWaitMaxMs };
  const override = Object.hasOwn(RDAP_OVERRIDES, out.tld) ? RDAP_OVERRIDES[out.tld] : null;

  let candidates = [];
  let lastErr = null;
  try {
    const services = await loadBootstrap('dns', opts);
    const svc = findDomainService(services, name);
    if (!svc || svc.urls.length === 0) {
      if (!override) {
        out.unsupportedTld = true;
        out.error = `No RDAP service is published for .${out.tld}`;
        out.errorKind = 'unsupported';
        return out;
      }
      candidates = [override];
    } else {
      candidates = svc.urls;
    }
  } catch (err) {
    if (isAbort(err)) throw err;
    lastErr = err; // bootstrap unreachable → the override's server if any, then rdap.org
    if (override) candidates = [override];
  }
  let paused = false;
  if (fallback && !candidates.includes(RDAP_ORG)) {
    // rdap.org paused after an unreadable answer: the registry's own error stands.
    if (rdapOrgPaused(fetchImpl) && (candidates.length || lastErr)) paused = true;
    else candidates = [...candidates, RDAP_ORG];
  }

  // A registry that rate-limits us, or an override server that does not know the name: rdap.org
  // would only forward to the same registry (or does not serve the TLD). A registry without a
  // readable answer: rdap.org's own unreadable answer after it is no sign of its rate limit.
  let skipOrg = false;
  let registryUnreadable = false;
  for (const base of candidates) {
    if (base === RDAP_ORG && skipOrg) continue;
    const url = `${base}domain/${name}`;
    try {
      const json = await askRdap(base, url, { ...opts, registryUnreadable });
      const parsed = parseRdapDomain(json);
      let server = base;
      if (base === RDAP_ORG && parsed.selfUrl) {
        const m = /^(https?:\/\/.+?\/)domain\//i.exec(parsed.selfUrl);
        if (m) server = m[1];
      }
      return {
        ...out,
        ok: true,
        registrar: parsed.registrar,
        registrarIanaId: parsed.registrarIanaId,
        created: parsed.created,
        updated: parsed.updated,
        expires: parsed.expires,
        status: parsed.status,
        nameservers: parsed.nameservers,
        dnssecSigned: parsed.dnssecSigned,
        rdapServer: server,
        url,
        handle: parsed.handle,
        registrarUrl: parsed.registrarUrl,
        abuseEmail: parsed.abuseEmail,
        error: null,
        errorKind: null
      };
    } catch (err) {
      if (isAbort(err)) throw err;
      if (err instanceof RdapOrgPausedError) {
        // paused while it waited for its turn: the registry's own error stands
        paused = true;
        continue;
      }
      if (isNoServiceBody(err)) {
        return { ...out, unsupportedTld: true, error: `No RDAP service is published for .${out.tld}`, errorKind: 'unsupported', url };
      }
      if (err instanceof HttpError && err.status === 404 && base === override) {
        // The override server answers 404 for a TLD it does not serve too: not conclusive.
        lastErr = Object.assign(new HttpError(404, url, err.body), { message: 'HTTP 404 from a registry server the IANA bootstrap does not name: not conclusive' });
        skipOrg = true;
        continue;
      }
      if (err instanceof HttpError && err.status === 404) {
        // The registry is authoritative: the domain is not registered there.
        return { ...out, notFound: true, rdapServer: base, url, error: 'Domain not found in the registry', errorKind: 'http' };
      }
      if (base !== RDAP_ORG && err instanceof HttpError && err.status === 429) skipOrg = true;
      if (base !== RDAP_ORG && err instanceof TypeError) registryUnreadable = true;
      lastErr = err;
    }
  }
  return { ...out, ...failureFields(lastErr), ...(paused ? { rdapOrgPaused: true } : {}) };
}

/* ------------------------------------------------------------------------ */
/* IP                                                                       */
/* ------------------------------------------------------------------------ */

function trailingZeros(v, bits) {
  if (v === 0n) return bits;
  let n = 0;
  while (((v >> BigInt(n)) & 1n) === 0n && n < bits) n += 1;
  return n;
}

/**
 * Minimal list of CIDR blocks exactly covering an address range.
 * @param {string} start
 * @param {string} end
 * @param {number} [max=32] cap on the number of blocks returned
 * @returns {string[]}
 */
export function rangeToCidrs(start, end, max = 32) {
  const a = parseIP(start);
  const b = parseIP(end);
  if (!a || !b || a.version !== b.version || a.value > b.value) return [];
  const bits = a.version === 4 ? 32 : 128;
  const out = [];
  let cur = a.value;
  while (cur <= b.value && out.length < max) {
    let prefix = bits - trailingZeros(cur, bits);
    while (prefix < bits && cur + (1n << BigInt(bits - prefix)) - 1n > b.value) prefix += 1;
    out.push(`${formatIP(cur, a.version)}/${prefix}`);
    cur += 1n << BigInt(bits - prefix);
  }
  return out;
}

const RIR_HINTS = [
  [/arin\.net/i, 'ARIN'],
  [/ripe\.net/i, 'RIPE NCC'],
  [/apnic\.net/i, 'APNIC'],
  [/lacnic\.net|registro\.br/i, 'LACNIC'],
  [/afrinic\.net/i, 'AFRINIC']
];

/**
 * Extract the useful fields of an RDAP IP network object.
 * @param {object} json RDAP response (objectClassName 'ip network')
 * @returns {{ name: string|null, handle: string|null, country: string|null, startAddress: string|null,
 *   endAddress: string|null, cidr: string|null, cidrs: string[], org: string|null, type: string|null,
 *   parentHandle: string|null, abuseEmail: string|null, description: string[], rir: string|null,
 *   registered: Date|null, updated: Date|null }}
 * @throws {SyntaxError} when `json` is not an object
 */
export function parseRdapIp(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) throw new SyntaxError('RDAP response is not an object');
  const startAddress = typeof json.startAddress === 'string' ? normalizeIP(json.startAddress) : null;
  const endAddress = typeof json.endAddress === 'string' ? normalizeIP(json.endAddress) : null;
  let cidrs = [];
  for (const c of Array.isArray(json.cidr0_cidrs) ? json.cidr0_cidrs : []) {
    const prefix = c && (c.v4prefix || c.v6prefix);
    const len = Number(c && c.length);
    const ip = typeof prefix === 'string' ? normalizeIP(prefix) : null;
    if (ip && Number.isInteger(len)) cidrs.push(`${ip}/${len}`);
  }
  if (!cidrs.length && startAddress && endAddress) cidrs = rangeToCidrs(startAddress, endAddress);

  const entities = json.entities;
  const orgEntity = findEntity(entities, (e) => hasRole(e, 'registrant') && vcardValues(e, 'kind').includes('org'))
    || findEntity(entities, (e) => vcardValues(e, 'kind').includes('org'));
  let org = entityName(orgEntity);
  if (!org) {
    const registrant = findEntity(entities, (e) => hasRole(e, 'registrant'));
    const n = entityName(registrant);
    // RIPE often lists a maintainer ("RIPE-NCC-MNT", "MNT-GOOG-PROD") as registrant; not an org name.
    if (n && !/(^MNT-|-MNT$)/i.test(n)) org = n;
  }
  const description = [];
  for (const r of Array.isArray(json.remarks) ? json.remarks : []) {
    const title = String(r?.title || '').toLowerCase();
    if (title && !/^(description|descr|remarks?)$/.test(title)) continue;
    for (const d of Array.isArray(r?.description) ? r.description : []) {
      if (typeof d === 'string' && d.trim() && !/^-+$/.test(d.trim())) description.push(d.trim());
    }
  }
  const hintSource = [json.port43, selfLink(json)].filter((x) => typeof x === 'string').join(' ');
  const rir = RIR_HINTS.find(([re]) => re.test(hintSource));
  const country = typeof json.country === 'string' && /^[a-z]{2}$/i.test(json.country.trim())
    ? json.country.trim().toUpperCase() : null;
  const events = eventDates(json.events);
  return {
    name: typeof json.name === 'string' && json.name.trim() ? json.name.trim() : null,
    handle: typeof json.handle === 'string' ? json.handle : null,
    country,
    startAddress,
    endAddress,
    cidr: cidrs.length ? cidrs.join(', ') : null,
    cidrs,
    org,
    type: typeof json.type === 'string' ? json.type : null,
    parentHandle: typeof json.parentHandle === 'string' ? json.parentHandle : null,
    abuseEmail: abuseEmail(entities),
    description: description.slice(0, 10),
    rir: rir ? rir[1] : null,
    registered: events.registration || null,
    updated: events['last changed'] || null
  };
}

function ipResult(ip) {
  return {
    ok: false,
    name: null,
    handle: null,
    country: null,
    startAddress: null,
    endAddress: null,
    cidr: null,
    org: null,
    error: null,
    // extensions
    ip,
    errorKind: null,
    private: false,
    notFound: false,
    cidrs: [],
    type: null,
    parentHandle: null,
    abuseEmail: null,
    description: [],
    rir: null,
    registered: null,
    updated: null,
    rdapServer: null,
    url: null
  };
}

/**
 * Network registration data (RIR) for an IP address via RDAP. The RIR is
 * found through the IANA ipv4/ipv6 bootstrap (longest prefix); rdap.org is
 * the fallback. Private addresses are not looked up (`private: true`).
 * Never rejects except with AbortError when `signal` aborts.
 *
 * @param {string} ip
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number, fallback?: boolean }} [opts]
 * @returns {Promise<{ ok: boolean, name: string|null, handle: string|null, country: string|null,
 *   startAddress: string|null, endAddress: string|null, cidr: string|null, org: string|null, error: string|null,
 *   ip: string, errorKind: string|null, private: boolean, notFound: boolean, cidrs: string[], type: string|null,
 *   parentHandle: string|null, abuseEmail: string|null, description: string[], rir: string|null,
 *   registered: Date|null, updated: Date|null, rdapServer: string|null, url: string|null }>}
 */
export async function rdapIp(ip, {
  fetchImpl = globalThis.fetch, signal, timeoutMs = DEFAULT_TIMEOUT_MS, fallback = true,
  rdapOrgIntervalMs = RDAP_ORG_INTERVAL_MS, rdapOrgCooldownMs = RDAP_ORG_COOLDOWN_MS,
  registryRetryMs = RDAP_REGISTRY_RETRY_MS, registry429Retries = RDAP_REGISTRY_429_RETRIES, registryWaitMaxMs = RDAP_REGISTRY_WAIT_MAX_MS
} = {}) {
  throwIfAborted(signal);
  const canonical = normalizeIP(typeof ip === 'string' ? ip : '');
  if (!canonical) {
    const out = ipResult(String(ip ?? ''));
    out.error = 'Invalid IP address';
    out.errorKind = 'invalid';
    return out;
  }
  const out = ipResult(canonical);
  if (isPrivateIP(canonical)) {
    out.private = true;
    out.error = 'Private or reserved address (not looked up)';
    out.errorKind = 'invalid';
    return out;
  }
  // IPv4-mapped IPv6 is registered as the IPv4 address.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(canonical);
  const lookupIp = mapped ? mapped[1] : canonical;
  const kind = lookupIp.includes(':') ? 'ipv6' : 'ipv4';
  const opts = { fetchImpl, signal, timeoutMs, rdapOrgIntervalMs, rdapOrgCooldownMs, registryRetryMs, registry429Retries, registryWaitMaxMs };

  let candidates = [];
  let lastErr = null;
  try {
    const services = await loadBootstrap(kind, opts);
    const svc = findIpService(services, lookupIp);
    if (svc) candidates = svc.urls;
  } catch (err) {
    if (isAbort(err)) throw err;
    lastErr = err;
  }
  if (fallback && !candidates.includes(RDAP_ORG) && !(rdapOrgPaused(fetchImpl) && (candidates.length || lastErr))) {
    candidates = [...candidates, RDAP_ORG];
  }

  let registryUnreadable = false;
  for (const base of candidates) {
    const url = `${base}ip/${lookupIp}`;
    try {
      const parsed = parseRdapIp(await askRdap(base, url, { ...opts, registryUnreadable }));
      return { ...out, ...parsed, ok: true, rdapServer: base, url, error: null, errorKind: null };
    } catch (err) {
      if (isAbort(err)) throw err;
      if (err instanceof RdapOrgPausedError) continue;
      if (base !== RDAP_ORG && err instanceof TypeError) registryUnreadable = true;
      if (err instanceof HttpError && err.status === 404) {
        return { ...out, notFound: true, rdapServer: base, url, error: 'Address not found in the registry', errorKind: 'http' };
      }
      lastErr = err;
    }
  }
  return { ...out, error: describe(lastErr || new Error('No RDAP server found')), errorKind: lastErr ? errorKind(lastErr) : 'unknown' };
}
