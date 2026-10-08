/**
 * doh.js — DNS-over-HTTPS client (RFC 8484 wire format, GET `?dns=`; the JSON form `?name=&type=`
 * for a resolver a page can read only that way, lib/dohjson.js, loaded with its first question).
 *
 * Features:
 *  - failover over a resolver chain (transport error / timeout / HTTP error /
 *    SERVFAIL / REFUSED → next resolver), or a single explicit resolver;
 *  - retries with exponential backoff + jitter (extra passes over the chain);
 *  - a per-resolver circuit breaker so a resolver that keeps failing (e.g.
 *    Quad9 in browsers, HTTP/3 without CORS) is tried last for a while. The
 *    breaker is re-checked right before every request (a burst of queries
 *    stops hitting a resolver the moment its breaker opens) and, after the
 *    cooldown, lets a single trial request through (half-open) instead of
 *    sending every concurrent query back to a resolver that may still be down;
 *  - one shared concurrency limiter for every HTTP request of the client;
 *  - a TTL-aware LRU cache and in-flight de-duplication of identical queries;
 *  - per-resolver statistics.
 *
 * DOM-free: runs in browsers and Node 22. I/O goes through an injectable
 * `fetchImpl`, so everything is unit-testable with mocks. DNS-level failures
 * never throw — they are reported in the response. Only cancellation through
 * the caller's AbortSignal rejects (with an AbortError).
 */

import {
  encodeQuery, decodeMessage, base64UrlEncode, typeToNumber, typeToName, DnsWireError
} from './dnswire.js';
import { RESOLVERS, ECS_RESOLVERS, DEFAULT_CHAIN } from './resolvers.js';
import {
  AbortError, TimeoutError, HttpError, fetchWithTimeout, createLimiter, createCache, errorKind,
  randomLabel, mergeSignals, abortReasonToError, parseRetryAfter, sleep, defaultShouldRetry, onceAsync
} from './util.js';
import { normalizeIP, reversePtrName } from './netinfo.js';
import { normalizeHostname } from './domain.js';

/* ------------------------------------------------------------------------ */
/* Types                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} DnsResponse
 * @property {string} name query name (lowercase, no trailing dot; root = '.')
 * @property {string} type query type mnemonic ('A', 'AAAA', 'TYPE65534', ...)
 * @property {string|null} resolver id of the resolver that answered (or the last one tried)
 * @property {boolean} ok true when a DNS message was received (any rcode)
 * @property {string|null} rcode 'NOERROR'|'NXDOMAIN'|'SERVFAIL'|... (null when ok=false)
 * @property {object|null} flags decoded header flags ({ qr, opcode, aa, tc, rd, ra, z, ad, cd })
 * @property {object[]} answers decoded RRs (see dnswire.decodeMessage)
 * @property {object[]} authorities
 * @property {object[]} additionals extension
 * @property {object|null} ecs echoed EDNS Client Subnet ({ family, sourcePrefix, scopePrefix, address, subnet })
 * @property {Array<{code:number,name:string,text:string}>} ede Extended DNS Errors (RFC 8914)
 * @property {string|null} nsid extension: server instance id (RFC 5001), e.g. 'ist03'
 * @property {boolean} ad extension: shortcut for flags.ad (DNSSEC-validated answer)
 * @property {number} elapsedMs round-trip time of the answering request (ms)
 * @property {number} totalMs extension: total time including failover / retries
 * @property {string|null} error transport error message when ok=false
 * @property {string|null} errorKind util.errorKind() of the error (null when ok)
 * @property {Array<{resolver:string,ok:boolean,rcode?:string,error?:string,errorKind?:string,elapsedMs?:number}>} attempts extension
 * @property {boolean} cached extension: served from the client cache
 * @property {boolean} truncated extension: TC bit / message cut short
 */

/**
 * @typedef {object} HostResolution
 * @property {string} name
 * @property {'NOERROR'|'NXDOMAIN'|'SERVFAIL'|'REFUSED'|'ERROR'} status
 * @property {string[]} cnames CNAME chain in order (targets only, not the queried name)
 * @property {string[]} ipv4 canonical, answer order, de-duplicated
 * @property {string[]} ipv6 canonical, answer order, de-duplicated
 * @property {number|null} ttl minimum TTL of the records used
 * @property {string|null} resolver
 * @property {string|null} error
 * @property {string|null} errorKind extension
 * @property {boolean} ad extension: every answer used was DNSSEC-validated
 * @property {Array<{code:number,name:string,text:string}>} ede extension
 * @property {number} elapsedMs extension: max elapsed of the A / AAAA queries
 * @property {Array<{type:'A'|'AAAA',error:string,errorKind:string|null}>} [familyErrors] extension: with
 *   status NOERROR, the family whose question got no answer (a transport error, a rate limit, a
 *   SERVFAIL): its addresses are unknown, never "none"; absent otherwise
 */

/* ------------------------------------------------------------------------ */
/* Constants                                                                */
/* ------------------------------------------------------------------------ */

const DNS_MESSAGE = 'application/dns-message';
// SERVFAIL / REFUSED per contract; NOTIMP too (e.g. Cloudflare refuses ANY
// queries with NOTIMP while other resolvers answer them).
const FAILOVER_RCODES = new Set(['SERVFAIL', 'REFUSED', 'NOTIMP']);
const HOST_STATUSES = new Set(['NOERROR', 'NXDOMAIN', 'SERVFAIL', 'REFUSED']);
const MAX_MESSAGE = 65535;
// A JSON answer (lib/dohjson.js) is text: a full 64 KB message takes a few times its size.
const MAX_JSON = 1024 * 1024;
// The JSON form is loaded with its first question: only Global DNS's mainland China rows use it.
const loadJson = onceAsync(() => import('./dohjson.js'));
const MAX_CHAIN = 16;
// Circuit breaker: after this many consecutive transport failures a resolver
// is moved to the end of the failover order for BREAKER_COOLDOWN_MS. When the
// cooldown is over, one trial request is let through (half-open); the others
// keep treating the resolver as down until that request succeeds or fails.
const BREAKER_THRESHOLD = 3;
const BREAKER_COOLDOWN_MS = 30000;
// Returned by the limiter task instead of a response when the breaker of the
// resolver opened while the query was waiting for a request slot.
const SKIPPED = Symbol('skipped');
// Bulk balance mode (query({ balance: true })) spreads queries across this pool
// so no single resolver is hammered — the courtesy that matters when resolving
// thousands of wordlist / permutation candidates. Only large anycast,
// unfiltered resolvers that real browsers read reliably (18/18 in Chrome + Edge,
// tests/live/browser-doh-matrix.mjs) and that tolerate bulk rates (Cloudflare
// ~280 qps, Google ~740 qps without 429). Left out: Quad9 — over HTTP/3 it omits
// the CORS header and Chrome/Edge use HTTP/3 for it from the first request
// (resolvers.js issue 'h3-no-cors'), which fetch() cannot work around; Control D
// — unreachable from some networks during testing, so every query rotated to it
// waited for the full timeout (p95 8.5 s over 60 bulk queries). A custom pool may
// still include browser-unreliable resolvers: balance mode then uses them only
// as failover, never as the rotating primary, and the circuit breaker drops them
// after repeated transport errors.
const DEFAULT_BALANCE_POOL = Object.freeze(['cloudflare', 'google', 'dnssb']);
// A wildcard probe sent to one named resolver has no failover: cap it short with
// no retry pass, so a black-holed resolver cannot stall every wildcard check.
const WILDCARD_RESOLVER_TIMEOUT_MS = 2500;

const clock = () => (globalThis.performance && typeof globalThis.performance.now === 'function'
  ? globalThis.performance.now()
  : Date.now());

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

/** Caller cancellation is always reported as an AbortError. */
function toAbortError(reason) {
  const err = abortReasonToError(reason);
  return err instanceof AbortError ? err : new AbortError(err.message, { cause: err });
}

function checkAbort(signal) {
  if (signal && signal.aborted) throw toAbortError(signal.reason);
}

/**
 * Lowercase, trim, drop one trailing dot ('' → root '.'). Non-ASCII names are
 * converted to punycode when possible.
 */
function canonicalName(name) {
  let s = String(name ?? '').trim().toLowerCase();
  if (s.length > 1 && s.endsWith('.')) s = s.slice(0, -1);
  if (!s || s === '.') return '.';
  if (/[^\x00-\x7f]/.test(s)) {
    const ascii = normalizeHostname(s, { allowSingleLabel: true });
    if (ascii) s = ascii;
  }
  return s;
}

/** Stable text form of an ECS spec for cache keys. */
function ecsKey(ecs) {
  if (ecs === null || ecs === undefined || ecs === false || ecs === '') return '';
  if (typeof ecs === 'string') return ecs.trim();
  if (typeof ecs === 'object') {
    if (typeof ecs.subnet === 'string') return ecs.subnet.trim();
    return `${ecs.address ?? ''}/${ecs.sourcePrefix ?? ecs.prefix ?? ''}`;
  }
  return String(ecs);
}

/** Race a promise against an AbortSignal (for body reads that may stall). */
function raceSignal(promise, signal) {
  if (!signal) return promise;
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

async function readSnippet(response, signal) {
  try {
    return String(await raceSignal(response.text(), signal)).slice(0, 500);
  } catch {
    return '';
  }
}

/** Human-readable error text (HTTP errors include a short body excerpt). */
function describeError(err) {
  if (!err) return 'Unknown error';
  if (err instanceof HttpError) {
    const body = err.body ? err.body.replace(/\s+/g, ' ').trim().slice(0, 120) : '';
    return body ? `${err.message}: ${body}` : err.message;
  }
  return err.message || String(err);
}

/**
 * Should a failed attempt be retried in the next pass? Timeouts, network
 * errors and HTTP 408/429/5xx yes; other 4xx and malformed answers no.
 */
function isRetryable(err) {
  if (err instanceof HttpError) return err.status === 408 || err.status === 429 || err.status >= 500;
  if (err instanceof DnsWireError) return false;
  return defaultShouldRetry(err);
}

/** The JSON body of a JSON DoH answer; text that is not JSON is a DnsWireError (never retried). */
function parseJsonBody(bytes) {
  try {
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    throw new DnsWireError('DoH response is not JSON');
  }
}

function minTtl(rrs) {
  let min = null;
  for (const rr of rrs) {
    if (rr && Number.isFinite(rr.ttl) && (min === null || rr.ttl < min)) min = rr.ttl;
  }
  return min;
}

function clamp(v, lo, hi) {
  return Math.min(hi, Math.max(lo, v));
}

/* ------------------------------------------------------------------------ */
/* Answer helpers (exported extensions)                                     */
/* ------------------------------------------------------------------------ */

/**
 * Follow the CNAME chain for `name` through an answer section.
 * @param {object[]} answers decoded RRs
 * @param {string} name query name
 * @returns {{ cnames: string[], records: object[], target: string }} targets in
 *   chain order, the CNAME RRs used, and the final name the chain points to.
 */
export function followCnames(answers, name) {
  const list = Array.isArray(answers) ? answers : [];
  let current = canonicalName(name);
  const cnames = [];
  const records = [];
  const seen = new Set([current]);
  for (let hop = 0; hop < MAX_CHAIN; hop += 1) {
    const rr = list.find((r) => r && r.type === 'CNAME' && canonicalName(r.name) === current);
    if (!rr || typeof rr.data !== 'string') break;
    const target = canonicalName(rr.data);
    records.push(rr);
    if (seen.has(target)) break; // CNAME loop: stop, keep what we have
    cnames.push(target);
    seen.add(target);
    current = target;
  }
  return { cnames, records, target: current };
}

/**
 * Address records (A or AAAA) of the chain's owners, canonical and
 * de-duplicated, in answer order. Records of other owners are ignored.
 */
function chainAddresses(answers, owners, type) {
  const ips = [];
  const rrs = [];
  for (const rr of Array.isArray(answers) ? answers : []) {
    if (!rr || rr.type !== type || !owners.has(canonicalName(rr.name))) continue;
    const ip = normalizeIP(rr.data);
    if (!ip) continue;
    rrs.push(rr);
    if (!ips.includes(ip)) ips.push(ip);
  }
  return { ips, rrs };
}

function statusOf(response) {
  if (!response || !response.ok) return 'ERROR';
  return HOST_STATUSES.has(response.rcode) ? response.rcode : 'ERROR';
}

function edeText(ede) {
  if (!Array.isArray(ede) || !ede.length) return '';
  return ede.map((e) => (e.text ? `${e.name}: ${e.text}` : e.name)).join('; ');
}

/** The error of a response with no usable answer: the transport error, else the rcode with its EDE. */
function failureText(response) {
  if (!response) return 'No response';
  if (!response.ok) return response.error || 'Query failed';
  const extra = edeText(response.ede);
  return extra ? `${response.rcode} (${extra})` : response.rcode;
}

/**
 * Build a {@link HostResolution} from an A and an AAAA {@link DnsResponse}
 * (either may be null). The status comes from the A query; the AAAA query is
 * used when the A query failed at transport level (or returned SERVFAIL /
 * REFUSED while AAAA got a real answer). A lookup that got no answer is never
 * hidden behind the other one's NOERROR without an address: that would read
 * as "the name has no address" (NODATA), so the failure is the status then.
 * Next to an address of the other family it stays NOERROR and `familyErrors` names it.
 * @param {string} name
 * @param {DnsResponse|null} a
 * @param {DnsResponse|null} aaaa
 * @returns {HostResolution}
 */
export function hostResolutionFrom(name, a, aaaa) {
  const qname = canonicalName(name);
  const usable = (r) => r && r.ok && (r.rcode === 'NOERROR' || r.rcode === 'NXDOMAIN');
  let primary = a && a.ok ? a : aaaa && aaaa.ok ? aaaa : a || aaaa;
  if (primary === a && a && a.ok && FAILOVER_RCODES.has(a.rcode) && usable(aaaa)) primary = aaaa;

  const chainA = a && a.ok ? followCnames(a.answers, qname) : { cnames: [], records: [], target: qname };
  const chainB = aaaa && aaaa.ok ? followCnames(aaaa.answers, qname) : { cnames: [], records: [], target: qname };
  const chain = chainA.cnames.length ? chainA : chainB;
  const ownersA = new Set([qname, ...chainA.cnames]);
  const ownersB = new Set([qname, ...chainB.cnames]);
  const v4 = a && a.ok ? chainAddresses(a.answers, ownersA, 'A') : { ips: [], rrs: [] };
  const v6 = aaaa && aaaa.ok ? chainAddresses(aaaa.answers, ownersB, 'AAAA') : { ips: [], rrs: [] };
  // A transport error, a rate limit or a SERVFAIL leaves that family unknown; NXDOMAIN settles both.
  const lost = [['A', a], ['AAAA', aaaa]].filter(([, r]) => r && !usable(r));
  if (lost.length && usable(primary) && primary.rcode === 'NOERROR' && !v4.ips.length && !v6.ips.length) primary = lost[0][1];

  const status = statusOf(primary);
  const error = status === 'NOERROR' || status === 'NXDOMAIN' ? null : failureText(primary);
  const used = [...chain.records, ...v4.rrs, ...v6.rrs];
  const answered = [a, aaaa].filter((r) => r && r.ok);
  return {
    name: qname,
    status,
    cnames: chain.cnames,
    ipv4: v4.ips,
    ipv6: v6.ips,
    ttl: minTtl(used),
    resolver: primary ? primary.resolver : null,
    error,
    errorKind: primary && !primary.ok ? primary.errorKind : null,
    ad: answered.length > 0 && answered.every((r) => !!(r.flags && r.flags.ad)),
    ede: primary && Array.isArray(primary.ede) ? primary.ede : [],
    elapsedMs: Math.max(0, ...[a, aaaa].map((r) => (r && Number.isFinite(r.elapsedMs) ? r.elapsedMs : 0))),
    ...(status === 'NOERROR' && lost.length
      ? { familyErrors: lost.map(([type, r]) => ({ type, error: failureText(r), errorKind: r.ok ? null : r.errorKind || null })) }
      : {})
  };
}

/** Are two arrays equal as sets? */
function setsEqual(a, b) {
  if (a.length !== b.length) return false;
  const s = new Set(a);
  return b.every((x) => s.has(x));
}

/**
 * Classify one wildcard probe into the wildcard "kind" it evidences:
 * a CNAME chain, address records ('A'), an empty NOERROR ('NODATA'), or nothing
 * (NXDOMAIN / SERVFAIL / transport error).
 */
function classifyProbe(res) {
  if (!res || res.status === 'ERROR') return { kind: null };
  if (Array.isArray(res.cnames) && res.cnames.length) {
    return { kind: 'CNAME', cname: res.cnames[0], cnames: res.cnames };
  }
  if ((res.ipv4 && res.ipv4.length) || (res.ipv6 && res.ipv6.length)) {
    return { kind: 'A', ipv4: res.ipv4 || [], ipv6: res.ipv6 || [] };
  }
  if (res.status === 'NOERROR') return { kind: 'NODATA' };
  return { kind: null };
}

/**
 * Does a DNSSEC query for `probeName` prove the exact name does NOT exist?
 * True for compact denial of existence (Cloudflare "black lies") and RFC 9250
 * NXNAME: the authority carries an NSEC owned by the queried name whose bitmap
 * is NXNAME (TYPE128) or only RRSIG+NSEC. Such an answer is a NODATA-looking
 * denial, not a wildcard, so it must not flag every label as a wildcard suspect.
 * Any inconclusive result (no DNSSEC, no NSEC, error) returns false.
 */
async function dnssecProvesNonexistent(dns, probeName, signal) {
  if (!dns || typeof dns.query !== 'function') return false;
  let res;
  try {
    res = await dns.query(probeName, 'A', { signal, dnssec: true });
  } catch (err) {
    if (err instanceof AbortError) throw err;
    return false;
  }
  if (!res || !res.ok) return false;
  const qn = canonicalName(probeName);
  for (const rr of res.authorities || []) {
    if (rr.type !== 'NSEC' || !rr.data || canonicalName(rr.name) !== qn) continue;
    const types = Array.isArray(rr.data.types) ? rr.data.types : [];
    if (types.includes('NXNAME') || types.includes('TYPE128')) return true; // RFC 9250 NXNAME
    const meaningful = types.filter((t) => t !== 'RRSIG' && t !== 'NSEC');
    if (meaningful.length === 0) return true; // "black lie": NSEC proving the qname has nothing
  }
  return false;
}

/**
 * Deep wildcard detection that treats NODATA and CNAME wildcards correctly.
 *
 * Some zones answer *any* label with NODATA (NOERROR, no records) or with a
 * fixed CNAME rather than an address — the plain "did a random label get an A?"
 * test misses those and lets wildcard hits pollute results. This resolves
 * random labels below `parent`: `probes` on the failover chain (2 by default)
 * plus one on each resolver of `resolvers`.
 *
 * A synthesized kind ('A' or 'CNAME') is a wildcard when every chain probe
 * shows it, or at least two probes do. A probe of another kind does not veto
 * it: a resolver may answer NODATA or NXDOMAIN where the others see the
 * wildcard (GeoDNS with no default record, a stale resolver), and its guesses
 * are no hits anyway. An answer only one probe saw (one region of such a
 * wildcard) is asked once more on the same resolver before it can count.
 * Without a synthesized kind, the chain probes decide: all NOERROR-empty is a
 * NODATA wildcard, all NXDOMAIN is none, and chain probes that disagree prove
 * nothing. A probe that failed (transport error, SERVFAIL) says nothing and is
 * skipped.
 *
 * A wildcard's answer need not be one fixed value: GeoDNS / ECS steering or a
 * CDN alias answers each resolver differently, and a multivalue / weighted
 * wildcard answers each label with another subset of a pool. So an 'A'
 * wildcard carries the UNION of the probes' addresses, and a 'CNAME' one every
 * first target in `targets` (`cnames` is the first probe's chain); `variable`
 * is set when the probes disagreed on the value.
 *
 * A NODATA (NOERROR-empty) result is only reported as a wildcard when a DNSSEC
 * query does NOT prove the name's non-existence: many DNSSEC zones (all
 * Cloudflare-hosted ones) use compact denial of existence / NXNAME, answering
 * NOERROR-empty for every nonexistent label. Treating that as a wildcard would
 * flag every NXDOMAIN-equivalent name (including ones the user typed) as a
 * wildcard suspect.
 *
 * `conclusive` is false when the check proved nothing (too few answers, chain
 * probes that disagree, an NXDOMAIN next to an answer); a "no wildcard" from
 * probes that all got NXDOMAIN (or a DNSSEC-proven non-existence) is
 * conclusive, and so is every wildcard.
 *
 * @param {{ resolveHost: Function, query?: Function }} dns injected DoH client
 * @param {string} parent the zone to test (apex or any level)
 * @param {{ signal?: AbortSignal, resolvers?: string[], probes?: number }} [opts]
 *   resolvers: extra probes, one sent to each of these resolver ids (the pool bulk
 *   queries rotate across); probes: random labels on the chain (2–16, default 2)
 * @returns {Promise<{ wildcard: boolean, kind: 'A'|'CNAME'|'NODATA'|null, ipv4: string[], ipv6: string[],
 *   cnames: string[], targets: string[], variable: boolean, conclusive: boolean }>}
 */
export async function detectWildcardDeep(dns, parent, { signal, resolvers = [], probes = 2 } = {}) {
  const none = (conclusive = false) => ({
    wildcard: false, kind: null, ipv4: [], ipv6: [], cnames: [], targets: [], variable: false, conclusive
  });
  const base = normalizeHostname(String(parent ?? ''), { allowSingleLabel: true });
  if (!base || !dns || typeof dns.resolveHost !== 'function') return none();

  /** One random label on `resolver` (null: the failover chain), classified; null when it failed. */
  const probe = async (resolver) => {
    const name = `${randomLabel(12)}.${base}`;
    const r = await dns.resolveHost(name, resolver
      ? { signal, resolver, timeoutMs: WILDCARD_RESOLVER_TIMEOUT_MS, retries: 0 } : { signal });
    const p = classifyProbe(r);
    if (p.kind) return { ...p, name, resolver };
    return r && r.status === 'NXDOMAIN' ? { kind: 'NXDOMAIN', name, resolver } : null;
  };
  const count = Math.max(2, Math.min(16, Math.floor(Number(probes)) || 2));
  const named = new Set((Array.isArray(resolvers) ? resolvers : []).filter((id) => typeof id === 'string' && id));
  const answers = (await Promise.all([...Array(count).fill(null), ...named].map(probe))).filter(Boolean);
  const synthesized = (kind) => kind === 'A' || kind === 'CNAME';
  const votes = (kind) => answers.filter((p) => p.kind === kind).length;
  const lone = answers.filter((p) => synthesized(p.kind) && votes(p.kind) === 1);
  answers.push(...(await Promise.all(lone.map((p) => probe(p.resolver)))).filter(Boolean));

  /** The kind every answer of `list` shows, when at least two answered. */
  const agreed = (list) => (list.length >= 2 && list.every((p) => p.kind === list[0].kind) ? list[0].kind : null);
  const chain = answers.filter((p) => !p.resolver);
  let kind = synthesized(agreed(chain)) ? agreed(chain) : null;
  if (!kind && Math.max(votes('A'), votes('CNAME')) >= 2) kind = votes('A') >= votes('CNAME') ? 'A' : 'CNAME';

  if (!kind) {
    // Nothing synthesized: the chain sample decides (every answer when fewer than two chain probes answered).
    const verdict = agreed(chain.length >= 2 ? chain : answers);
    if (!verdict) return none();
    if (verdict === 'NXDOMAIN') return none(answers.every((p) => p.kind === 'NXDOMAIN'));
    // NOERROR-empty. This is a NODATA wildcard only if DNSSEC does not prove the
    // probe name's non-existence (compact denial of existence / NXNAME).
    if (await dnssecProvesNonexistent(dns, answers.find((p) => p.kind === 'NODATA').name, signal)) return none(true);
    return { wildcard: true, kind: 'NODATA', ipv4: [], ipv6: [], cnames: [], targets: [], variable: false, conclusive: true };
  }

  const hits = answers.filter((p) => p.kind === kind);
  if (kind === 'CNAME') {
    const targets = [...new Set(hits.map((p) => p.cname))];
    return {
      wildcard: true, kind: 'CNAME', ipv4: [], ipv6: [], cnames: [...hits[0].cnames],
      targets, variable: targets.length > 1, conclusive: true
    };
  }
  const union = (key) => [...new Set(hits.flatMap((p) => p[key]))];
  const variable = hits.some((p) => !setsEqual(p.ipv4, hits[0].ipv4) || !setsEqual(p.ipv6, hits[0].ipv6));
  return { wildcard: true, kind: 'A', ipv4: union('ipv4'), ipv6: union('ipv6'), cnames: [], targets: [], variable, conclusive: true };
}

/* ------------------------------------------------------------------------ */
/* Client                                                                   */
/* ------------------------------------------------------------------------ */

function failureResponse(name, type, resolver, message, kind, extra = {}) {
  return {
    name,
    type,
    resolver,
    ok: false,
    rcode: null,
    flags: null,
    answers: [],
    authorities: [],
    additionals: [],
    ecs: null,
    ede: [],
    nsid: null,
    ad: false,
    elapsedMs: 0,
    totalMs: 0,
    error: message,
    errorKind: kind,
    attempts: [],
    cached: false,
    truncated: false,
    ...extra
  };
}

function messageResponse(name, type, resolverId, msg, elapsedMs) {
  const edns = msg.edns || null;
  return {
    name,
    type,
    resolver: resolverId,
    ok: true,
    rcode: msg.rcodeName,
    flags: msg.flags,
    answers: msg.answers,
    authorities: msg.authorities,
    additionals: msg.additionals,
    ecs: edns && edns.ecs ? edns.ecs : null,
    ede: edns && Array.isArray(edns.ede) ? edns.ede : [],
    nsid: edns && edns.nsid ? edns.nsid : null,
    ad: !!msg.flags.ad,
    elapsedMs,
    totalMs: elapsedMs,
    error: null,
    errorKind: null,
    attempts: [],
    cached: false,
    truncated: !!(msg.truncated || msg.flags.tc)
  };
}

/**
 * DNS-over-HTTPS client. One instance is meant to be shared by a whole view /
 * scan so that its limiter, cache and statistics are shared too.
 *
 * Extensions beyond the contract (all optional constructor options):
 *  - `resolvers` (default RESOLVERS and ECS_RESOLVERS): resolver definitions ids are looked up in; a
 *    definition with `format: 'json'` is asked in the JSON form (lib/dohjson.js), the others in RFC 8484;
 *    `chain` / `query({ resolver })` may also pass `{ id, url }` objects;
 *  - `baseDelayMs` (250) / `maxDelayMs` (4000): backoff between retry passes;
 *  - `cache`: true | false | a cache object with get/set (e.g. shared);
 *    `cacheSize` (5000), `minCacheTtl` (10 s) / `maxCacheTtl` (300 s);
 *  - `now` (Date.now): clock for cache TTLs and the circuit breaker.
 */
export class DohClient {
  #resolverDefs;
  #chain;
  #timeoutMs;
  #retries;
  #fetchImpl;
  #cache;
  #limiter;
  #baseDelayMs;
  #maxDelayMs;
  #minCacheTtl;
  #maxCacheTtl;
  #now;
  #inflight = new Map();
  #health = new Map();
  #counters = { queries: 0, cacheHits: 0, failures: 0, requests: 0, shared: 0 };
  #byResolver = new Map();
  #balancePool = [];
  #balancePoolExplicit = false;
  #balanceKey = '';
  #balanceCursor = 0;

  /**
   * @param {object} [opts]
   * @param {Array<string|{id:string,url:string}>} [opts.chain=DEFAULT_CHAIN] failover order
   * @param {number} [opts.concurrency=12] max parallel HTTP requests
   * @param {number} [opts.timeoutMs=8000] per-request timeout (headers + body)
   * @param {number} [opts.retries=1] extra passes over the chain for transient failures
   * @param {typeof fetch} [opts.fetchImpl=globalThis.fetch]
   * @param {boolean|{get:Function,set:Function}} [opts.cache=true]
   */
  constructor({
    chain = DEFAULT_CHAIN,
    concurrency = 12,
    timeoutMs = 8000,
    retries = 1,
    fetchImpl = globalThis.fetch,
    cache = true,
    resolvers = [...RESOLVERS, ...ECS_RESOLVERS],
    baseDelayMs = 250,
    maxDelayMs = 4000,
    cacheSize = 5000,
    minCacheTtl = 10,
    maxCacheTtl = 300,
    now = Date.now,
    balancePool = DEFAULT_BALANCE_POOL
  } = {}) {
    this.#resolverDefs = new Map();
    for (const r of Array.isArray(resolvers) ? resolvers : []) {
      if (r && typeof r.id === 'string' && typeof r.url === 'string') this.#resolverDefs.set(r.id, r);
    }
    this.#fetchImpl = fetchImpl;
    this.#timeoutMs = Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : 8000;
    this.#retries = Number.isFinite(retries) && retries > 0 ? Math.floor(retries) : 0;
    this.#baseDelayMs = Number.isFinite(baseDelayMs) && baseDelayMs >= 0 ? baseDelayMs : 250;
    this.#maxDelayMs = Number.isFinite(maxDelayMs) && maxDelayMs >= 0 ? maxDelayMs : 4000;
    this.#minCacheTtl = Number.isFinite(minCacheTtl) && minCacheTtl >= 0 ? minCacheTtl : 10;
    this.#maxCacheTtl = Number.isFinite(maxCacheTtl) && maxCacheTtl >= this.#minCacheTtl ? maxCacheTtl : Math.max(300, this.#minCacheTtl);
    this.#now = typeof now === 'function' ? now : Date.now;
    this.#limiter = createLimiter(concurrency);
    if (cache && typeof cache === 'object' && typeof cache.get === 'function' && typeof cache.set === 'function') {
      this.#cache = cache;
    } else if (cache) {
      this.#cache = createCache({ maxEntries: cacheSize, now: this.#now });
    } else {
      this.#cache = null;
    }
    this.setChain(chain);
    this.#setBalancePool(balancePool, balancePool !== DEFAULT_BALANCE_POOL);
  }

  /**
   * Set the resolver pool used by bulk `balance` mode (extension). Unknown ids
   * are skipped; if none are known the failover chain is used instead.
   * `explicit` records whether the caller chose this pool (an explicit pool is
   * honoured as given; the built-in default is intersected with the chain by
   * {@link #balancedChain} so bulk queries respect the user's resolver choice).
   * @param {Array<string|{id:string,url:string}>} pool
   * @param {boolean} [explicit=true]
   */
  #setBalancePool(pool, explicit = true) {
    const list = [];
    for (const entry of Array.isArray(pool) ? pool : []) {
      const r = this.#lookupResolver(entry);
      if (r && !list.some((x) => x.id === r.id)) list.push(r);
    }
    this.#balancePool = list.length ? list : this.#chain;
    this.#balancePoolExplicit = !!explicit && list.length > 0;
    this.#recomputeBalanceKey();
  }

  /** Cache key for balanced answers: depends on the pool AND the chain, so a
   *  chain change never reuses answers from resolvers the user removed. */
  #recomputeBalanceKey() {
    const pool = this.#balancePool.map((r) => r.id).slice().sort().join(',');
    const chain = this.#chain ? this.#chain.map((r) => r.id).slice().sort().join(',') : '';
    this.#balanceKey = `${pool};${chain}`;
  }

  /**
   * Replace the failover chain (extension).
   * @param {Array<string|{id:string,url:string}>} chain
   * @throws {TypeError} when no entry is a known resolver
   */
  setChain(chain) {
    const list = [];
    for (const entry of Array.isArray(chain) ? chain : []) {
      const r = this.#lookupResolver(entry);
      if (r && !list.some((x) => x.id === r.id)) list.push(r);
    }
    if (!list.length) throw new TypeError('DohClient: the resolver chain has no known resolver');
    this.#chain = list;
    // The balance key includes the chain, so a chain change invalidates cached
    // balanced answers (and the default pool now follows the new chain).
    if (this.#balancePool.length) this.#recomputeBalanceKey();
  }

  /** Resolver ids of the failover chain, in configured order (extension). */
  get chain() {
    return this.#chain.map((r) => r.id);
  }

  /**
   * Resolver ids bulk `balance` queries rotate across (extension): the pool as
   * {@link #balancedChain} uses it, without the browser-unreliable members that
   * only ever serve as failover. A wildcard check probes each of them.
   */
  get balancePool() {
    return this.#rotatingPool().filter((r) => r.browserReliable !== false).map((r) => r.id);
  }

  /**
   * Change the maximum number of parallel HTTP requests.
   * @param {number} n
   */
  setConcurrency(n) {
    this.#limiter.setConcurrency(n);
  }

  /** Current maximum number of parallel HTTP requests (extension). */
  get concurrency() {
    return this.#limiter.concurrency;
  }

  /** Drop every cached answer (extension). */
  clearCache() {
    if (this.#cache && typeof this.#cache.clear === 'function') this.#cache.clear();
  }

  /**
   * Snapshot of the client statistics.
   * `queries` counts query() calls (cache hits included), `failures` the calls
   * that ended with ok=false. Per resolver: `ok` = HTTP requests that returned
   * a DNS message, `fail` = transport failures, `avgMs` = mean RTT of the ok
   * ones. Extensions: `requests`, `shared` (joined an identical in-flight
   * query), `active` / `pending` (limiter), per-resolver `lastError`, `down`.
   * @returns {{ queries:number, cacheHits:number, failures:number,
   *   byResolver: Object<string,{ok:number,fail:number,avgMs:number|null}> }}
   */
  stats() {
    const byResolver = {};
    for (const [id, s] of this.#byResolver) {
      const h = this.#health.get(id);
      byResolver[id] = {
        ok: s.ok,
        fail: s.fail,
        avgMs: s.ok ? Math.round(s.totalMs / s.ok) : null,
        lastError: s.lastError,
        down: !!(h && h.downUntil > this.#now())
      };
    }
    return {
      ...this.#counters,
      active: this.#limiter.active,
      pending: this.#limiter.pending,
      byResolver
    };
  }

  /**
   * Send one query.
   * @param {string} name
   * @param {string|number} [type='A']
   * @param {object} [opts]
   * @param {string|{id:string,url:string}} [opts.resolver] query only this resolver (no failover)
   * @param {string|{address:string,sourcePrefix:number}} [opts.ecs] EDNS Client Subnet
   * @param {boolean} [opts.dnssec=false] set the DO bit (RRSIG/NSEC records)
   * @param {boolean} [opts.cd=false] checking disabled (no DNSSEC validation)
   * @param {AbortSignal} [opts.signal]
   * @param {boolean} [opts.noCache=false] bypass the cache (the answer is still stored)
   * @param {boolean} [opts.balance=false] bulk mode: round-robin across the healthy
   *   resolver pool (ignored when an explicit `resolver` is given)
   * @param {number} [opts.timeoutMs] extension: per-request timeout for this query
   *   (default: the client's `timeoutMs`), e.g. a short one for one-shot comparisons
   * @param {number} [opts.retries] extension: extra passes for this query (default: the
   *   client's `retries`). An identical query already in flight is shared as it is.
   * @returns {Promise<DnsResponse>} never rejects except with AbortError
   */
  async query(name, type = 'A', {
    resolver, ecs = null, dnssec = false, cd = false, signal, noCache = false, balance = false, timeoutMs, retries
  } = {}) {
    checkAbort(signal);
    this.#counters.queries += 1;
    const qname = canonicalName(name);
    const typeNum = typeToNumber(type);
    const typeName = typeNum === null ? String(type) : typeToName(typeNum);

    let targets = null;
    if (resolver !== undefined && resolver !== null && resolver !== '') {
      const r = this.#lookupResolver(resolver);
      if (!r) {
        const id = typeof resolver === 'string' ? resolver : resolver && resolver.id ? String(resolver.id) : null;
        return this.#failed(failureResponse(qname, typeName, id, `Unknown resolver "${id ?? resolver}"`, 'unknown'));
      }
      targets = [r];
    }

    let wire;
    try {
      if (typeNum === null) throw new DnsWireError(`unknown RR type "${type}"`);
      wire = encodeQuery(qname, typeNum, {
        id: 0, dnssecOk: !!dnssec, cd: !!cd, ecs: ecs || null, nsid: true
      });
    } catch (err) {
      return this.#failed(failureResponse(qname, typeName, targets ? targets[0].id : null,
        `Invalid query: ${err.message}`, 'parse'));
    }

    const balanced = !targets && !!balance;
    const scope = targets
      ? `r:${targets[0].id}`
      : balanced ? `b:${this.#balanceKey}` : `c:${this.#chain.map((r) => r.id).join(',')}`;
    const key = `${qname}|${typeNum}|${scope}|${ecsKey(ecs)}|${dnssec ? 1 : 0}|${cd ? 1 : 0}`;
    if (this.#cache && !noCache) {
      const hit = this.#cache.get(key);
      if (hit) {
        this.#counters.cacheHits += 1;
        return { ...hit, cached: true };
      }
    }

    // Rotate the balance pool only on a real (cache-miss) request.
    const chainList = balanced ? this.#balancedChain() : null;
    const ctx = {
      qname, typeNum, typeName, wire: base64UrlEncode(wire), ecs: ecs || null, targets, chainList, key, noCache,
      timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : this.#timeoutMs,
      retries: Number.isFinite(retries) && retries >= 0 ? Math.floor(retries) : this.#retries
    };
    const response = await this.#shared(key, (sharedSignal) => this.#run(ctx, sharedSignal), signal);
    if (!response.ok) this.#counters.failures += 1;
    return { ...response };
  }

  /**
   * Resolve a host: A and AAAA concurrently, CNAME chain in order, addresses
   * of the final target.
   * @param {string} name
   * @param {{ signal?: AbortSignal, resolver?: string, noCache?: boolean, balance?: boolean, timeoutMs?: number, retries?: number }} [opts]
   * @returns {Promise<HostResolution>}
   */
  async resolveHost(name, { signal, resolver, noCache = false, balance = false, timeoutMs, retries } = {}) {
    checkAbort(signal);
    const opts = { signal, resolver, noCache, balance, timeoutMs, retries };
    const [a, aaaa] = await Promise.all([this.query(name, 'A', opts), this.query(name, 'AAAA', opts)]);
    return hostResolutionFrom(name, a, aaaa);
  }

  /**
   * Detect a wildcard record below `domain` by resolving two random labels.
   * A probe is a hit when it answered NOERROR with addresses, or with a CNAME
   * chain whatever the final rcode: a `*` CNAME to a target that no longer
   * exists answers NXDOMAIN with the CNAME (RFC 6604), the takeover-prone case
   * (detectWildcardDeep classifies it the same way).
   * Extensions: `probes` ([{ name, status }]), `ttl`, `error` (set when no
   * probe got a DNS answer — the result is then inconclusive, wildcard=false),
   * `dangling` (every hit's chain ends in NXDOMAIN with no address).
   * @param {string} domain
   * @param {{ signal?: AbortSignal }} [opts]
   * @returns {Promise<{ wildcard: boolean, ipv4: string[], ipv6: string[], cnames: string[] }>}
   */
  async detectWildcard(domain, { signal } = {}) {
    checkAbort(signal);
    const base = normalizeHostname(String(domain ?? ''), { allowSingleLabel: true });
    if (!base) {
      return { wildcard: false, ipv4: [], ipv6: [], cnames: [], probes: [], ttl: null, error: 'Invalid domain', dangling: false };
    }
    const names = [`${randomLabel(12)}.${base}`, `${randomLabel(12)}.${base}`];
    const results = await Promise.all(names.map((n) => this.resolveHost(n, { signal })));
    const hits = results.filter((r) => r.status !== 'ERROR'
      && (r.cnames.length || (r.status === 'NOERROR' && (r.ipv4.length || r.ipv6.length))));
    const merge = (key) => {
      const out = [];
      for (const r of hits) for (const v of r[key]) if (!out.includes(v)) out.push(v);
      return key === 'cnames' ? out : out.sort();
    };
    const answered = results.some((r) => r.status !== 'ERROR');
    const ttls = hits.map((r) => r.ttl).filter((t) => Number.isFinite(t));
    return {
      wildcard: hits.length > 0,
      ipv4: merge('ipv4'),
      ipv6: merge('ipv6'),
      cnames: hits.length ? [...hits[0].cnames] : [],
      probes: results.map((r) => ({ name: r.name, status: r.status })),
      ttl: ttls.length ? Math.min(...ttls) : null,
      error: answered ? null : results[0].error,
      dangling: hits.length > 0 && hits.every((r) => r.status === 'NXDOMAIN' && !r.ipv4.length && !r.ipv6.length)
    };
  }

  /**
   * Reverse DNS (PTR) names of an IP address. Invalid IPs and failed lookups
   * yield []. RFC 2317 CNAME-delegated PTRs are followed by the resolver.
   * @param {string} ip
   * @param {{ signal?: AbortSignal, resolver?: string, throwOnError?: boolean }} [opts]
   *   throwOnError (extension): a lookup that got no DNS answer, or an rcode other than NOERROR /
   *   NXDOMAIN (SERVFAIL, REFUSED …), rejects with an Error (`kind`: util.errorKind() of the failure,
   *   `retryAfterMs` when known, `rcode` for an answer such as SERVFAIL) instead of yielding [] — so a
   *   caller can tell "no PTR record" from "could not ask" (lib/ipintel.js, lib/sourcestatus.js)
   * @returns {Promise<string[]>}
   */
  async ptr(ip, { signal, resolver, throwOnError = false } = {}) {
    checkAbort(signal);
    let qname;
    try {
      qname = reversePtrName(ip);
    } catch {
      return [];
    }
    const res = await this.query(qname, 'PTR', { signal, resolver });
    if (throwOnError && (!res.ok || (res.rcode !== 'NOERROR' && res.rcode !== 'NXDOMAIN'))) {
      const err = new Error(res.ok ? `PTR lookup answered ${res.rcode}` : res.error || 'PTR lookup failed');
      err.kind = res.ok ? 'unknown' : res.errorKind || 'unknown';
      // A broken reverse delegation answers SERVFAIL every time: said as such, not as "failed".
      if (res.ok) err.rcode = res.rcode;
      if (Number.isFinite(res.retryAfterMs)) err.retryAfterMs = res.retryAfterMs;
      throw err;
    }
    if (!res.ok || res.rcode !== 'NOERROR') return [];
    const out = [];
    for (const rr of res.answers) {
      if (rr.type === 'PTR' && typeof rr.data === 'string' && !out.includes(rr.data)) out.push(rr.data);
    }
    return out;
  }

  /* ---------------------------------------------------------------------- */
  /* Internals                                                              */
  /* ---------------------------------------------------------------------- */

  #lookupResolver(entry) {
    if (typeof entry === 'string') return this.#resolverDefs.get(entry) || null;
    if (entry && typeof entry === 'object' && typeof entry.id === 'string' && typeof entry.url === 'string') {
      return entry;
    }
    return null;
  }

  #failed(response) {
    this.#counters.failures += 1;
    return response;
  }

  #resolverStats(id) {
    let s = this.#byResolver.get(id);
    if (!s) {
      s = { ok: 0, fail: 0, totalMs: 0, lastError: null };
      this.#byResolver.set(id, s);
    }
    return s;
  }

  #recordSuccess(id, elapsedMs) {
    const s = this.#resolverStats(id);
    s.ok += 1;
    s.totalMs += elapsedMs;
    this.#health.delete(id);
  }

  #recordFailure(id, err) {
    const s = this.#resolverStats(id);
    s.fail += 1;
    s.lastError = describeError(err);
    const h = this.#health.get(id) || { consecutive: 0, downUntil: 0, probeUntil: 0 };
    h.consecutive += 1;
    h.probeUntil = 0;
    if (h.consecutive >= BREAKER_THRESHOLD) h.downUntil = this.#now() + BREAKER_COOLDOWN_MS;
    this.#health.set(id, h);
  }

  /**
   * Should `id` be treated as down right now? True while its breaker is open,
   * and — once the cooldown is over (half-open) — while a trial request is in
   * flight. With `claimProbe`, the caller that finds the resolver half-open and
   * idle becomes that trial request (only one per request timeout).
   */
  #breakerDown(id, { claimProbe = false } = {}) {
    const h = this.#health.get(id);
    if (!h || h.consecutive < BREAKER_THRESHOLD) return false;
    const now = this.#now();
    if (h.downUntil > now || h.probeUntil > now) return true;
    if (claimProbe) h.probeUntil = now + this.#timeoutMs;
    return false;
  }

  /** Chain order with resolvers whose breaker is open moved to the end. */
  #orderedChain() {
    const up = [];
    const down = [];
    for (const r of this.#chain) (this.#breakerDown(r.id) ? down : up).push(r);
    return [...up, ...down];
  }

  /** The pool bulk queries rotate across: the default one intersected with the chain. */
  #rotatingPool() {
    if (this.#balancePoolExplicit) return this.#balancePool;
    const chainIds = new Set(this.#chain.map((r) => r.id));
    const inChain = this.#balancePool.filter((r) => chainIds.has(r.id));
    return inChain.length ? inChain : this.#chain;
  }

  /**
   * Balance-mode failover list: the pool rotated by a per-client cursor so each
   * bulk query starts on a different resolver, with browser-unreliable
   * resolvers (h3-no-cors) and breaker-open ones pushed to the end (used only
   * as failover), followed by any remaining chain resolvers as a final failover.
   *
   * The rotating set respects the user's chain: the built-in default pool is
   * intersected with the chain (so removing Google from the chain also removes
   * it from bulk traffic, and a chain of only unusual resolvers still gets
   * queried); an explicitly configured pool is honoured as given. When every
   * rotating candidate is unreachable, the ordered chain is still appended, so
   * bulk queries fail over to a working resolver instead of returning ERROR.
   */
  #balancedChain() {
    const rotatingPool = this.#rotatingPool();
    const reliable = [];
    const unreliable = [];
    const down = [];
    for (const r of rotatingPool) {
      if (this.#breakerDown(r.id)) down.push(r);
      else if (r.browserReliable === false) unreliable.push(r);
      else reliable.push(r);
    }
    const rot = reliable.length ? this.#balanceCursor % reliable.length : 0;
    this.#balanceCursor = (this.#balanceCursor + 1) % 1e9;
    const rotated = reliable.length ? [...reliable.slice(rot), ...reliable.slice(0, rot)] : [];
    // Append the rest of the chain (breaker order) as failover, de-duplicated,
    // so a query is never stranded when the whole rotating pool is down.
    const listed = new Set([...rotated, ...unreliable, ...down].map((r) => r.id));
    const chainFailover = this.#orderedChain().filter((r) => !listed.has(r.id));
    const list = [...rotated, ...unreliable, ...chainFailover, ...down];
    return list.length ? list : this.#orderedChain();
  }

  /**
   * Share one network resolution between identical concurrent queries. The
   * shared work is cancelled only when every caller waiting for it aborted.
   */
  #shared(key, work, signal) {
    let entry = this.#inflight.get(key);
    if (!entry) {
      const ctl = new AbortController();
      entry = { ctl, refs: 0, promise: null };
      const created = entry;
      created.promise = work(ctl.signal).finally(() => {
        if (this.#inflight.get(key) === created) this.#inflight.delete(key);
      });
      created.promise.catch(() => {});
      this.#inflight.set(key, created);
    } else {
      this.#counters.shared += 1;
    }
    const current = entry;
    current.refs += 1;
    return new Promise((resolve, reject) => {
      let done = false;
      const release = () => {
        current.refs -= 1;
        if (current.refs <= 0 && !current.ctl.signal.aborted) {
          if (this.#inflight.get(key) === current) this.#inflight.delete(key);
          current.ctl.abort(new AbortError('All callers cancelled'));
        }
      };
      const onAbort = () => {
        if (done) return;
        done = true;
        release();
        reject(toAbortError(signal.reason));
      };
      if (signal) {
        if (signal.aborted) {
          onAbort();
          return;
        }
        signal.addEventListener('abort', onAbort, { once: true });
      }
      current.promise.then(
        (value) => {
          if (done) return;
          done = true;
          if (signal) signal.removeEventListener('abort', onAbort);
          current.refs -= 1;
          resolve(value);
        },
        (err) => {
          if (done) return;
          done = true;
          if (signal) signal.removeEventListener('abort', onAbort);
          current.refs -= 1;
          reject(err);
        }
      );
    });
  }

  #backoff(pass, lastError) {
    const retryAfter = lastError && Number.isFinite(lastError.retryAfterMs) ? lastError.retryAfterMs : null;
    if (retryAfter !== null) return Math.min(retryAfter, this.#maxDelayMs);
    const exp = Math.min(this.#maxDelayMs, this.#baseDelayMs * 2 ** (pass - 1));
    return Math.round(exp / 2 + Math.random() * (exp / 2));
  }

  /** Resolve one (de-duplicated) query over the chain or the explicit resolver. */
  async #run(ctx, signal) {
    const started = clock();
    const explicit = !!ctx.targets;
    const list = explicit ? ctx.targets : (ctx.chainList || this.#orderedChain());
    const attempts = [];
    let dnsFailure = null;
    let lastError = null;
    let lastResolver = list[0].id;
    let pending = list;

    // If every candidate's breaker is already open (a blocked / offline pool),
    // one pass is enough — a retry pass would only re-send doomed requests and
    // stall the sweep for another full timeout each.
    const allDown = !explicit && list.every((r) => this.#breakerDown(r.id));
    const maxRetries = allDown ? 0 : ctx.retries;
    for (let pass = 0; pass <= maxRetries && pending.length; pass += 1) {
      if (pass > 0) {
        try {
          await sleep(this.#backoff(pass, lastError), signal);
        } catch {
          throw toAbortError(signal.reason);
        }
      }
      const retryNext = [];
      const queue = pending.slice();
      const deferred = new Set();
      while (queue.length) {
        const r = queue.shift();
        let result;
        try {
          result = await this.#limiter.run(async () => {
            // The order was fixed when the query started; the breaker may have opened (or a
            // half-open trial started) while this query waited for a slot. Try the others
            // first then — this resolver is still tried last in the pass if nobody answers.
            if (!explicit) {
              const down = this.#breakerDown(r.id, { claimProbe: true });
              if (down && queue.length && !deferred.has(r.id)) return SKIPPED;
            }
            // Health is recorded before the slot is released, so the next queued request
            // already sees an opened breaker.
            try {
              const out = await this.#request(r, ctx, signal);
              this.#recordSuccess(r.id, out.elapsedMs);
              return out;
            } catch (err) {
              if (!signal.aborted) this.#recordFailure(r.id, err);
              throw err;
            }
          }, { signal });
        } catch (err) {
          if (signal.aborted) throw toAbortError(signal.reason);
          attempts.push({ resolver: r.id, ok: false, error: describeError(err), errorKind: errorKind(err) });
          lastError = err;
          lastResolver = r.id;
          if (isRetryable(err)) retryNext.push(r);
          continue;
        }
        if (result === SKIPPED) {
          deferred.add(r.id);
          queue.push(r);
          continue;
        }
        const resp = messageResponse(ctx.qname, ctx.typeName, r.id, result.msg, result.elapsedMs);
        attempts.push({ resolver: r.id, ok: true, rcode: resp.rcode, elapsedMs: resp.elapsedMs });
        if (!explicit && FAILOVER_RCODES.has(resp.rcode)) {
          if (!dnsFailure) dnsFailure = resp;
          continue;
        }
        return this.#complete(ctx, resp, attempts, started);
      }
      if (dnsFailure) break; // some resolver answered: do not retry the transport failures
      pending = retryNext;
    }
    if (dnsFailure) return this.#complete(ctx, dnsFailure, attempts, started);
    const totalMs = Math.round(clock() - started);
    return failureResponse(ctx.qname, ctx.typeName, lastResolver, describeError(lastError), errorKind(lastError), {
      attempts, totalMs, elapsedMs: totalMs
    });
  }

  #complete(ctx, resp, attempts, started) {
    const final = { ...resp, attempts, totalMs: Math.round(clock() - started) };
    this.#store(ctx.key, final);
    return final;
  }

  /** Cache an answer for its TTL (clamped); negative answers use the SOA minimum. */
  #store(key, resp) {
    if (!this.#cache || !resp.ok) return;
    let ttl = null;
    if (resp.rcode === 'NOERROR' && resp.answers.length) {
      ttl = minTtl(resp.answers);
    } else if (resp.rcode === 'NOERROR' || resp.rcode === 'NXDOMAIN') {
      const soa = resp.authorities.find((rr) => rr.type === 'SOA');
      ttl = soa ? Math.min(soa.ttl, Number(soa.data && soa.data.minimum) || soa.ttl) : 60;
    } else {
      ttl = this.#minCacheTtl; // SERVFAIL / REFUSED: short, only to absorb bursts
    }
    const seconds = clamp(Number.isFinite(ttl) ? ttl : 60, this.#minCacheTtl, this.#maxCacheTtl);
    if (seconds <= 0) return;
    try {
      this.#cache.set(key, resp, seconds * 1000);
    } catch {
      /* a custom cache must never break a query */
    }
  }

  /** One HTTP request; resolves with the decoded message or throws. */
  async #request(r, ctx, signal) {
    const json = r.format === 'json';
    const J = json ? await loadJson() : null;
    this.#counters.requests += 1;
    const t0 = clock();
    const timeoutMs = ctx.timeoutMs;
    const timeoutCtl = new AbortController();
    const timer = setTimeout(() => {
      timeoutCtl.abort(new TimeoutError(`${r.id}: no answer within ${timeoutMs} ms`, { timeoutMs }));
    }, timeoutMs);
    const linked = signal ? mergeSignals(signal, timeoutCtl.signal) : timeoutCtl.signal;
    const url = json
      ? J.dnsJsonUrl(r.url, { name: ctx.qname, type: ctx.typeNum, ecs: ctx.ecs })
      : `${r.url}${r.url.includes('?') ? '&' : '?'}dns=${ctx.wire}`;
    try {
      const res = await fetchWithTimeout(url, {
        fetchImpl: this.#fetchImpl,
        signal: linked,
        timeoutMs: 0, // our own timer covers headers and body
        method: 'GET',
        headers: { accept: json ? J.DNS_JSON : DNS_MESSAGE },
        credentials: 'omit',
        referrerPolicy: 'no-referrer',
        cache: ctx.noCache ? 'no-store' : 'default'
      });
      if (!res.ok) {
        const body = await readSnippet(res, linked);
        const retryAfterMs = res.headers && typeof res.headers.get === 'function'
          ? parseRetryAfter(res.headers.get('retry-after'))
          : null;
        throw new HttpError(res.status, url, body, { statusText: res.statusText || '', retryAfterMs });
      }
      const bytes = new Uint8Array(await raceSignal(res.arrayBuffer(), linked));
      if (bytes.length > (json ? MAX_JSON : MAX_MESSAGE)) throw new DnsWireError(`DoH response larger than ${json ? MAX_JSON : MAX_MESSAGE} bytes`);
      const msg = json ? J.decodeDnsJson(parseJsonBody(bytes)) : decodeMessage(bytes);
      if (!msg.flags.qr) throw new DnsWireError('DoH response is not a DNS response (QR=0)');
      const q = msg.questions[0];
      if (q && (canonicalName(q.name) !== ctx.qname || q.typeNum !== ctx.typeNum)) {
        throw new DnsWireError(`DoH response is for ${q.name}/${q.type}, not ${ctx.qname}/${ctx.typeName}`);
      }
      return { msg, elapsedMs: Math.round(clock() - t0) };
    } catch (err) {
      if (signal && signal.aborted) throw toAbortError(signal.reason);
      if (timeoutCtl.signal.aborted) {
        throw err instanceof TimeoutError ? err : new TimeoutError(`${r.id}: no answer within ${timeoutMs} ms`, { cause: err, timeoutMs });
      }
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }
}
