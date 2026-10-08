/**
 * reverseip.js — "Domains on this IP" (reverse IP v2): every name tied to an address, from several
 * sources, normalised, merged with the source and the first / last sighting of each, then checked
 * in DNS as it is now (here / moved elsewhere / behind a CDN / does not resolve / lookup failed).
 *
 * Sources (response shapes and CORS checked live on 2026-10-08 with an Origin header):
 *  - workspace: what the view already knows — origin map entries at the address (their names), and
 *    the servers of the server list that hold it (named in a note, never as names: server names
 *    are never sent anywhere);
 *  - ptr: reverse DNS through the shared DohClient; the forward check below confirms it (FCrDNS);
 *  - hackertarget, thc: lib/ipintel.js `reverseIp` / `reverseIpThc` (their quotas, caches, parsers);
 *  - otx: AlienVault OTX passive DNS, GET /api/v1/indicators/IPv4|IPv6/{ip}/passive_dns →
 *    `{ passive_dns: [{ hostname, address, first, last, record_type, … }], count }` (UTC times without
 *    a zone); ACAO reflects the origin. Slow for a busy address (1.1.1.1 took over 25 s);
 *  - robtex: Robtex free API, GET /pdns/reverse/{ip} → ndjson lines `{ rrname, rrdata, rrtype,
 *    time_first, time_last, count }` (Unix seconds); ACAO reflects the origin;
 *  - internetdb: Shodan InternetDB, GET /{ip} → `{ ip, hostnames, ports, tags, vulns, cpes }`, HTTP 404
 *    `{ detail: 'No information available' }` for an address it does not know; ACAO *. Free for
 *    non-commercial use; a burst of requests locks a client out for about an hour, so it is asked
 *    one address at a time, on demand, and its first 429 stops it until the lock ends;
 *  - shodan (the user's key): Shodan API, GET /shodan/host/{ip}?key= → `{ hostnames, domains, ports,
 *    … }`, HTTP 401 text for a bad key, 404 for an unknown address; ACAO *;
 *  - whoisxml (the user's key): WhoisXML API reverse IP, GET /api/v1?apiKey=&ip= → `{ result:
 *    [{ name, first_seen, last_visit }], size, current_page }`, HTTP 403 `{ code, messages }` for a bad
 *    key or no credits; ACAO *.
 *
 * Names are normalised (case, trailing dot, punycode, a leading `*.` dropped) and junk is dropped
 * (addresses written as names, reverse-zone names, invalid labels). A private or reserved address
 * never goes to a third party — not even to the DNS resolver as a PTR question: only the
 * workspace's data is used. A user's API key is used for one request per address and is never
 * kept, logged or put in a result or an error message. Only an abort rejects: every other failure
 * is a source status (lib/sourcestatus.js). DOM-free; runs in browsers and Node 22; all I/O is
 * injectable. lib/netinfo.js (the CDN classification) is loaded on the first check that needs it.
 */

import { fetchJson, fetchText, createLimiter, createCache, errorKind, HttpError, throwIfAborted, onceAsync, sleep } from './util.js';
import { normalizeIP, ipVersion, isPrivateIP, isGloballyRoutable, ipInCidr } from './ip.js';
import { normalizeHostname, registrableDomain, sortHostnames } from './domain.js';

/** AlienVault OTX indicators API base (`/IPv4/{ip}/passive_dns`, `/IPv6/{ip}/passive_dns`). */
export const OTX_INDICATORS = 'https://otx.alienvault.com/api/v1/indicators';
/** Robtex free passive-DNS API: names seen pointing at an address (ndjson). */
export const ROBTEX_PDNS_REVERSE = 'https://freeapi.robtex.com/pdns/reverse/';
/** Shodan InternetDB (free, non-commercial, no key): `/{ip}`. */
export const INTERNETDB_BASE = 'https://internetdb.shodan.io/';
/** Shodan API host lookup (`/{ip}?key=`), with the key the user types. */
export const SHODAN_HOST = 'https://api.shodan.io/shodan/host/';
/** WhoisXML API reverse IP (`?apiKey=&ip=`), with the key the user types. */
export const WHOISXML_REVERSE_IP = 'https://reverse-ip.whoisxmlapi.com/api/v1';

/** Every source, in the order the panel shows them. */
export const REVERSE_SOURCES = Object.freeze(['workspace', 'ptr', 'hackertarget', 'thc', 'otx', 'robtex', 'internetdb', 'shodan', 'whoisxml']);
/** The sources that need a key the user types (never stored). */
export const KEYED_SOURCES = Object.freeze(['shodan', 'whoisxml']);
/** Why a source was not asked: a private / reserved address, no key typed, InternetDB's lockout, no DNS client. */
export const SKIP_REASONS = Object.freeze(['local', 'no-key', 'locked', 'no-dns']);
/**
 * What the DNS check says of a name: `pending` while it runs, `unchecked` before (or beyond the
 * batch); never sent: `internal` (it looks internal) and `workspace` (only the workspace knows it,
 * and the workspace is never sent).
 */
export const NAME_STATUSES = Object.freeze(['pending', 'here', 'moved', 'cdn', 'none', 'failed', 'internal', 'workspace', 'unchecked']);
/** Names checked per batch ("Check more" asks the next batch). */
export const VERIFY_BATCH = 300;
/** Addresses per lookup at most. */
export const MAX_REVERSE_IPS = 10;
/** How long InternetDB locks a client out after a burst when it does not say (about an hour). */
export const INTERNETDB_LOCK_MS = 60 * 60 * 1000;
/** Names kept per source and address (a shared host can carry hundreds of thousands). */
export const MAX_NAMES_PER_SOURCE = 5000;

const DEFAULT_TIMEOUT_MS = 15000;
// OTX answers a busy address slowly (over 25 s for 1.1.1.1, checked 2026-10-08).
const SLOW_TIMEOUT_MS = 45000;
const CACHE_TTL_MS = 30 * 60 * 1000;
// Documentation ranges are reserved, but they hold no server, so asking about one tells nobody
// anything: they stay usable, which lets the offline tests run the real path.
const DOCUMENTATION = Object.freeze(['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32', '3fff::/20']);
// Names under these never go to a public resolver (lib/zoneorigins.js INTERNAL_SUFFIXES).
const INTERNAL_SUFFIXES = Object.freeze(['local', 'internal', 'lan', 'corp', 'home.arpa', 'localhost', 'invalid', 'test']);
// Sanity bounds of a "seen" time (ms): after 1990, at most a day in the future.
const MIN_TIME = Date.UTC(1990, 0, 1);
const DAY = 24 * 60 * 60 * 1000;

const loadNetinfo = onceAsync(() => import('./netinfo.js'));
// Statuses of names that are never sent to a resolver.
const NEVER_SENT = Object.freeze(['internal', 'workspace']);

/**
 * @typedef {object} NameHit one name a source tied to the address
 * @property {string} name normalised host name
 * @property {number|null} first first seen (ms), when the source says
 * @property {number|null} last last seen (ms), when the source says
 */

/**
 * @typedef {object} SourceResult what one source said of one address
 * @property {string} source a {@link REVERSE_SOURCES} id
 * @property {'ok'|'failed'|'skipped'} state
 * @property {string|null} skip a {@link SKIP_REASONS} code when skipped
 * @property {NameHit[]} names
 * @property {number|null} total how many names the source holds, when it says (more than `names` when cut)
 * @property {boolean} truncated the source holds more names than it gave
 * @property {object|null} failure a lib/sourcestatus.js SourceFailure (`{ source, error, errorKind, status,
 *   retryAfterMs, limited, rcode?, at }`), when failed or locked out
 * @property {object|null} extra internetdb / shodan: `{ ports, tags, vulns, cpes }`; workspace: `{ servers }`
 * @property {number} at when it answered (ms)
 */

/**
 * @typedef {object} IpReverse every source's answer for one address
 * @property {string} ip canonical address
 * @property {boolean} local private or reserved: only the workspace was used
 * @property {Record<string, SourceResult>} results by source id
 * @property {number} at
 */

/**
 * @typedef {object} NameRow one name of the merged table
 * @property {string} name
 * @property {string|null} domain its registrable domain
 * @property {string[]} ips the looked-up addresses it was found on
 * @property {string[]} sources {@link REVERSE_SOURCES} order
 * @property {number|null} first earliest sighting any source gave (ms)
 * @property {number|null} last latest sighting (ms)
 * @property {string} status a {@link NAME_STATUSES} code
 * @property {string[]} resolvesTo its addresses now (after a check)
 * @property {string|null} provider the CDN / proxy in front of it (status `cdn`)
 * @property {string|null} rcode the DNS status of a failed check
 * @property {string|null} error the failed check's message
 */

/* ------------------------------------------------------------------------ */
/* Pure helpers and parsers (exported for tests and reuse)                  */
/* ------------------------------------------------------------------------ */

/**
 * Is this address kept from every third party (private, or reserved and not a documentation
 * range)? Such an address is answered from the workspace alone. Invalid input counts as local.
 * @param {string} ip
 * @returns {boolean}
 */
export function isLocalOnly(ip) {
  const n = normalizeIP(String(ip ?? ''));
  if (!n || isPrivateIP(n)) return true;
  if (isGloballyRoutable(n)) return false;
  return !DOCUMENTATION.some((c) => ipInCidr(n, c));
}

/**
 * A name as a source wrote it, normalised: lower case, no trailing dot, punycode, a leading `*.`
 * dropped. Junk is null: an address written as a name, a reverse-zone name, a single label, an
 * invalid label.
 * @param {unknown} raw
 * @returns {string|null}
 */
export function normalizeName(raw) {
  if (typeof raw !== 'string') return null;
  let s = raw.trim();
  while (s.startsWith('*.')) s = s.slice(2);
  s = s.replace(/^\.+/, '');
  if (!s || normalizeIP(s.replace(/\.$/, ''))) return null;
  const host = normalizeHostname(s);
  if (!host || host.endsWith('.in-addr.arpa') || host.endsWith('.ip6.arpa')) return null;
  return host;
}

/**
 * Does a name look internal (a single label or under .local, .internal, .lan, .corp, .home.arpa …)?
 * Such a name is never sent to a public resolver.
 * @param {string} name
 * @returns {boolean}
 */
export function looksInternal(name) {
  const n = String(name ?? '').toLowerCase();
  if (!n.includes('.')) return true;
  return INTERNAL_SUFFIXES.some((s) => n === s || n.endsWith(`.${s}`));
}

/**
 * A time a source gave: ms (or Unix seconds with `seconds`), or an ISO string (one without a zone
 * is UTC). Null for anything else, before 1990 or more than a day after `now`.
 * @param {unknown} value
 * @param {{ seconds?: boolean, now?: number }} [opts]
 * @returns {number|null} ms
 */
export function seenTime(value, { seconds = false, now = Date.now() } = {}) {
  let ms = null;
  if (typeof value === 'number' && Number.isFinite(value)) ms = seconds ? value * 1000 : value;
  else if (typeof value === 'string' && value.trim()) {
    const s = value.trim();
    if (/^\d+$/.test(s)) ms = Number(s) * (seconds ? 1000 : 1);
    else if (/^\d{4}-\d\d-\d\d$/.test(s)) ms = Date.parse(`${s}T00:00:00Z`);
    else ms = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? s : `${s.replace(' ', 'T')}Z`);
  }
  return Number.isFinite(ms) && ms >= MIN_TIME && ms <= now + DAY ? ms : null;
}

/** Hits from a list of `{ name, first, last }`: normalised, merged per name, at most {@link MAX_NAMES_PER_SOURCE}. */
function hitsOf(list) {
  const byName = new Map();
  for (const item of list) {
    const name = normalizeName(item.name);
    if (!name) continue;
    const prev = byName.get(name);
    if (!prev) {
      if (byName.size >= MAX_NAMES_PER_SOURCE) continue;
      byName.set(name, { name, first: item.first ?? null, last: item.last ?? null });
      continue;
    }
    prev.first = minTime(prev.first, item.first ?? null);
    prev.last = maxTime(prev.last, item.last ?? null);
  }
  return [...byName.values()];
}

const minTime = (a, b) => (a === null ? b : b === null ? a : Math.min(a, b));
const maxTime = (a, b) => (a === null ? b : b === null ? a : Math.max(a, b));

/**
 * Read an OTX passive-DNS answer for an address.
 * @param {unknown} json
 * @param {{ now?: number }} [opts]
 * @returns {{ ok: boolean, names: NameHit[], total: number|null, error: string|null }}
 */
export function parseOtxPassiveDns(json, { now = Date.now() } = {}) {
  if (!json || typeof json !== 'object' || !Array.isArray(json.passive_dns)) {
    return { ok: false, names: [], total: null, error: 'Unexpected OTX response (no passive_dns list)' };
  }
  const names = hitsOf(json.passive_dns.filter((r) => r && typeof r === 'object').map((r) => ({
    name: r.hostname, first: seenTime(r.first, { now }), last: seenTime(r.last, { now })
  })));
  const total = Number.isFinite(json.count) ? json.count : null;
  return { ok: true, names, total, error: null };
}

/**
 * Read a Robtex `pdns/reverse` answer (ndjson; a blank body is "nothing seen").
 * @param {string} text
 * @param {{ now?: number }} [opts]
 * @returns {{ ok: boolean, names: NameHit[], error: string|null }}
 */
export function parseRobtexReverse(text, { now = Date.now() } = {}) {
  const lines = String(text ?? '').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const list = [];
  let bad = 0;
  for (const line of lines) {
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      bad += 1;
      continue;
    }
    if (!rec || typeof rec !== 'object' || typeof rec.rrname !== 'string') {
      bad += 1;
      continue;
    }
    list.push({ name: rec.rrname, first: seenTime(rec.time_first, { seconds: true, now }), last: seenTime(rec.time_last, { seconds: true, now }) });
  }
  if (!list.length && bad) return { ok: false, names: [], error: `Unexpected Robtex response: ${lines[0].slice(0, 120)}` };
  return { ok: true, names: hitsOf(list), error: null };
}

/** Numbers / strings of a list field, cleaned. */
const numList = (v) => (Array.isArray(v) ? [...new Set(v.filter((x) => Number.isInteger(x) && x >= 0 && x <= 65535))].sort((a, b) => a - b) : []);
const strList = (v) => (Array.isArray(v) ? [...new Set(v.filter((x) => typeof x === 'string' && x.trim()).map((x) => x.trim().slice(0, 80)))] : []);

/**
 * Read a Shodan InternetDB answer: its host names, and the open ports, tags, known
 * vulnerabilities and CPEs it holds for the address.
 * @param {unknown} json
 * @returns {{ ok: boolean, names: NameHit[], extra: { ports: number[], tags: string[], vulns: string[], cpes: string[] }|null, error: string|null }}
 */
export function parseInternetDb(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json) || !('hostnames' in json || 'ports' in json)) {
    return { ok: false, names: [], extra: null, error: 'Unexpected InternetDB response' };
  }
  const names = hitsOf(strList(json.hostnames).map((name) => ({ name, first: null, last: null })));
  return { ok: true, names, extra: { ports: numList(json.ports), tags: strList(json.tags), vulns: strList(json.vulns), cpes: strList(json.cpes) }, error: null };
}

/**
 * Read a Shodan API host answer: its host names and domains (and the open ports it lists).
 * @param {unknown} json
 * @param {{ now?: number }} [opts]
 * @returns {{ ok: boolean, names: NameHit[], extra: object|null, error: string|null }}
 */
export function parseShodanHost(json, { now = Date.now() } = {}) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return { ok: false, names: [], extra: null, error: 'Unexpected Shodan response' };
  if (typeof json.error === 'string' && !('hostnames' in json)) return { ok: false, names: [], extra: null, error: `Shodan: ${json.error.slice(0, 160)}` };
  const last = seenTime(json.last_update, { now });
  const names = hitsOf([...strList(json.hostnames), ...strList(json.domains)].map((name) => ({ name, first: null, last })));
  return { ok: true, names, extra: { ports: numList(json.ports), tags: strList(json.tags), vulns: Array.isArray(json.vulns) ? strList(json.vulns) : strList(Object.keys(json.vulns || {})), cpes: strList(json.cpes) }, error: null };
}

/**
 * Read a WhoisXML reverse-IP answer.
 * @param {unknown} json
 * @param {{ now?: number }} [opts]
 * @returns {{ ok: boolean, names: NameHit[], total: number|null, error: string|null }}
 */
export function parseWhoisXmlReverse(json, { now = Date.now() } = {}) {
  if (!json || typeof json !== 'object' || Array.isArray(json)) return { ok: false, names: [], total: null, error: 'Unexpected WhoisXML response' };
  const list = Array.isArray(json.result) ? json.result : Array.isArray(json.results) ? json.results : null;
  if (!list) {
    const msg = typeof json.messages === 'string' ? json.messages : typeof json.message === 'string' ? json.message : 'no result list';
    return { ok: false, names: [], total: null, error: `WhoisXML: ${msg.slice(0, 160)}` };
  }
  const names = hitsOf(list.filter((r) => r && typeof r === 'object').map((r) => ({
    name: r.name ?? r.domain, first: seenTime(r.first_seen, { seconds: true, now }), last: seenTime(r.last_visit ?? r.last_seen, { seconds: true, now })
  })));
  const size = Number(json.size);
  return { ok: true, names, total: Number.isFinite(size) && size >= names.length ? size : null, error: null };
}

/** OTX passive-DNS URL of an address. */
export const otxUrl = (ip) => `${OTX_INDICATORS}/${ipVersion(ip) === 6 ? 'IPv6' : 'IPv4'}/${ip}/passive_dns`;
/** Robtex reverse URL of an address. */
export const robtexUrl = (ip) => `${ROBTEX_PDNS_REVERSE}${ip}`;
/** InternetDB URL of an address. */
export const internetDbUrl = (ip) => `${INTERNETDB_BASE}${ip}`;

/**
 * Merge every address's answers into one row per name: the addresses and sources it came from,
 * the earliest and latest sighting. Rows keep the check of `previous` rows of the same name (a
 * Retry adds sources without losing it). A name that looks internal, or that only the workspace
 * knows, is never checked (`internal` / `workspace`). Sorted like lib/domain.js sortHostnames.
 * @param {IpReverse[]} lookups
 * @param {{ previous?: NameRow[] }} [opts]
 * @returns {NameRow[]}
 */
export function mergeNames(lookups, { previous = [] } = {}) {
  const prev = new Map((previous || []).map((r) => [r.name, r]));
  const rows = new Map();
  for (const lookup of lookups || []) {
    if (!lookup || !lookup.results) continue;
    for (const source of REVERSE_SOURCES) {
      const res = lookup.results[source];
      if (!res || res.state !== 'ok') continue;
      for (const hit of res.names) {
        let row = rows.get(hit.name);
        if (!row) {
          const old = prev.get(hit.name);
          row = {
            name: hit.name, domain: registrableDomain(hit.name), ips: [], sources: [], first: null, last: null, status: 'unchecked',
            resolvesTo: old ? [...old.resolvesTo] : [], provider: old ? old.provider : null, rcode: old ? old.rcode : null, error: old ? old.error : null
          };
          rows.set(hit.name, row);
        }
        if (!row.ips.includes(lookup.ip)) row.ips.push(lookup.ip);
        if (!row.sources.includes(source)) row.sources.push(source);
        row.first = minTime(row.first, hit.first);
        row.last = maxTime(row.last, hit.last);
      }
    }
  }
  const out = sortHostnames([...rows.keys()]).map((n) => rows.get(n));
  for (const r of out) {
    r.sources.sort((a, b) => REVERSE_SOURCES.indexOf(a) - REVERSE_SOURCES.indexOf(b));
    const old = prev.get(r.name);
    const kept = looksInternal(r.name) ? 'internal' : r.sources.every((s) => s === 'workspace') ? 'workspace' : null;
    r.status = kept || (old && !NEVER_SENT.includes(old.status) && old.status !== 'pending' ? old.status : 'unchecked');
  }
  return out;
}

/**
 * What a forward lookup says of a name found on `ips`: here (it resolves to one of them), behind
 * a CDN (its addresses are a CDN's / proxy's: the origin cannot be seen in DNS), moved elsewhere,
 * does not resolve (NXDOMAIN, or no address), or failed (no usable answer).
 * @param {{ status?: string, ipv4?: string[], ipv6?: string[], cnames?: string[], error?: string|null }} res
 *   lib/doh.js HostResolution
 * @param {string[]} ips
 * @param {(res: object) => { hidesOrigin?: boolean, provider?: { name?: string }|null }} classify
 *   lib/netinfo.js classifyResolution
 * @returns {{ status: string, resolvesTo: string[], provider: string|null, rcode: string|null, error: string|null }}
 */
export function forwardStatus(res, ips, classify) {
  const r = res && typeof res === 'object' ? res : {};
  const resolvesTo = [...new Set([...(r.ipv4 || []), ...(r.ipv6 || [])].map((a) => normalizeIP(String(a))).filter(Boolean))];
  const st = typeof r.status === 'string' ? r.status.toUpperCase() : 'ERROR';
  const base = { resolvesTo, provider: null, rcode: null, error: null };
  if (resolvesTo.some((a) => ips.includes(a))) return { ...base, status: 'here' };
  if (!resolvesTo.length) {
    if (st === 'NXDOMAIN' || st === 'NOERROR') return { ...base, status: 'none', rcode: st };
    return { ...base, status: 'failed', rcode: st, error: typeof r.error === 'string' ? r.error : null };
  }
  const cls = classify ? classify({ status: st, ipv4: r.ipv4 || [], ipv6: r.ipv6 || [], cnames: r.cnames || [] }) : null;
  if (cls && cls.hidesOrigin) return { ...base, status: 'cdn', provider: cls.provider && cls.provider.name ? cls.provider.name : null };
  return { ...base, status: 'moved' };
}

/**
 * Counts of a table: names per status and per source, and the registrable domains.
 * @param {NameRow[]} rows
 * @returns {{ names: number, byStatus: Record<string, number>, bySource: Record<string, number>, domains: string[] }}
 */
export function reverseCounts(rows) {
  const byStatus = Object.fromEntries(NAME_STATUSES.map((s) => [s, 0]));
  const bySource = Object.fromEntries(REVERSE_SOURCES.map((s) => [s, 0]));
  const domains = new Set();
  for (const r of rows || []) {
    byStatus[r.status] = (byStatus[r.status] || 0) + 1;
    for (const s of r.sources) bySource[s] = (bySource[s] || 0) + 1;
    if (r.domain) domains.add(r.domain);
  }
  return { names: (rows || []).length, byStatus, bySource, domains: sortHostnames([...domains]) };
}

/**
 * The rows of a table as an export: one object per name (dates as ISO strings).
 * @param {NameRow[]} rows
 * @returns {object[]}
 */
export function reverseExportRows(rows) {
  const iso = (ms) => (ms === null || ms === undefined ? null : new Date(ms).toISOString());
  return (rows || []).map((r) => ({
    name: r.name, status: r.status, domain: r.domain, addresses: [...r.ips], sources: [...r.sources],
    firstSeen: iso(r.first), lastSeen: iso(r.last), resolvesTo: [...r.resolvesTo], provider: r.provider, rcode: r.rcode
  }));
}

/* ------------------------------------------------------------------------ */
/* Service                                                                  */
/* ------------------------------------------------------------------------ */

/** A key never appears in a message, whatever an error says. */
function redact(message, keys) {
  let s = String(message ?? '');
  for (const k of keys) if (k) s = s.split(k).join('…');
  return s.slice(0, 300);
}

/**
 * The reverse-IP service: one lookup per address over every source, a Retry of the failed ones,
 * and the DNS check of the merged names.
 * @param {{ fetchImpl?: typeof fetch, dns?: { ptr?: Function, resolveHost?: Function }|null,
 *   intel?: { reverseIp: Function, reverseIpThc: Function }|null, timeoutMs?: number, slowTimeoutMs?: number,
 *   now?: () => number, classify?: Function|null, concurrency?: number, shodanPaceMs?: number }} [opts]
 *   intel: a lib/ipintel.js service (HackerTarget, ip.thc.org); classify: lib/netinfo.js
 *   classifyResolution (loaded on first use when not given); concurrency: DNS checks at once.
 * @returns {{ lookup: Function, retry: Function, verify: Function, lockedUntil: () => number|null }}
 */
export function createReverseIp({
  fetchImpl = globalThis.fetch, dns = null, intel = null, timeoutMs = DEFAULT_TIMEOUT_MS, slowTimeoutMs = SLOW_TIMEOUT_MS,
  now = Date.now, classify = null, concurrency = 8, shodanPaceMs = 1100
} = {}) {
  const verifyLimiter = createLimiter(concurrency);
  // InternetDB one address at a time (a burst locks a client out); Shodan's API takes one a second.
  const internetdbLimiter = createLimiter(1);
  const shodanLimiter = createLimiter(1);
  const cache = createCache({ maxEntries: 500, ttlMs: CACHE_TTL_MS, now });
  let internetdbLock = null;
  let lastShodan = 0;

  const result = (source, fields = {}) => ({
    source, state: 'ok', skip: null, names: [], total: null, truncated: false, failure: null, extra: null, at: now(), ...fields
  });
  const skipped = (source, skip, fields = {}) => result(source, { state: 'skipped', skip, ...fields });
  const failed = (source, failure) => result(source, { state: 'failed', failure: { source, at: now(), status: null, retryAfterMs: null, limited: false, ...failure } });

  /** A thrown error as a failed result (an abort rethrows). */
  function fromError(source, err, keys = []) {
    if (errorKind(err) === 'abort') throw err;
    const status = err instanceof HttpError ? err.status : null;
    const kind = errorKind(err);
    return failed(source, {
      error: err instanceof HttpError ? `HTTP ${err.status}` : redact(err && err.message ? err.message : err, keys),
      errorKind: kind === 'unknown' && err && typeof err.kind === 'string' ? err.kind : kind,
      status,
      retryAfterMs: err && Number.isFinite(err.retryAfterMs) ? err.retryAfterMs : null,
      ...(err && typeof err.rcode === 'string' && err.rcode ? { rcode: err.rcode } : {})
    });
  }

  /** An answer of lib/ipintel.js (ReverseIpResult) as a source result. */
  function fromIntel(source, res) {
    if (res && res.ok) {
      return result(source, {
        names: hitsOf((res.domains || []).map((name) => ({ name, first: null, last: null }))),
        total: Number.isFinite(res.total) ? res.total : null, truncated: !!res.truncated
      });
    }
    return failed(source, { error: (res && res.error) || 'failed', errorKind: (res && res.errorKind) || 'unknown', limited: !!(res && res.limited) });
  }

  async function cached(key, noCache, fn) {
    if (!noCache) {
      const hit = cache.get(key);
      if (hit) return hit;
    }
    const res = await fn();
    if (res.state === 'ok') cache.set(key, res);
    return res;
  }

  /** Ask one source about one (public) address. */
  async function ask(source, ip, { signal, keys, workspace, noCache }) {
    switch (source) {
      case 'workspace': {
        const w = workspace && typeof workspace === 'object' ? workspace : {};
        const names = hitsOf((Array.isArray(w.origins) ? w.origins : []).map((o) => ({
          name: o && o.name, first: seenTime(o && o.first, { now: now() }), last: seenTime(o && o.last, { now: now() })
        })));
        const servers = strList(w.servers);
        return result(source, { names, extra: { servers } });
      }
      case 'ptr': {
        if (!dns || typeof dns.ptr !== 'function') return skipped(source, 'no-dns');
        try {
          const list = await dns.ptr(ip, { signal, throwOnError: true });
          return result(source, { names: hitsOf((list || []).map((name) => ({ name, first: null, last: null }))) });
        } catch (err) {
          return fromError(source, err);
        }
      }
      case 'hackertarget':
      case 'thc': {
        if (!intel) return skipped(source, 'no-dns');
        try {
          const res = source === 'thc' ? await intel.reverseIpThc(ip, { signal, noCache }) : await intel.reverseIp(ip, { signal, noCache });
          return fromIntel(source, res);
        } catch (err) {
          return fromError(source, err);
        }
      }
      case 'otx':
        return cached(`otx ${ip}`, noCache, async () => {
          try {
            const json = await fetchJson(otxUrl(ip), { fetchImpl, signal, timeoutMs: slowTimeoutMs, headers: { accept: 'application/json' } });
            const p = parseOtxPassiveDns(json, { now: now() });
            if (!p.ok) return failed(source, { error: p.error, errorKind: 'parse' });
            return result(source, { names: p.names, total: p.total, truncated: p.total !== null && p.total > p.names.length });
          } catch (err) {
            return fromError(source, err);
          }
        });
      case 'robtex':
        return cached(`robtex ${ip}`, noCache, async () => {
          try {
            const text = await fetchText(robtexUrl(ip), { fetchImpl, signal, timeoutMs });
            const p = parseRobtexReverse(text, { now: now() });
            return p.ok ? result(source, { names: p.names }) : failed(source, { error: p.error, errorKind: 'parse' });
          } catch (err) {
            return fromError(source, err);
          }
        });
      case 'internetdb':
        return cached(`internetdb ${ip}`, noCache, () => internetdbLimiter.run(async () => {
          const locked = lockedFailure();
          if (locked) return locked;
          try {
            const json = await fetchJson(internetDbUrl(ip), { fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' } });
            const p = parseInternetDb(json);
            return p.ok ? result(source, { names: p.names, extra: p.extra }) : failed(source, { error: p.error, errorKind: 'parse' });
          } catch (err) {
            // An address InternetDB does not know is an answer: nothing on it.
            if (err instanceof HttpError && err.status === 404) return result(source, { extra: { ports: [], tags: [], vulns: [], cpes: [] } });
            if (err instanceof HttpError && err.status === 429) {
              const wait = Number.isFinite(err.retryAfterMs) && err.retryAfterMs > 0 ? err.retryAfterMs : INTERNETDB_LOCK_MS;
              internetdbLock = now() + wait;
              return failed(source, { error: 'HTTP 429', errorKind: 'rate-limit', status: 429, retryAfterMs: wait, limited: true });
            }
            return fromError(source, err);
          }
        }, { signal }));
      case 'shodan': {
        const key = keys && typeof keys.shodan === 'string' ? keys.shodan.trim() : '';
        if (!key) return skipped(source, 'no-key');
        return cached(`shodan ${ip}`, noCache, () => shodanLimiter.run(async () => {
          const wait = lastShodan + shodanPaceMs - now();
          if (wait > 0) await sleep(wait, signal);
          lastShodan = now();
          try {
            const json = await fetchJson(`${SHODAN_HOST}${ip}?key=${encodeURIComponent(key)}`, { fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' } });
            const p = parseShodanHost(json, { now: now() });
            return p.ok ? result(source, { names: p.names, extra: p.extra }) : failed(source, { error: redact(p.error, [key]), errorKind: 'parse' });
          } catch (err) {
            // An address Shodan has no record of is an answer: nothing on it.
            if (err instanceof HttpError && err.status === 404) return result(source);
            return fromError(source, err, [key]);
          }
        }, { signal }));
      }
      case 'whoisxml': {
        const key = keys && typeof keys.whoisxml === 'string' ? keys.whoisxml.trim() : '';
        if (!key) return skipped(source, 'no-key');
        return cached(`whoisxml ${ip}`, noCache, async () => {
          try {
            const json = await fetchJson(`${WHOISXML_REVERSE_IP}?apiKey=${encodeURIComponent(key)}&ip=${ip}`, { fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' } });
            const p = parseWhoisXmlReverse(json, { now: now() });
            return p.ok ? result(source, { names: p.names, total: p.total, truncated: p.total !== null && p.total > p.names.length })
              : failed(source, { error: redact(p.error, [key]), errorKind: 'http' });
          } catch (err) {
            return fromError(source, err, [key]);
          }
        });
      }
      default:
        return skipped(source, 'no-dns');
    }
  }

  /** InternetDB's lockout as a failure ("rate limited — try again in N min"), or null when it is over. */
  function lockedFailure() {
    if (internetdbLock === null) return null;
    const left = internetdbLock - now();
    if (left <= 0) {
      internetdbLock = null;
      return null;
    }
    return { ...failed('internetdb', { error: 'HTTP 429', errorKind: 'rate-limit', status: 429, retryAfterMs: left, limited: true }), skip: 'locked' };
  }

  /**
   * Every source's answer for one address. A private or reserved address is answered from the
   * workspace alone (every other source `skipped: 'local'`). `onSource(result)` hears each answer
   * as it comes.
   * @param {string} ip
   * @param {{ sources?: string[], keys?: { shodan?: string, whoisxml?: string }, workspace?: { servers?: string[],
   *   origins?: Array<{ name: string, first?: unknown, last?: unknown }> }|null, signal?: AbortSignal, noCache?: boolean,
   *   onSource?: (r: SourceResult) => void, previous?: IpReverse|null }} [opts]
   * @returns {Promise<IpReverse>}
   */
  async function lookup(ip, { sources = REVERSE_SOURCES, keys = {}, workspace = null, signal, noCache = false, onSource = null, previous = null } = {}) {
    throwIfAborted(signal);
    const canonical = normalizeIP(String(ip ?? ''));
    const local = !canonical || isLocalOnly(canonical);
    const results = previous && previous.results ? { ...previous.results } : {};
    await Promise.all(REVERSE_SOURCES.filter((s) => sources.includes(s)).map(async (source) => {
      const res = local && source !== 'workspace' ? skipped(source, 'local')
        : await ask(source, canonical, { signal, keys, workspace, noCache });
      throwIfAborted(signal);
      results[source] = res;
      if (onSource) onSource(res);
    }));
    return { ip: canonical || String(ip ?? ''), local, results, at: now() };
  }

  /**
   * Ask the failed sources of a lookup again (only those, or those of `sources`), past the cache.
   * @param {IpReverse} prev
   * @param {{ sources?: string[]|null, keys?: object, workspace?: object|null, signal?: AbortSignal, onSource?: Function }} [opts]
   * @returns {Promise<IpReverse>}
   */
  function retry(prev, { sources = null, keys = {}, workspace = null, signal, onSource = null } = {}) {
    const failedSources = REVERSE_SOURCES.filter((s) => prev.results[s] && prev.results[s].state === 'failed' && (!sources || sources.includes(s)));
    return lookup(prev.ip, { sources: failedSources, keys, workspace, signal, noCache: true, onSource, previous: prev });
  }

  /**
   * Check the next `limit` unchecked names in DNS (A / AAAA through the shared DohClient, a few at
   * a time). Each row's status is set in place; `onRow(row)` hears each one. Internal-looking names
   * are never sent (status `internal`). An abort leaves the rest unchecked and rejects.
   * @param {NameRow[]} rows
   * @param {{ signal?: AbortSignal, limit?: number, onRow?: (row: NameRow) => void }} [opts]
   * @returns {Promise<number>} names checked
   */
  async function verify(rows, { signal, limit = VERIFY_BATCH, onRow = null } = {}) {
    throwIfAborted(signal);
    if (!dns || typeof dns.resolveHost !== 'function') return 0;
    const batch = (rows || []).filter((r) => r.status === 'unchecked' && !looksInternal(r.name)).slice(0, Math.max(0, limit));
    if (!batch.length) return 0;
    const fn = classify || (await loadNetinfo()).classifyResolution;
    for (const r of batch) r.status = 'pending';
    try {
      await Promise.all(batch.map((row) => verifyLimiter.run(async () => {
        const res = await dns.resolveHost(row.name, { signal });
        throwIfAborted(signal);
        Object.assign(row, forwardStatus(res, row.ips, fn));
        if (onRow) onRow(row);
      }, { signal })));
    } finally {
      for (const r of batch) if (r.status === 'pending') r.status = 'unchecked';
    }
    return batch.length;
  }

  return { lookup, retry, verify, lockedUntil: () => (internetdbLock !== null && internetdbLock > now() ? internetdbLock : null) };
}
