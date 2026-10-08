/**
 * dnsbl.js — blocklist (DNSBL / RHSBL) reputation of an IP address or a domain over DoH.
 *
 * An IP list is asked for `<reversed address>.<zone>` (RFC 5782: IPv4 octets reversed, IPv6
 * nibbles reversed), a domain list for `<registrable domain>.<zone>`. An A answer in 127.0.0.0/8
 * means "listed" and its code says why (decoded per list); NXDOMAIN means "not listed".
 *
 * Public resolvers: several lists refuse them. Spamhaus answers 127.255.255.254 (and, through
 * Google, NXDOMAIN even for its own test point), URIBL and SURBL answer 127.0.0.1, so a "not
 * listed" through a public resolver can mean nothing. Before a list is trusted, its RFC 5782 test
 * point (127.0.0.2, ::ffff:127.0.0.2, or the documented test domain) is asked through the same
 * resolver: when that does not come back listed, the list is `refused` ("cannot be checked from a
 * public resolver") and the target is never sent to it. A refusal code is decoded per list and is
 * never "listed". The test-point verdict is kept per zone for ten minutes; the target is then asked
 * through the resolver that answered the test point.
 *
 * Lists, codes and test points verified through Cloudflare and Google DoH on 2026-10-08 (SPEC §5.83).
 *
 * Private, reserved and documentation addresses and internal names are never asked
 * (lib/ip.js isGloballyRoutable; special-use suffixes). Only an abort rejects: every other failure
 * is a per-list status.
 *
 * DOM-free: takes `{ dns }` (lib/doh.js DohClient, or a fake with `query(name, type, opts)`).
 */

import { createLimiter, throwIfAborted } from './util.js';
import { normalizeIP, ipVersion, isPrivateIP, isGloballyRoutable, reversePtrName } from './ip.js';
import { normalizeHostname, registrableDomain } from './domain.js';

/** Per-list outcome of a check. */
export const DNSBL_STATUSES = Object.freeze(['listed', 'not-listed', 'refused', 'error', 'skipped']);
/** Why a list cannot be checked through this resolver (`status: 'refused'`). */
export const DNSBL_REFUSALS = Object.freeze(['public-resolver', 'rate-limited', 'bad-query', 'query-refused', 'test-point', 'rcode']);
/** Why a list's answer could not be read (`status: 'error'`): an rcode, an odd answer or the transport (util.errorKind). */
export const DNSBL_ERRORS = Object.freeze(['servfail', 'rcode', 'bad-answer', 'timeout', 'network', 'http', 'rate-limit', 'parse', 'unknown']);
/** Why a list was not asked (`status: 'skipped'`). */
export const DNSBL_SKIPS = Object.freeze(['ipv4-only']);
/** Why a target is never checked ({@link dnsblTarget}). */
export const DNSBL_TARGET_ERRORS = Object.freeze(['invalid', 'private', 'reserved', 'internal']);
/** How long a test-point verdict is trusted (ms). */
export const TEST_POINT_TTL_MS = 10 * 60 * 1000;
/** Default per-query timeout (ms) and concurrency (lists asked at once). */
export const DNSBL_TIMEOUT_MS = 6000;
export const DNSBL_CONCURRENCY = 4;

/** Name suffixes that never leave the browser (RFC 6761 / 6762 / 8375 special-use and common internal TLDs). */
const INTERNAL_SUFFIXES = ['local', 'localhost', 'internal', 'intranet', 'lan', 'corp', 'home', 'home.arpa', 'private', 'test', 'invalid', 'example', 'onion', 'alt', 'arpa'];
/** RFC 5782 IPv6 test points (::ffff:127.0.0.2 listed), reversed nibbles. */
const V6_TEST = '2.0.0.0.0.0.f.7.f.f.f.f.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0';

const SPAMHAUS_REFUSALS = Object.freeze({ '127.255.255.252': 'bad-query', '127.255.255.254': 'public-resolver', '127.255.255.255': 'rate-limited' });
const SPAMHAUS_SITE = 'https://check.spamhaus.org/';
const UCE_SITE = 'https://www.uceprotect.net/en/rblcheck.php';

/**
 * @typedef {object} DnsblList
 * @property {string} id
 * @property {string} name display name (a product name: never translated)
 * @property {'ip'|'domain'} kind what the list holds
 * @property {string} zone
 * @property {boolean|string} v6 IP lists: true when the zone takes IPv6 addresses, the IPv6 zone when it has its own, false for IPv4 only
 * @property {string} test domain lists: the documented test domain (IP lists use 127.0.0.2)
 * @property {'exact'|'bitmask'|'age'} decode how an answer reads: one code per address, bits of the last octet, or an age in hours (ZRD)
 * @property {Readonly<Record<string,string>>} codes answer → meaning (exact) or bit → meaning (bitmask)
 * @property {Readonly<Record<string,string>>} refusals answer → refusal reason ({@link DNSBL_REFUSALS})
 * @property {readonly string[]} clean answers that are reputation only, not a listing
 * @property {string} site delist / lookup page (`{ip}` / `{domain}` filled in by {@link delistUrl})
 */

function list(id, name, kind, zone, { v6 = false, test = '', decode = 'exact', codes = { '127.0.0.2': 'listed' }, refusals = {}, clean = [], site }) {
  return Object.freeze({ id, name, kind, zone, v6, test, decode, codes: Object.freeze({ ...codes }), refusals: Object.freeze({ ...refusals }), clean: Object.freeze([...clean]), site });
}

const DRONEBL_CODES = {
  '127.0.0.1': 'test', '127.0.0.3': 'drone', '127.0.0.5': 'drone', '127.0.0.6': 'drone', '127.0.0.7': 'ddos', '127.0.0.8': 'proxy',
  '127.0.0.9': 'proxy', '127.0.0.10': 'proxy', '127.0.0.11': 'proxy', '127.0.0.12': 'open-dns', '127.0.0.13': 'brute-force',
  '127.0.0.14': 'proxy', '127.0.0.15': 'router', '127.0.0.16': 'drone', '127.0.0.17': 'drone', '127.0.0.18': 'drone', '127.0.0.19': 'vpn',
  '127.0.0.255': 'listed'
};

/** IP blocklists that answer public resolvers (and Spamhaus ZEN, which says it does not). */
export const DNSBL_IP_LISTS = Object.freeze([
  list('spamhaus-zen', 'Spamhaus ZEN', 'ip', 'zen.spamhaus.org', {
    v6: true,
    codes: { '127.0.0.2': 'sbl', '127.0.0.3': 'css', '127.0.0.4': 'xbl', '127.0.0.5': 'xbl', '127.0.0.6': 'xbl', '127.0.0.7': 'xbl', '127.0.0.9': 'drop', '127.0.0.10': 'pbl', '127.0.0.11': 'pbl' },
    refusals: SPAMHAUS_REFUSALS, site: SPAMHAUS_SITE
  }),
  list('barracuda', 'Barracuda BRBL', 'ip', 'b.barracudacentral.org', { v6: true, site: 'https://www.barracudacentral.org/rbl/removal-request' }),
  list('spamcop', 'SpamCop', 'ip', 'bl.spamcop.net', { v6: true, site: 'https://www.spamcop.net/bl.shtml?{ip}' }),
  list('psbl', 'PSBL', 'ip', 'psbl.surriel.com', { site: 'https://psbl.org/listing?ip={ip}' }),
  list('mailspike', 'Mailspike', 'ip', 'bl.mailspike.net', {
    codes: { '127.0.0.2': 'listed', '127.0.0.10': 'rep-worst', '127.0.0.11': 'rep-very-bad', '127.0.0.12': 'rep-bad', '127.0.0.13': 'rep-suspicious' },
    clean: ['127.0.0.14', '127.0.0.15', '127.0.0.16', '127.0.0.17', '127.0.0.18', '127.0.0.19', '127.0.0.20'],
    site: 'https://mailspike.io/ip_verify'
  }),
  list('uceprotect-1', 'UCEPROTECT 1', 'ip', 'dnsbl-1.uceprotect.net', { codes: { '127.0.0.2': 'uce-1' }, site: UCE_SITE }),
  list('uceprotect-2', 'UCEPROTECT 2', 'ip', 'dnsbl-2.uceprotect.net', { codes: { '127.0.0.2': 'uce-2' }, site: UCE_SITE }),
  list('uceprotect-3', 'UCEPROTECT 3', 'ip', 'dnsbl-3.uceprotect.net', { codes: { '127.0.0.2': 'uce-3' }, site: UCE_SITE }),
  list('s5h', 's5h.net', 'ip', 'all.s5h.net', { v6: true, site: 'https://www.s5h.net/rbl' }),
  list('dronebl', 'DroneBL', 'ip', 'dnsbl.dronebl.org', { v6: true, codes: DRONEBL_CODES, site: 'https://dronebl.org/lookup?ip={ip}' }),
  list('blocklist-de', 'blocklist.de', 'ip', 'bl.blocklist.de', { v6: true, codes: { '127.0.0.2': 'attacks' }, site: 'https://www.blocklist.de/en/delist.html?ip={ip}' }),
  list('backscatterer', 'Backscatterer', 'ip', 'ips.backscatterer.org', { v6: true, codes: { '127.0.0.2': 'backscatter' }, site: 'https://www.backscatterer.org/' }),
  list('nordspam', 'NordSpam', 'ip', 'bl.nordspam.com', { v6: true, site: 'https://www.nordspam.com/' }),
  list('sem', 'SpamEatingMonkey', 'ip', 'bl.spameatingmonkey.net', { v6: 'bl.ipv6.spameatingmonkey.net', site: 'https://spameatingmonkey.com/' }),
  list('0spam', '0spam', 'ip', 'bl.0spam.org', { site: 'https://0spam.org/' })
]);

/** Domain blocklists (RHSBL / URI lists). Spamhaus and URIBL refuse public resolvers; SURBL answers some of them. */
export const DNSBL_DOMAIN_LISTS = Object.freeze([
  list('spamhaus-dbl', 'Spamhaus DBL', 'domain', 'dbl.spamhaus.org', {
    test: 'dbltest.com',
    codes: {
      '127.0.1.2': 'dbl-spam', '127.0.1.4': 'dbl-phish', '127.0.1.5': 'dbl-malware', '127.0.1.6': 'dbl-botnet', '127.0.1.102': 'dbl-abused',
      '127.0.1.103': 'dbl-abused', '127.0.1.104': 'dbl-abused', '127.0.1.105': 'dbl-abused', '127.0.1.106': 'dbl-abused'
    },
    refusals: { ...SPAMHAUS_REFUSALS, '127.0.1.255': 'bad-query' }, site: SPAMHAUS_SITE
  }),
  list('spamhaus-zrd', 'Spamhaus ZRD', 'domain', 'zrd.spamhaus.org', { test: 'dbltest.com', decode: 'age', codes: {}, refusals: SPAMHAUS_REFUSALS, site: SPAMHAUS_SITE }),
  list('surbl', 'SURBL', 'domain', 'multi.surbl.org', {
    test: 'test.surbl.org', decode: 'bitmask', codes: { 8: 'phishing', 16: 'malware', 64: 'abuse', 128: 'cracked' },
    refusals: { '127.0.0.1': 'query-refused' }, site: 'https://www.surbl.org/surbl-analysis'
  }),
  list('uribl', 'URIBL', 'domain', 'multi.uribl.com', {
    test: 'test.uribl.com', decode: 'bitmask', codes: { 2: 'uribl-black', 4: 'uribl-grey', 8: 'uribl-red' },
    refusals: { '127.0.0.1': 'query-refused' }, site: 'https://admin.uribl.com/'
  }),
  list('nordspam-dbl', 'NordSpam DBL', 'domain', 'dbl.nordspam.com', { test: 'test', site: 'https://www.nordspam.com/' })
]);

/** Every list, IP lists first. */
export const DNSBL_LISTS = Object.freeze([...DNSBL_IP_LISTS, ...DNSBL_DOMAIN_LISTS]);

/** Every meaning code a list can answer with (the UI words each one). */
export const DNSBL_MEANINGS = Object.freeze([...new Set([
  ...DNSBL_LISTS.flatMap((l) => Object.values(l.codes)), 'listed', 'young', 'reputation'
])]);

/**
 * @typedef {object} DnsblTarget
 * @property {boolean} ok
 * @property {'ip'|'domain'} [kind]
 * @property {string} [value] the normalized address, or the registrable domain
 * @property {4|6} [version] IP targets
 * @property {string} [label] the query label (reversed address, or the domain)
 * @property {string} [reason] when not ok: {@link DNSBL_TARGET_ERRORS}
 */

/**
 * What a check would ask about `input`: an IP address (never a private, reserved or documentation
 * one) or the registrable domain of a host name (never an internal name).
 * @param {string} input
 * @returns {DnsblTarget}
 */
export function dnsblTarget(input) {
  const raw = String(input ?? '').trim();
  const ip = normalizeIP(raw);
  if (ip) {
    if (isPrivateIP(ip)) return { ok: false, reason: 'private' };
    if (!isGloballyRoutable(ip)) return { ok: false, reason: 'reserved' };
    const version = ipVersion(ip);
    return { ok: true, kind: 'ip', value: ip, version, label: reversePtrName(ip).replace(/\.(?:in-addr|ip6)\.arpa$/, '') };
  }
  const host = normalizeHostname(raw, { allowSingleLabel: true });
  if (!host) return { ok: false, reason: 'invalid' };
  if (INTERNAL_SUFFIXES.some((s) => host === s || host.endsWith(`.${s}`)) || !host.includes('.')) return { ok: false, reason: 'internal' };
  const domain = registrableDomain(host);
  if (!domain) return { ok: false, reason: 'invalid' };
  return { ok: true, kind: 'domain', value: domain, label: domain };
}

/**
 * The lists that hold this kind of target.
 * @param {'ip'|'domain'} kind
 * @returns {readonly DnsblList[]}
 */
export function listsFor(kind) {
  return kind === 'domain' ? DNSBL_DOMAIN_LISTS : DNSBL_IP_LISTS;
}

/**
 * The zone a list is asked in for a target, or null when the list does not take it (IPv6 on an
 * IPv4-only list).
 * @param {DnsblList} l
 * @param {DnsblTarget} target
 * @returns {string|null}
 */
export function zoneFor(l, target) {
  if (target.kind !== 'ip' || target.version !== 6) return l.zone;
  if (typeof l.v6 === 'string') return l.v6;
  return l.v6 ? l.zone : null;
}

/**
 * The list's own test point in `zone`: the name that must come back listed (RFC 5782).
 * @param {DnsblList} l
 * @param {string} zone
 * @param {4|6} [version]
 * @returns {string}
 */
export function testPointName(l, zone, version = 4) {
  if (l.kind === 'domain') return `${l.test}.${zone}`;
  return `${version === 6 ? V6_TEST : '2.0.0.127'}.${zone}`;
}

/**
 * The list's delist / lookup page for a target.
 * @param {DnsblList} l
 * @param {string} value the address or the domain
 * @returns {string}
 */
export function delistUrl(l, value) {
  return l.site.replace('{ip}', encodeURIComponent(value)).replace('{domain}', encodeURIComponent(value));
}

/** True for a dotted IPv4 address inside 127.0.0.0/8. */
function isLoopbackCode(s) {
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(s) && s.split('.').every((o) => Number(o) <= 255);
}

/**
 * The meanings of a list's answer codes: one per address (exact), one per set bit of the last
 * octet (bitmask) or an age in hours (Spamhaus ZRD: 127.0.2.2–127.0.2.24). A code the list does
 * not document reads `listed`.
 * @param {DnsblList} l
 * @param {string[]} codes 127.0.0.0/8 answers
 * @returns {Array<{ code: string, meaning: string, hours?: number }>}
 */
export function decodeCodes(l, codes) {
  const out = [];
  for (const code of codes) {
    if (l.clean.includes(code)) {
      out.push({ code, meaning: 'reputation' });
    } else if (l.decode === 'bitmask') {
      const last = Number(code.split('.')[3]);
      const bits = Object.keys(l.codes).map(Number).filter((b) => last & b);
      if (!bits.length) out.push({ code, meaning: 'listed' });
      for (const b of bits) out.push({ code, meaning: l.codes[b] });
    } else if (l.decode === 'age') {
      const [, , third, last] = code.split('.').map(Number);
      out.push(third === 2 && last >= 2 && last <= 24 ? { code, meaning: 'young', hours: last } : { code, meaning: 'listed' });
    } else {
      out.push({ code, meaning: l.codes[code] || 'listed' });
    }
  }
  // One line per meaning (bitmask answers repeat a code, several codes can share a meaning).
  return out.filter((x, i) => out.findIndex((y) => y.meaning === x.meaning && y.code === x.code) === i);
}

/**
 * @typedef {object} DnsblResult
 * @property {string} list list id
 * @property {string} name list name
 * @property {'ip'|'domain'} kind
 * @property {string} zone the zone asked ('' when skipped)
 * @property {string} query the DNS name asked (or that would be asked), for `dig`
 * @property {'listed'|'not-listed'|'refused'|'error'|'skipped'} status
 * @property {string|null} reason refusal ({@link DNSBL_REFUSALS}), error ({@link DNSBL_ERRORS}) or skip ({@link DNSBL_SKIPS}) code
 * @property {Array<{ code: string, meaning: string, hours?: number }>} codes decoded answer (listed; the code of a refusal)
 * @property {boolean} testPoint true when the verdict comes from the list's test point (the target was not sent)
 * @property {string|null} rcode
 * @property {string|null} error transport error text
 * @property {string|null} resolver id of the resolver that answered
 * @property {string} delist the list's delist / lookup page for the target
 */

/**
 * Read one DNS answer of a list: listed / not listed / refused / error.
 * @param {DnsblList} l
 * @param {import('./doh.js').DnsResponse} res
 * @returns {{ status: string, reason: string|null, codes: Array<object>, rcode: string|null, error: string|null, resolver: string|null }}
 */
export function readAnswer(l, res) {
  const base = { reason: null, codes: [], rcode: res && res.rcode ? res.rcode : null, error: null, resolver: (res && res.resolver) || null };
  if (!res || !res.ok) {
    const kind = res && DNSBL_ERRORS.includes(res.errorKind) ? res.errorKind : 'unknown';
    return { ...base, status: 'error', reason: kind, error: (res && res.error) || null };
  }
  if (res.rcode === 'NXDOMAIN') return { ...base, status: 'not-listed' };
  if (res.rcode === 'REFUSED') return { ...base, status: 'refused', reason: 'rcode' };
  if (res.rcode === 'SERVFAIL') return { ...base, status: 'error', reason: 'servfail' };
  if (res.rcode !== 'NOERROR') return { ...base, status: 'error', reason: 'rcode' };
  const addrs = [...new Set((res.answers || []).filter((a) => a && a.type === 'A').map((a) => String(a.data)))];
  if (!addrs.length) return { ...base, status: 'not-listed' };
  const refusal = addrs.find((a) => l.refusals[a]);
  if (refusal) return { ...base, status: 'refused', reason: l.refusals[refusal], codes: [{ code: refusal, meaning: l.refusals[refusal] }] };
  // An answer outside 127.0.0.0/8 is no list's code: a resolver that rewrites NXDOMAIN, or a broken zone.
  if (!addrs.every(isLoopbackCode)) return { ...base, status: 'error', reason: 'bad-answer', codes: addrs.map((code) => ({ code, meaning: 'listed' })) };
  const codes = decodeCodes(l, addrs);
  const listed = codes.some((c) => c.meaning !== 'reputation');
  return { ...base, status: listed ? 'listed' : 'not-listed', codes };
}

/**
 * Counts per status.
 * @param {DnsblResult[]} results
 * @returns {{ total: number, listed: number, 'not-listed': number, refused: number, error: number, skipped: number }}
 */
export function dnsblCounts(results) {
  const out = { total: results.length, listed: 0, 'not-listed': 0, refused: 0, error: 0, skipped: 0 };
  for (const r of results) out[r.status] = (out[r.status] || 0) + 1;
  return out;
}

/**
 * Replace the results of `next` in `prev` (a Retry of some lists), keeping the list order.
 * @param {DnsblResult[]} prev
 * @param {DnsblResult[]} next
 * @returns {DnsblResult[]}
 */
export function mergeResults(prev, next) {
  const byId = new Map(next.map((r) => [r.list, r]));
  return prev.map((r) => byId.get(r.list) || r);
}

/**
 * A checker with its own test-point cache (one per DNS client).
 * @param {{ dns: { query: Function }, now?: () => number, concurrency?: number, timeoutMs?: number, testTtlMs?: number }} opts
 * @returns {{ check: (target: DnsblTarget, opts?: { signal?: AbortSignal, lists?: string[], noCache?: boolean, onResult?: (r: DnsblResult) => void }) => Promise<{ target: string, kind: string, results: DnsblResult[], at: number }> }}
 */
export function createDnsblChecker({ dns, now = Date.now, concurrency = DNSBL_CONCURRENCY, timeoutMs = DNSBL_TIMEOUT_MS, testTtlMs = TEST_POINT_TTL_MS } = {}) {
  /** zone|version → { at, verdict } (usable or refused; errors are not kept). */
  const tests = new Map();
  const limiter = createLimiter(concurrency);

  async function testPoint(l, zone, version, { signal, noCache }) {
    const key = `${zone}|${version}`;
    const hit = tests.get(key);
    if (!noCache && hit && now() - hit.at < testTtlMs) return hit.verdict;
    const res = await dns.query(testPointName(l, zone, version), 'A', { signal, noCache, timeoutMs });
    throwIfAborted(signal);
    const read = readAnswer(l, res);
    let verdict;
    if (read.status === 'listed') verdict = { usable: true, resolver: read.resolver };
    else if (read.status === 'not-listed') verdict = { usable: false, ...read, status: 'refused', reason: 'test-point', codes: [] };
    else verdict = { usable: false, ...read };
    if (verdict.usable || verdict.status === 'refused') tests.set(key, { at: now(), verdict });
    return verdict;
  }

  async function checkList(l, target, opts) {
    const zone = zoneFor(l, target);
    const query = `${target.label}.${zone || l.zone}`;
    const base = { list: l.id, name: l.name, kind: l.kind, zone: zone || '', query, testPoint: false, delist: delistUrl(l, target.value) };
    if (!zone) return { ...base, status: 'skipped', reason: 'ipv4-only', codes: [], rcode: null, error: null, resolver: null };
    const verdict = await testPoint(l, zone, target.version || 4, opts);
    if (!verdict.usable) {
      const { usable, ...rest } = verdict;
      return { ...base, ...rest, testPoint: true };
    }
    const res = await dns.query(query, 'A', { signal: opts.signal, noCache: opts.noCache, timeoutMs, ...(verdict.resolver ? { resolver: verdict.resolver } : {}) });
    throwIfAborted(opts.signal);
    return { ...base, ...readAnswer(l, res) };
  }

  return {
    /**
     * Ask every list for this kind of target (or only `lists`), at most `concurrency` at once.
     * Rejects only with an AbortError. Never asks for a target that {@link dnsblTarget} refused.
     */
    async check(target, { signal, lists = null, noCache = false, onResult = null } = {}) {
      throwIfAborted(signal);
      if (!target || !target.ok) throw new TypeError(`not a blocklist target: ${target && target.reason}`);
      const chosen = listsFor(target.kind).filter((l) => !lists || lists.includes(l.id));
      const results = await Promise.all(chosen.map((l) => limiter.run(async () => {
        throwIfAborted(signal);
        const r = await checkList(l, target, { signal, noCache });
        if (onResult) onResult(r);
        return r;
      }, { signal })));
      return { target: target.value, kind: target.kind, results, at: now() };
    }
  };
}
