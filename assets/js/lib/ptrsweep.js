/**
 * ptrsweep.js — reverse-DNS sweep of a network, a range, a list of addresses or the prefixes
 * an AS announces, with forward confirmation (FCrDNS). DOM-free; runs in browsers and Node 22.
 *
 * - {@link parseSweepTarget}: what the user typed → the addresses to sweep: an IPv4 network
 *   up to a /22 ({@link SWEEP_MAX_ADDRESSES} addresses), a range (`192.0.2.10-192.0.2.50` or
 *   `192.0.2.10-50`), single IPv4 / IPv6 addresses, or one AS number (`AS64496`). IPv6
 *   networks are never swept: even a /64 holds 2^64 addresses and nothing in DNS lists which
 *   of them have a reverse record. Private addresses are left out (public resolvers cannot
 *   see an internal reverse zone), and so are multicast / reserved ones.
 * - {@link announcedPrefixes}: the prefixes an AS announced over the last two weeks, from
 *   RIPEstat (one request, only the AS number is sent), for the user to pick from.
 * - {@link checkFcrdns}: one address → its PTR names → each name's A / AAAA records, and the
 *   verdict ({@link FCRDNS_STATUSES}): `confirmed` when a PTR name resolves back to the address.
 *   Domain Health runs it for the MX hosts' addresses too.
 * - {@link runPtrSweep}: every address through the injected DohClient (its limiter caps the
 *   HTTP requests in flight at the Settings value), streamed to `onResult`, cancellable.
 * - {@link ptrTemplate}: ISP-templated names (the address written into the name,
 *   `203-0-113-5.isp.example.net`, `ec2-…compute.amazonaws.com`, or a dynamic / pool word with a
 *   number) — they forward-confirm but say nothing about who runs the host, so
 *   {@link sweepRows} collapses each template into one row with a count.
 * - {@link sweepRows}, {@link sweepSummary} and the exports / hand-offs the view offers
 *   ({@link sweepExportRows}, {@link sweepExportJson}, {@link sweepNames},
 *   {@link inventoryAdditions}, {@link inventoryDraft}, {@link scanHandoff}).
 *
 * Nothing is sent by importing this module. A sweep sends PTR queries (the reverse names) and
 * A / AAAA queries (the PTR names) to the resolvers of the client it is given; the network's
 * own name servers see them coming from those resolvers.
 */

import { fetchJson, retry, errorKind, throwIfAborted, uniq, splitList } from './util.js';
import {
  parseIP, parseCidr, formatIP, normalizeIP, ipVersion, ipInCidr, isPrivateIP, privateRangeOf, reversePtrName,
  matchProviderByCname, classifyResolution, PRIVATE_V4_RANGES
} from './netinfo.js';
import { normalizeHostname, isSubdomainOf, registrableDomain, sortHostnames } from './domain.js';
import { lookupServers, buildIpIndex, parseInventory, inventoryFormat } from './inventory.js';
import { followCnames } from './doh.js';
import { RIPESTAT_BASE, RIPESTAT_SOURCEAPP } from './ipintel.js';

/* ------------------------------------------------------------------------ */
/* Limits and vocabularies (frozen; the i18n coverage test derives keys)    */
/* ------------------------------------------------------------------------ */

/** Most addresses one sweep looks up: an IPv4 /22 (1,024 PTR queries, about 4–10 s over DoH). */
export const SWEEP_MAX_ADDRESSES = 1024;
/** The widest IPv4 network one sweep takes. */
export const SWEEP_MAX_PREFIX = 22;
/** PTR names forward-checked per address (a PTR set rarely holds more than one or two). */
export const FCRDNS_MAX_NAMES = 4;
/** Addresses in flight at most; the DohClient's own limiter still caps the HTTP requests. */
export const SWEEP_MAX_CONCURRENCY = 64;

/**
 * Per-address verdicts, best first:
 * - confirmed: a PTR name resolves back to the address (forward-confirmed reverse DNS);
 * - mismatch: PTR names exist, but none of them resolves to the address (NXDOMAIN, no record
 *   of the address's type, or other addresses);
 * - no-ptr: the reverse name exists but holds no PTR record (NOERROR, empty);
 * - nxdomain: no reverse record at all;
 * - servfail: the reverse lookup failed with SERVFAIL (a broken or lame reverse delegation);
 * - error: no answer (transport failure, timeout, another rcode), or (`stage: 'forward'`) no PTR
 *   name confirmed and at least one forward lookup failed that way, so a mismatch cannot be claimed.
 */
export const FCRDNS_STATUSES = Object.freeze(['confirmed', 'mismatch', 'no-ptr', 'nxdomain', 'servfail', 'error']);
/** What a PTR name's forward lookup gave: the address, only other addresses, no record, no name, a failure. */
export const FORWARD_STATES = Object.freeze(['match', 'other', 'nodata', 'nxdomain', 'error']);
/**
 * Target parse issues: `invalid` (not an address, range, network or AS number), `v6-range` (an
 * IPv6 network or range), `reversed` (a range that ends before it starts), `too-large` (one
 * IPv4 network or range over the cap), `over-cap` (everything together over the cap),
 * `asn-many` (more than one AS number), `asn-mixed` (an AS number next to addresses),
 * `private` / `reserved` (addresses left out), `host-bits` (a network written with host bits,
 * read as its network), `nothing` (nothing left to sweep).
 */
export const TARGET_ISSUES = Object.freeze([
  'invalid', 'v6-range', 'reversed', 'too-large', 'over-cap', 'asn-many', 'asn-mixed', 'private', 'reserved', 'host-bits', 'nothing'
]);
/** Severity of each issue: an error blocks the sweep, a warning drops the token, info only says. */
export const TARGET_ISSUE_SEVERITY = Object.freeze({
  invalid: 'warn',
  'v6-range': 'warn',
  reversed: 'warn',
  'too-large': 'error',
  'over-cap': 'error',
  'asn-many': 'error',
  'asn-mixed': 'error',
  private: 'warn',
  reserved: 'warn',
  'host-bits': 'info',
  nothing: 'error'
});
/** Display order of the rows: names under the focus domain, other names, templated names, no name, failures. */
export const ROW_RANKS = Object.freeze({ focus: 0, named: 1, templated: 2, none: 3, failed: 4 });
/** Filters of the results table. */
export const SWEEP_FILTERS = Object.freeze(['all', 'ptr', 'focus', 'confirmed', 'mismatch', 'none', 'failed']);

const MAX_ASN = 4294967295;
const RESERVED_V4 = ['224.0.0.0/4', '240.0.0.0/4'].map(parseCidr);
/** 224/4 and 240/4 together: the top eighth of IPv4, one contiguous block. */
const RESERVED_V4_FIRST = parseCidr('224.0.0.0/3').network;
/** Every IPv4 block {@link skipReason} leaves out, as [first, last] (none of them overlap). */
const SKIPPED_V4 = [...PRIVATE_V4_RANGES.map((c) => [c, 'private']), ['224.0.0.0/3', 'reserved']].map(([cidr, why]) => {
  const c = parseCidr(cidr);
  return { first: c.network, last: c.network + 2n ** BigInt(32 - c.prefix) - 1n, why };
});
const MULTICAST_V6 = parseCidr('ff00::/8');

/* ------------------------------------------------------------------------ */
/* Addresses, networks and ranges                                           */
/* ------------------------------------------------------------------------ */

/**
 * An AS number from `AS64496` / `as64496` / `ASN 64496` (a bare number is not taken: it could
 * be anything). AS0 is reserved (RFC 7607) and never announced.
 * @param {unknown} token
 * @returns {number|null}
 */
export function parseAsn(token) {
  const m = /^AS(?:N)?\s?(\d{1,10})$/i.exec(String(token ?? '').trim());
  if (!m) return null;
  const n = Number(m[1]);
  return Number.isInteger(n) && n > 0 && n <= MAX_ASN ? n : null;
}

/** IPv4-mapped IPv6 (`::ffff:192.0.2.1`) is looked up as the IPv4 address itself. */
function canonicalAddress(raw) {
  const ip = normalizeIP(raw);
  if (!ip) return null;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
  return mapped ? mapped[1] : ip;
}

/**
 * Why an address is never swept: 'private' (netinfo.isPrivateIP: public resolvers cannot see an
 * internal reverse zone, and the address would leak), 'reserved' (IPv4 multicast and 240/4,
 * IPv6 multicast, not an address) or null.
 * @param {string} ip
 * @returns {'private'|'reserved'|null}
 */
export function skipReason(ip) {
  if (!parseIP(ip)) return 'reserved';
  if (isPrivateIP(ip)) return 'private';
  return RESERVED_V4.some((c) => ipInCidr(ip, c)) || ipInCidr(ip, MULTICAST_V6) ? 'reserved' : null;
}

/** The IPv4 prefix length of a network holding at most `max` addresses (1024 → 22). */
function prefixFor(max) {
  return 32 - Math.floor(Math.log2(Math.max(1, max)));
}

/**
 * Why EVERY address from `first` to `last` (bigint, IPv4) is left out: 'private' when one
 * private range holds both ends (netinfo.privateRangeOf: no two of them touch), 'reserved'
 * when both are in 224/3; null when at least one address would be swept.
 */
function wholeBlockSkipped(first, last) {
  const range = parseCidr(privateRangeOf(formatIP(first, 4)) || '');
  if (range && range.version === 4 && last < range.network + 2n ** BigInt(32 - range.prefix)) return 'private';
  return first >= RESERVED_V4_FIRST ? 'reserved' : null;
}

/**
 * The blocks as disjoint spans in address order (IPv4 first): overlapping ones (a network and
 * a smaller one inside it, the same network twice) and neighbours merge.
 * @param {Array<{ version: 4|6, first: bigint, count: number }>} blocks
 * @returns {Array<{ version: 4|6, first: bigint, last: bigint }>}
 */
function mergedSpans(blocks) {
  const sorted = blocks.map((b) => ({ version: b.version, first: b.first, last: b.first + BigInt(b.count) - 1n }))
    .sort((a, b) => a.version - b.version || (a.first < b.first ? -1 : a.first > b.first ? 1 : 0));
  const out = [];
  for (const span of sorted) {
    const prev = out[out.length - 1];
    if (prev && prev.version === span.version && span.first <= prev.last + 1n) {
      if (span.last > prev.last) prev.last = span.last;
    } else {
      out.push({ ...span });
    }
  }
  return out;
}

/**
 * Distinct addresses in a set of blocks, overlaps counted once.
 * @param {Array<{ version: 4|6, first: bigint, count: number }>} blocks
 * @returns {number}
 */
function uniqueAddressCount(blocks) {
  return Number(mergedSpans(blocks).reduce((n, s) => n + s.last - s.first + 1n, 0n));
}

/**
 * How many distinct addresses of the blocks {@link skipReason} leaves out, by reason, without
 * listing them (a pasted list of private /22s costs nothing): IPv4 spans are intersected with
 * the private and reserved blocks, IPv6 ones (exact addresses only) are asked one by one.
 * @param {Array<{ version: 4|6, first: bigint, count: number }>} blocks
 * @returns {{ private: number, reserved: number }}
 */
function skippedCounts(blocks) {
  const out = { private: 0n, reserved: 0n };
  for (const span of mergedSpans(blocks)) {
    if (span.version === 4) {
      for (const r of SKIPPED_V4) {
        const lo = span.first > r.first ? span.first : r.first;
        const hi = span.last < r.last ? span.last : r.last;
        if (hi >= lo) out[r.why] += hi - lo + 1n;
      }
      continue;
    }
    for (let v = span.first; v <= span.last; v += 1n) {
      const why = skipReason(formatIP(v, 6));
      if (why) out[why] += 1n;
    }
  }
  return { private: Number(out.private), reserved: Number(out.reserved) };
}

/**
 * The number of addresses in a network (a Number: exact for IPv4, a float for IPv6).
 * @param {string} cidr
 * @returns {number|null}
 */
export function prefixSize(cidr) {
  const c = parseCidr(cidr);
  if (!c) return null;
  return 2 ** ((c.version === 4 ? 32 : 128) - c.prefix);
}

/**
 * The canonical form of a network: host bits masked, RFC 5952 for IPv6 (`192.0.2.77/24` →
 * `192.0.2.0/24`). Null when it is not a network.
 * @param {string} cidr
 * @returns {string|null}
 */
export function canonicalCidr(cidr) {
  const c = parseCidr(cidr);
  return c ? `${formatIP(c.network, c.version)}/${c.prefix}` : null;
}

/**
 * The first sub-network of `cidr` at `prefix` (the first /22 of a /16), so a network too
 * large to sweep can be taken apart; the network itself when it already is that small.
 * @param {string} cidr
 * @param {number} [prefix=SWEEP_MAX_PREFIX]
 * @returns {string|null}
 */
export function firstSubnet(cidr, prefix = SWEEP_MAX_PREFIX) {
  const c = parseCidr(cidr);
  if (!c) return null;
  return `${formatIP(c.network, c.version)}/${Math.max(c.prefix, prefix)}`;
}

/** Every address from `first` (bigint) for `count` addresses, formatted. */
function addressesFrom(first, count, version) {
  const out = [];
  for (let i = 0; i < count; i += 1) out.push(formatIP(first + BigInt(i), version));
  return out;
}

/** Split `a-b` into a range: `192.0.2.10-192.0.2.50` or the short `192.0.2.10-50`. */
function parseRange(token) {
  const m = /^([^-\s]+)-([^-\s]+)$/.exec(token);
  if (!m) return null;
  const start = parseIP(m[1]);
  if (!start) return null;
  if (start.version === 6 || m[2].includes(':')) return { version: 6 };
  let end = parseIP(m[2]);
  if (!end && /^\d{1,3}$/.test(m[2]) && Number(m[2]) <= 255) {
    end = { version: 4, value: (start.value & ~0xffn) | BigInt(Number(m[2])) };
  }
  if (!end || end.version !== 4) return null;
  return { version: 4, first: start.value, last: end.value };
}

/**
 * @typedef {object} SweepBlock
 * @property {string} input the token as typed
 * @property {'cidr'|'range'|'ip'} kind
 * @property {4|6} version
 * @property {string} label canonical text: '192.0.2.0/24', '192.0.2.10-192.0.2.50' or the address
 * @property {bigint} first
 * @property {number} count addresses in the block
 */

/**
 * @typedef {object} SweepIssue
 * @property {string} code one of {@link TARGET_ISSUES}
 * @property {'error'|'warn'|'info'} severity
 * @property {Record<string, string|number>} params language-neutral (lists pre-joined)
 */

/**
 * @typedef {object} SweepTarget
 * @property {'empty'|'asn'|'addresses'} kind
 * @property {number|null} asn the AS number (kind 'asn')
 * @property {SweepBlock[]} blocks
 * @property {string[]} addresses what a sweep looks up, input order, de-duplicated (none while an error stands)
 * @property {number} total distinct addresses in the blocks before the private / reserved ones are left out
 * @property {{ private: number, reserved: number }} skipped distinct addresses left out (zero while an error stands)
 * @property {SweepIssue[]} issues
 * @property {boolean} ok nothing blocks a sweep (or an AS lookup)
 * @property {string} label short text for the results heading and the share link
 */

const issue = (code, params = {}) => ({ code, severity: TARGET_ISSUE_SEVERITY[code], params });
const listText = (items, max = 6) => (items.length > max ? `${items.slice(0, max).join(', ')} (+${items.length - max})` : items.join(', '));

/**
 * One token per address, range, network or AS number: `AS 64496` / `ASN 64496` and a range
 * typed with spaces or an en dash (`192.0.2.10 - 192.0.2.20`, `192.0.2.10–20`) are joined
 * before the text is split. Two words around a dash are joined only when together they read
 * as a range: two networks (`192.0.2.0/24 - 198.51.100.0/24`) stay two tokens.
 * @param {string} text
 * @returns {string[]}
 */
function targetTokens(text) {
  const joined = String(text ?? '')
    .replace(/(^|[\s,;])(ASN?)[ \t]+(\d{1,10})(?=$|[\s,;#])/gim, '$1$2$3')
    .replace(/([^\s,;#]+)[ \t]*[-\u2013][ \t]*(?=([^\s,;#]+))/g,
      (whole, left, right) => (parseRange(`${left}-${right}`) ? `${left}-` : whole));
  return splitList(joined);
}

/**
 * Read what the user typed. Tokens are split on whitespace, commas and semicolons (`#` starts
 * a comment). Every IPv4 network or range must fit the cap on its own, and the addresses all
 * of them together would look up must too (overlaps counted once, the private and reserved
 * ones left out as they are from the sweep); an error issue then stands and `addresses` stays
 * empty. A network too large and wholly private or reserved says so instead of suggesting a
 * part of it (`params.skipped`); the suggested first /22 is never one with nothing to sweep.
 * @param {string} text
 * @param {{ max?: number }} [opts]
 * @returns {SweepTarget}
 */
export function parseSweepTarget(text, { max = SWEEP_MAX_ADDRESSES } = {}) {
  const tokens = targetTokens(text);
  const out = {
    kind: 'empty', asn: null, blocks: [], addresses: [], total: 0,
    skipped: { private: 0, reserved: 0 }, issues: [], ok: false, label: ''
  };
  if (!tokens.length) return out;
  const asns = [];
  const invalid = [];
  const v6Ranges = [];
  const reversed = [];
  for (const token of tokens) {
    const asn = parseAsn(token);
    if (asn !== null) {
      if (!asns.includes(asn)) asns.push(asn);
      continue;
    }
    if (token.includes('/')) {
      const c = parseCidr(token);
      if (!c) {
        invalid.push(token);
        continue;
      }
      const bits = c.version === 4 ? 32 : 128;
      if (c.version === 6 && c.prefix < 128) {
        v6Ranges.push(token);
        continue;
      }
      const label = c.prefix === bits ? formatIP(c.network, c.version) : `${formatIP(c.network, c.version)}/${c.prefix}`;
      const typed = parseIP(token.slice(0, token.indexOf('/')));
      if (typed && typed.value !== c.network) out.issues.push(issue('host-bits', { input: token, cidr: label }));
      out.blocks.push({ input: token, kind: c.prefix === bits ? 'ip' : 'cidr', version: c.version, label, first: c.network, count: 2 ** (bits - c.prefix) });
      continue;
    }
    if (token.includes('-') && !normalizeIP(token)) {
      const r = parseRange(token);
      if (!r) {
        invalid.push(token);
      } else if (r.version === 6) {
        v6Ranges.push(token);
      } else if (r.last < r.first) {
        reversed.push(token);
      } else {
        const count = Number(r.last - r.first) + 1;
        out.blocks.push({
          input: token, kind: count === 1 ? 'ip' : 'range', version: 4,
          label: count === 1 ? formatIP(r.first, 4) : `${formatIP(r.first, 4)}-${formatIP(r.last, 4)}`, first: r.first, count
        });
      }
      continue;
    }
    const ip = canonicalAddress(token);
    if (!ip) {
      invalid.push(token);
      continue;
    }
    const addr = parseIP(ip);
    out.blocks.push({ input: token, kind: 'ip', version: addr.version, label: ip, first: addr.value, count: 1 });
  }
  if (invalid.length) out.issues.push(issue('invalid', { items: listText(invalid), count: invalid.length }));
  if (v6Ranges.length) out.issues.push(issue('v6-range', { items: listText(v6Ranges), count: v6Ranges.length }));
  if (reversed.length) out.issues.push(issue('reversed', { items: listText(reversed), count: reversed.length }));

  if (asns.length) {
    out.kind = 'asn';
    out.asn = asns[0];
    out.label = `AS${asns[0]}`;
    if (asns.length > 1) out.issues.push(issue('asn-many', { items: listText(asns.map((a) => `AS${a}`)) }));
    if (out.blocks.length) out.issues.push(issue('asn-mixed', { asn: `AS${asns[0]}` }));
    out.ok = !out.issues.some((i) => i.severity === 'error');
    return out;
  }
  if (!out.blocks.length) {
    out.issues.push(issue('nothing'));
    return out;
  }
  out.kind = 'addresses';
  // The same address or network typed twice is named once.
  const labels = uniq(out.blocks.map((b) => b.label));
  out.label = labels.length === 1 ? labels[0] : listText(labels, 3);
  out.total = uniqueAddressCount(out.blocks);
  for (const b of out.blocks) {
    if (b.count > max) {
      const skipped = b.version === 4 ? wholeBlockSkipped(b.first, b.first + BigInt(b.count) - 1n) : null;
      let suggestion = !skipped && b.kind === 'cidr' ? firstSubnet(b.label, prefixFor(max)) : '';
      const part = suggestion ? parseCidr(suggestion) : null;
      if (part && wholeBlockSkipped(part.network, part.network + 2n ** BigInt(32 - part.prefix) - 1n)) suggestion = '';
      out.issues.push(issue('too-large', { input: b.label, count: b.count, max, suggestion, kind: b.kind, skipped: skipped || '' }));
    }
  }
  if (!out.issues.some((i) => i.code === 'too-large')) {
    const skipped = skippedCounts(out.blocks);
    const lookups = out.total - skipped.private - skipped.reserved;
    if (lookups > max) out.issues.push(issue('over-cap', { count: lookups, max }));
    else out.skipped = skipped;
  }
  if (out.issues.some((i) => i.severity === 'error')) return out;

  const seen = new Set();
  for (const b of out.blocks) {
    // A block wholly private or reserved has nothing to list (its addresses are counted above).
    if (b.version === 4 && wholeBlockSkipped(b.first, b.first + BigInt(b.count) - 1n)) continue;
    for (const ip of addressesFrom(b.first, b.count, b.version)) {
      if (seen.has(ip)) continue;
      seen.add(ip);
      if (!skipReason(ip)) out.addresses.push(ip);
    }
  }
  if (out.skipped.private) out.issues.push(issue('private', { count: out.skipped.private }));
  if (out.skipped.reserved) out.issues.push(issue('reserved', { count: out.skipped.reserved }));
  if (!out.addresses.length) out.issues.push(issue('nothing'));
  out.ok = !out.issues.some((i) => i.severity === 'error');
  return out;
}

/* ------------------------------------------------------------------------ */
/* An AS's announced prefixes (RIPEstat)                                     */
/* ------------------------------------------------------------------------ */

/**
 * The RIPEstat announced-prefixes URL of an AS (ACAO `*`, verified 2026-09-27).
 * @param {number|string} asn 64496 or 'AS64496'
 * @returns {string}
 * @throws {TypeError} when it is not an AS number
 */
export function announcedPrefixesUrl(asn) {
  const n = typeof asn === 'number' ? asn : parseAsn(asn);
  if (!Number.isInteger(n) || n <= 0 || n > MAX_ASN) throw new TypeError(`Not an AS number: ${String(asn)}`);
  return `${RIPESTAT_BASE}/announced-prefixes/data.json?resource=AS${n}&sourceapp=${RIPESTAT_SOURCEAPP}`;
}

/**
 * @typedef {object} AnnouncedPrefix
 * @property {string} prefix canonical network
 * @property {4|6} version
 * @property {number} length prefix length
 * @property {number} size addresses (a float for IPv6)
 * @property {boolean} current seen until the end of the queried window (still announced)
 * @property {boolean} sweepable IPv4, at most {@link SWEEP_MAX_ADDRESSES} addresses, and not
 *   wholly private or reserved
 * @property {'private'|'reserved'|null} skipped the whole IPv4 prefix is private or reserved
 *   space (announced by mistake, or a lab): nothing in it would be swept
 * @property {string|null} part the first /22 of a public IPv4 prefix too large to sweep whole
 *   (null when that /22 holds nothing to sweep)
 */

/**
 * Parse a RIPEstat announced-prefixes answer: IPv4 first in address order, then IPv6.
 * RIPEstat looks back two weeks; a prefix whose last timeline ends before the window does is
 * no longer announced (`current: false`). A wholly private or reserved IPv4 prefix is listed
 * but never sweepable (`skipped`): public resolvers cannot see its reverse zone.
 * @param {object} json the full response ({ status, data: { prefixes: [{ prefix, timelines }], query_endtime } })
 * @param {{ asn?: number, max?: number }} [opts]
 * @returns {{ asn: number|null, prefixes: AnnouncedPrefix[], v4: number, v6: number, v4Addresses: number, sweepable: number,
 *   queryStart: string|null, queryEnd: string|null }}
 * @throws {Error} when RIPEstat reports an error or the answer has no data
 */
export function parseAnnouncedPrefixes(json, { asn = null, max = SWEEP_MAX_ADDRESSES } = {}) {
  if (!json || typeof json !== 'object') throw new SyntaxError('RIPEstat: empty response');
  if (json.status && json.status !== 'ok') {
    const msg = Array.isArray(json.messages) ? json.messages.map((m) => (Array.isArray(m) ? m[1] : m)).join('; ') : '';
    throw new Error(`RIPEstat: ${msg || json.status}`);
  }
  const data = json.data;
  if (!data || typeof data !== 'object' || !Array.isArray(data.prefixes)) throw new SyntaxError('RIPEstat: response has no prefix list');
  const end = typeof data.query_endtime === 'string' ? data.query_endtime : null;
  const byPrefix = new Map();
  for (const p of data.prefixes) {
    const c = p && typeof p.prefix === 'string' ? parseCidr(p.prefix) : null;
    if (!c || !String(p.prefix).includes('/')) continue;
    const prefix = `${formatIP(c.network, c.version)}/${c.prefix}`;
    const timelines = Array.isArray(p.timelines) ? p.timelines : [];
    const current = !end || !timelines.length || timelines.some((t) => t && typeof t.endtime === 'string' && t.endtime >= end);
    const prev = byPrefix.get(prefix);
    if (prev) {
      prev.current = prev.current || current;
      continue;
    }
    const size = 2 ** ((c.version === 4 ? 32 : 128) - c.prefix);
    const skipped = c.version === 4 ? wholeBlockSkipped(c.network, c.network + BigInt(size) - 1n) : null;
    const sweepable = c.version === 4 && !skipped && size <= max;
    // The first /22 of a larger public prefix, unless that /22 has nothing to sweep either.
    let part = c.version === 4 && !skipped && size > max ? firstSubnet(prefix, prefixFor(max)) : null;
    const first = part ? parseCidr(part) : null;
    if (first && wholeBlockSkipped(first.network, first.network + 2n ** BigInt(32 - first.prefix) - 1n)) part = null;
    byPrefix.set(prefix, {
      prefix, version: c.version, length: c.prefix, size, current, sweepable, skipped, part,
      sortKey: (BigInt(c.version) << 130n) + c.network
    });
  }
  const prefixes = [...byPrefix.values()]
    .sort((a, b) => (a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : a.length - b.length))
    .map(({ sortKey, ...rest }) => rest);
  const v4 = prefixes.filter((p) => p.version === 4);
  const resource = Number(String(data.resource ?? '').replace(/^AS/i, ''));
  return {
    asn: asn ?? (Number.isInteger(resource) && resource > 0 ? resource : null),
    prefixes,
    v4: v4.length,
    v6: prefixes.length - v4.length,
    v4Addresses: v4.reduce((n, p) => n + p.size, 0),
    sweepable: v4.filter((p) => p.sweepable).length,
    queryStart: typeof data.query_starttime === 'string' ? data.query_starttime : null,
    queryEnd: end
  };
}

/**
 * The prefixes an AS announced over the last two weeks: ONE RIPEstat request that sends only
 * the AS number (a large ISP's answer is about 50 KB). One retry on a network error or a 5xx.
 * Rejects with the HttpError / network error (an unknown AS answers an empty list, not an error).
 * @param {number|string} asn
 * @param {{ fetchImpl?: typeof fetch, signal?: AbortSignal, timeoutMs?: number }} [opts]
 * @returns {Promise<ReturnType<typeof parseAnnouncedPrefixes>>}
 */
export async function announcedPrefixes(asn, { fetchImpl = globalThis.fetch, signal, timeoutMs = 30000 } = {}) {
  const url = announcedPrefixesUrl(asn);
  throwIfAborted(signal);
  const json = await retry(() => fetchJson(url, {
    fetchImpl, signal, timeoutMs, headers: { accept: 'application/json' }, credentials: 'omit', referrerPolicy: 'no-referrer'
  }), { retries: 1, signal, baseDelayMs: 500, maxDelayMs: 4000 });
  return parseAnnouncedPrefixes(json, { asn: typeof asn === 'number' ? asn : parseAsn(asn) });
}

/**
 * What a set of picked prefixes adds up to (`addresses`: distinct ones, overlaps counted once).
 * @param {AnnouncedPrefix[]} prefixes
 * @param {Iterable<string>} selected picked prefixes
 * @param {{ max?: number }} [opts]
 * @returns {{ cidrs: string[], count: number, addresses: number, over: boolean, max: number }}
 */
export function prefixSelection(prefixes, selected, { max = SWEEP_MAX_ADDRESSES } = {}) {
  const want = new Set(selected || []);
  const cidrs = (Array.isArray(prefixes) ? prefixes : []).filter((p) => p.sweepable && want.has(p.prefix)).map((p) => p.prefix);
  // An AS often announces a prefix and a more specific one inside it: their addresses count once.
  const addresses = uniqueAddressCount(cidrs.map(parseCidr).filter(Boolean)
    .map((c) => ({ version: c.version, first: c.network, count: 2 ** ((c.version === 4 ? 32 : 128) - c.prefix) })));
  return { cidrs, count: cidrs.length, addresses, over: addresses > max, max };
}

/* ------------------------------------------------------------------------ */
/* Forward-confirmed reverse DNS                                            */
/* ------------------------------------------------------------------------ */

const canonName = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');

/**
 * Read a PTR answer. RFC 2317 classless delegation answers with a CNAME to another reverse
 * name first; the PTR records at the end of that chain count (`delegated` names it).
 * @param {object|null} response DohClient DnsResponse
 * @param {string} qname the reverse name asked for
 * @returns {{ state: 'names'|'no-ptr'|'nxdomain'|'servfail'|'error', names: string[], rcode: string|null,
 *   error: string|null, delegated: string|null }}
 */
export function ptrOutcome(response, qname) {
  const res = response && typeof response === 'object' ? response : null;
  if (!res || res.ok === false) {
    return { state: 'error', names: [], rcode: null, error: res && res.error ? String(res.error) : 'no answer', delegated: null };
  }
  const rcode = typeof res.rcode === 'string' ? res.rcode.toUpperCase() : 'NOERROR';
  const chain = followCnames(res.answers, qname);
  const delegated = chain.cnames.length ? chain.target : null;
  if (rcode === 'NXDOMAIN') return { state: 'nxdomain', names: [], rcode, error: null, delegated };
  if (rcode === 'SERVFAIL') return { state: 'servfail', names: [], rcode, error: null, delegated };
  if (rcode !== 'NOERROR') return { state: 'error', names: [], rcode, error: rcode, delegated };
  const owners = new Set([canonName(qname), ...chain.cnames]);
  const names = uniq((Array.isArray(res.answers) ? res.answers : [])
    .filter((rr) => rr && rr.type === 'PTR' && owners.has(canonName(rr.name)) && typeof rr.data === 'string')
    .map((rr) => canonName(rr.data))
    .filter(Boolean));
  return { state: names.length ? 'names' : 'no-ptr', names, rcode, error: null, delegated };
}

/**
 * Read one PTR name's forward answer (A for an IPv4 address, AAAA for IPv6), CNAMEs followed.
 * @param {object|null} response DohClient DnsResponse
 * @param {string} name the PTR name asked for
 * @param {string} ip the swept address (canonical)
 * @returns {{ state: 'match'|'other'|'nodata'|'nxdomain'|'error', addresses: string[], rcode: string|null, error: string|null }}
 */
export function forwardOutcome(response, name, ip) {
  const res = response && typeof response === 'object' ? response : null;
  if (!res || res.ok === false) return { state: 'error', addresses: [], rcode: null, error: res && res.error ? String(res.error) : 'no answer' };
  const rcode = typeof res.rcode === 'string' ? res.rcode.toUpperCase() : 'NOERROR';
  if (rcode === 'NXDOMAIN') return { state: 'nxdomain', addresses: [], rcode, error: null };
  if (rcode !== 'NOERROR') return { state: 'error', addresses: [], rcode, error: rcode };
  const type = ipVersion(ip) === 6 ? 'AAAA' : 'A';
  const chain = followCnames(res.answers, name);
  const owners = new Set([canonName(name), ...chain.cnames]);
  const addresses = uniq((Array.isArray(res.answers) ? res.answers : [])
    .filter((rr) => rr && rr.type === type && owners.has(canonName(rr.name)))
    .map((rr) => canonicalAddress(String(rr.data)))
    .filter(Boolean));
  if (!addresses.length) return { state: 'nodata', addresses, rcode, error: null };
  return { state: addresses.includes(ip) ? 'match' : 'other', addresses, rcode, error: null };
}

/**
 * @typedef {object} FcrdnsResult
 * @property {string} ip canonical address
 * @property {4|6} version
 * @property {string} query the reverse name (`5.2.0.192.in-addr.arpa`)
 * @property {string} status one of {@link FCRDNS_STATUSES}
 * @property {string[]} names PTR names (lowercase, no trailing dot)
 * @property {string[]} confirmed the PTR names that resolve back to the address
 * @property {Array<{ name: string, state: string, addresses: string[], error: string|null }>} forward
 *   forward lookups, one per checked PTR name (at most {@link FCRDNS_MAX_NAMES})
 * @property {number} unchecked PTR names not forward-checked (over the cap)
 * @property {string|null} rcode of the PTR answer
 * @property {string|null} error why the lookup failed (transport error text or rcode)
 * @property {'ptr'|'forward'|null} stage where an 'error' / 'servfail' came from
 * @property {string|null} delegated the RFC 2317 reverse name the answer was delegated to
 * @property {string|null} resolver the resolver that answered the PTR query
 */

/**
 * The verdict of one address from its PTR outcome and its names' forward outcomes (pure).
 * @param {{ ip: string, ptr: ReturnType<typeof ptrOutcome>, forward?: Array<{ name: string } & ReturnType<typeof forwardOutcome>>,
 *   unchecked?: number, resolver?: string|null }} input
 * @returns {FcrdnsResult}
 */
export function fcrdnsVerdict({ ip, ptr, forward = [], unchecked = 0, resolver = null }) {
  const canonical = canonicalAddress(ip) || String(ip);
  const base = {
    ip: canonical,
    version: ipVersion(canonical),
    query: (() => {
      try {
        return reversePtrName(canonical);
      } catch {
        return '';
      }
    })(),
    status: 'error',
    names: ptr ? [...ptr.names] : [],
    confirmed: [],
    forward: forward.map((f) => ({ name: f.name, state: f.state, addresses: [...(f.addresses || [])], error: f.error || null })),
    unchecked,
    rcode: ptr ? ptr.rcode : null,
    error: ptr ? ptr.error : 'no answer',
    stage: null,
    delegated: ptr ? ptr.delegated : null,
    resolver
  };
  if (!ptr) return { ...base, stage: 'ptr' };
  if (ptr.state === 'error') return { ...base, status: 'error', stage: 'ptr' };
  if (ptr.state === 'servfail') return { ...base, status: 'servfail', stage: 'ptr' };
  if (ptr.state === 'nxdomain') return { ...base, status: 'nxdomain' };
  if (ptr.state === 'no-ptr') return { ...base, status: 'no-ptr' };
  const confirmed = base.forward.filter((f) => f.state === 'match').map((f) => f.name);
  if (confirmed.length) return { ...base, status: 'confirmed', confirmed, error: null };
  const failed = base.forward.filter((f) => f.state === 'error');
  if (failed.length || !base.forward.length) {
    return { ...base, status: 'error', stage: 'forward', error: failed.length ? failed[0].error : 'not checked' };
  }
  return { ...base, status: 'mismatch', error: null };
}

/**
 * Forward-confirmed reverse DNS of one address: the PTR query, then an A (IPv4) or AAAA (IPv6)
 * query per PTR name (at most `maxNames`, stopping at the first that confirms). Never rejects
 * except with AbortError; a failed lookup is an 'error' verdict.
 * @param {string} ip
 * @param {{ dns: { query: Function }, signal?: AbortSignal, balance?: boolean, maxNames?: number, noCache?: boolean }} opts
 * @returns {Promise<FcrdnsResult>}
 */
export async function checkFcrdns(ip, { dns, signal, balance = false, maxNames = FCRDNS_MAX_NAMES, noCache = false } = {}) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('checkFcrdns: a DNS client with query(name, type, opts) is required');
  const canonical = canonicalAddress(ip);
  if (!canonical) throw new TypeError(`checkFcrdns: not an IP address: ${String(ip)}`);
  throwIfAborted(signal);
  const qname = reversePtrName(canonical);
  const ask = async (name, type) => {
    try {
      return await dns.query(name, type, { signal, balance, noCache });
    } catch (err) {
      if (errorKind(err) === 'abort') throw err;
      return { ok: false, error: err && err.message ? err.message : String(err) };
    }
  };
  const ptrRes = await ask(qname, 'PTR');
  const ptr = ptrOutcome(ptrRes, qname);
  const resolver = ptrRes && typeof ptrRes.resolver === 'string' ? ptrRes.resolver : null;
  if (ptr.state !== 'names') return fcrdnsVerdict({ ip: canonical, ptr, resolver });
  const type = ipVersion(canonical) === 6 ? 'AAAA' : 'A';
  const limit = Math.max(1, Math.floor(Number(maxNames)) || FCRDNS_MAX_NAMES);
  const forward = [];
  let unchecked = 0;
  for (const name of ptr.names) {
    if (forward.length >= limit) {
      unchecked += 1;
      continue;
    }
    if (forward.some((f) => f.state === 'match')) {
      unchecked += 1;
      continue;
    }
    // A PTR value that is no host name (an address, junk) is never asked for.
    if (!normalizeHostname(name, { allowSingleLabel: true })) {
      forward.push({ name, state: 'nxdomain', addresses: [], rcode: null, error: null });
      continue;
    }
    forward.push({ name, ...forwardOutcome(await ask(name, type), name, canonical) });
  }
  return fcrdnsVerdict({ ip: canonical, ptr, forward, unchecked, resolver });
}

/* ------------------------------------------------------------------------ */
/* Templated (ISP / cloud default) names                                    */
/* ------------------------------------------------------------------------ */

/**
 * Words ISPs put into generated names (with a number): dynamic / static pools, DSL, cable,
 * dial-up, customer premises, CGNAT, fibre access. Deliberately narrow: `web`, `host`, `srv`,
 * `node` … name real servers too.
 */
export const GENERIC_PTR_WORDS = Object.freeze([
  'dynamic', 'dyn', 'dynip', 'dhcp', 'pool', 'static', 'dsl', 'adsl', 'vdsl', 'xdsl', 'sdsl', 'cable', 'dial', 'dialup',
  'dialin', 'ppp', 'pppoe', 'broadband', 'customer', 'cust', 'client', 'clients', 'subscriber', 'residential', 'cpe',
  'cgnat', 'ftth', 'fttx', 'fttb', 'fttc', 'gpon', 'unassigned', 'unused'
]);
const GENERIC_SET = new Set(GENERIC_PTR_WORDS);
const IP_PLACEHOLDER = '{ip}';
const NUM_PLACEHOLDER = '{n}';

/** The ways an IPv4 address is written into a name, longest first. */
function v4Forms(addr) {
  const o = formatIP(addr.value, 4).split('.').map(Number);
  const r = [...o].reverse();
  const pad = (n) => String(n).padStart(3, '0');
  const forms = [];
  for (const sep of ['-', '.', '_']) {
    forms.push(o.join(sep), r.join(sep), o.map(pad).join(sep), r.map(pad).join(sep));
  }
  forms.push(o.map(pad).join(''), r.map(pad).join(''));
  forms.push({ text: o.map((n) => n.toString(16).padStart(2, '0')).join(''), hex: true });
  forms.push(String(Number(addr.value)));
  for (const sep of ['-', '.', '_']) forms.push(o.slice(1).join(sep), r.slice(0, 3).join(sep));
  return forms;
}

/** The ways an IPv6 address is written into a name, longest first. */
function v6Forms(addr) {
  const nibbles = addr.value.toString(16).padStart(32, '0');
  const groups = nibbles.match(/.{4}/g);
  const compressed = formatIP(addr.value, 6);
  return [
    { text: nibbles.split('').reverse().join('.'), hex: true },
    { text: groups.join('-'), hex: true },
    { text: nibbles, hex: true },
    { text: compressed.replace(/:/g, '-'), hex: true }
  ];
}

/** First occurrence of `form` in `name` that is not part of a longer number (or hex run). */
function findForm(name, form) {
  const text = typeof form === 'string' ? form : form.text;
  const hex = typeof form === 'object' && form.hex;
  const edge = hex ? /[0-9a-f]/ : /[0-9]/;
  let from = 0;
  while (text && from <= name.length) {
    const i = name.indexOf(text, from);
    if (i === -1) return -1;
    const before = i > 0 ? name[i - 1] : '';
    const after = name[i + text.length] || '';
    if (!edge.test(before) && !edge.test(after)) return i;
    from = i + 1;
  }
  return -1;
}

/**
 * The template of a generated PTR name, or null for a name that looks chosen by a person.
 * - `embedded`: the address is written into the name (dashes, dots, zero-padded, reversed, hex,
 *   as one number, or its last three octets): `203-0-113-5.isp.example.net` →
 *   `{ip}.isp.example.net`, `ec2-…compute.amazonaws.com`, `5.113.0.203.bc.googleusercontent.com`.
 * - `generic`: a pool word ({@link GENERIC_PTR_WORDS}) and a number: `dsl-pool-4471.isp.example.net`
 *   → `dsl-pool-{n}.isp.example.net`.
 * @param {string} name
 * @param {string} ip the address the name was found for
 * @returns {{ key: string, template: string, kind: 'embedded'|'generic', word: string|null }|null}
 */
export function ptrTemplate(name, ip) {
  const n = canonName(name);
  const addr = parseIP(canonicalAddress(ip) || '');
  if (!n || !addr) return null;
  const forms = (addr.version === 4 ? v4Forms(addr) : v6Forms(addr))
    .map((f) => (typeof f === 'string' ? { text: f, hex: false } : f))
    .filter((f, i, all) => f.text && all.findIndex((g) => g.text === f.text) === i)
    .sort((a, b) => b.text.length - a.text.length);
  for (const f of forms) {
    const i = findForm(n, f);
    if (i === -1) continue;
    const template = `${n.slice(0, i)}${IP_PLACEHOLDER}${n.slice(i + f.text.length)}`;
    return { key: `embedded:${template}`, template, kind: 'embedded', word: null };
  }
  if (!/\d/.test(n)) return null;
  const word = n.split(/[.\-_]/).map((tok) => tok.replace(/\d+/g, '')).find((tok) => GENERIC_SET.has(tok)) || null;
  if (!word) return null;
  const template = n.replace(/\d+/g, NUM_PLACEHOLDER);
  return { key: `generic:${template}`, template, kind: 'generic', word };
}

/**
 * Is a PTR name generated (see {@link ptrTemplate})?
 * @param {string} name
 * @param {string} ip
 * @returns {boolean}
 */
export function isTemplatedPtr(name, ip) {
  return ptrTemplate(name, ip) !== null;
}

/**
 * The operator of a swept address: a provider whose published ranges hold it (netinfo), else
 * one whose domain the PTR name sits under (`server-….r.cloudfront.net`, `a2-….deploy.static.
 * akamaitechnologies.com`: `via: 'ptr'`). A plain address gets netinfo's 'direct' / 'private'.
 * @param {string} ip
 * @param {string[]} [names] PTR names
 * @returns {object} netinfo.classifyResolution result (+ `via: 'ip'|'ptr'|null`)
 */
export function sweepClassification(ip, names = []) {
  const v = ipVersion(ip);
  const addrs = { ipv4: v === 4 ? [ip] : [], ipv6: v === 6 ? [ip] : [] };
  const byIp = classifyResolution({ status: 'NOERROR', ...addrs });
  if (byIp.provider && !byIp.provider.dnsOnly) return byIp;
  for (const name of Array.isArray(names) ? names : []) {
    const provider = matchProviderByCname(name);
    if (!provider || provider.dnsOnly) continue;
    const c = classifyResolution({ status: 'NOERROR', ...addrs, cnames: [name] });
    return { ...c, via: 'ptr', reasonKey: `ptr.op.${c.kind === 'cloudflare' ? 'cloudflare' : provider.category}` };
  }
  return byIp;
}

/* ------------------------------------------------------------------------ */
/* The sweep                                                                */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {FcrdnsResult & { template: ReturnType<typeof ptrTemplate>, classification: object, index: number }} SweepResult
 *   `template` of the first PTR name (null without one), `index` = position in the swept list
 */

/**
 * Sweep `addresses`: {@link checkFcrdns} for each, at most `concurrency` addresses at a time
 * (the DohClient's limiter still caps the HTTP requests at its own concurrency), each result
 * streamed to `onResult` with its template and operator. Resolves when every address is done
 * or the signal aborts (`aborted: true`; the addresses not reached are simply missing).
 * Never rejects on a DNS failure.
 * @param {string[]} addresses canonical addresses (parseSweepTarget().addresses)
 * @param {{ dns: { query: Function }, signal?: AbortSignal, concurrency?: number, balance?: boolean, maxNames?: number,
 *   noCache?: boolean, onResult?: (result: SweepResult) => void }} opts
 * @returns {Promise<{ results: SweepResult[], aborted: boolean }>} results in address order
 */
export async function runPtrSweep(addresses, {
  dns, signal, concurrency = 12, balance = true, maxNames = FCRDNS_MAX_NAMES, noCache = false, onResult
} = {}) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('runPtrSweep: a DNS client with query(name, type, opts) is required');
  const list = Array.isArray(addresses) ? addresses : [];
  const results = new Array(list.length);
  const width = Math.max(1, Math.min(SWEEP_MAX_CONCURRENCY, Math.floor(Number(concurrency)) || 12, list.length || 1));
  let next = 0;
  let aborted = false;
  const worker = async () => {
    while (next < list.length && !aborted) {
      if (signal && signal.aborted) {
        aborted = true;
        return;
      }
      const index = next;
      next += 1;
      let r;
      try {
        r = await checkFcrdns(list[index], { dns, signal, balance, maxNames, noCache });
      } catch (err) {
        if (errorKind(err) === 'abort') {
          aborted = true;
          return;
        }
        r = fcrdnsVerdict({ ip: list[index], ptr: { state: 'error', names: [], rcode: null, error: String((err && err.message) || err), delegated: null } });
      }
      const result = {
        ...r,
        index,
        template: r.names.length ? ptrTemplate(r.names[0], r.ip) : null,
        classification: sweepClassification(r.ip, r.names)
      };
      results[index] = result;
      if (typeof onResult === 'function') {
        try {
          onResult(result);
        } catch {
          // an observer error never stops the sweep
        }
      }
    }
  };
  await Promise.all(Array.from({ length: width }, worker));
  return { results: results.filter(Boolean), aborted: aborted || !!(signal && signal.aborted) };
}

/* ------------------------------------------------------------------------ */
/* Rows, summary, exports and hand-offs                                     */
/* ------------------------------------------------------------------------ */

/**
 * Is `name` the focus domain or under it?
 * @param {string} name
 * @param {string|null} focus
 * @returns {boolean}
 */
export function isFocusName(name, focus) {
  return !!focus && isSubdomainOf(canonName(name), canonName(focus));
}

const hasPtr = (r) => r.names.length > 0;
const failedStatus = (s) => s === 'servfail' || s === 'error';

/** The rank of one result (see {@link ROW_RANKS}). */
function rankOf(r, focus, collapsed) {
  if (r.names.some((n) => isFocusName(n, focus))) return ROW_RANKS.focus;
  if (hasPtr(r)) return collapsed || r.template ? ROW_RANKS.templated : ROW_RANKS.named;
  return failedStatus(r.status) ? ROW_RANKS.failed : ROW_RANKS.none;
}

const ipKey = (ip) => {
  const p = parseIP(ip);
  return p ? (BigInt(p.version) << 130n) + p.value : 0n;
};

/**
 * @typedef {object} SweepRow
 * @property {'address'|'pattern'} type
 * @property {string} key stable row key (the address, or 'pattern:' + template key)
 * @property {number} rank {@link ROW_RANKS}
 * @property {bigint} sortKey rank, then address order (the table's default sort)
 * @property {boolean} focus a PTR name is under the focus domain
 * @property {Array<{ serverId: string, name: string, ip: string }>} servers inventory matches
 * @property {SweepResult} [result] address rows
 * @property {string} [template] pattern rows: the template ('{ip}.isp.example.net')
 * @property {'embedded'|'generic'} [kind] pattern rows
 * @property {SweepResult[]} [members] pattern rows, address order
 * @property {Record<string, number>} [counts] pattern rows: members per status
 */

/**
 * The table rows of a sweep: one per address, except that addresses whose (first) PTR name
 * follows the same template are collapsed into one pattern row when there are at least
 * `minPattern` of them. A name under the focus domain is never collapsed. Rows are ordered by
 * rank ({@link ROW_RANKS}), then address.
 * @param {SweepResult[]} results
 * @param {{ focus?: string|null, collapse?: boolean, minPattern?: number, index?: Map<string, object[]>|null }} [opts]
 * @returns {SweepRow[]}
 */
export function sweepRows(results, { focus = null, collapse = true, minPattern = 2, index = null } = {}) {
  const list = (Array.isArray(results) ? results : []).filter(Boolean);
  const serversOf = (ips) => (index ? lookupServers(ips, index).map(({ server, ip }) => ({ serverId: server.id, name: server.name, ip })) : []);
  const groups = new Map();
  if (collapse) {
    for (const r of list) {
      if (!r.template || r.names.some((n) => isFocusName(n, focus))) continue;
      const g = groups.get(r.template.key);
      if (g) g.push(r);
      else groups.set(r.template.key, [r]);
    }
    for (const [k, g] of groups) if (g.length < minPattern) groups.delete(k);
  }
  const rows = [];
  const emitted = new Set();
  for (const r of list) {
    const key = r.template ? r.template.key : null;
    if (key && groups.has(key)) {
      if (emitted.has(key)) continue;
      emitted.add(key);
      const members = [...groups.get(key)].sort((a, b) => (ipKey(a.ip) < ipKey(b.ip) ? -1 : 1));
      const counts = Object.fromEntries(FCRDNS_STATUSES.map((s) => [s, 0]));
      for (const m of members) counts[m.status] += 1;
      rows.push({
        type: 'pattern',
        key: `pattern:${key}`,
        rank: ROW_RANKS.templated,
        sortKey: (BigInt(ROW_RANKS.templated) << 140n) + ipKey(members[0].ip),
        focus: false,
        servers: serversOf(members.map((m) => m.ip)),
        template: r.template.template,
        kind: r.template.kind,
        members,
        counts,
        classification: members[0].classification
      });
      continue;
    }
    const rank = rankOf(r, focus, false);
    rows.push({
      type: 'address',
      key: r.ip,
      rank,
      sortKey: (BigInt(rank) << 140n) + ipKey(r.ip),
      focus: rank === ROW_RANKS.focus,
      servers: serversOf([r.ip]),
      result: r
    });
  }
  return rows.sort((a, b) => (a.sortKey < b.sortKey ? -1 : a.sortKey > b.sortKey ? 1 : 0));
}

/**
 * Does one address pass a results filter ({@link SWEEP_FILTERS}) on its own?
 * @param {SweepResult} result
 * @param {string} filter
 * @param {{ focus?: string|null }} [opts] the focus domain, for the 'focus' filter
 * @returns {boolean}
 */
export function sweepResultMatches(result, filter, { focus = null } = {}) {
  switch (filter) {
    case 'ptr': return hasPtr(result);
    case 'focus': return result.names.some((n) => isFocusName(n, focus));
    case 'confirmed': return result.status === 'confirmed';
    case 'mismatch': return result.status === 'mismatch';
    case 'none': return result.status === 'no-ptr' || result.status === 'nxdomain';
    case 'failed': return failedStatus(result.status);
    default: return true;
  }
}

/**
 * Does a row pass a results filter ({@link SWEEP_FILTERS})? A pattern row passes when one of
 * its members does (a name under the focus domain is never in a pattern).
 * @param {SweepRow} row
 * @param {string} filter
 * @returns {boolean}
 */
export function sweepRowMatches(row, filter) {
  if (filter === 'focus') return row.focus;
  return (row.type === 'pattern' ? row.members : [row.result]).some((r) => sweepResultMatches(r, filter));
}

/**
 * The addresses of a row that pass a results filter, and `match` (the view's search), each on
 * its own: an address row gives its address or nothing, a pattern row the members that pass
 * (one mismatch among eight confirmed names is what the 'mismatch' filter asks for, not the
 * eight). What an export of a filtered table writes.
 * @param {SweepRow} row
 * @param {string} filter
 * @param {{ match?: ((result: SweepResult) => boolean)|null }} [opts]
 * @returns {SweepResult[]}
 */
export function sweepRowResults(row, filter, { match = null } = {}) {
  const pass = (r) => !match || match(r);
  if (row.type !== 'pattern') return sweepRowMatches(row, filter) && pass(row.result) ? [row.result] : [];
  return filter === 'focus' ? [] : row.members.filter((r) => sweepResultMatches(r, filter) && pass(r));
}

/**
 * Counts over a sweep's results.
 * @param {SweepResult[]} results
 * @param {{ focus?: string|null, minPattern?: number }} [opts]
 * @returns {{ done: number, byStatus: Record<string, number>, withPtr: number, noReverse: number, failed: number,
 *   forwardFailed: number, templated: number, patterns: number, focus: number, names: number, v6: number }}
 *   `forwardFailed`: addresses with PTR names none of which confirmed, where at least one forward lookup failed
 *   (an 'error' at the forward stage: a mismatch cannot be claimed)
 */
export function sweepSummary(results, { focus = null, minPattern = 2 } = {}) {
  const list = (Array.isArray(results) ? results : []).filter(Boolean);
  const byStatus = Object.fromEntries(FCRDNS_STATUSES.map((s) => [s, 0]));
  for (const r of list) byStatus[r.status] = (byStatus[r.status] || 0) + 1;
  const patternRows = sweepRows(list, { focus, collapse: true, minPattern }).filter((row) => row.type === 'pattern');
  return {
    done: list.length,
    byStatus,
    withPtr: list.filter(hasPtr).length,
    noReverse: byStatus['no-ptr'] + byStatus.nxdomain,
    failed: byStatus.servfail + byStatus.error,
    forwardFailed: list.filter((r) => r.status === 'error' && r.stage === 'forward').length,
    templated: list.filter((r) => r.template).length,
    patterns: patternRows.length,
    focus: list.filter((r) => r.names.some((n) => isFocusName(n, focus))).length,
    names: new Set(list.flatMap((r) => r.names)).size,
    v6: list.filter((r) => r.version === 6).length
  };
}

/** CSV columns of {@link sweepExportRows}, in order. */
export const SWEEP_CSV_COLUMNS = Object.freeze(['ip', 'status', 'ptr', 'confirmed', 'forward', 'template', 'operator', 'servers', 'focus', 'error']);

/**
 * One plain row per address (patterns expanded), for CSV: the forward answers as
 * `name=state:addr addr`, lists space-joined.
 * @param {SweepResult[]} results
 * @param {{ focus?: string|null, index?: Map<string, object[]>|null }} [opts]
 * @returns {Array<Record<string, string>>}
 */
export function sweepExportRows(results, { focus = null, index = null } = {}) {
  return (Array.isArray(results) ? results : []).filter(Boolean).map((r) => ({
    ip: r.ip,
    status: r.status,
    ptr: r.names.join(' '),
    confirmed: r.confirmed.join(' '),
    forward: r.forward.map((f) => `${f.name}=${f.state}${f.addresses.length ? `:${f.addresses.join(' ')}` : ''}`).join('; '),
    template: r.template ? r.template.template : '',
    operator: r.classification && r.classification.provider ? r.classification.provider.name : '',
    servers: index ? lookupServers([r.ip], index).map(({ server }) => server.name).join(' ') : '',
    focus: r.names.some((n) => isFocusName(n, focus)) ? 'yes' : '',
    error: r.error || ''
  }));
}

/**
 * The JSON export (`schema: 'domainscope.ptr-sweep/1'`). `summary` always counts the whole
 * sweep (`results`); `results` in the file are the `exported` ones (the rows the table shows),
 * and `filter` says what left the others out, so a reader can tell an address filtered out
 * from one never looked up (`planned` − `summary.done`, with `aborted`).
 * @param {SweepResult[]} results every result of the sweep
 * @param {{ exported?: SweepResult[]|null, filter?: { show?: string, search?: string }|null, target?: string,
 *   focus?: string|null, startedAt?: Date|null, finishedAt?: Date|null, planned?: number, aborted?: boolean,
 *   index?: Map<string, object[]>|null, app?: string, version?: string }} [meta] `exported`: the subset written
 *   (default: every result); `filter`: the table's filter ({@link SWEEP_FILTERS}) and search text, recorded as
 *   `{ show, search }` (null when nothing was filtered out)
 * @returns {object}
 */
export function sweepExportJson(results, {
  exported = null, filter = null, target = '', focus = null, startedAt = null, finishedAt = null, planned = null, aborted = false,
  index = null, app = 'DomainScope', version = ''
} = {}) {
  const all = (Array.isArray(results) ? results : []).filter(Boolean);
  const list = Array.isArray(exported) ? exported.filter(Boolean) : all;
  const summary = sweepSummary(all, { focus });
  const show = filter && SWEEP_FILTERS.includes(filter.show) ? filter.show : 'all';
  const search = filter && typeof filter.search === 'string' ? filter.search.trim() : '';
  return {
    schema: 'domainscope.ptr-sweep/1',
    app,
    version,
    target,
    focus: focus || null,
    startedAt: startedAt instanceof Date ? startedAt.toISOString() : null,
    finishedAt: finishedAt instanceof Date ? finishedAt.toISOString() : null,
    planned: Number.isFinite(planned) ? planned : all.length,
    aborted: !!aborted,
    filter: show !== 'all' || search ? { show, search } : null,
    exported: list.length,
    summary: { ...summary, byStatus: { ...summary.byStatus } },
    results: list.map((r) => ({
      ip: r.ip,
      status: r.status,
      names: [...r.names],
      confirmed: [...r.confirmed],
      forward: r.forward.map((f) => ({ ...f, addresses: [...f.addresses] })),
      unchecked: r.unchecked,
      rcode: r.rcode,
      error: r.error,
      stage: r.stage,
      delegated: r.delegated,
      template: r.template ? { template: r.template.template, kind: r.template.kind } : null,
      operator: r.classification && r.classification.provider ? { id: r.classification.provider.id, name: r.classification.provider.name, via: r.classification.via || 'ip' } : null,
      servers: index ? lookupServers([r.ip], index).map(({ server }) => server.name) : [],
      focus: r.names.some((n) => isFocusName(n, focus))
    }))
  };
}

/**
 * The PTR names of a sweep (sortHostnames order, unique), templated names left out unless
 * asked for; with `onlyFocus`, only the names under the focus domain.
 * @param {SweepResult[]} results
 * @param {{ focus?: string|null, templated?: boolean, onlyFocus?: boolean, confirmedOnly?: boolean }} [opts]
 * @returns {string[]}
 */
export function sweepNames(results, { focus = null, templated = false, onlyFocus = false, confirmedOnly = false } = {}) {
  const names = [];
  for (const r of (Array.isArray(results) ? results : []).filter(Boolean)) {
    for (const name of confirmedOnly ? r.confirmed : r.names) {
      if (!normalizeHostname(name)) continue;
      if (!templated && ptrTemplate(name, r.ip) && !isFocusName(name, focus)) continue;
      if (onlyFocus && !isFocusName(name, focus)) continue;
      names.push(name);
    }
  }
  return sortHostnames(uniq(names));
}

/**
 * The hosts "Add to Servers" offers: forward-confirmed, not templated (unless under the focus
 * domain), and neither an address nor a name the server list already has (so a second click
 * adds nothing twice). One entry per PTR name, with every address that confirms it.
 * @param {SweepResult[]} results
 * @param {{ servers?: Array<{ name: string, ips: string[], aliases?: string[] }>|null, index?: Map<string, object[]>|null,
 *   focus?: string|null }} [opts] `servers`: the list the hosts go into (the saved inventory, or the Servers editor's
 *   draft parsed); `index`: its IP index (inventory.buildIpIndex), built from `servers` when left out
 * @returns {Array<{ name: string, ips: string[] }>} sortHostnames order
 */
export function inventoryAdditions(results, { servers = null, index = null, focus = null } = {}) {
  const list = Array.isArray(servers) ? servers.filter((s) => s && typeof s.name === 'string') : [];
  const idx = index || (list.length ? buildIpIndex(list) : null);
  const known = new Set(list.flatMap((s) => [s.name, ...(Array.isArray(s.aliases) ? s.aliases : [])]).map(canonName));
  const byName = new Map();
  for (const r of (Array.isArray(results) ? results : []).filter(Boolean)) {
    if (r.status !== 'confirmed') continue;
    if (idx && lookupServers([r.ip], idx).length) continue;
    const name = r.confirmed[0];
    if (!name || known.has(name) || (ptrTemplate(name, r.ip) && !isFocusName(name, focus))) continue;
    const ips = byName.get(name) || [];
    if (!ips.includes(r.ip)) ips.push(r.ip);
    byName.set(name, ips);
  }
  return sortHostnames([...byName.keys()]).map((name) => ({ name, ips: byName.get(name) }));
}

/** The group an Ansible inventory (INI or YAML) gets the added hosts under. */
export const INVENTORY_GROUP = 'reverse_dns';

/**
 * The additions as plain `name ip [ip …]` lines: the simplest inventory format, which the
 * Servers editor and the CLI both read.
 * @param {Array<{ name: string, ips: string[] }>} additions
 * @returns {string[]}
 */
export function inventoryLines(additions) {
  return (Array.isArray(additions) ? additions : []).map((a) => `${a.name} ${a.ips.join(' ')}`);
}

const NAME_KEY_RE = /^(?:name|host_?name|fqdn|server(?:_?name)?|host|inventory_hostname)$/i;

/**
 * The name and address keys of a record to copy (the first element of a JSON / YAML list, the
 * first line of JSON Lines), and whether it holds its addresses as a list (`list`: then even one
 * address is written as one). `found`: the record has such keys (else `name` / `ip`).
 */
function recordKeys(first) {
  const keys = { name: 'name', ip: 'ip', list: false, found: false };
  if (!first || typeof first !== 'object' || Array.isArray(first)) return keys;
  const entries = Object.entries(first);
  const name = entries.find(([k, v]) => NAME_KEY_RE.test(k) && typeof v === 'string' && !normalizeIP(v));
  const ip = entries.find(([, v]) => (typeof v === 'string' && normalizeIP(v))
    || (Array.isArray(v) && v.length && v.every((x) => typeof x === 'string' && normalizeIP(x))));
  if (name && ip && name[0] !== ip[0]) return { name: name[0], ip: ip[0], list: Array.isArray(ip[1]), found: true };
  return keys;
}

/** The first `{…}` line of a text as an object (JSON Lines), or null. */
function firstJsonLine(text) {
  const line = text.split(/\r\n|\r|\n/).map((l) => l.trim()).find((l) => l.startsWith('{'));
  try {
    return line ? JSON.parse(line) : null;
  } catch {
    return null;
  }
}

/** A host's addresses in the record's shape: a string for one, a list for several (or when the list's records use lists). */
const recordIps = (a, keys) => (a.ips.length === 1 && !keys.list ? a.ips[0] : [...a.ips]);
/** One host as a record. */
const hostRecord = (a, keys) => ({ [keys.name]: a.name, [keys.ip]: recordIps(a, keys) });

/** A CSV cell, quoted when it holds the delimiter, a quote or a line break. */
const csvField = (value, delimiter) => (value.includes(delimiter) || /["\r\n]/.test(value) ? `"${value.replace(/"/g, '""')}"` : value);

/** A host name or IPv4 address as a plain YAML scalar; anything else (IPv6, a number) as a JSON string, valid YAML too. */
const yamlValue = (v) => (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(v)
  || (/^[A-Za-z0-9_][A-Za-z0-9_.-]*$/.test(v) && /[A-Za-z]/.test(v) && !/^(?:true|false|yes|no|on|off|null)$/i.test(v))
  ? v
  : JSON.stringify(v));
const yamlList = (ips, list = false) => (ips.length === 1 && !list ? yamlValue(ips[0]) : `[${ips.map(yamlValue).join(', ')}]`);
const indentOf = (line) => /^ */.exec(line)[0].length;
/** A line with content: not blank, not a comment only. */
const yamlContent = (line) => /\S/.test(line) && !/^\s*#/.test(line);

/** Nothing but a comment (or nothing) after a YAML key's colon. */
const noValue = (rest) => /^\s*(#.*)?$/.test(rest);

/**
 * `hostLines(indent, unit)` inserted under the `hosts:` of the top-level `group` of an Ansible
 * YAML inventory, after its last host (a `hosts:` key is added to a group without one),
 * wherever the group sits in the file; `unit` is the file's indentation step. Null when the
 * group or its `hosts:` is not a block map (a flow value such as `hosts: {}`): the caller then
 * uses a group of another name.
 * @param {string} text
 * @param {string} group
 * @param {(indent: string, unit: string) => string[]} hostLines
 * @returns {string|null}
 */
function yamlAddToGroup(text, group, hostLines) {
  const lines = text.split(/\r\n|\r|\n/);
  const start = lines.findIndex((l) => l.startsWith(`${group}:`) && noValue(l.slice(group.length + 1)));
  if (start === -1) return null;
  let end = lines.findIndex((l, i) => i > start && /^[^\s#]/.test(l));
  if (end === -1) end = lines.length;
  const lastContent = (from, to) => {
    for (let i = to - 1; i > from; i -= 1) if (yamlContent(lines[i])) return i;
    return from;
  };
  const first = lines.findIndex((l, i) => i > start && i < end && yamlContent(l));
  const unit = ' '.repeat(first === -1 ? 2 : indentOf(lines[first]));
  if (!unit) return null;
  const hosts = lines.findIndex((l, i) => i > start && i < end && indentOf(l) === unit.length && /^\s*hosts:(\s|$)/.test(l));
  let at;
  let add;
  if (hosts === -1) {
    // A group with vars / children only (or nothing yet): its hosts go into a new `hosts:` key.
    at = lastContent(start, end);
    add = [`${unit}hosts:`, ...hostLines(unit.repeat(2), unit)];
  } else {
    if (!noValue(lines[hosts].trim().slice('hosts:'.length))) return null;
    let stop = lines.findIndex((l, i) => i > hosts && i < end && yamlContent(l) && indentOf(l) <= unit.length);
    if (stop === -1) stop = end;
    const host = lines.findIndex((l, i) => i > hosts && i < stop && yamlContent(l));
    at = lastContent(hosts, stop);
    add = hostLines(host === -1 ? unit.repeat(2) : ' '.repeat(indentOf(lines[host])), unit);
  }
  lines.splice(at + 1, 0, ...add);
  return `${lines.join('\n').replace(/\s+$/, '')}\n`;
}

/** Does `after` parse to exactly the servers of `before` plus the additions, with no new warning? */
function addsExactly(before, after, additions) {
  const a = parseInventory(before);
  const b = parseInventory(after);
  const sig = (name, ips) => `${String(name).toLowerCase()}\u0000${ips.join(' ')}`;
  const want = [...a.servers.map((s) => sig(s.name, s.ips)), ...additions.map((x) => sig(x.name, x.ips))].sort();
  const got = b.servers.map((s) => sig(s.name, s.ips)).sort();
  return b.warnings.length <= a.warnings.length && want.length === got.length && want.every((v, i) => v === got[i]);
}

/**
 * The Servers editor text with the additions written in the text's own format
 * (inventory.inventoryFormat), for `state.session.inventoryDraft`: the user reviews and saves
 * it, nothing is saved here.
 * - plain lines and an empty text: `name ip …` lines under a comment line (`ip name` in a hosts file);
 * - Ansible INI: `name ansible_host=ip` lines under a `[reverse_dns]` header ({@link INVENTORY_GROUP};
 *   a second one when the file has the group already, which Ansible merges);
 * - JSON Lines (a host record alone on one line too): one object per line; a JSON array: one
 *   element per host. Both with the name and address keys of the first record when it has plain
 *   ones (`name` / `ip` otherwise), and its addresses as a list when that record holds them so;
 * - CSV: one row per host in the header's column order (the name and first address columns);
 * - YAML: an Ansible inventory gets a top-level `reverse_dns` group, or, when it has one (an
 *   earlier addition), the hosts go under that group's `hosts:`; a list gets one item per host.
 * Anything else (a JSON object such as Terraform or ansible-inventory output, a YAML map of
 * another shape, a CSV without a name column) is not rewritten: `text` is null with
 * `reason: 'format'`, and the caller offers `lines` to copy. The new text is always parsed
 * back: unless it gives exactly the old servers plus the additions, with no new warning,
 * `text` is null with `reason: 'check'`.
 * @param {string} base the editor's current text (an unsaved draft, else the saved inventory)
 * @param {Array<{ name: string, ips: string[] }>} additions
 * @param {{ label?: string, date?: Date }} [opts] the sweep's target and the date, for the comment line
 * @returns {{ text: string|null, format: string, reason: null|'format'|'check', group: string|null,
 *   newGroup: boolean, lines: string[] }} `group`: the Ansible group the hosts went into, `newGroup`: the list did not
 *   have it before
 */
export function inventoryDraft(base, additions, { label = '', date = new Date() } = {}) {
  const head = String(base ?? '').replace(/\s+$/, '');
  const list = (Array.isArray(additions) ? additions : []).filter((a) => a && a.name && Array.isArray(a.ips) && a.ips.length);
  const lines = inventoryLines(list);
  const info = inventoryFormat(head);
  const out = { text: null, format: info.format, reason: null, group: null, newGroup: false, lines };
  if (!list.length) return { ...out, text: head ? `${head}\n` : '' };
  const day = date instanceof Date && !Number.isNaN(date.getTime()) ? date.toISOString().slice(0, 10) : '';
  // The label is user text: one line, no comment-breaking characters.
  const what = String(label || '').replace(/[\r\n]+/g, ' ').slice(0, 120);
  const comment = `# reverse DNS sweep${what ? ` of ${what}` : ''}${day ? ` (${day})` : ''}: forward-confirmed hosts`;
  const append = (block, sep = '\n\n') => `${head ? `${head}${sep}` : ''}${block.join('\n')}\n`;
  const perAddress = list.flatMap((a) => a.ips.map((ip) => ({ name: a.name, ip })));
  let text = null;
  switch (info.format) {
    case 'empty':
    case 'lines': {
      // A hosts file (`ip name` lines) keeps its order.
      const firsts = head.split(/\r\n|\r|\n/).map((l) => l.trim()).filter((l) => l && !/^(#|;|\/\/)/.test(l)).map((l) => l.split(/\s+/)[0]);
      const ipFirst = firsts.length > 0 && firsts.filter((x) => normalizeIP(x)).length * 2 > firsts.length;
      text = append([comment, ...(ipFirst ? perAddress.map((x) => `${x.ip} ${x.name}`) : lines)]);
      break;
    }
    case 'ini':
      out.group = INVENTORY_GROUP;
      out.newGroup = !head.split(/\r\n|\r|\n/).some((l) => l.trim() === `[${INVENTORY_GROUP}]`);
      text = append([comment, `[${INVENTORY_GROUP}]`, ...perAddress.map((x) => `${x.name} ansible_host=${x.ip}`)]);
      break;
    case 'jsonl': {
      const keys = recordKeys(firstJsonLine(head));
      text = append(list.map((a) => JSON.stringify(hostRecord(a, keys))), '\n');
      break;
    }
    case 'json': {
      // One host record alone on one line is JSON Lines of one host: each addition gets a line.
      const one = info.data && typeof info.data === 'object' && !Array.isArray(info.data) && !/[\r\n]/.test(head) ? recordKeys(info.data) : null;
      if (one && one.found) {
        text = append(list.map((a) => JSON.stringify(hostRecord(a, one))), '\n');
        break;
      }
      if (!Array.isArray(info.data) || !info.data.every((x) => x && typeof x === 'object' && !Array.isArray(x))) break;
      const keys = recordKeys(info.data[0]);
      const items = list.map((a) => JSON.stringify(hostRecord(a, keys)));
      const end = head.lastIndexOf(']');
      const before = head.slice(0, end).replace(/\s+$/, '');
      const comma = info.data.length ? ',' : '';
      if (!head.includes('\n')) {
        text = `${before}${comma}${comma ? ' ' : ''}${items.join(', ')}]\n`;
      } else {
        const indent = (/\[[ \t]*\r?\n([ \t]*)\S/.exec(head) || [null, '  '])[1];
        text = `${before}${comma}\n${items.map((x) => `${indent}${x}`).join(',\n')}\n]\n`;
      }
      break;
    }
    case 'csv': {
      const ipColumn = info.header.findIndex((c) => c.role === 'ip');
      if (info.nameColumn < 0 || ipColumn < 0) break;
      const d = info.delimiter;
      const row = (a) => info.header.map((c, i) => csvField(i === info.nameColumn ? a.name : i === ipColumn ? a.ips.join(' ') : '', d)).join(d);
      text = append(list.map(row), '\n');
      break;
    }
    case 'yaml': {
      const data = info.data;
      if (Array.isArray(data) && data.every((x) => x && typeof x === 'object' && !Array.isArray(x))) {
        const keys = recordKeys(data[0]);
        const indent = (/^([ \t]*)-[ \t]/m.exec(head) || [null, ''])[1];
        text = append([comment, ...list.flatMap((a) => [
          `${indent}- ${keys.name}: ${yamlValue(a.name)}`, `${indent}  ${keys.ip}: ${yamlList(a.ips, keys.list)}`
        ])]);
      } else if (data && !Array.isArray(data) && ('all' in data || /(^|\s)ansible_host\s*:/m.test(head))) {
        // A top-level group next to `all` (a host's further addresses go into `ips`): the
        // reverse_dns group an earlier click wrote gets the new hosts under its `hosts:`; when
        // that cannot be done, a group of the next free name (reverse_dns_2 …) is added.
        const hosts = (pad, unit = '  ') => list.flatMap((a) => [
          `${pad}${yamlValue(a.name)}:`, `${pad}${unit}ansible_host: ${yamlValue(a.ips[0])}`,
          ...(a.ips.length > 1 ? [`${pad}${unit}ips: ${yamlList(a.ips)}`] : [])
        ]);
        const into = INVENTORY_GROUP in data ? yamlAddToGroup(head, INVENTORY_GROUP, (pad, unit) => [`${pad}${comment}`, ...hosts(pad, unit)]) : null;
        if (into && addsExactly(head, into, list)) {
          out.group = INVENTORY_GROUP;
          text = into;
          break;
        }
        const group = [INVENTORY_GROUP, ...Array.from({ length: 98 }, (_, i) => `${INVENTORY_GROUP}_${i + 2}`)].find((g) => !(g in data));
        if (!group) break;
        out.group = group;
        out.newGroup = true;
        text = append([comment, `${group}:`, '  hosts:', ...hosts('    ')]);
      }
      break;
    }
    default:
      break;
  }
  if (text === null) return { ...out, group: null, newGroup: false, reason: 'format' };
  if (!addsExactly(head, text, list)) return { ...out, group: null, newGroup: false, reason: 'check' };
  return { ...out, text };
}

/**
 * What "Add names to a Subdomains scan" hands over: the PTR names (not templated, under the
 * focus domain when one is given) and the domains to type into the scan — the focus domain,
 * else the registrable domains of the names, the most frequent first (at most `maxDomains`).
 * @param {SweepResult[]} results
 * @param {{ focus?: string|null, maxDomains?: number, maxNames?: number }} [opts]
 * @returns {{ names: string[], domains: string[], moreDomains: number }}
 */
export function scanHandoff(results, { focus = null, maxDomains = 5, maxNames = 2000 } = {}) {
  const f = focus ? normalizeHostname(focus) : null;
  const names = sweepNames(results, { focus: f, onlyFocus: !!f }).slice(0, maxNames);
  if (f) return { names, domains: names.length ? [f] : [], moreDomains: 0 };
  const counts = new Map();
  for (const n of names) {
    const d = registrableDomain(n) || n;
    counts.set(d, (counts.get(d) || 0) + 1);
  }
  const ranked = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).map(([d]) => d);
  return { names, domains: ranked.slice(0, maxDomains), moreDomains: Math.max(0, ranked.length - maxDomains) };
}
