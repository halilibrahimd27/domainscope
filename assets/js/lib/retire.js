/**
 * retire.js — "what still points at this address?": before a server is switched off or
 * renumbered, every DNS record, CNAME chain, SPF mechanism, MX / NS host, HTTPS address hint and
 * zone-file record that still reaches the address, as a change list. DOM-free; runs in browsers
 * and Node 22.
 *
 * - {@link parseRetireTargets}: what the user typed → the blocks to retire (single addresses and
 *   networks up to {@link RETIRE_MAX_ADDRESSES} addresses: an IPv4 /24, an IPv6 /120).
 * - {@link checkDomain}: one domain over the injected DNS client — its own name, the host names it
 *   is given (a Subdomains / SSL Targets result of the page session, the imported zone, a passive
 *   hit the user asked to check), its MX and NS hosts, its SPF policy (lib/health.js
 *   spfLookupCount, which walks the include tree) and the HTTPS record of its name.
 * - {@link spfCoverage}: every ip4 / ip6 / a / mx mechanism of an SPF tree that covers a retiring
 *   address, with the include path and the qualifier it has at the top (a match inside an include
 *   authorizes only when every link passes it on); a macro that needs the sender (`%{i}`, `%{s}` …),
 *   a `ptr` mechanism, a failed or skipped lookup → "cannot tell", never "not covered".
 * - {@link zoneCandidates}: the imported zone's records that reach an address (A / AAAA, in-zone
 *   CNAME chains, MX / NS / SRV / HTTPS targets, HTTPS hints, SPF ip4 / ip6), proxied origins
 *   included; {@link verifyZoneRefs} asks public DNS whether each is still served, and
 *   {@link buildChanges} lists them with the live findings: seen over DoH (`live`), found only in
 *   the file (`file`), hidden behind the proxy (`hidden`) or not asked because the name looks
 *   internal (`internal`).
 * - {@link runRetireCheck}: the whole check (every domain, then the zone's candidates), streamed
 *   as events and cancellable; what finished before an abort is kept. {@link retireGaps}: what it
 *   could not settle (failed lookups, "cannot tell", a stop) — only a check without any of it may
 *   say that nothing points at the address.
 * - Passive reverse IP (HackerTarget, ip.thc.org: lib/ipintel.js, only on a click) finds names
 *   outside the user's list; they stay `unverified` until checked like any other host name.
 * - {@link inventoryOwners}: which servers of the user's list own the addresses.
 * - {@link retireExportRows} / {@link retireExportJson}: CSV / JSON of the change list.
 *
 * Severity, worst first ({@link SEVERITIES}): `mail` (an SPF mechanism that authorizes the
 * address, an MX host on it) > `ns` (a name server on it) > `live` (an A / AAAA record or an HTTPS
 * hint that answers it) > `origin` (a proxied record's origin: visitors never see the address, the
 * proxy does) > `chain` (a CNAME chain ending at it) > `file` (only in the zone file) > `stale` (an
 * SPF term that does not authorize it, a passive hit nobody checked) > `unknown` (cannot tell).
 *
 * Nothing is sent by importing this module. A check sends DNS queries (names and types) to the
 * resolvers of the client it is given; the addresses themselves are only compared here.
 */

import { throwIfAborted, errorKind, uniq } from './util.js';
import { parseIP, parseCidr, formatIP, normalizeIP, isPrivateIP } from './netinfo.js';
import { normalizeHostname, isSubdomainOf, registrableDomain, sortHostnames } from './domain.js';
import { spfLookupCount, parseSpf } from './health.js';

/* ------------------------------------------------------------------------ */
/* Limits and vocabularies (frozen; the i18n coverage test derives keys)    */
/* ------------------------------------------------------------------------ */

/** Most addresses one check retires: an IPv4 /24 or an IPv6 /120. */
export const RETIRE_MAX_ADDRESSES = 256;
/** The widest network per family ({@link RETIRE_MAX_ADDRESSES} addresses). */
export const RETIRE_MIN_PREFIX = Object.freeze({ 4: 24, 6: 120 });
/** Most domains one check takes. */
export const RETIRE_MAX_DOMAINS = 25;
/** Most known host names resolved in one check, every domain together (2 queries each). */
export const RETIRE_MAX_HOSTS = 1000;
/** MX / NS hosts followed per domain (more is a misconfiguration; RFC 7208 stops at 10 MX). */
export const RETIRE_MAX_MX = 10;
export const RETIRE_MAX_NS = 13;
/** Zone-file records verified live in one check (1–3 queries each); the rest stay unverified. */
export const RETIRE_MAX_ZONE_REFS = 1000;
/**
 * Addresses one passive lookup asks about: each costs one HackerTarget request (about 50 free a day
 * from the user's address, shared with the Subdomains source) and one ip.thc.org request.
 */
export const PASSIVE_MAX_ADDRESSES = 8;
/** The passive reverse-IP services, in the order they are shown. */
export const PASSIVE_SOURCES = Object.freeze(['hackertarget', 'thc']);
/** Severity of a change, worst first (`retire.sev.<id>`). */
export const SEVERITIES = Object.freeze(['mail', 'ns', 'live', 'origin', 'chain', 'file', 'stale', 'unknown']);
/** How a change was confirmed (`retire.ver.<id>`). */
export const VERIFIED_STATES = Object.freeze(['live', 'file', 'hidden', 'internal', 'unverified', 'unknown']);
/**
 * What to change (`retire.act.<id>`): remove the value (or put the new address in), point the
 * record at a host that stays, narrow an SPF range that covers more than the retired addresses,
 * nothing in the record itself (an SPF a / mx mechanism, a CNAME: it follows the record it names),
 * change the glue at the parent too, a provider's record (not the user's), the proxy's origin
 * setting, or look at it by hand (cannot tell).
 */
export const CHANGE_ACTIONS = Object.freeze(['remove', 'repoint', 'narrow', 'follow', 'glue', 'provider', 'origin', 'check']);
/** Why an SPF term's coverage cannot be told (`retire.act.check.<id>`). */
export const UNKNOWN_REASONS = Object.freeze(['macro', 'ptr', 'lookup-failed', 'skipped', 'include-failed', 'multiple']);
/** What a failed lookup of one domain was for (DomainCheck.failures `what`; `retire.fail.<id>`). */
export const FAILURE_KINDS = Object.freeze(['name', 'mx', 'ns', 'spf', 'https']);
/** Where a known host name came from (`retire.src.<id>`). */
export const HOST_SOURCES = Object.freeze(['scan', 'zone', 'passive', 'discovered']);
/** Issues of {@link parseRetireTargets} (`retire.issue.<code>`). */
export const TARGET_ISSUES = Object.freeze(['invalid', 'too-large', 'host-bits', 'over-cap', 'private', 'nothing']);
/** Columns of {@link retireExportRows} (language-neutral codes; the view writes the same headers). */
export const RETIRE_CSV_COLUMNS = Object.freeze(['group', 'severity', 'name', 'type', 'value', 'address', 'action', 'verified', 'via', 'sources', 'line']);

const SEVERITY_RANK = Object.freeze(Object.fromEntries(SEVERITIES.map((s, i) => [s, i])));
const PREFIX_BITS = { 4: 32, 6: 128 };

/* ------------------------------------------------------------------------ */
/* Addresses and blocks                                                     */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} RetireBlock
 * @property {string} input what the user typed
 * @property {string} cidr canonical `network/prefix`
 * @property {string} label the address for a single one, else the CIDR
 * @property {4|6} version
 * @property {bigint} network
 * @property {number} prefix
 * @property {number} size addresses in it
 * @property {string} first
 * @property {string} last
 * @property {boolean} single one address (/32, /128)
 */

const maskFor = (version, prefix) => {
  const bits = BigInt(PREFIX_BITS[version]);
  const all = (1n << bits) - 1n;
  return all ^ ((1n << (bits - BigInt(prefix))) - 1n);
};

/** An IPv4-mapped IPv6 address (`::ffff:192.0.2.1`) as the IPv4 address it stands for. */
function unmapped(ip) {
  if (!ip) return null;
  if (ip.version === 6 && ip.value >> 32n === 0xffffn) return { version: 4, value: ip.value & 0xffffffffn };
  return ip;
}

/**
 * A range `{ version, network, prefix }` of an address and a prefix length (host bits masked);
 * a mapped IPv6 address is its IPv4 address. Null for a bad address or prefix.
 * @param {string} address
 * @param {number|null} [prefix] null → a single address
 * @returns {{ version: 4|6, network: bigint, prefix: number }|null}
 */
export function rangeOf(address, prefix = null) {
  const ip = unmapped(parseIP(String(address ?? '')));
  if (!ip) return null;
  const bits = PREFIX_BITS[ip.version];
  const p = prefix === null || prefix === undefined ? bits : Number(prefix);
  if (!Number.isInteger(p) || p < 0 || p > bits) return null;
  return { version: ip.version, network: ip.value & maskFor(ip.version, p), prefix: p };
}

/**
 * How a range (an SPF ip4 / ip6 term, an a / mx term's address with its CIDR length) relates to a
 * retiring block. CIDR blocks either nest or do not touch.
 * @param {{ version: number, network: bigint, prefix: number }} range
 * @param {{ version: number, network: bigint, prefix: number }} block
 * @returns {'equal'|'contains'|'within'|null} equal: the same block; contains: the range covers the
 *   block and more; within: the range is part of the block; null: no overlap (or another family)
 */
export function rangeRelation(range, block) {
  if (!range || !block || range.version !== block.version) return null;
  if (range.prefix <= block.prefix) {
    if ((block.network & maskFor(range.version, range.prefix)) !== range.network) return null;
    return range.prefix === block.prefix ? 'equal' : 'contains';
  }
  return (range.network & maskFor(block.version, block.prefix)) === block.network ? 'within' : null;
}

/**
 * The retiring block holding an address, or null.
 * @param {string} address
 * @param {RetireBlock[]} blocks
 * @returns {RetireBlock|null}
 */
export function blockOf(address, blocks) {
  const r = rangeOf(address);
  if (!r) return null;
  return (blocks || []).find((b) => rangeRelation(r, b) === 'within' || rangeRelation(r, b) === 'equal') || null;
}

/**
 * The tokens of the address box: one per word, `#` starts a comment, commas / semicolons separate.
 * @param {string} text
 * @returns {string[]}
 */
export function retireTokens(text) {
  return String(text ?? '').split(/\r?\n/).flatMap((line) => line.replace(/#.*$/, '').split(/[\s,;]+/)).filter(Boolean);
}

function makeBlock(input, range) {
  const size = Number(1n << BigInt(PREFIX_BITS[range.version] - range.prefix));
  const first = formatIP(range.network, range.version);
  const last = formatIP(range.network + BigInt(size) - 1n, range.version);
  const single = range.prefix === PREFIX_BITS[range.version];
  const cidr = `${first}/${range.prefix}`;
  return { input, cidr, label: single ? first : cidr, version: range.version, network: range.network, prefix: range.prefix, size, first, last, single };
}

/**
 * Read the addresses to retire: IPv4 / IPv6 addresses (brackets, a mapped IPv4) and networks
 * (`192.0.2.0/28`, host bits masked with a `host-bits` note) up to {@link RETIRE_MIN_PREFIX}. A block
 * inside another one counts once. Private addresses are kept (a zone file may point at them) with a
 * `private` note: public resolvers do not see internal (split-horizon) records.
 * @param {string} text
 * @param {{ max?: number }} [opts]
 * @returns {{ kind: 'empty'|'addresses', blocks: RetireBlock[], addresses: string[], total: number,
 *   issues: Array<{ code: string, severity: 'error'|'warn'|'info', params: object }>, ok: boolean, label: string }}
 *   `addresses`: every single address of the blocks (for the passive lookups and the owner match)
 */
export function parseRetireTargets(text, { max = RETIRE_MAX_ADDRESSES } = {}) {
  const tokens = retireTokens(text);
  const issues = [];
  const invalid = [];
  const hostBits = [];
  let found = [];
  for (const token of tokens) {
    const slash = token.indexOf('/');
    if (slash === -1) {
      const r = rangeOf(token);
      if (r) found.push(makeBlock(token, r));
      else invalid.push(token);
      continue;
    }
    const parsed = parseCidr(token);
    if (!parsed) {
      invalid.push(token);
      continue;
    }
    // A mapped IPv6 network (`::ffff:192.0.2.0/120`) is its IPv4 network.
    const mapped = parsed.version === 6 && parsed.prefix >= 96 && parsed.network >> 32n === 0xffffn;
    const block = makeBlock(token, mapped
      ? { version: 4, network: parsed.network & 0xffffffffn, prefix: parsed.prefix - 96 }
      : { version: parsed.version, network: parsed.network, prefix: parsed.prefix });
    if (block.prefix < RETIRE_MIN_PREFIX[block.version]) {
      issues.push({ code: 'too-large', severity: 'error', params: { input: token, prefix: RETIRE_MIN_PREFIX[block.version], max } });
      continue;
    }
    const typed = unmapped(parseIP(token.slice(0, slash)));
    if (typed && typed.value !== block.network && !block.single) hostBits.push({ input: token, network: block.cidr });
    found.push(block);
  }
  if (invalid.length) issues.push({ code: 'invalid', severity: 'warn', params: { items: invalid.slice(0, 5).join(', '), count: invalid.length } });
  for (const hb of hostBits.slice(0, 3)) issues.push({ code: 'host-bits', severity: 'info', params: hb });
  // Widest first, so a block inside a kept one is dropped (one address counts once).
  found.sort((a, b) => a.prefix - b.prefix);
  const blocks = [];
  for (const b of found) {
    if (!blocks.some((k) => rangeRelation(b, k) === 'within' || rangeRelation(b, k) === 'equal')) blocks.push(b);
  }
  // Back in the order they were typed.
  found = blocks.sort((a, b) => tokens.indexOf(a.input) - tokens.indexOf(b.input));
  const total = found.reduce((n, b) => n + b.size, 0);
  if (total > max) issues.push({ code: 'over-cap', severity: 'error', params: { count: total, max } });
  const priv = found.filter((b) => isPrivateIP(b.first));
  if (priv.length) issues.push({ code: 'private', severity: 'info', params: { items: priv.slice(0, 3).map((b) => b.label).join(', '), count: priv.length } });
  const kind = tokens.length ? 'addresses' : 'empty';
  if (kind === 'addresses' && !found.length && !issues.some((i) => i.severity === 'error')) {
    issues.push({ code: 'nothing', severity: 'error', params: {} });
  }
  const ok = found.length > 0 && !issues.some((i) => i.severity === 'error');
  const addresses = [];
  if (ok) {
    for (const b of found) for (let i = 0n; i < BigInt(b.size); i += 1n) addresses.push(formatIP(b.network + i, b.version));
  }
  const labels = found.map((b) => b.label);
  const label = labels.length > 3 ? `${labels.slice(0, 3).join(', ')} (+${labels.length - 3})` : labels.join(', ');
  return { kind, blocks: ok ? found : [], addresses, total, issues, ok, label };
}

/**
 * Read the domain box: host names (URLs, a trailing dot and `*.` are cleaned), one per word;
 * duplicates dropped, at most `max`.
 * @param {string} text
 * @param {{ max?: number }} [opts]
 * @returns {{ domains: string[], invalid: string[], truncated: number }}
 */
export function parseDomainList(text, { max = RETIRE_MAX_DOMAINS } = {}) {
  const domains = [];
  const invalid = [];
  for (const token of retireTokens(text)) {
    const name = normalizeHostname(token.replace(/^\*\./, ''));
    if (!name || !name.includes('.') || normalizeIP(name)) invalid.push(token);
    else if (!domains.includes(name)) domains.push(name);
  }
  return { domains: domains.slice(0, max), invalid, truncated: Math.max(0, domains.length - max) };
}

/* ------------------------------------------------------------------------ */
/* SPF                                                                      */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} SpfMatch
 * @property {string[]} path the policies from the checked domain to the one holding the term
 * @property {string} holder the domain whose SPF record holds the term
 * @property {string|null} record that record
 * @property {string} term the term as written (`ip4:192.0.2.0/24`, `a:mail.example.com/24`)
 * @property {'ip4'|'ip6'|'a'|'mx'} mechanism
 * @property {'+'|'-'|'~'|'?'} qualifier the term's own qualifier
 * @property {'+'|'-'|'~'|'?'|null} effective the result it gives the checked domain: through an
 *   `include` only a pass counts (then the include's qualifier applies), a `redirect` passes the
 *   result on; null when a link in the path turns it into "no match"
 * @property {'equal'|'contains'|'within'} relation of the term's range to the block
 * @property {string} block the retiring block (CIDR)
 * @property {string} range the term's range (`192.0.2.0/24`)
 * @property {{ host: string, address: string }|null} via an a / mx term: the host and the address that matched
 */

/**
 * @typedef {object} SpfUnknown
 * @property {string[]} path
 * @property {string} holder
 * @property {string|null} record
 * @property {string} term
 * @property {string} mechanism
 * @property {string} reason one of {@link UNKNOWN_REASONS}
 * @property {string|null} target the host the term names, when known
 */

/**
 * The result a term gives the checked domain through its include / redirect chain (RFC 7208 §5.2:
 * an include matches only when the included policy passes).
 * @param {Array<{ kind: 'include'|'redirect', qualifier: string }>} chain outermost first
 * @param {string} qualifier the term's own qualifier
 * @returns {'+'|'-'|'~'|'?'|null}
 */
export function effectiveQualifier(chain, qualifier) {
  let cur = qualifier;
  for (let i = (chain || []).length - 1; i >= 0; i -= 1) {
    const link = chain[i];
    if (link.kind === 'redirect') continue;
    if (cur !== '+') return null;
    cur = link.qualifier || '+';
  }
  return cur;
}

/**
 * Every mechanism of an SPF tree (lib/health.js spfLookupCount().tree, with its term extensions)
 * that covers a retiring address, and every one whose coverage cannot be told.
 * - ip4 / ip6: the term's range against each block;
 * - a: each address of the named host, widened by the term's CIDR length (`a/24`);
 * - mx: each MX host's addresses (`mxAddresses`: host → { addresses, error }), widened the same way;
 * - include / redirect: followed with the path; a policy that could not be read → include-failed;
 * - a macro that needs the sender (`%{i}`, `%{s}`, `%{l}` …), `ptr`, a failed or skipped lookup → unknown.
 * `exists` without such a macro does not depend on the address (it matches every sender or none).
 * @param {object|null} tree
 * @param {RetireBlock[]} blocks
 * @param {{ mxAddresses?: Map<string, { addresses: string[], error?: string|null }> }} [opts]
 * @returns {{ matches: SpfMatch[], unknown: SpfUnknown[] }}
 */
export function spfCoverage(tree, blocks, { mxAddresses = new Map() } = {}) {
  const matches = [];
  const unknown = [];
  if (!tree || !Array.isArray(tree.terms)) return { matches, unknown };
  const at = (node, path, t, reason, target = null) => unknown.push({
    path: [...path], holder: node.domain, record: node.record, term: t.term, mechanism: t.mechanism, reason, target
  });
  const matchRange = (node, path, chain, t, range, via = null) => {
    if (!range) return;
    for (const b of blocks) {
      const relation = rangeRelation(range, b);
      if (!relation) continue;
      matches.push({
        path: [...path], holder: node.domain, record: node.record, term: t.term, mechanism: t.mechanism,
        qualifier: t.qualifier, effective: effectiveQualifier(chain, t.qualifier), relation, block: b.cidr,
        range: `${formatIP(range.network, range.version)}/${range.prefix}`, via
      });
    }
  };
  const hostRanges = (node, path, chain, t, host, addresses) => {
    for (const address of addresses) {
      const v = parseIP(address);
      if (!v) continue;
      const prefix = v.version === 4 ? t.cidr4 : t.cidr6;
      matchRange(node, path, chain, t, rangeOf(address, prefix ?? null), { host, address: normalizeIP(address) });
    }
  };
  const seen = new Set();
  const walk = (node, path, chain) => {
    // A loop is reported by health.js; never walk one twice here.
    const key = `${path.join('>')}`;
    if (seen.has(key) || path.length > 12) return;
    seen.add(key);
    for (const t of node.terms || []) {
      switch (t.mechanism) {
        case 'ip4':
        case 'ip6':
          matchRange(node, path, chain, t, rangeOf(t.value, t.mechanism === 'ip4' ? t.cidr4 : t.cidr6));
          break;
        case 'a':
          if (!t.target) at(node, path, t, t.macro ? 'macro' : 'lookup-failed');
          else if (t.skipped) at(node, path, t, 'skipped', t.target);
          else if (t.error || !Array.isArray(t.addresses)) at(node, path, t, 'lookup-failed', t.target);
          else hostRanges(node, path, chain, t, t.target, t.addresses);
          break;
        case 'mx':
          if (!t.target) at(node, path, t, t.macro ? 'macro' : 'lookup-failed');
          else if (t.skipped) at(node, path, t, 'skipped', t.target);
          else if (t.error || !Array.isArray(t.hosts)) at(node, path, t, 'lookup-failed', t.target);
          else {
            for (const host of t.hosts) {
              const hit = mxAddresses.get(host);
              if (!hit || hit.error) at(node, path, t, 'lookup-failed', host);
              else hostRanges(node, path, chain, t, host, hit.addresses || []);
            }
          }
          break;
        case 'ptr':
          at(node, path, t, 'ptr', t.target);
          break;
        case 'exists':
          if (!t.target && t.macro) at(node, path, t, 'macro');
          break;
        case 'include':
        case 'redirect': {
          if (!t.target) {
            if (t.macro) at(node, path, t, 'macro');
            break;
          }
          if (t.skipped) {
            at(node, path, t, 'skipped', t.target);
            break;
          }
          const child = t.child;
          if (!child) {
            // loop / depth: reported by health.js; a loop adds nothing new to walk.
            if (t.error && t.error !== 'loop') at(node, path, t, 'include-failed', t.target);
            break;
          }
          if (child.record === null) {
            const failedLookup = (child.errors || []).some((e) => e.domain === child.domain && (e.code === 'dns-error' || e.code === 'multiple-records'));
            if (failedLookup) at(node, path, t, 'include-failed', t.target);
            break;
          }
          walk(child, [...path, child.domain], [...chain, { kind: t.mechanism, qualifier: t.qualifier || '+' }]);
          break;
        }
        default:
          break;
      }
    }
  };
  walk(tree, [tree.domain], []);
  return { matches, unknown };
}

/** The a / mx hosts an SPF tree names (to resolve before {@link spfCoverage}: mx needs their addresses). */
export function spfMxHosts(tree) {
  const out = [];
  const walk = (node, depth) => {
    if (!node || depth > 12) return;
    for (const t of node.terms || []) {
      if (t.mechanism === 'mx' && Array.isArray(t.hosts)) out.push(...t.hosts);
      if (t.child) walk(t.child, depth + 1);
    }
  };
  walk(tree, 0);
  return uniq(out);
}

/* ------------------------------------------------------------------------ */
/* Live evidence of one domain                                              */
/* ------------------------------------------------------------------------ */

/** Answer records of a type (a DohClient DnsResponse). */
function records(res, type) {
  return (res && Array.isArray(res.answers) ? res.answers : []).filter((rr) => rr && rr.type === type);
}

const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const failedResponse = (res) => !res || !res.ok || (res.rcode !== 'NOERROR' && res.rcode !== 'NXDOMAIN');
const responseError = (res) => (!res ? 'No response' : res.ok ? String(res.rcode) : String(res.error || 'DNS query failed'));

function isAbort(err) {
  return errorKind(err) === 'abort';
}

/**
 * @typedef {object} NameCheck
 * @property {string} name
 * @property {string} status 'NOERROR' | 'NXDOMAIN' | 'SERVFAIL' | … | 'ERROR'
 * @property {string[]} cnames the CNAME chain, in order
 * @property {string[]} ipv4
 * @property {string[]} ipv6
 * @property {string|null} error
 * @property {string|null} errorKind
 * @property {string[]} roles why it was resolved: 'apex', 'host', 'mx', 'ns', 'spf'
 * @property {string[]} sources where a known host came from ({@link HOST_SOURCES})
 */

/**
 * @typedef {object} DomainCheck
 * @property {string} domain
 * @property {NameCheck[]} names every name resolved, in the order asked
 * @property {{ status: 'ok'|'none'|'failed', error: string|null, hosts: Array<{ host: string, preference: number }> }} mx
 * @property {{ status: 'ok'|'none'|'failed', error: string|null, hosts: string[] }} ns
 * @property {{ status: 'ok'|'none'|'failed'|'multiple', record: string|null, error: string|null, lookups: number,
 *   matches: SpfMatch[], unknown: SpfUnknown[] }} spf
 * @property {{ status: 'ok'|'none'|'failed', error: string|null, hints: Array<{ owner: string, address: string }> }} https
 * @property {Array<{ what: 'name'|'mx'|'ns'|'spf'|'https', name: string, error: string, errorKind: string|null }>} failures
 */

/**
 * Check one domain over DoH: its own name, the given host names, its MX and NS hosts (each
 * resolved), its SPF policy (the whole include tree, plus the addresses of every host an `mx`
 * mechanism names) and the address hints of its HTTPS record. Failed lookups are reported in
 * `failures`, never as "nothing points here"; only an abort rejects.
 * @param {string} domain
 * @param {{ dns: object, blocks: RetireBlock[], hosts?: Array<string|{ name: string, source?: string }>, signal?: AbortSignal,
 *   onLookup?: (done: number, total: number) => void }} opts `dns`: a DohClient (query, resolveHost)
 * @returns {Promise<DomainCheck>}
 */
export async function checkDomain(domain, { dns, blocks, hosts = [], signal, onLookup } = {}) {
  const d = normalizeHostname(String(domain ?? ''));
  if (!d) throw new TypeError(`Invalid domain: ${String(domain)}`);
  if (!dns || typeof dns.query !== 'function' || typeof dns.resolveHost !== 'function') {
    throw new TypeError('checkDomain: a DNS client with query() and resolveHost() is required');
  }
  throwIfAborted(signal);
  const names = new Map();
  const failures = [];
  let done = 0;
  let total = 4;
  const tick = () => {
    done += 1;
    if (typeof onLookup === 'function') {
      try {
        onLookup(done, total);
      } catch {
        // a progress hook never breaks the check
      }
    }
  };

  /** Resolve a name once (roles and sources merge); a failure is a result, never a throw. */
  const resolve = (name, role, source = null) => {
    const n = canon(name);
    let entry = names.get(n);
    if (!entry) {
      total += 1;
      entry = { check: { name: n, status: 'ERROR', cnames: [], ipv4: [], ipv6: [], error: null, errorKind: null, roles: [], sources: [] } };
      names.set(n, entry);
      entry.promise = (async () => {
        try {
          const h = await dns.resolveHost(n, { signal });
          Object.assign(entry.check, {
            status: String(h.status || 'ERROR'),
            cnames: (h.cnames || []).map(canon),
            ipv4: (h.ipv4 || []).map(normalizeIP).filter(Boolean),
            ipv6: (h.ipv6 || []).map(normalizeIP).filter(Boolean),
            error: h.error || null,
            errorKind: h.errorKind || null
          });
        } catch (err) {
          if (isAbort(err)) throw err;
          Object.assign(entry.check, { status: 'ERROR', error: String((err && err.message) || err), errorKind: errorKind(err) });
        }
        const s = entry.check.status;
        if (s !== 'NOERROR' && s !== 'NXDOMAIN') failures.push({ what: 'name', name: n, error: entry.check.error || s, errorKind: entry.check.errorKind });
        tick();
        return entry.check;
      })();
    }
    if (role && !entry.check.roles.includes(role)) entry.check.roles.push(role);
    if (source && !entry.check.sources.includes(source)) entry.check.sources.push(source);
    return entry.promise;
  };

  const ask = async (type) => {
    try {
      return await dns.query(d, type, { signal });
    } catch (err) {
      if (isAbort(err)) throw err;
      return { ok: false, rcode: null, answers: [], error: String((err && err.message) || err), errorKind: errorKind(err) };
    } finally {
      tick();
    }
  };

  const hostJobs = [];
  hostJobs.push(resolve(d, 'apex'));
  for (const h of hosts || []) {
    const name = typeof h === 'string' ? h : h && h.name;
    const n = normalizeHostname(String(name ?? ''));
    if (n) hostJobs.push(resolve(n, 'host', typeof h === 'object' && h ? h.source || null : null));
  }

  const mxJob = ask('MX').then(async (res) => {
    if (failedResponse(res)) {
      failures.push({ what: 'mx', name: d, error: responseError(res), errorKind: res && res.errorKind ? res.errorKind : null });
      return { status: 'failed', error: responseError(res), hosts: [] };
    }
    const list = records(res, 'MX').filter((rr) => rr.data && canon(rr.data.exchange) && canon(rr.data.exchange) !== '.')
      .map((rr) => ({ host: canon(rr.data.exchange), preference: Number(rr.data.preference) || 0 }))
      .sort((a, b) => a.preference - b.preference || a.host.localeCompare(b.host));
    const hostsMx = [];
    for (const m of list) if (!hostsMx.some((x) => x.host === m.host)) hostsMx.push(m);
    const kept = hostsMx.slice(0, RETIRE_MAX_MX);
    await Promise.all(kept.map((m) => resolve(m.host, 'mx')));
    return { status: kept.length ? 'ok' : 'none', error: null, hosts: kept };
  });

  const nsJob = ask('NS').then(async (res) => {
    if (failedResponse(res)) {
      failures.push({ what: 'ns', name: d, error: responseError(res), errorKind: res && res.errorKind ? res.errorKind : null });
      return { status: 'failed', error: responseError(res), hosts: [] };
    }
    const list = uniq(records(res, 'NS').filter((rr) => canon(rr.name) === d).map((rr) => canon(rr.data)).filter(Boolean)).slice(0, RETIRE_MAX_NS);
    await Promise.all(list.map((host) => resolve(host, 'ns')));
    return { status: list.length ? 'ok' : 'none', error: null, hosts: list };
  });

  const httpsJob = ask('HTTPS').then((res) => {
    if (failedResponse(res)) {
      failures.push({ what: 'https', name: d, error: responseError(res), errorKind: res && res.errorKind ? res.errorKind : null });
      return { status: 'failed', error: responseError(res), hints: [] };
    }
    const hints = [];
    for (const rr of records(res, 'HTTPS')) {
      const p = (rr.data && rr.data.params) || {};
      for (const ip of [...(p.ipv4hint || []), ...(p.ipv6hint || [])]) {
        const address = normalizeIP(String(ip));
        if (address) hints.push({ owner: canon(rr.name), address });
      }
    }
    return { status: records(res, 'HTTPS').length ? 'ok' : 'none', error: null, hints };
  });

  // The domain's own SPF record could not be read: whether it authorizes the address cannot be
  // told, so it is a "cannot tell" row of its own — never an empty SPF result.
  const recordFailed = [{ path: [d], holder: d, record: null, term: '', mechanism: 'record', reason: 'lookup-failed', target: d }];
  const spfJob = (async () => {
    let r;
    try {
      r = await spfLookupCount(d, { dns, signal });
    } catch (err) {
      if (isAbort(err)) throw err;
      tick();
      failures.push({ what: 'spf', name: d, error: String((err && err.message) || err), errorKind: errorKind(err) });
      return { status: 'failed', record: null, error: String((err && err.message) || err), lookups: 0, matches: [], unknown: recordFailed };
    }
    tick();
    const rootErrors = (r.errors || []).filter((e) => e.domain === d);
    const base = { record: r.tree ? r.tree.record : null, lookups: r.count };
    if (rootErrors.some((e) => e.code === 'dns-error') && (!r.tree || r.tree.record === null)) {
      const e = rootErrors.find((x) => x.code === 'dns-error');
      failures.push({ what: 'spf', name: d, error: e.detail || 'SPF lookup failed', errorKind: null });
      return { ...base, status: 'failed', error: e.detail || null, matches: [], unknown: recordFailed };
    }
    if (rootErrors.some((e) => e.code === 'no-record')) return { ...base, status: 'none', error: null, matches: [], unknown: [] };
    if (rootErrors.some((e) => e.code === 'multiple-records')) {
      return {
        ...base, status: 'multiple', error: null, matches: [],
        unknown: [{ path: [d], holder: d, record: null, term: '', mechanism: 'record', reason: 'multiple', target: null }]
      };
    }
    // An mx mechanism covers the addresses of the hosts it names: resolve those too.
    const mxHosts = spfMxHosts(r.tree);
    const resolvedMx = await Promise.all(mxHosts.map((host) => resolve(host, 'spf')));
    const mxAddresses = new Map(resolvedMx.map((c) => [c.name, {
      addresses: [...c.ipv4, ...c.ipv6], error: c.status !== 'NOERROR' && c.status !== 'NXDOMAIN' ? c.error || c.status : null
    }]));
    const cov = spfCoverage(r.tree, blocks, { mxAddresses });
    return { ...base, status: 'ok', error: null, matches: cov.matches, unknown: cov.unknown };
  })();

  const [mx, ns, https, spf] = await Promise.all([mxJob, nsJob, httpsJob, spfJob]);
  await Promise.all(hostJobs);
  // A name a later job added (an SPF mx host) is settled too.
  await Promise.all([...names.values()].map((e) => e.promise));
  throwIfAborted(signal);
  return { domain: d, names: [...names.values()].map((e) => e.check), mx, ns, spf, https, failures };
}

/* ------------------------------------------------------------------------ */
/* The imported zone                                                        */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ZoneRef
 * @property {string} name the record's owner
 * @property {string} type A, AAAA, CNAME, MX, NS, SRV, HTTPS, SVCB, TXT, SPF
 * @property {string} value the record's value as the zone has it (a hint: the hint's address)
 * @property {string} address the retiring address it reaches (an SPF term: the block's label)
 * @property {string} block the retiring block (CIDR)
 * @property {string[]} via the in-zone names followed from the record's target to the address record
 * @property {string|null} holder the name whose A / AAAA holds the address (null for a hint / SPF)
 * @property {boolean} hint an HTTPS / SVCB address hint
 * @property {boolean|null} proxied
 * @property {boolean} internal
 * @property {boolean} occluded
 * @property {number|null} line
 * @property {number|null} preference
 * @property {{ term: string, qualifier: string, relation: string, range: string }|null} spf an SPF ip4 / ip6 term
 * @property {boolean|null} [live] set by {@link verifyZoneRefs}: true / false, null when the lookup failed;
 *   undefined when it was not asked (proxied, internal, wildcard)
 */

/**
 * The imported zone's records that reach a retiring address (zoneorigins referenceRecords, as
 * published in `state.session.zone.records`): A / AAAA with the address, CNAMEs whose in-zone chain
 * ends at one, MX / NS / SRV / HTTPS / SVCB whose in-zone target (through a chain) holds one, HTTPS /
 * SVCB address hints, and SPF ip4 / ip6 terms covering one. Pure; nothing is looked up.
 * @param {Array<object>} records
 * @param {RetireBlock[]} blocks
 * @returns {ZoneRef[]}
 */
export function zoneCandidates(records, blocks) {
  const list = (Array.isArray(records) ? records : []).filter((r) => r && typeof r.name === 'string' && typeof r.type === 'string');
  const addresses = new Map();
  const cnames = new Map();
  for (const r of list) {
    if (r.type === 'A' || r.type === 'AAAA') {
      const a = addresses.get(r.name) || [];
      a.push(r);
      addresses.set(r.name, a);
    } else if (r.type === 'CNAME' && !cnames.has(r.name)) {
      cnames.set(r.name, canon(r.value));
    }
  }
  /** The in-zone chain from a name to its A / AAAA records (at most 16 hops; a loop stops). */
  const follow = (name) => {
    const via = [];
    let cur = name;
    for (let i = 0; i < 16; i += 1) {
      if (addresses.has(cur)) return { holder: cur, via, recs: addresses.get(cur) };
      const next = cnames.get(cur);
      if (!next || next === name || via.includes(next)) return null;
      via.push(next);
      cur = next;
    }
    return null;
  };
  const out = [];
  const push = (r, extra) => out.push({
    name: r.name, type: r.type, value: r.value, proxied: r.proxied ?? null, internal: !!r.internal, occluded: !!r.occluded,
    line: Number.isFinite(r.line) ? r.line : null, preference: Number.isFinite(r.preference) ? r.preference : null,
    via: [], holder: null, hint: false, spf: null, ...extra
  });
  const viaTarget = (r, target) => {
    const start = canon(target);
    const hit = follow(start);
    if (!hit) return;
    for (const rec of hit.recs) {
      const b = blockOf(rec.value, blocks);
      if (!b) continue;
      // A DNS-only CNAME into a proxied name reaches the origin through the proxy: its record decides.
      push(r, { address: normalizeIP(rec.value), block: b.cidr, via: [start, ...hit.via], holder: hit.holder, proxied: rec.proxied === true ? true : r.proxied ?? null });
    }
  };
  for (const r of list) {
    switch (r.type) {
      case 'A':
      case 'AAAA': {
        const b = blockOf(r.value, blocks);
        if (b) push(r, { address: normalizeIP(r.value), block: b.cidr, holder: r.name });
        break;
      }
      case 'CNAME':
      case 'MX':
      case 'NS':
      case 'SRV':
        viaTarget(r, r.value);
        break;
      case 'HTTPS':
      case 'SVCB':
        for (const hint of r.hints || []) {
          const b = blockOf(hint, blocks);
          if (b) push(r, { value: normalizeIP(hint), address: normalizeIP(hint), block: b.cidr, hint: true });
        }
        // An empty / '.' target is the owner itself, whose own addresses are listed already.
        if (r.value && r.value !== '.') viaTarget(r, r.value);
        break;
      case 'TXT':
      case 'SPF': {
        const parsed = parseSpf(r.value);
        if (!parsed.version) break;
        for (const term of parsed.terms) {
          if (term.mechanism !== 'ip4' && term.mechanism !== 'ip6') continue;
          const range = rangeOf(term.value, term.mechanism === 'ip4' ? term.cidr4 : term.cidr6);
          for (const b of blocks) {
            const relation = rangeRelation(range, b);
            if (!relation) continue;
            push(r, {
              address: b.label, block: b.cidr,
              spf: { term: term.raw, qualifier: term.qualifier, relation, range: `${formatIP(range.network, range.version)}/${range.prefix}` }
            });
          }
        }
        break;
      }
      default:
        break;
    }
  }
  return out;
}

/** Does an answer hold the record a zone ref describes? */
function answerHas(res, ref) {
  const type = ref.type === 'SPF' ? 'TXT' : ref.type;
  const rrs = records(res, type);
  switch (type) {
    case 'MX':
      return rrs.some((rr) => rr.data && canon(rr.data.exchange) === canon(ref.value));
    case 'NS':
      return rrs.some((rr) => canon(rr.data) === canon(ref.value));
    case 'SRV':
      return rrs.some((rr) => rr.data && canon(rr.data.target) === canon(ref.value));
    case 'HTTPS':
    case 'SVCB':
      if (ref.hint) {
        return rrs.some((rr) => {
          const p = (rr.data && rr.data.params) || {};
          return [...(p.ipv4hint || []), ...(p.ipv6hint || [])].map((ip) => normalizeIP(String(ip))).includes(ref.address);
        });
      }
      return rrs.some((rr) => rr.data && canon(rr.data.target) === canon(ref.value));
    case 'TXT': {
      // The term, as a whole word, in the domain's SPF policy.
      const term = ref.spf ? ref.spf.term.toLowerCase() : '';
      return rrs.some((rr) => {
        const text = (Array.isArray(rr.data) ? rr.data.join('') : String(rr.data ?? '')).toLowerCase();
        return /^v=spf1(?:\s|$)/.test(text) && text.split(/\s+/).includes(term);
      });
    }
    default:
      return false;
  }
}

/**
 * Verify the imported zone's candidates live over DoH: does public DNS still serve each record?
 * - A / AAAA and CNAME: the owner resolves to the address (a CNAME: through the same first target);
 * - MX / NS / SRV / HTTPS / SVCB: the owner's record set holds the target, and the target resolves
 *   to the address (an address hint: the record set holds the hint);
 * - an SPF term: the owner's SPF policy holds the term.
 * A proxied record's origin (the proxy answers with its own edges), a name that looks internal
 * (never sent to a public resolver) and a wildcard owner are not asked (`live` stays undefined).
 * The DohClient caches, so a name the domain checks resolved costs nothing more.
 * @param {ZoneRef[]} refs
 * @param {{ dns: object, signal?: AbortSignal }} opts
 * @returns {Promise<ZoneRef[]>} copies with `live`
 */
export async function verifyZoneRefs(refs, { dns, signal } = {}) {
  if (!dns || typeof dns.query !== 'function' || typeof dns.resolveHost !== 'function') {
    throw new TypeError('verifyZoneRefs: a DNS client with query() and resolveHost() is required');
  }
  const host = async (name) => {
    try {
      return await dns.resolveHost(name, { signal });
    } catch (err) {
      if (isAbort(err)) throw err;
      return { status: 'ERROR', cnames: [], ipv4: [], ipv6: [] };
    }
  };
  const ask = async (name, type) => {
    try {
      return await dns.query(name, type, { signal });
    } catch (err) {
      if (isAbort(err)) throw err;
      return { ok: false, answers: [] };
    }
  };
  const usable = (h) => h && (h.status === 'NOERROR' || h.status === 'NXDOMAIN');
  const reaches = (h, address) => [...(h.ipv4 || []), ...(h.ipv6 || [])].map((ip) => normalizeIP(ip)).includes(address);
  const out = await Promise.all((refs || []).map(async (ref) => {
    const copy = { ...ref, via: [...ref.via] };
    const aliasOrAddress = ref.type === 'A' || ref.type === 'AAAA' || ref.type === 'CNAME';
    if ((ref.proxied === true && aliasOrAddress) || ref.internal || ref.name.startsWith('*.')) return copy;
    if (aliasOrAddress) {
      const h = await host(ref.name);
      if (!usable(h)) copy.live = null;
      else copy.live = reaches(h, ref.address) && (ref.type !== 'CNAME' || canon((h.cnames || [])[0]) === canon(ref.value));
      return copy;
    }
    const res = await ask(ref.name, ref.type === 'SPF' ? 'TXT' : ref.type);
    if (failedResponse(res)) {
      copy.live = null;
      return copy;
    }
    if (!answerHas(res, ref)) {
      copy.live = false;
      return copy;
    }
    if (ref.spf || ref.hint) {
      copy.live = true;
      return copy;
    }
    const h = await host(canon(ref.value));
    copy.live = usable(h) ? reaches(h, ref.address) : null;
    return copy;
  }));
  throwIfAborted(signal);
  return out;
}

/* ------------------------------------------------------------------------ */
/* Known host names                                                         */
/* ------------------------------------------------------------------------ */

/**
 * The host names to resolve for one domain: the names equal to it or under it from each source
 * (the page session's last Subdomains / SSL Targets result, the zone's names, passive hits the user
 * asked to check, a discovery run), de-duplicated in that order.
 * @param {string} domain
 * @param {Partial<Record<'scan'|'zone'|'passive'|'discovered', Iterable<string>>>} sources
 * @returns {Array<{ name: string, source: string }>}
 */
export function knownHostsFor(domain, sources = {}) {
  const out = [];
  const seen = new Set([domain]);
  for (const source of HOST_SOURCES) {
    for (const raw of sources[source] || []) {
      const name = normalizeHostname(String(raw ?? ''));
      if (!name || seen.has(name) || !isSubdomainOf(name, domain)) continue;
      seen.add(name);
      out.push({ name, source });
    }
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* A whole check                                                            */
/* ------------------------------------------------------------------------ */

/**
 * Run a whole check: every domain ({@link checkDomain}, `concurrency` at a time, each with its
 * known host names) and the zone's candidates ({@link verifyZoneRefs}). Events: `{ type: 'start',
 * domain }`, `{ type: 'progress', domain, done, total }`, `{ type: 'domain', domain, check }`,
 * `{ type: 'zone', refs }`. An abort ends it with what finished (`aborted: true`); any other
 * failure of one domain is that domain's `error`, never the end of the check.
 * @param {{ blocks: RetireBlock[], domains: string[], hosts?: Map<string, Array<{ name: string, source: string }>>|object,
 *   zoneRefs?: ZoneRef[], dns: object, signal?: AbortSignal, concurrency?: number, onEvent?: Function }} opts
 * @returns {Promise<{ checks: DomainCheck[], errors: Array<{ domain: string, error: string }>, zone: ZoneRef[],
 *   aborted: boolean }>} `checks` in the order of `domains` (the finished ones)
 */
export async function runRetireCheck({ blocks, domains, hosts = new Map(), zoneRefs = [], dns, signal, concurrency = 2, onEvent } = {}) {
  const emit = (e) => {
    if (typeof onEvent !== 'function') return;
    try {
      onEvent(e);
    } catch {
      // a listener never breaks the check
    }
  };
  const hostsOf = (d) => (hosts instanceof Map ? hosts.get(d) : hosts && hosts[d]) || [];
  const results = new Map();
  const errors = [];
  let zone = (zoneRefs || []).map((r) => ({ ...r }));
  let aborted = false;
  const queue = [...(domains || [])];
  const worker = async () => {
    while (queue.length) {
      const domain = queue.shift();
      emit({ type: 'start', domain });
      try {
        const check = await checkDomain(domain, {
          dns, blocks, hosts: hostsOf(domain), signal, onLookup: (done, total) => emit({ type: 'progress', domain, done, total })
        });
        results.set(domain, check);
        emit({ type: 'domain', domain, check });
      } catch (err) {
        if (isAbort(err)) throw err;
        errors.push({ domain, error: String((err && err.message) || err) });
        emit({ type: 'domain', domain, check: null, error: err });
      }
    }
  };
  try {
    throwIfAborted(signal);
    await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, queue.length || 1)) }, worker));
    if (zone.length) {
      zone = await verifyZoneRefs(zone, { dns, signal });
      emit({ type: 'zone', refs: zone });
    }
  } catch (err) {
    if (!isAbort(err)) throw err;
    aborted = true;
  }
  return { checks: (domains || []).filter((d) => results.has(d)).map((d) => results.get(d)), errors, zone, aborted };
}

/**
 * What a check could not settle. Only a check with none of it may say "nothing points at the
 * address"; otherwise that is "nothing found, but the list may be incomplete".
 * - failed lookups: each domain's names, MX, NS, SPF and HTTPS ({@link FAILURE_KINDS}), a domain
 *   that could not be checked at all (`domain`), a zone-file record whose live lookup failed (`zone`);
 * - `unknown`: rows that cannot be told (an SPF macro, a failed SPF lookup …; `counts.bySeverity.unknown`);
 * - `notChecked`: domains a stop left unchecked (a domain that failed is counted under `domain`).
 * @param {{ domains?: string[], checks?: DomainCheck[], errors?: Array<{ domain: string }>, zone?: ZoneRef[]|null,
 *   aborted?: boolean, counts?: { bySeverity?: Record<string, number> }|null }} r
 * @returns {{ failed: number, failures: Record<string, number>, unknown: number, notChecked: string[], stopped: boolean,
 *   settled: boolean }}
 */
export function retireGaps({ domains = [], checks = [], errors = [], zone = [], aborted = false, counts = null } = {}) {
  const failures = Object.fromEntries([...FAILURE_KINDS, 'domain', 'zone'].map((k) => [k, 0]));
  for (const c of checks || []) {
    for (const f of c.failures || []) failures[f.what] = (failures[f.what] || 0) + 1;
  }
  failures.domain = (errors || []).length;
  failures.zone = (zone || []).filter((z) => z.live === null).length;
  const failed = Object.values(failures).reduce((n, v) => n + v, 0);
  const done = new Set([...(checks || []).map((c) => c.domain), ...(errors || []).map((e) => e.domain)]);
  const notChecked = (domains || []).filter((d) => !done.has(d));
  const unknown = Number(counts && counts.bySeverity && counts.bySeverity.unknown) || 0;
  const stopped = !!aborted;
  return { failed, failures, unknown, notChecked, stopped, settled: !failed && !unknown && !notChecked.length && !stopped };
}

/* ------------------------------------------------------------------------ */
/* Inventory                                                                */
/* ------------------------------------------------------------------------ */

/**
 * The servers of the user's list that own a retiring address, with their other addresses (where
 * a renumbered service may already live).
 * @param {RetireBlock[]} blocks
 * @param {Array<{ id?: string, name: string, ips: string[] }>} servers lib/inventory.js Server[]
 * @returns {Array<{ name: string, addresses: string[], others: string[] }>}
 */
export function inventoryOwners(blocks, servers) {
  const out = [];
  for (const s of servers || []) {
    const ips = uniq((s && Array.isArray(s.ips) ? s.ips : []).map((ip) => normalizeIP(ip)).filter(Boolean));
    const addresses = ips.filter((ip) => blockOf(ip, blocks));
    if (addresses.length) out.push({ name: String(s.name || s.id || addresses[0]), addresses, others: ips.filter((ip) => !addresses.includes(ip)) });
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* The change list                                                          */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} Change
 * @property {string} key `name|type|value`
 * @property {string} group the checked domain (or the zone's origin) the owner belongs to; `other`
 *   for a record in a zone nobody checked (a CNAME target's, a provider's SPF include), `passive` for
 *   an unverified passive hit
 * @property {'domain'|'zone'|'other'|'passive'} groupKind
 * @property {string} severity one of {@link SEVERITIES}
 * @property {string} name the record's owner
 * @property {string} type A, AAAA, CNAME, MX, NS, SRV, HTTPS, SVCB, TXT (an SPF policy)
 * @property {string} value the record's current value (an SPF record: the term; an MX: `preference host`)
 * @property {string[]} addresses the retiring addresses (or blocks) it reaches
 * @property {string[]} blocks their blocks (CIDR)
 * @property {string} action one of {@link CHANGE_ACTIONS}
 * @property {string} verified one of {@link VERIFIED_STATES}
 * @property {string[]} via a CNAME chain (owner first), an MX / NS host's chain, or an SPF include path
 * @property {string[]} roles what else the owner is: 'mx', 'ns', 'spf'
 * @property {string[]} sources 'dns', 'spf', 'zone' (the zone file holds the record), 'passive' and where a known host came
 *   from ({@link HOST_SOURCES}; a name listed in the zone file is 'zone-name')
 * @property {number|null} line the zone file line
 * @property {boolean|null} proxied
 * @property {object|null} spf `{ term, qualifier, effective, relation, range, holder, record, mechanism, host }`
 * @property {string|null} reason an unknown row's reason ({@link UNKNOWN_REASONS})
 * @property {string[]} foundFor the checked domains whose check found it
 */

/** The checked domain (or zone origin) a name belongs to: the most specific one it is equal to or under. */
function groupFor(name, groups) {
  let best = null;
  for (const g of groups) {
    if (isSubdomainOf(name, g) && (!best || g.length > best.length)) best = g;
  }
  return best;
}

/** Severity of a live record by its type (an SPF term: by what it gives the checked domain). */
function typeSeverity(type, { effective = null } = {}) {
  if (type === 'MX') return 'mail';
  if (type === 'NS') return 'ns';
  if (type === 'CNAME') return 'chain';
  if (type === 'TXT' || type === 'SPF') return effective === '+' ? 'mail' : 'stale';
  return 'live';
}

function compareNames(a, b) {
  if (a === b) return 0;
  return sortHostnames([a, b])[0] === a ? -1 : 1;
}

/**
 * Merge the evidence into one change list: one row per record (owner, type, value) with the
 * retiring addresses it reaches, grouped by the checked domain it belongs to (or the zone's
 * origin; `other` for records in zones nobody checked, `passive` for unverified passive hits),
 * worst first.
 * @param {{ blocks: RetireBlock[], checks?: DomainCheck[], zone?: { origin: string|null, refs: ZoneRef[] }|null,
 *   passive?: Array<{ address: string, names: string[] }>|null }} input `zone.refs` as
 *   {@link verifyZoneRefs} returns them
 * @returns {{ changes: Change[], groups: Array<{ key: string, kind: string, changes: Change[] }>,
 *   counts: { total: number, breaking: number, passive: number, bySeverity: Record<string, number>, byVerified: Record<string, number> },
 *   gone: Array<{ name: string, address: string, now: string[] }> }}
 *   `gone`: passive hits that were checked and no longer point at the address
 */
export function buildChanges({ blocks = [], checks = [], zone = null, passive = null } = {}) {
  const domains = (checks || []).map((c) => c.domain);
  const zoneOrigin = zone && zone.origin ? canon(zone.origin) : null;
  const homes = uniq([...domains, ...(zoneOrigin ? [zoneOrigin] : [])]);
  const byCidr = new Map(blocks.map((b) => [b.cidr, b]));
  const label = (cidr) => (byCidr.get(cidr) ? byCidr.get(cidr).label : cidr);
  const rows = new Map();
  const resolved = new Map();
  for (const c of checks || []) for (const n of c.names) if (!resolved.has(n.name)) resolved.set(n.name, n);

  const add = (row, found) => {
    const key = `${row.name}|${row.type}|${row.value}`;
    let cur = rows.get(key);
    if (!cur) {
      const passiveRow = row.groupKind === 'passive';
      const home = passiveRow ? null : groupFor(row.name, homes);
      cur = {
        key,
        group: passiveRow ? 'passive' : home || 'other',
        groupKind: passiveRow ? 'passive' : !home ? 'other' : home === zoneOrigin && !domains.includes(home) ? 'zone' : 'domain',
        severity: row.severity, name: row.name, type: row.type, value: row.value, addresses: [], blocks: [],
        action: row.action, verified: row.verified, via: row.via || [], roles: [], sources: [], line: row.line ?? null,
        proxied: row.proxied ?? null, spf: row.spf || null, reason: row.reason || null, foundFor: []
      };
      rows.set(key, cur);
    } else {
      if (SEVERITY_RANK[row.severity] < SEVERITY_RANK[cur.severity]) {
        cur.severity = row.severity;
        cur.action = row.action;
      }
      // What was seen live wins over the file and over "not checked".
      if (row.verified === 'live' || cur.verified === 'unverified' || (cur.verified === 'unknown' && row.verified !== 'unverified')) cur.verified = row.verified;
      if (!cur.via.length && row.via && row.via.length) cur.via = row.via;
      if (cur.line === null && Number.isFinite(row.line)) cur.line = row.line;
      if (cur.proxied === null && typeof row.proxied === 'boolean') cur.proxied = row.proxied;
      if (!cur.spf && row.spf) cur.spf = row.spf;
    }
    for (const a of row.addresses || []) if (!cur.addresses.includes(a)) cur.addresses.push(a);
    for (const b of row.blocks || []) if (!cur.blocks.includes(b)) cur.blocks.push(b);
    for (const r of row.roles || []) if (!cur.roles.includes(r)) cur.roles.push(r);
    for (const s of row.sources || []) if (!cur.sources.includes(s)) cur.sources.push(s);
    if (found && !cur.foundFor.includes(found)) cur.foundFor.push(found);
    return cur;
  };

  const hits = (n) => (n ? [...n.ipv4, ...n.ipv6].map((a) => ({ address: a, block: blockOf(a, blocks) })).filter((x) => x.block) : []);

  for (const c of checks || []) {
    // Every resolved name: the A / AAAA record holding the address, and the CNAME that leads there.
    for (const n of c.names) {
      const holder = n.cnames.length ? n.cnames[n.cnames.length - 1] : n.name;
      const roles = n.roles.filter((r) => r === 'mx' || r === 'ns' || r === 'spf');
      const severity = roles.includes('mx') ? 'mail' : roles.includes('ns') ? 'ns' : 'live';
      for (const { address, block } of hits(n)) {
        // A name the zone file listed is not a record the file holds: its source says so apart ('zone-name').
        const hostSources = n.sources.map((s) => (s === 'zone' ? 'zone-name' : s));
        const common = { addresses: [address], blocks: [block.cidr], roles, sources: ['dns', ...hostSources], verified: 'live' };
        add({ ...common, name: holder, type: address.includes(':') ? 'AAAA' : 'A', value: address, severity, action: 'remove', via: n.cnames.length ? [n.name, ...n.cnames] : [] }, c.domain);
        if (n.cnames.length) add({ ...common, name: n.name, type: 'CNAME', value: n.cnames[0], severity: 'chain', action: 'follow', via: [n.name, ...n.cnames] }, c.domain);
      }
    }
    for (const m of c.mx.hosts) {
      const n = resolved.get(m.host);
      const found = hits(n);
      if (!found.length) continue;
      add({
        name: c.domain, type: 'MX', value: `${m.preference} ${m.host}`, addresses: found.map((x) => x.address), blocks: found.map((x) => x.block.cidr),
        severity: 'mail', action: 'repoint', verified: 'live', sources: ['dns'], via: [m.host, ...(n ? n.cnames : [])]
      }, c.domain);
    }
    for (const host of c.ns.hosts) {
      const n = resolved.get(host);
      const found = hits(n);
      if (!found.length) continue;
      add({
        name: c.domain, type: 'NS', value: host, addresses: found.map((x) => x.address), blocks: found.map((x) => x.block.cidr),
        severity: 'ns', action: isSubdomainOf(host, c.domain) ? 'glue' : 'repoint', verified: 'live', sources: ['dns'], via: [host, ...(n ? n.cnames : [])]
      }, c.domain);
    }
    for (const hint of c.https.hints) {
      const b = blockOf(hint.address, blocks);
      if (!b) continue;
      add({
        name: hint.owner, type: 'HTTPS', value: hint.address, addresses: [hint.address], blocks: [b.cidr],
        severity: 'live', action: 'remove', verified: 'live', sources: ['dns']
      }, c.domain);
    }
    const own = registrableDomain(c.domain) || c.domain;
    for (const m of c.spf.matches) {
      const ownRecord = (registrableDomain(m.holder) || m.holder) === own;
      let action;
      if (!ownRecord) action = 'provider';
      else if (m.mechanism === 'a' || m.mechanism === 'mx') action = 'follow';
      else action = m.relation === 'contains' ? 'narrow' : 'remove';
      add({
        name: m.holder, type: 'TXT', value: m.term, addresses: [m.via ? m.via.address : label(m.block)], blocks: [m.block],
        severity: typeSeverity('TXT', { effective: m.effective }), action, verified: 'live', sources: ['spf'], via: m.path,
        spf: {
          term: m.term, qualifier: m.qualifier, effective: m.effective, relation: m.relation, range: m.range,
          holder: m.holder, record: m.record, mechanism: m.mechanism, host: m.via ? m.via.host : null
        }
      }, c.domain);
    }
    for (const u of c.spf.unknown) {
      add({
        name: u.holder, type: 'TXT', value: u.term || '', addresses: blocks.map((b) => b.label), blocks: blocks.map((b) => b.cidr),
        severity: 'unknown', action: 'check', verified: 'unknown', sources: ['spf'], via: u.path, reason: u.reason,
        spf: { term: u.term, qualifier: null, effective: null, relation: null, range: null, holder: u.holder, record: u.record, mechanism: u.mechanism, host: u.target }
      }, c.domain);
    }
  }

  // The zone file: a record seen live joins its live row; the rest stand as file / hidden / internal rows.
  for (const z of (zone && zone.refs) || []) {
    const type = z.hint ? 'HTTPS' : z.type === 'SPF' ? 'TXT' : z.type;
    const value = type === 'MX' ? `${z.preference ?? 0} ${canon(z.value)}` : z.spf ? z.spf.term : type === 'A' || type === 'AAAA' || z.hint ? z.value : canon(z.value);
    const proxiedOrigin = z.proxied === true && (type === 'A' || type === 'AAAA' || type === 'CNAME');
    let verified;
    let severity;
    if (proxiedOrigin) {
      verified = 'hidden';
      severity = 'origin';
    } else if (z.internal) {
      verified = 'internal';
      severity = typeSeverity(type, { effective: z.spf ? z.spf.qualifier : null });
    } else if (z.live === true) {
      verified = 'live';
      severity = typeSeverity(type, { effective: z.spf ? z.spf.qualifier : null });
    } else if (z.live === false || z.name.startsWith('*.')) {
      verified = 'file';
      severity = 'file';
    } else {
      // The lookup failed (or was never made): not known either way.
      verified = z.live === null ? 'unknown' : 'unverified';
      severity = typeSeverity(type, { effective: z.spf ? z.spf.qualifier : null });
    }
    let action = 'remove';
    if (proxiedOrigin) action = 'origin';
    else if (type === 'CNAME') action = 'follow';
    else if (type === 'NS') action = isSubdomainOf(canon(z.value), z.name) ? 'glue' : 'repoint';
    else if (type === 'MX' || type === 'SRV' || ((type === 'HTTPS' || type === 'SVCB') && !z.hint)) action = 'repoint';
    else if (z.spf && z.spf.relation === 'contains') action = 'narrow';
    add({
      name: z.name, type, value, addresses: [z.address], blocks: [z.block], severity, action, verified,
      via: z.via.length ? [z.name, ...z.via] : [], line: z.line, proxied: z.proxied, sources: ['zone'],
      spf: z.spf ? { term: z.spf.term, qualifier: z.spf.qualifier, effective: z.spf.qualifier, relation: z.spf.relation, range: z.spf.range, holder: z.name, record: z.value, mechanism: z.spf.term.replace(/^[-+~?]/, '').split(/[:/]/)[0], host: null } : null
    }, groupFor(z.name, homes) || zoneOrigin);
  }

  // Passive reverse-IP hits: a name already resolved joins its live row (or is gone); the rest stay unverified.
  const gone = [];
  for (const p of passive || []) {
    const address = normalizeIP(p.address);
    const b = blockOf(address, blocks);
    if (!b) continue;
    for (const name of p.names || []) {
      const n = resolved.get(name);
      if (n) {
        const holder = n.cnames.length ? n.cnames[n.cnames.length - 1] : n.name;
        const row = rows.get(`${holder}|${address.includes(':') ? 'AAAA' : 'A'}|${address}`);
        if (row && !row.sources.includes('passive')) row.sources.push('passive');
        if (!row && !gone.some((g) => g.name === name && g.address === address)) gone.push({ name, address, now: [...n.ipv4, ...n.ipv6] });
        continue;
      }
      add({
        name, type: address.includes(':') ? 'AAAA' : 'A', value: address, addresses: [address], blocks: [b.cidr],
        severity: 'stale', action: 'check', verified: 'unverified', sources: ['passive'], groupKind: 'passive'
      }, null);
    }
  }

  const changes = [...rows.values()].sort((a, b) => SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]
    || compareNames(a.name, b.name) || a.type.localeCompare(b.type) || a.value.localeCompare(b.value));
  const order = [...homes, 'other', 'passive'];
  const groups = order.map((key) => ({
    key,
    kind: key === 'other' ? 'other' : key === 'passive' ? 'passive' : key === zoneOrigin && !domains.includes(key) ? 'zone' : 'domain',
    changes: changes.filter((c) => c.group === key)
  })).filter((g) => g.changes.length || domains.includes(g.key));
  const bySeverity = Object.fromEntries(SEVERITIES.map((s) => [s, changes.filter((c) => c.severity === s).length]));
  const byVerified = Object.fromEntries(VERIFIED_STATES.map((s) => [s, changes.filter((c) => c.verified === s).length]));
  const passiveRows = changes.filter((c) => c.groupKind === 'passive').length;
  return {
    changes,
    groups,
    counts: { total: changes.length, breaking: breakingChanges(changes).length, passive: passiveRows, bySeverity, byVerified },
    gone: gone.sort((a, b) => compareNames(a.name, b.name))
  };
}

/**
 * The records that break something once the address is gone: every change but the `stale` and
 * `unknown` ones and a record found only in the zone file.
 * @param {Change[]} changes
 * @returns {Change[]}
 */
export function breakingChanges(changes) {
  return (changes || []).filter((c) => c.severity !== 'stale' && c.severity !== 'unknown' && c.severity !== 'file');
}

/* ------------------------------------------------------------------------ */
/* Passive reverse IP                                                       */
/* ------------------------------------------------------------------------ */

/**
 * The names a passive lookup found that the check has not resolved yet (so neither confirmed nor
 * ruled out), and their registrable domains that are not checked yet ("Check these too" adds those
 * to the list and the names as known hosts).
 * @param {Array<{ address: string, names: string[] }>} passive
 * @param {{ checked?: Iterable<string>, resolved?: Iterable<string> }} [opts] checked domains, names already resolved
 * @returns {{ names: string[], domains: string[] }}
 */
export function passiveNewNames(passive, { checked = [], resolved = [] } = {}) {
  const done = new Set(resolved);
  const checkedList = [...checked];
  const names = [];
  for (const p of passive || []) for (const n of p.names || []) if (!done.has(n) && !names.includes(n)) names.push(n);
  const domains = [];
  for (const n of names) {
    const reg = registrableDomain(n) || n;
    if (!checkedList.some((d) => isSubdomainOf(n, d)) && !domains.includes(reg)) domains.push(reg);
  }
  return { names: sortHostnames(names), domains: sortHostnames(domains) };
}

/* ------------------------------------------------------------------------ */
/* Exports                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * CSV rows of the change list ({@link RETIRE_CSV_COLUMNS}; codes, not translated words, so a
 * script can read them).
 * @param {Change[]} changes
 * @returns {object[]}
 */
export function retireExportRows(changes) {
  return (changes || []).map((c) => ({
    group: c.group,
    severity: c.severity,
    name: c.name,
    type: c.type === 'TXT' && c.spf ? 'TXT (SPF)' : c.type,
    value: c.value,
    address: c.addresses.join(' '),
    action: c.action,
    verified: c.verified,
    via: c.via.join(' > '),
    sources: c.sources.join(' '),
    line: c.line ?? ''
  }));
}

/**
 * The JSON export (`domainscope.ip-retire/1`).
 * @param {{ blocks?: RetireBlock[], domains?: string[], changes?: Change[], counts?: object|null, gone?: object[],
 *   owners?: object[], failures?: object[], startedAt?: Date|null, finishedAt?: Date|null, aborted?: boolean,
 *   zone?: string|null, app?: string, version?: string }} r
 * @returns {object}
 */
export function retireExportJson({
  blocks = [], domains = [], changes = [], counts = null, gone = [], owners = [], failures = [], startedAt = null,
  finishedAt = null, aborted = false, zone = null, app = 'DomainScope', version = ''
} = {}) {
  const iso = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString() : null);
  return {
    schema: 'domainscope.ip-retire/1',
    app,
    version,
    addresses: blocks.map((b) => b.cidr),
    domains: [...domains],
    zone: zone || null,
    startedAt: iso(startedAt),
    finishedAt: iso(finishedAt),
    aborted: !!aborted,
    counts: counts ? { ...counts, bySeverity: { ...counts.bySeverity }, byVerified: { ...counts.byVerified } } : null,
    owners: owners.map((o) => ({ name: o.name, addresses: [...o.addresses], others: [...o.others] })),
    changes: changes.map((c) => ({
      group: c.group, severity: c.severity, name: c.name, type: c.type, value: c.value, addresses: [...c.addresses], blocks: [...c.blocks],
      action: c.action, verified: c.verified, via: [...c.via], roles: [...c.roles], sources: [...c.sources], line: c.line,
      proxied: c.proxied, reason: c.reason, spf: c.spf ? { ...c.spf } : null, foundFor: [...c.foundFor]
    })),
    passiveGone: gone.map((g) => ({ ...g, now: [...g.now] })),
    failures: failures.map((f) => ({ ...f }))
  };
}
