/**
 * ip.js — IP parsing/formatting (hand-written, BigInt for IPv6), CIDR math, private-range
 * checks and PTR names. DOM-free; runs in browsers and Node 22. The part of lib/netinfo.js
 * the start route needs; the provider ranges and their classification stay in netinfo.js,
 * which re-exports this module.
 */

/* ------------------------------------------------------------------------ */
/* Parsing / formatting                                                     */
/* ------------------------------------------------------------------------ */

const V4_PART_RE = /^(?:0|[1-9]\d{0,2})$/;
const V6_GROUP_RE = /^[0-9a-f]{1,4}$/;
const MASK32 = 0xffffffffn;

/** Strict dotted-quad (no leading zeros, no shorthand) → BigInt or null. */
function parseV4(s) {
  const parts = s.split('.');
  if (parts.length !== 4) return null;
  let value = 0n;
  for (const part of parts) {
    if (!V4_PART_RE.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = (value << 8n) | BigInt(n);
  }
  return value;
}

/** Colon-separated groups (optionally ending in dotted IPv4) → numbers. */
function v6Groups(str, allowV4) {
  if (str === '') return [];
  const parts = str.split(':');
  const out = [];
  for (let i = 0; i < parts.length; i += 1) {
    const p = parts[i];
    if (p.includes('.')) {
      if (!allowV4 || i !== parts.length - 1) return null;
      const v4 = parseV4(p);
      if (v4 === null) return null;
      out.push(Number(v4 >> 16n), Number(v4 & 0xffffn));
    } else if (V6_GROUP_RE.test(p)) {
      out.push(parseInt(p, 16));
    } else {
      return null;
    }
  }
  return out;
}

/** RFC 4291 text form (incl. `::` and embedded IPv4) → BigInt or null. */
function parseV6(input) {
  const s = input.toLowerCase();
  if (s.length < 2 || s.length > 45 || !/^[0-9a-f:.]+$/.test(s)) return null;
  const dbl = s.indexOf('::');
  let groups;
  if (dbl === -1) {
    groups = v6Groups(s, true);
    if (!groups || groups.length !== 8) return null;
  } else {
    if (s.indexOf('::', dbl + 1) !== -1) return null;
    const head = v6Groups(s.slice(0, dbl), false);
    const tail = v6Groups(s.slice(dbl + 2), true);
    if (!head || !tail) return null;
    const used = head.length + tail.length;
    if (used > 7) return null; // '::' must stand for at least one group
    groups = [...head, ...new Array(8 - used).fill(0), ...tail];
  }
  let value = 0n;
  for (const g of groups) value = (value << 16n) | BigInt(g);
  return value;
}

function formatV4(n) {
  return [24n, 16n, 8n, 0n].map((shift) => String((n >> shift) & 0xffn)).join('.');
}

/** RFC 5952: lowercase, no leading zeros, longest (leftmost) zero run ≥ 2 → '::'. */
function formatV6(n) {
  if (n >> 32n === 0xffffn) return `::ffff:${formatV4(n & MASK32)}`; // IPv4-mapped
  const groups = [];
  for (let i = 7; i >= 0; i -= 1) groups.push(Number((n >> BigInt(i * 16)) & 0xffffn));
  let bestStart = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (groups[i] !== 0) {
      i += 1;
      continue;
    }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLen) {
      bestStart = i;
      bestLen = j - i;
    }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (bestLen < 2) return hex.join(':');
  return `${hex.slice(0, bestStart).join(':')}::${hex.slice(bestStart + bestLen).join(':')}`;
}

/** Trim, strip `[...]` brackets and an IPv6 `%zone`. */
function cleanIpText(s) {
  if (typeof s !== 'string') return '';
  let t = s.trim();
  if (t.startsWith('[') && t.endsWith(']')) t = t.slice(1, -1).trim();
  const pct = t.indexOf('%');
  if (pct !== -1 && t.includes(':')) t = t.slice(0, pct);
  return t;
}

/**
 * Parse an IP address.
 * @param {string} s IPv4 dotted quad or IPv6 text (brackets / %zone allowed).
 * @returns {{ version: 4|6, value: bigint } | null}
 */
export function parseIP(s) {
  const t = cleanIpText(s);
  if (!t) return null;
  if (t.includes(':')) {
    const value = parseV6(t);
    return value === null ? null : { version: 6, value };
  }
  const value = parseV4(t);
  return value === null ? null : { version: 4, value };
}

/**
 * @param {string} s
 * @returns {4|6|0} IP version, or 0 when `s` is not an IP address.
 */
export function ipVersion(s) {
  const ip = parseIP(s);
  return ip ? ip.version : 0;
}

/**
 * Canonical text form: IPv4 dotted quad; IPv6 RFC 5952 (lowercase,
 * compressed); IPv4-mapped kept as `::ffff:1.2.3.4`. Brackets and `%zone`
 * are stripped. Leading-zero IPv4 octets (`010.0.0.1`, ambiguous octal) are
 * rejected.
 * @param {string} s
 * @returns {string|null}
 */
export function normalizeIP(s) {
  const ip = parseIP(s);
  if (!ip) return null;
  return ip.version === 4 ? formatV4(ip.value) : formatV6(ip.value);
}

/**
 * Format a numeric address.
 * @param {bigint} value
 * @param {4|6} version
 * @returns {string}
 */
export function formatIP(value, version) {
  return version === 4 ? formatV4(BigInt(value) & MASK32) : formatV6(BigInt(value) & ((1n << 128n) - 1n));
}

/** For `::ffff:a.b.c.d` return the embedded IPv4 value, else null. */
function mappedV4(ip) {
  return ip.version === 6 && ip.value >> 32n === 0xffffn ? ip.value & MASK32 : null;
}

function maskFor(version, prefix) {
  const bits = version === 4 ? 32 : 128;
  const all = (1n << BigInt(bits)) - 1n;
  return all ^ ((1n << BigInt(bits - prefix)) - 1n);
}

/**
 * Parse `addr/prefix` (host bits are masked off). A bare address is treated
 * as a host route (/32 or /128).
 * @param {string} s
 * @returns {{ version: 4|6, network: bigint, prefix: number } | null}
 */
export function parseCidr(s) {
  if (typeof s !== 'string') return null;
  const t = s.trim();
  const slash = t.indexOf('/');
  const addr = slash === -1 ? t : t.slice(0, slash);
  const ip = parseIP(addr);
  if (!ip) return null;
  const bits = ip.version === 4 ? 32 : 128;
  let prefix = bits;
  if (slash !== -1) {
    const p = t.slice(slash + 1).trim();
    if (!/^\d{1,3}$/.test(p)) return null;
    prefix = Number(p);
    if (prefix > bits) return null;
  }
  return { version: ip.version, network: ip.value & maskFor(ip.version, prefix), prefix };
}

/** Is the parsed `ip` inside the parsed `cidr`? (An IPv4-mapped IPv6 address matches IPv4 ranges.) */
export function cidrContains(cidr, ip) {
  let value = ip.value;
  if (cidr.version !== ip.version) {
    const v4 = cidr.version === 4 ? mappedV4(ip) : null;
    if (v4 === null) return false;
    value = v4;
  }
  return (value & maskFor(cidr.version, cidr.prefix)) === cidr.network;
}

/**
 * Is `ip` inside `cidr`? IPv4-mapped IPv6 addresses match IPv4 ranges.
 * @param {string} ip
 * @param {string|{ version: 4|6, network: bigint, prefix: number }} cidr
 * @returns {boolean}
 */
export function ipInCidr(ip, cidr) {
  const addr = parseIP(ip);
  const range = typeof cidr === 'string' ? parseCidr(cidr) : cidr;
  if (!addr || !range || typeof range.network !== 'bigint') return false;
  return cidrContains(range, addr);
}

/** The IPv4 ranges {@link isPrivateIP} holds private (no two of them touch). */
export const PRIVATE_V4_RANGES = Object.freeze([
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.168.0.0/16', '192.0.0.0/24', '198.18.0.0/15'
]);
const PRIVATE_V4 = PRIVATE_V4_RANGES.map(parseCidr);
const PRIVATE_V6 = ['::/128', '::1/128', 'fc00::/7', 'fe80::/10'].map(parseCidr);

/**
 * Non-public address? v4: 0/8, 10/8, 100.64/10 (CGNAT), 127/8, 169.254/16,
 * 172.16/12, 192.168/16, 192.0.0/24, 198.18/15; v6: ::, ::1, fc00::/7,
 * fe80::/10; IPv4-mapped v6 uses the v4 rules. Invalid input → false.
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateIP(ip) {
  return privateRangeOf(ip) !== null;
}

/**
 * The private range ({@link isPrivateIP}) holding `ip`, e.g. '10.0.0.0/8' for 10.1.2.3 (the
 * IPv4 range for an IPv4-mapped IPv6 address); null for a public or invalid address. No two
 * IPv4 ranges touch, so a block of IPv4 addresses is all private exactly when one range
 * holds both its ends.
 * @param {string} ip
 * @returns {string|null}
 */
export function privateRangeOf(ip) {
  const addr = parseIP(ip);
  if (!addr) return null;
  const v4 = addr.version === 4 ? addr.value : mappedV4(addr);
  const hit = v4 !== null
    ? PRIVATE_V4.find((c) => cidrContains(c, { version: 4, value: v4 }))
    : PRIVATE_V6.find((c) => cidrContains(c, addr));
  return hit ? `${formatIP(hit.network, hit.version)}/${hit.prefix}` : null;
}

// Beyond PRIVATE_V4: documentation (TEST-NET-1/2/3), the deprecated 6to4 relay anycast,
// multicast and 240/4 (incl. 255.255.255.255).
const NON_GLOBAL_V4 = [
  '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '192.88.99.0/24', '224.0.0.0/4', '240.0.0.0/4'
].map(parseCidr);
const GLOBAL_UNICAST_V6 = parseCidr('2000::/3');
// Inside 2000::/3 but not a reachable server address: Teredo, benchmarking, ORCHID and ORCHIDv2
// (identifiers, not locators), documentation (2001:db8::/32 and RFC 9637's 3fff::/20) and 6to4.
const NON_GLOBAL_V6 = [
  '2001::/32', '2001:2::/48', '2001:10::/28', '2001:20::/28', '2001:db8::/32', '2002::/16', '3fff::/20'
].map(parseCidr);

/**
 * Globally routable unicast: an address a probe on the public internet (Globalping, later
 * InternetDB) can reach. An allowlist for IPv6, because the API accepts — and charges for —
 * prefixes it cannot reach (3fff::1 was accepted at cost 1, verified 2026-09-24).
 *
 * - IPv4: false when {@link isPrivateIP}, or in 192.0.2/24, 198.51.100/24, 203.0.113/24,
 *   192.88.99/24, 224/4 or 240/4 (incl. 255.255.255.255). Every listed range was refused by
 *   Globalping with a free 400 ("must not be a private hostname"), except 192.88.99/24 (added
 *   conservatively: deprecated 6to4 relay anycast).
 * - IPv6: true only inside 2000::/3 and outside 2001::/32 (Teredo), 2001:2::/48 (benchmarking),
 *   2001:10::/28 and 2001:20::/28 (ORCHID), 2001:db8::/32, 2002::/16 (6to4) and 3fff::/20. This
 *   also rules out ::, ::1, fc00::/7, fe80::/10, fec0::/10, ff00::/8, 100::/64 and 64:ff9b::/96.
 * - IPv4-mapped IPv6 (::ffff:a.b.c.d) follows the IPv4 rules.
 * - Invalid input → false.
 *
 * {@link isPrivateIP} is unchanged: it keeps its app-wide meaning ("an internal address").
 * @param {string} ip
 * @returns {boolean}
 */
export function isGloballyRoutable(ip) {
  const addr = parseIP(ip);
  if (!addr) return false;
  const v4 = addr.version === 4 ? addr.value : mappedV4(addr);
  if (v4 !== null) {
    const a = { version: 4, value: v4 };
    return !PRIVATE_V4.some((c) => cidrContains(c, a)) && !NON_GLOBAL_V4.some((c) => cidrContains(c, a));
  }
  return cidrContains(GLOBAL_UNICAST_V6, addr) && !NON_GLOBAL_V6.some((c) => cidrContains(c, addr));
}

/**
 * Reverse-DNS query name: `4.3.2.1.in-addr.arpa` / nibble `….ip6.arpa`.
 * @param {string} ip
 * @returns {string}
 * @throws {TypeError} when `ip` is not a valid address.
 */
export function reversePtrName(ip) {
  const addr = parseIP(ip);
  if (!addr) throw new TypeError(`Invalid IP address: ${String(ip)}`);
  if (addr.version === 4) return `${formatV4(addr.value).split('.').reverse().join('.')}.in-addr.arpa`;
  const nibbles = addr.value.toString(16).padStart(32, '0').split('').reverse();
  return `${nibbles.join('.')}.ip6.arpa`;
}
