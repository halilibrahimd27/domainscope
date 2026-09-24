/**
 * netinfo.js — IP parsing/formatting (hand-written, BigInt for IPv6), CIDR
 * math, private-range checks, PTR names, and CDN/WAF/platform detection by
 * IP range or CNAME suffix. DOM-free; runs in browsers and Node 22.
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

function cidrContains(cidr, ip) {
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

const PRIVATE_V4 = [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
  '172.16.0.0/12', '192.168.0.0/16', '192.0.0.0/24', '198.18.0.0/15'
].map(parseCidr);
const PRIVATE_V6 = ['::/128', '::1/128', 'fc00::/7', 'fe80::/10'].map(parseCidr);

/**
 * Non-public address? v4: 0/8, 10/8, 100.64/10 (CGNAT), 127/8, 169.254/16,
 * 172.16/12, 192.168/16, 192.0.0/24, 198.18/15; v6: ::, ::1, fc00::/7,
 * fe80::/10; IPv4-mapped v6 uses the v4 rules. Invalid input → false.
 * @param {string} ip
 * @returns {boolean}
 */
export function isPrivateIP(ip) {
  const addr = parseIP(ip);
  if (!addr) return false;
  const v4 = addr.version === 4 ? addr.value : mappedV4(addr);
  if (v4 !== null) return PRIVATE_V4.some((c) => cidrContains(c, { version: 4, value: v4 }));
  return PRIVATE_V6.some((c) => cidrContains(c, addr));
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

/* ------------------------------------------------------------------------ */
/* Providers                                                                */
/* ------------------------------------------------------------------------ */

/** Date the embedded IP ranges were fetched from their official sources. */
export const RANGES_UPDATED = '2026-09-23';

// Official range sources (all fetched 2026-09-23). IP ranges are included
// ONLY where an official, machine- or docs-published list was retrieved:
//   Cloudflare  https://www.cloudflare.com/ips-v4 , /ips-v6
//   Fastly      https://api.fastly.com/public-ip-list
//   CloudFront  https://ip-ranges.amazonaws.com/ip-ranges.json (service "CLOUDFRONT",
//               syncToken 1790141226; equals the union of
//               https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips)
//   Imperva     https://my.imperva.com/api/integration/v1/ips (POST resp_format=json)
//   Sucuri      https://docs.sucuri.net/website-firewall/sucuri-firewall-troubleshooting-guide/
//               (documented firewall ranges; edge IPs outside them rely on CNAME detection)
//   GitHub Pages https://api.github.com/meta ("pages")
//   Netlify     https://docs.netlify.com/manage/domains/configure-domains/configure-external-dns/
//               (apex load balancer 75.2.60.5)
//   Vercel      https://vercel.com/docs/domains/working-with-domains/add-a-domain (apex A 76.76.21.21)
// Not included (no stable official list): Akamai, Azure Front Door (weekly
// service-tag file), Bunny & Gcore (hundreds of churning /32 edge IPs; Gcore's
// list even contains 172.31.0.7), KeyCDN (origin-shield list only), CDN77,
// Medianova, StackPath, Edgio, Shopify (docs not retrievable), others.

const CLOUDFLARE_CIDRS = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
  '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
  '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
  '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
  '2a06:98c0::/29', '2c0f:f248::/32'
];

const FASTLY_CIDRS = [
  '23.235.32.0/20', '43.249.72.0/22', '103.244.50.0/24', '103.245.222.0/23', '103.245.224.0/24',
  '104.156.80.0/20', '140.248.64.0/18', '140.248.128.0/17', '146.75.0.0/17', '151.101.0.0/16',
  '157.52.64.0/18', '167.82.0.0/17', '167.82.128.0/20', '167.82.160.0/20', '167.82.224.0/20',
  '172.111.64.0/18', '185.31.16.0/22', '199.27.72.0/21', '199.232.0.0/16',
  '2a04:4e40::/32', '2a04:4e42::/32'
];

const CLOUDFRONT_CIDRS = [
  '3.10.17.128/25', '3.11.53.0/24', '3.29.40.64/26', '3.29.40.128/26', '3.29.40.192/26', '3.29.57.0/26',
  '3.35.130.128/25', '3.101.158.0/23', '3.107.43.128/25', '3.107.44.0/25', '3.107.44.128/25', '3.128.93.0/24',
  '3.134.215.0/24', '3.146.232.0/22', '3.147.164.0/22', '3.147.244.0/22', '3.160.0.0/14', '3.164.0.0/18',
  '3.164.64.0/18', '3.164.128.0/17', '3.165.0.0/16', '3.166.0.0/15', '3.168.0.0/14', '3.172.0.0/18',
  '3.172.64.0/18', '3.173.0.0/17', '3.173.128.0/18', '3.173.192.0/18', '3.174.0.0/15', '3.231.2.0/25',
  '3.234.232.224/27', '3.236.48.0/23', '3.236.169.192/26', '13.32.0.0/15', '13.35.0.0/16', '13.54.63.128/26',
  '13.59.250.0/26', '13.113.196.64/26', '13.113.203.0/24', '13.124.199.0/24', '13.134.24.0/23', '13.134.94.0/23',
  '13.203.133.0/26', '13.210.67.128/26', '13.224.0.0/14', '13.228.69.0/24', '13.233.177.192/26', '13.249.0.0/16',
  '15.158.0.0/16', '15.188.184.0/24', '15.207.13.128/25', '15.207.213.128/25', '18.64.0.0/14', '18.68.0.0/16',
  '18.154.0.0/15', '18.160.0.0/15', '18.164.0.0/15', '18.172.0.0/15', '18.175.65.0/24', '18.175.66.0/24',
  '18.175.67.0/24', '18.192.142.0/23', '18.199.68.0/22', '18.199.72.0/22', '18.199.76.0/22', '18.200.212.0/23',
  '18.216.170.128/25', '18.229.220.192/26', '18.230.229.0/24', '18.230.230.0/25', '18.238.0.0/15', '18.244.0.0/15',
  '23.91.0.0/19', '23.228.212.0/24', '23.228.213.0/24', '23.228.214.0/24', '23.228.220.0/24', '23.228.221.0/24',
  '23.228.222.0/24', '23.228.223.0/24', '23.228.244.0/24', '23.228.246.0/24', '23.228.247.0/24', '23.228.248.0/24',
  '23.228.249.0/24', '23.228.250.0/24', '23.228.251.0/24', '23.234.192.0/18', '24.110.32.0/19', '24.110.128.0/17',
  '34.195.252.0/24', '34.216.51.0/25', '34.223.12.224/27', '34.223.80.192/26', '34.226.14.0/24', '35.93.168.0/23',
  '35.93.170.0/23', '35.93.172.0/23', '35.158.136.0/24', '35.162.63.192/26', '35.167.191.128/26', '36.103.232.0/25',
  '36.103.232.128/26', '43.218.56.64/26', '43.218.56.128/26', '43.218.56.192/26', '43.218.71.0/26', '44.220.194.0/23',
  '44.220.196.0/23', '44.220.198.0/23', '44.220.200.0/23', '44.220.202.0/23', '44.222.66.0/24', '44.227.178.0/24',
  '44.234.90.252/30', '44.234.108.128/25', '47.129.82.0/24', '47.129.83.0/24', '47.129.84.0/24', '51.44.234.0/23',
  '51.44.236.0/23', '51.44.238.0/23', '51.74.192.0/18', '52.15.127.128/26', '52.46.0.0/18', '52.47.139.0/24',
  '52.52.191.128/26', '52.56.127.0/25', '52.57.254.0/24', '52.66.194.128/26', '52.78.247.128/26', '52.82.128.0/19',
  '52.84.0.0/15', '52.124.128.0/17', '52.199.127.192/26', '52.212.248.0/26', '52.220.191.0/26', '52.222.128.0/17',
  '54.182.0.0/16', '54.192.0.0/16', '54.230.0.0/17', '54.230.128.0/18', '54.230.200.0/21', '54.230.208.0/20',
  '54.230.224.0/19', '54.233.255.128/26', '54.239.128.0/18', '54.239.192.0/19', '54.240.128.0/18', '56.125.46.0/24',
  '56.125.47.0/32', '56.125.48.0/24', '57.182.253.0/24', '57.183.42.0/25', '58.254.138.0/25', '58.254.138.128/26',
  '64.252.64.0/18', '64.252.128.0/18', '65.8.0.0/16', '65.9.0.0/17', '65.9.128.0/18', '70.132.0.0/18',
  '71.152.0.0/17', '99.79.169.0/24', '99.84.0.0/16', '99.86.0.0/16', '108.138.0.0/15', '108.156.0.0/14',
  '111.13.171.128/26', '111.13.171.192/26', '111.13.185.32/27', '111.13.185.64/27', '116.129.226.0/25', '116.129.226.128/26',
  '118.193.97.64/26', '118.193.97.128/25', '119.147.182.0/25', '119.147.182.128/26', '120.52.12.64/26', '120.52.22.96/27',
  '120.52.39.128/27', '120.52.153.192/26', '120.232.236.0/25', '120.232.236.128/26', '120.253.240.192/26', '120.253.241.160/27',
  '120.253.245.128/26', '120.253.245.192/27', '130.176.0.0/17', '130.176.128.0/18', '130.176.192.0/19', '130.176.224.0/20',
  '143.204.0.0/16', '144.220.0.0/16', '180.163.57.0/25', '180.163.57.128/26', '204.246.164.0/22', '204.246.168.0/22',
  '204.246.172.0/24', '204.246.173.0/24', '204.246.174.0/23', '204.246.176.0/20', '205.251.202.0/23', '205.251.204.0/23',
  '205.251.206.0/23', '205.251.208.0/20', '205.251.249.0/24', '205.251.250.0/23', '205.251.252.0/23', '205.251.254.0/24',
  '216.137.32.0/19',
  '2001:3fc6:20::/43', '2400:7fc0:500::/40', '2404:c2c0:500::/40', '2409:8c00:2421:300::/56',
  '2409:8c00:2421:400::/56', '2600:9000:ddd::/48', '2600:9000:eee::/48', '2600:9000:fff::/48',
  '2600:9000:1000::/36', '2600:9000:2000::/36', '2600:9000:3000::/36', '2600:9000:4000::/36',
  '2600:9000:5200::/40', '2600:9000:5308::/45', '2600:9000:5310::/44', '2600:9000:5320::/43',
  '2600:9000:5340::/42', '2600:9000:5380::/41', '2600:9000:6000::/36', '2600:9000:f000::/38',
  '2600:9000:f400::/40', '2600:9000:f500::/43', '2600:9000:f520::/44', '2600:9000:f534::/46',
  '2600:9000:f538::/45', '2600:9000:f540::/42', '2600:9000:f580::/41', '2600:9000:f600::/39',
  '2600:9000:f800::/37', '2600:f0f0:601::/48', '2600:f0f0:602::/47', '2600:f0f0:5504::/46'
];

const IMPERVA_CIDRS = [
  '199.83.128.0/21', '198.143.32.0/19', '149.126.72.0/21', '103.28.248.0/22', '185.11.124.0/22',
  '192.230.64.0/18', '45.64.64.0/22', '107.154.0.0/16', '45.60.0.0/16', '45.223.0.0/16',
  '131.125.128.0/17',
  '2a02:e980::/29'
];

const SUCURI_CIDRS = [
  '192.88.134.0/23', '185.93.228.0/22', '66.248.200.0/22', '208.109.0.0/22',
  '2a02:fe80::/29'
];

const GITHUB_PAGES_CIDRS = [
  '192.30.252.153/32', '192.30.252.154/32', '185.199.108.153/32', '185.199.109.153/32',
  '185.199.110.153/32', '185.199.111.153/32',
  '2606:50c0:8000::153/128', '2606:50c0:8001::153/128', '2606:50c0:8002::153/128',
  '2606:50c0:8003::153/128'
];

/**
 * Build a frozen provider record. `toJSON` (non-enumerable) omits the large
 * `cidrs` array (replaced by `cidrCount`) and stringifies regexes, so JSON
 * exports that embed providers stay small.
 */
function defineProvider(def) {
  const p = {
    id: def.id,
    name: def.name,
    category: def.category,
    hidesOrigin: def.hidesOrigin,
    certManagedByProvider: def.certManagedByProvider,
    cidrs: Object.freeze([...(def.cidrs || [])]),
    cnameSuffixes: Object.freeze([...(def.cnameSuffixes || [])]),
    cnamePatterns: Object.freeze([...(def.cnamePatterns || [])]),
    dnsOnly: !!def.dnsOnly,
    homepage: def.homepage || null,
    rangesSource: def.rangesSource || null
  };
  Object.defineProperty(p, 'toJSON', {
    enumerable: false,
    value() {
      const { cidrs, cnamePatterns, ...rest } = this;
      return { ...rest, cidrCount: cidrs.length, cnamePatterns: cnamePatterns.map((r) => r.source) };
    }
  });
  return Object.freeze(p);
}

/**
 * Known CDNs, WAFs, load balancers and hosting platforms.
 *
 * Fields: `id`, `name`, `category` ('cdn'|'waf'|'platform'|'loadbalancer'|
 * 'hosting'), `hidesOrigin` (visitors reach the provider, your origin server
 * is hidden behind it), `certManagedByProvider` (TLS for the hostname is
 * terminated by the provider — the certificate visitors see lives there, not
 * on your servers), `cidrs` (verified official ranges only), `cnameSuffixes`
 * (label-boundary suffix match). Extensions: `cnamePatterns` (RegExp[]),
 * `dnsOnly` (DNS-level traffic steering: the answer IPs are your real
 * endpoints), `homepage`, `rangesSource`.
 * @type {ReadonlyArray<object>}
 */
export const PROVIDERS = Object.freeze([
  defineProvider({
    id: 'cloudflare', name: 'Cloudflare', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cidrs: CLOUDFLARE_CIDRS, cnameSuffixes: ['cdn.cloudflare.net', 'cloudflare.net'],
    homepage: 'https://www.cloudflare.com/', rangesSource: 'https://www.cloudflare.com/ips/'
  }),
  defineProvider({
    id: 'fastly', name: 'Fastly', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cidrs: FASTLY_CIDRS, cnameSuffixes: ['fastly.net', 'fastlylb.net'],
    homepage: 'https://www.fastly.com/', rangesSource: 'https://api.fastly.com/public-ip-list'
  }),
  defineProvider({
    id: 'cloudfront', name: 'Amazon CloudFront', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cidrs: CLOUDFRONT_CIDRS, cnameSuffixes: ['cloudfront.net'],
    homepage: 'https://aws.amazon.com/cloudfront/', rangesSource: 'https://ip-ranges.amazonaws.com/ip-ranges.json'
  }),
  defineProvider({
    id: 'akamai', name: 'Akamai', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['akamaiedge.net', 'akamai.net', 'edgekey.net', 'edgesuite.net', 'akamaized.net',
      'akamaihd.net', 'akamaitechnologies.com', 'akamaiedge-staging.net', 'edgekey-staging.net',
      'edgesuite-staging.net'],
    homepage: 'https://www.akamai.com/'
  }),
  defineProvider({
    id: 'azure-frontdoor', name: 'Azure Front Door / Azure CDN', category: 'cdn', hidesOrigin: true,
    certManagedByProvider: true, cnameSuffixes: ['azurefd.net', 'azureedge.net', 't-msedge.net'],
    homepage: 'https://azure.microsoft.com/products/frontdoor'
  }),
  defineProvider({
    id: 'imperva', name: 'Imperva (Incapsula)', category: 'waf', hidesOrigin: true, certManagedByProvider: true,
    cidrs: IMPERVA_CIDRS, cnameSuffixes: ['incapdns.net', 'impervadns.net'],
    homepage: 'https://www.imperva.com/', rangesSource: 'https://my.imperva.com/api/integration/v1/ips'
  }),
  defineProvider({
    id: 'sucuri', name: 'Sucuri Website Firewall', category: 'waf', hidesOrigin: true, certManagedByProvider: true,
    cidrs: SUCURI_CIDRS, cnameSuffixes: ['sucuri.net'],
    homepage: 'https://sucuri.net/',
    rangesSource: 'https://docs.sucuri.net/website-firewall/sucuri-firewall-troubleshooting-guide/'
  }),
  defineProvider({
    id: 'stackpath', name: 'StackPath / Highwinds', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['stackpathdns.com', 'stackpathcdn.com', 'hwcdn.net'], homepage: 'https://www.stackpath.com/'
  }),
  defineProvider({
    id: 'bunny', name: 'Bunny CDN', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['b-cdn.net'], homepage: 'https://bunny.net/'
  }),
  defineProvider({
    id: 'keycdn', name: 'KeyCDN', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['kxcdn.com'], homepage: 'https://www.keycdn.com/'
  }),
  defineProvider({
    id: 'cdn77', name: 'CDN77', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['cdn77.org', 'cdn77.net'], homepage: 'https://www.cdn77.com/'
  }),
  defineProvider({
    id: 'edgio', name: 'Edgio / Edgecast', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['edgecastcdn.net', 'systemcdn.net', 'edgio.net', 'llnwd.net'], homepage: 'https://edg.io/'
  }),
  defineProvider({
    id: 'medianova', name: 'Medianova', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['mncdn.com', 'mncdn.net'], homepage: 'https://www.medianova.com/'
  }),
  defineProvider({
    id: 'gcore', name: 'Gcore CDN', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['gcdn.co'], homepage: 'https://gcore.com/'
  }),
  defineProvider({
    id: 'cachefly', name: 'CacheFly', category: 'cdn', hidesOrigin: true, certManagedByProvider: true,
    cnameSuffixes: ['cachefly.net'], homepage: 'https://www.cachefly.com/'
  }),
  defineProvider({
    id: 'aws-elb', name: 'AWS Elastic Load Balancing', category: 'loadbalancer', hidesOrigin: true,
    certManagedByProvider: true, cnameSuffixes: ['elb.amazonaws.com', 'elb.amazonaws.com.cn'],
    homepage: 'https://aws.amazon.com/elasticloadbalancing/'
  }),
  defineProvider({
    id: 'azure-trafficmanager', name: 'Azure Traffic Manager', category: 'loadbalancer', hidesOrigin: false,
    certManagedByProvider: false, dnsOnly: true, cnameSuffixes: ['trafficmanager.net'],
    homepage: 'https://azure.microsoft.com/products/traffic-manager'
  }),
  defineProvider({
    id: 'aws-s3', name: 'Amazon S3', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['s3.amazonaws.com'],
    // s3.amazonaws.com, s3-website-us-east-1.amazonaws.com, bucket.s3.eu-west-1.amazonaws.com,
    // bucket.s3-website.eu-central-1.amazonaws.com, s3.dualstack.… (label must start with "s3")
    cnamePatterns: [/(?:^|\.)s3(?:[.-][a-z0-9-]+)*\.amazonaws\.com(?:\.cn)?$/],
    homepage: 'https://aws.amazon.com/s3/'
  }),
  defineProvider({
    id: 'azure-appservice', name: 'Azure App Service / Static Web Apps', category: 'platform', hidesOrigin: false,
    certManagedByProvider: true, cnameSuffixes: ['azurewebsites.net', 'azurestaticapps.net'],
    homepage: 'https://azure.microsoft.com/products/app-service'
  }),
  defineProvider({
    id: 'github-pages', name: 'GitHub Pages', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cidrs: GITHUB_PAGES_CIDRS, cnameSuffixes: ['github.io'],
    homepage: 'https://pages.github.com/', rangesSource: 'https://api.github.com/meta'
  }),
  defineProvider({
    id: 'gitlab-pages', name: 'GitLab Pages', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['gitlab.io'], homepage: 'https://docs.gitlab.com/ee/user/project/pages/'
  }),
  defineProvider({
    id: 'heroku', name: 'Heroku', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['herokuapp.com', 'herokudns.com', 'herokussl.com'], homepage: 'https://www.heroku.com/'
  }),
  defineProvider({
    id: 'vercel', name: 'Vercel', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cidrs: ['76.76.21.21/32'], cnameSuffixes: ['vercel-dns.com', 'vercel.app'],
    cnamePatterns: [/(?:^|\.)vercel-dns-\d+\.com$/],
    homepage: 'https://vercel.com/', rangesSource: 'https://vercel.com/docs/domains/working-with-domains/add-a-domain'
  }),
  defineProvider({
    id: 'netlify', name: 'Netlify', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cidrs: ['75.2.60.5/32'], cnameSuffixes: ['netlify.app', 'netlify.com'],
    homepage: 'https://www.netlify.com/',
    rangesSource: 'https://docs.netlify.com/manage/domains/configure-domains/configure-external-dns/'
  }),
  defineProvider({
    id: 'google-hosted', name: 'Google-hosted (ghs.googlehosted.com)', category: 'platform', hidesOrigin: false,
    certManagedByProvider: true, cnameSuffixes: ['ghs.googlehosted.com', 'googlehosted.com'],
    homepage: 'https://support.google.com/a/answer/47283'
  }),
  defineProvider({
    id: 'firebase', name: 'Firebase Hosting', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['web.app', 'firebaseapp.com'], homepage: 'https://firebase.google.com/docs/hosting'
  }),
  defineProvider({
    id: 'shopify', name: 'Shopify', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['myshopify.com'], homepage: 'https://www.shopify.com/'
  }),
  defineProvider({
    id: 'wpengine', name: 'WP Engine', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['wpengine.com', 'wpenginepowered.com'], homepage: 'https://wpengine.com/'
  }),
  defineProvider({
    id: 'pantheon', name: 'Pantheon', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['pantheonsite.io', 'pantheon.io'], homepage: 'https://pantheon.io/'
  }),
  defineProvider({
    id: 'render', name: 'Render', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['onrender.com'], homepage: 'https://render.com/'
  }),
  defineProvider({
    id: 'fly', name: 'Fly.io', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['fly.dev'], homepage: 'https://fly.io/'
  }),
  defineProvider({
    id: 'railway', name: 'Railway', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['railway.app'], homepage: 'https://railway.com/'
  }),
  defineProvider({
    id: 'digitalocean-app', name: 'DigitalOcean App Platform', category: 'platform', hidesOrigin: false,
    certManagedByProvider: true, cnameSuffixes: ['ondigitalocean.app'],
    homepage: 'https://www.digitalocean.com/products/app-platform'
  }),
  defineProvider({
    id: 'wix', name: 'Wix', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['wixdns.net'], homepage: 'https://www.wix.com/'
  }),
  defineProvider({
    id: 'squarespace', name: 'Squarespace', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['squarespace.com'], homepage: 'https://www.squarespace.com/'
  }),
  defineProvider({
    id: 'webflow', name: 'Webflow', category: 'platform', hidesOrigin: false, certManagedByProvider: true,
    cnameSuffixes: ['webflow.com', 'webflow.io'], homepage: 'https://webflow.com/'
  })
]);

/**
 * Look up a provider by id.
 * @param {string} id
 * @returns {object|undefined}
 */
export function getProvider(id) {
  return PROVIDERS.find((p) => p.id === id);
}

let compiledRanges = null; // lazily parsed [{ cidr, provider }]
let suffixIndex = null; // Map<suffix, provider>

function ranges() {
  if (!compiledRanges) {
    compiledRanges = [];
    for (const provider of PROVIDERS) {
      for (const text of provider.cidrs) {
        const cidr = parseCidr(text);
        if (cidr) compiledRanges.push({ cidr, provider });
      }
    }
  }
  return compiledRanges;
}

function suffixes() {
  if (!suffixIndex) {
    suffixIndex = new Map();
    for (const provider of PROVIDERS) {
      for (const suffix of provider.cnameSuffixes) {
        if (!suffixIndex.has(suffix)) suffixIndex.set(suffix, provider);
      }
    }
  }
  return suffixIndex;
}

/**
 * Provider whose published IP ranges contain `ip` (first match in PROVIDERS
 * order), or null.
 * @param {string} ip
 * @returns {object|null}
 */
export function matchProviderByIP(ip) {
  const addr = parseIP(ip);
  if (!addr) return null;
  for (const { cidr, provider } of ranges()) {
    if (cidrContains(cidr, addr)) return provider;
  }
  return null;
}

/**
 * Provider whose CNAME suffix matches `hostname` on a label boundary
 * (longest suffix wins), then provider regex patterns; or null.
 * @param {string} hostname
 * @returns {object|null}
 */
export function matchProviderByCname(hostname) {
  if (typeof hostname !== 'string') return null;
  let h = hostname.trim().toLowerCase();
  if (h.endsWith('.')) h = h.slice(0, -1);
  if (!h) return null;
  const index = suffixes();
  const labels = h.split('.');
  for (let i = 0; i < labels.length; i += 1) {
    const hit = index.get(labels.slice(i).join('.'));
    if (hit) return hit;
  }
  for (const provider of PROVIDERS) {
    if (provider.cnamePatterns.some((re) => re.test(h))) return provider;
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* Classification                                                           */
/* ------------------------------------------------------------------------ */

function rankOf(provider) {
  if (provider.dnsOnly) return Infinity;
  if (provider.id === 'cloudflare') return 0;
  if (provider.category === 'cdn' || provider.category === 'waf') return 1;
  return 2; // platform / loadbalancer / hosting
}

function kindOf(provider) {
  if (provider.id === 'cloudflare') return 'cloudflare';
  if (provider.category === 'cdn' || provider.category === 'waf') return 'cdn';
  return 'platform';
}

function reasonOf(provider, via) {
  const group = provider.id === 'cloudflare' ? 'cloudflare' : provider.category;
  return `class.${group}.${via}`;
}

/**
 * Classify a host's DNS resolution.
 *
 * Priority: nxdomain (no CNAME) > dangling/unresolved > cloudflare > cdn/waf
 * > platform/loadbalancer > private (all IPs private) > direct.
 * `dangling` is true when a CNAME chain exists but yields no address
 * (NXDOMAIN target, NODATA, or a failed lookup).
 *
 * reasonKey values: class.nxdomain, class.dangling.nxdomain,
 * class.dangling.noaddress, class.dangling.error, class.nodata, class.error,
 * class.cloudflare.ip, class.cloudflare.cname, class.cdn.ip, class.cdn.cname,
 * class.waf.ip, class.waf.cname, class.platform.ip, class.platform.cname,
 * class.loadbalancer.ip, class.loadbalancer.cname, class.hosting.ip,
 * class.hosting.cname, class.private, class.direct.
 *
 * @param {{ status?: string, ipv4?: string[], ipv6?: string[], cnames?: string[] }} res
 * @returns {{ kind: 'cloudflare'|'cdn'|'platform'|'direct'|'private'|'unresolved'|'nxdomain',
 *   provider: object|null, hidesOrigin: boolean, certManagedByProvider: boolean,
 *   dangling: boolean, reasonKey: string, via: 'ip'|'cname'|null }}
 */
export function classifyResolution({ status, ipv4 = [], ipv6 = [], cnames = [] } = {}) {
  const ips = [...new Set([...(ipv4 || []), ...(ipv6 || [])].map(normalizeIP).filter(Boolean))];
  const chain = (cnames || [])
    .filter((c) => typeof c === 'string')
    .map((c) => c.trim().toLowerCase().replace(/\.$/, ''))
    .filter(Boolean);
  const st = typeof status === 'string' && status ? status.toUpperCase() : (ips.length ? 'NOERROR' : 'ERROR');
  const result = (kind, reasonKey, extra = {}) => ({
    kind, provider: null, hidesOrigin: false, certManagedByProvider: false, dangling: false, reasonKey, via: null, ...extra
  });

  // Provider evidence: IP matches first, then the CNAME chain in order.
  const candidates = [];
  for (const ip of ips) {
    const p = matchProviderByIP(ip);
    if (p) candidates.push({ provider: p, via: 'ip' });
  }
  for (const c of chain) {
    const p = matchProviderByCname(c);
    if (p) candidates.push({ provider: p, via: 'cname' });
  }

  if (ips.length === 0) {
    if (chain.length === 0) {
      if (st === 'NXDOMAIN') return result('nxdomain', 'class.nxdomain');
      return result('unresolved', st === 'NOERROR' ? 'class.nodata' : 'class.error');
    }
    // Dangling CNAME: the provider (if any) hints at takeover-prone services.
    let reasonKey = 'class.dangling.error';
    if (st === 'NXDOMAIN') reasonKey = 'class.dangling.nxdomain';
    else if (st === 'NOERROR') reasonKey = 'class.dangling.noaddress';
    const hit = candidates[0] || null;
    return result('unresolved', reasonKey, {
      dangling: true, provider: hit ? hit.provider : null, via: hit ? 'cname' : null
    });
  }

  let best = null;
  for (const c of candidates) {
    if (!best || rankOf(c.provider) < rankOf(best.provider)) best = c;
  }
  if (best && !best.provider.dnsOnly) {
    return result(kindOf(best.provider), reasonOf(best.provider, best.via), {
      provider: best.provider,
      hidesOrigin: best.provider.hidesOrigin,
      certManagedByProvider: best.provider.certManagedByProvider,
      via: best.via
    });
  }
  // Only DNS-level steering (or nothing): the answer IPs are the real endpoints.
  const extra = best ? { provider: best.provider, via: best.via } : {};
  if (ips.every(isPrivateIP)) return result('private', 'class.private', extra);
  return result('direct', 'class.direct', extra);
}
