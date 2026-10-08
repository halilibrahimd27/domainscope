/**
 * inventory.js — tolerant parser for server inventories pasted or imported by
 * the user, plus IP → server lookup helpers. DOM-free; never throws.
 *
 * Supported inputs (auto-detected, mixed garbage tolerated):
 *   - "name ip [ip…]", "ip name", bare "ip", /etc/hosts ("ip name alias…")
 *   - Ansible INI ([group], [group:children], [group:vars], key=value vars)
 *   - Ansible YAML / simple YAML (hosts maps, lists of {name, ip})
 *   - CSV / TSV / semicolon (Excel TR) with a header row in any column order
 *   - JSON (arrays/objects, terraform output/state, AWS describe-instances,
 *     ansible-inventory --list, kubectl -o json) and JSON Lines
 *   - comments: '#', ';' and '//' (whole line), ' #' / ' //' (inline)
 * The same server name on several lines/rows merges its IPs.
 *
 * An address may carry its own port (`203.0.113.10:8443`, `[2001:db8::1]:8443`), as
 * cli/ssl_origin_scan.py reads it: the CLI scans that address on that port instead of
 * `-p`. The port is kept in `Server.ports` and written back by {@link serverTargets}; a
 * port outside 1–65535 makes the token an INVALID_IP, never a silently dropped one. In an
 * Ansible INI context (a line under a `[group]` header or with `ansible_*` variables) a port
 * on the host pattern, the first token (`203.0.113.10:2222`, `badwolf.example.com:5309`), is
 * Ansible's SSH port: the host stays on `-p` and a PARSE warning (reason 'sshPort') says so.
 *
 * Topology keys (TOPOLOGY_KEYS) say where TLS terminates, in every format, as the CLI reads them.
 */

import { normalizeIP, parseCidr, ipInCidr } from './ip.js';

/**
 * @typedef {object} Server
 * @property {string} id        Stable id: the name, or the first IP for unnamed servers.
 * @property {string} name      Server name (the first IP for unnamed servers).
 * @property {string[]} ips     Canonical IPs (normalizeIP), unique, input order.
 * @property {string[]} groups  Groups/roles (Ansible groups incl. parents, CSV group columns).
 * @property {number} line      1-based line where the server first appears.
 * @property {string[]} aliases Extension: other names (hosts-file aliases, secondary name columns).
 * @property {Object<string, Array<number|null>>} [ports] Extension, present only when an address
 *   was written with a port: address → its ports, `null` standing for the CLI's `-p` ports (the
 *   address was also given without one). An address missing here is scanned on `-p` only.
 * @property {number[]} [tlsPorts] `ports=`: for the addresses written without a port, not `-p`.
 * @property {boolean} [terminatesTls] `terminates_tls=` (absent: true).
 * @property {string[]} [vips] `vip=`: shared addresses it holds.
 * @property {string[]} [nats] `nat=`: public addresses it is reached at.
 * @property {string[]} [backends] `backends=`: the servers (`name`) it forwards to.
 */

/**
 * @typedef {object} InventoryWarning
 * @property {number} line 1-based line (approximate for JSON/YAML; 0 = whole input).
 * @property {'NO_IP'|'INVALID_IP'|'DUPLICATE_IP'|'PARSE'|'TOPOLOGY'} code
 * @property {string} text  The offending line (trimmed, ≤ 200 chars).
 * @property {string} [detail] Extension: offending token / IP / server name.
 * @property {string} [reason] Extension, a finer cause: 'port' — an
 *   INVALID_IP whose address is fine but whose port is not 1–65535 (`203.0.113.10:99999`); 'zone'
 *   — an INVALID_IP for an IPv6 zone id with a port (`[fe80::1%eth0]:8443`); 'hostPort' — a PARSE
 *   for a host name with a port (`web01.example.net:8443`), which the CLI can resolve but a server
 *   here is only matched by address; 'sshPort' — a PARSE for the port on an Ansible host pattern
 *   (`203.0.113.10:2222` under `[web]`), Ansible's SSH port: the address is kept, on `-p`.
 *   TOPOLOGY: see {@link TOPOLOGY_REASONS}.
 */

const MAX_INPUT = 10 * 1024 * 1024;
const MAX_DEPTH = 64;
const IGNORED_GROUPS = new Set(['all', 'ungrouped']);

/* ------------------------------------------------------------------------ */
/* Token helpers                                                            */
/* ------------------------------------------------------------------------ */

// Addresses that never identify a server: loopback, unspecified, multicast,
// broadcast, the /etc/hosts "fe00::0 ip6-localnet" boilerplate and IPv6
// link-local (macOS "fe80::1%lo0 localhost": meaningless once the zone is stripped).
const NON_HOST_RANGES = ['127.0.0.0/8', '0.0.0.0/32', '224.0.0.0/4', '255.255.255.255/32',
  '::1/128', '::/128', 'ff00::/8', 'fe00::/16', 'fe80::/10'].map(parseCidr);

function isNonHostIP(ip) {
  return NON_HOST_RANGES.some((c) => ipInCidr(ip, c));
}

/** Strip wrapping quotes/brackets/punctuation that surround values in prose/CSV/Excel. */
function unwrap(token) {
  return String(token)
    .trim()
    .replace(/^=(?=["'])/, '') // Excel ="10.0.0.1"
    .replace(/^["'`(<{]+/, '')
    .replace(/["'`)>},;]+$/, '');
}

/**
 * `ip` with the port text after it: none for '', null (invalid) for anything but digits
 * making 1–65535 (the CLI's `_endpoint_port`: `08443` is 8443, `0` and `https` are invalid).
 */
function withPort(ip, text) {
  if (!ip) return null;
  if (!text) return { ip, port: null };
  const port = /^\d+$/.test(text) ? Number(text) : 0;
  return port >= 1 && port <= 65535 ? { ip, port } : null;
}

/**
 * Parse one token as an IP with its optional port: accepts brackets, `ip:port`,
 * `[v6]:port`, `ip/32`, `ip/128`, a trailing sentence dot. An empty port (`ip:`,
 * as in "10.0.0.1: web01") means none; a port outside 1–65535 makes it invalid, and
 * so does a zone id with a port (`[fe80::1%eth0]:8443`: the CLI cannot keep the zone).
 * @param {unknown} token
 * @returns {{ ip: string, port: number|null }|null} canonical IP, or null
 */
function parseIpToken(token) {
  if (typeof token !== 'string') return null;
  let t = unwrap(token);
  if (!t || t.length > 64) return null;
  if (t.endsWith('.') && !t.includes(':')) t = t.slice(0, -1);
  let m = /^\[([^\]]+)\](?::(\d*))?$/.exec(t);
  if (m) return m[2] && m[1].includes('%') ? null : withPort(normalizeIP(m[1]), m[2]);
  m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d*)$/.exec(t);
  if (m) return withPort(normalizeIP(m[1]), m[2]);
  m = /^([^/]+)\/(\d{1,3})$/.exec(t);
  if (m) {
    const ip = normalizeIP(m[1]);
    if (!ip) return null;
    return Number(m[2]) === (ip.includes(':') ? 128 : 32) ? { ip, port: null } : null;
  }
  return withPort(normalizeIP(t), '');
}

/**
 * An `ip:port` / `[ip]:port` token whose address is valid but whose port is not
 * (`203.0.113.10:99999`, `[2001:db8::1]:https`): the INVALID_IP it makes is about the port.
 */
function isBadPort(token) {
  const t = unwrap(token);
  const m = /^\[([^\]]+)\]:(.*)$/.exec(t) || /^(\d{1,3}(?:\.\d{1,3}){3}):(.*)$/.exec(t);
  return !!(m && normalizeIP(m[1]) && !parseIpToken(t));
}

/**
 * Why an address token is invalid, when the address itself is fine: 'zone' — an IPv6 zone id
 * with a port (`[fe80::1%eth0]:8443`); 'port' — a port that is not 1–65535 ({@link isBadPort}).
 * The CLI (`split_endpoint`) refuses both. undefined for any other token.
 * @param {string} token
 * @returns {'zone'|'port'|undefined}
 */
function invalidReason(token) {
  const t = unwrap(token);
  const m = /^\[([^\]]+)\]:(\d+)$/.exec(t);
  if (m && m[1].includes('%') && normalizeIP(m[1])) return 'zone';
  return isBadPort(t) ? 'port' : undefined;
}

/**
 * The host of an Ansible host pattern written with its SSH port (`192.0.2.50:2222`,
 * `[2001:db8::1]:2222`, `badwolf.example.com:5309`), or null: no port, or one that is not
 * 1–65535 (then the token is invalid as any other).
 * @param {string} token
 * @returns {string|null}
 */
function sshHostOf(token) {
  const hit = parseIpToken(token);
  if (hit) return hit.port === null ? null : hit.ip;
  if (!HOST_PORT_RE.test(token)) return null;
  const at = token.lastIndexOf(':');
  const port = Number(token.slice(at + 1));
  return port >= 1 && port <= 65535 ? token.slice(0, at) : null;
}

/** {@link parseIpToken} without the port: the canonical IP or null. */
function cleanIpToken(token) {
  const hit = parseIpToken(token);
  return hit ? hit.ip : null;
}

/**
 * Token that is *meant* to be an IP but is not valid (10.0.0.256, 1::2::3, a CIDR, a port
 * outside 1–65535 or not a number: 10.0.0.1:99999, [2001:db8::1]:https, a bracketed address
 * with a zone id and a port or with text after it that is no port: [2001:db8::1]8443…).
 */
function looksLikeIp(token) {
  if (BRACKETED_ADDRESS_RE.test(unwrap(token))) return true;
  let t = unwrap(token).replace(/\/\d{1,3}(?::[^/]*)?$/, '');
  t = t.replace(/^\[/, '').replace(/\](?::.*)?$/, '');
  if (t.endsWith('.') && !t.includes(':')) t = t.slice(0, -1);
  if (/^\d+\.\d+\.\d+\.\d+(?::.*)?$/.test(t)) return true;
  const colons = (t.match(/:/g) || []).length;
  return colons >= 2
    && /^[0-9a-f:.%]+$/i.test(t)
    && /[0-9a-f]/i.test(t)
    && !/^\d{1,2}:\d{2}(?::\d{2})?$/.test(t); // clock times
}

/** A token that starts as a bracketed address (the CLI's `_BRACKETED_ADDRESS_RE`). */
const BRACKETED_ADDRESS_RE = /^\[(?:[0-9a-f.]*:[0-9a-f:.]*|\d{1,3}(?:\.\d{1,3}){3})(?:%[^\]\s]*)?\]/i;

const NAME_TOKEN_RE = /^[\p{L}\p{N}_](?:[\p{L}\p{N}_.-]*[\p{L}\p{N}_])?$/u;
const ANSIBLE_RANGE_RE = /^[\p{L}\p{N}_.-]*\[[^\]\s]+:[^\]\s]+\][\p{L}\p{N}_.-]*$/u;
const PLAIN_WORD_RE = /^\p{L}+$/u;
/**
 * A host name with a port (`web01.example.net:8443`): the CLI resolves it and scans that port,
 * but servers here are matched by address only, so it is a PARSE warning, never dropped
 * silently. The host part has a letter, so a clock time (`10:30`) is none.
 */
const HOST_PORT_RE = /^(?=[^:]*\p{L})[\p{L}\p{N}_][\p{L}\p{N}_.-]*:\d{1,5}$/u;

function isNameToken(t) {
  if (!t || t.length > 253) return false;
  if (/^[\d.]+$/.test(t)) return false; // numbers / version-ish
  return NAME_TOKEN_RE.test(t) || ANSIBLE_RANGE_RE.test(t);
}

const isHostish = (t) => /[\d._-]/.test(t);

/** A dotted host name (`web01.example.net`), as the CLI resolves the value of `NAME=HOST`. */
const isDottedHost = (t) => t.includes('.') && /\p{L}/u.test(t) && isNameToken(t) && !looksLikeIp(t);

/** Header/key normalisation: camelCase split, Turkish folding, snake_case. */
function normalizeKey(key) {
  return String(key)
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/\u0131/g, 'i')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
}

const IP_KEY_EXCLUDE_RE = /(^|_)(mac|e?mail|eposta|url|uri|link|web|website|site|gateway|gw|netmask|mask|subnet|dns|ilo|idrac|ipmi|bmc|ntp)(_|$)/;
const IP_KEY_RE = /(^|_)(ip|ips|ip\d+|ipv4|ipv6|ipaddr|ipaddress|ipaddresses|addr|address|addresses|adres|adresi|adresleri|ansible_host|ansible_ssh_host)(_|$)/;

/** Column header / object key that holds server IPs. */
function isIpKey(normalized) {
  if (!normalized || IP_KEY_EXCLUDE_RE.test(normalized)) return false;
  return IP_KEY_RE.test(normalized);
}

const NAME_HEADERS = ['hostname', 'host_name', 'name', 'host', 'server', 'server_name', 'servername',
  'sunucu', 'sunucu_adi', 'sunucu_ismi', 'makine', 'makine_adi', 'host_adi', 'hostadi', 'node',
  'node_name', 'fqdn', 'instance_name', 'instance', 'vm', 'vm_name', 'computer_name', 'computername',
  'device', 'device_name', 'cihaz', 'cihaz_adi', 'ad', 'adi', 'isim', 'label', 'display_name',
  'tag_name', 'inventory_hostname', 'dns_name'];
const NAME_HEADER_RANK = new Map(NAME_HEADERS.map((h, i) => [h, i]));
const GROUP_HEADERS = new Set(['group', 'groups', 'grup', 'gruplar', 'role', 'roles', 'rol', 'env',
  'environment', 'ortam', 'tag', 'tags', 'etiket', 'etiketler', 'cluster', 'project', 'proje']);
const FIELD_LABELS = new Set(['name', 'host', 'hostname', 'ip', 'ips', 'ipv4', 'ipv6', 'address',
  'addr', 'server', 'sunucu', 'adres', 'group', 'grup']);

/* ------------------------------------------------------------------------ */
/* Topology keys (cli/ssl_origin_scan.py reads them alike)                  */
/* ------------------------------------------------------------------------ */

/** Topology keys, normalised; in JSON / YAML only `tls_ports` gives TLS ports (`ports` is Shodan's). */
export const TOPOLOGY_KEYS = Object.freeze(['ports', 'tls_ports', 'terminates_tls', 'vip', 'backends', 'nat']);
const TOPOLOGY_KEY_SET = new Set(TOPOLOGY_KEYS);

/** TOPOLOGY warning reasons: a malformed value of a key, then the other causes. */
export const TOPOLOGY_REASONS = Object.freeze(['ports', 'terminatesTls', 'vip', 'nat', 'backends', 'plainPorts',
  'unknownBackend', 'selfBackend', 'conflict', 'noServer', 'groupVars', 'noTermination', 'vipMixed', 'cycle',
  'ownedAddress', 'nearMiss']);
const MALFORMED_REASON = { ports: 'ports', tls_ports: 'ports', terminates_tls: 'terminatesTls', vip: 'vip', nat: 'nat', backends: 'backends' };
/** Ports that usually carry no TLS: kept in a ports= list, with a warning. */
const PLAIN_PORTS = new Set([20, 21, 22, 23, 25, 53, 80, 110, 119, 143, 389, 3306, 3389, 5432, 6379, 8080, 27017]);
const isPortsKey = (k) => k === 'ports' || k === 'tls_ports';
/** Keys a letter off one (on a line, a CSV header): warned about, not read. */
const NEAR_MISS = new Map(Object.entries({ backend: 'backends', port: 'ports', tls_port: 'tls_ports', vips: 'vip',
  nats: 'nat', terminate_tls: 'terminates_tls', terminatestls: 'terminates_tls', terminates_ssl: 'terminates_tls',
  terminate_ssl: 'terminates_tls' }));

const TLS_YES = new Set(['yes', 'true', 'on', '1']);
const TLS_NO = new Set(['no', 'false', 'off', '0']);

function topologyKey(key, structured = false) {
  const k = normalizeKey(key);
  return TOPOLOGY_KEY_SET.has(k) && !(structured && k === 'ports') ? k : null;
}

const unquote = (s) => String(s).trim().replace(/^(["'])(.*)\1$/s, '$2').trim();

/** A value's items, null for an object; a line's split on spaces , ; |, a `structured` one on , ; only. */
function topologyItems(value, structured = false) {
  if (value === null || value === undefined) return [];
  if (typeof value === 'string') return unquote(value).split(structured ? /[,;]+/ : /[\s,;|]+/).map((v) => unquote(v)).filter(Boolean);
  if (typeof value === 'number') return [String(value)];
  if (typeof value === 'boolean') return [value ? 'yes' : 'no'];
  if (!Array.isArray(value)) return null;
  const out = [];
  for (const v of value) {
    if (v !== null && typeof v === 'object') return null;
    out.push(...topologyItems(v, structured));
  }
  return out;
}

/** A bare address (a /32 or /128 too), never one with a port. */
function topologyAddress(item) {
  if (/^\d{1,3}(?:\.\d{1,3}){3}:|\]:/.test(item)) return null;
  const hit = parseIpToken(item);
  return hit && hit.port === null ? hit.ip : null;
}

/** The value of `key` from its items; undefined when malformed. */
function topologyValue(key, items) {
  if (!items.length) return undefined;
  if (key === 'terminates_tls') {
    const v = items.length === 1 ? items[0].toLowerCase() : '';
    return TLS_YES.has(v) ? true : TLS_NO.has(v) ? false : undefined;
  }
  const out = [];
  for (const item of items) {
    let v;
    if (isPortsKey(key)) {
      v = /^\d+$/.test(item) ? Number(item) : 0;
      if (!(v >= 1 && v <= 65535)) return undefined;
    } else if (key === 'vip' || key === 'nat') {
      v = topologyAddress(item);
      if (!v) return undefined;
    } else {
      v = topologyAddress(item);
      if (!v && (looksLikeIp(item) || isBadPort(item))) return undefined;
      v = v || item;
    }
    if (!out.some((x) => String(x).toLowerCase() === String(v).toLowerCase())) out.push(v);
  }
  return out;
}

/** One key read: `{ key, value, raw, line }`, or null after a warning. */
function readTopology(ctx, key, items, raw, line) {
  const value = topologyValue(key, items);
  if (value === undefined) {
    ctx.warn(line, 'TOPOLOGY', undefined, `${key}=${raw}`, MALFORMED_REASON[key]);
    return null;
  }
  if (isPortsKey(key) && value.some((p) => PLAIN_PORTS.has(p))) ctx.warn(line, 'TOPOLOGY', undefined, `${key}=${raw}`, 'plainPorts');
  return { key, value, raw, line };
}

/** `key=value` on a line: a ; or | continues the value unless a key= follows. */
const TOPOLOGY_TOKEN_RE = /(^|[\s,;|])([A-Za-z][A-Za-z0-9_.-]*)=("[^"]*"|'[^']*'|(?:[^\s;|"']|[;|](?![A-Za-z][A-Za-z0-9_.-]*=)(?=[^\s;|"']))*)/g;

/** A line's topology tokens taken out (their values hold commas): `{ rest, found, near }`. */
function splitTopology(line) {
  const found = [];
  const near = [];
  const rest = line.replace(TOPOLOGY_TOKEN_RE, (all, sep, key, value) => {
    const k = topologyKey(key);
    const m = !k && NEAR_MISS.get(normalizeKey(key));
    if (m) near.push(`${key}=${unquote(value)} (${m}=?)`);
    if (!k) return all;
    found.push({ key: k, raw: value });
    return `${sep} `;
  });
  return { rest: found.length ? rest : line, found, near };
}

function lineTopology(ctx, found, line, structured = false) {
  const out = [];
  for (const { key, raw } of found) {
    const t = readTopology(ctx, key, topologyItems(raw, structured), unquote(raw), line);
    if (t) out.push(t);
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Collector: entries → merged servers                                     */
/* ------------------------------------------------------------------------ */

function createCollector(text, lines) {
  const entries = [];
  const warnings = [];
  /** @type {Map<string, { hosts: Set<string>, children: Set<string> }>} */
  const groupDefs = new Map();
  let lineStarts = null;
  let from = 0;

  const lineText = (n) => (n >= 1 && n <= lines.length ? lines[n - 1].trim().slice(0, 200) : '');

  return {
    lines,
    get warned() {
      return warnings.length;
    },
    warn(line, code, textOverride, detail, reason) {
      const w = { line, code, text: textOverride !== undefined ? String(textOverride).slice(0, 200) : lineText(line) };
      if (detail !== undefined) w.detail = String(detail).slice(0, 200);
      if (reason) w.reason = reason;
      warnings.push(w);
    },
    lineText,
    /** Approximate 1-based line of `needle`, searched from the last hit (records come in order: a parse stays linear), else from the top. */
    lineOf(needle) {
      if (!needle) return 1;
      let idx = text.indexOf(needle, from);
      if (idx === -1) idx = text.indexOf(needle);
      if (idx === -1) return 1;
      from = idx;
      if (!lineStarts) {
        lineStarts = [0];
        for (let i = 0; i < text.length; i += 1) if (text[i] === '\n') lineStarts.push(i + 1);
      }
      let lo = 0;
      let hi = lineStarts.length - 1;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (lineStarts[mid] <= idx) lo = mid;
        else hi = mid - 1;
      }
      return lo + 1;
    },
    defineGroup(name) {
      if (!groupDefs.has(name)) groupDefs.set(name, { hosts: new Set(), children: new Set() });
      return groupDefs.get(name);
    },
    /**
     * @param {{ name: string|null, ips: string[], ports?: Object<string, Array<number|null>>,
     *   groups?: string[], aliases?: string[], line: number, quiet?: boolean, topology?: object[] }} e
     *   ports: {@link portsOf}; quiet: never emit NO_IP for this entry alone.
     */
    add(e) {
      const all = e.ips || [];
      const ips = all.filter((ip) => !isNonHostIP(ip));
      if (all.length > 0 && ips.length === 0) return; // loopback/boilerplate only
      entries.push({
        name: e.name ? String(e.name).trim().replace(/\.$/, '') || null : null,
        ips,
        ports: e.ports || {},
        groups: (e.groups || []).filter(Boolean),
        aliases: (e.aliases || []).filter(Boolean),
        line: e.line || 1,
        quiet: !!e.quiet,
        topology: e.topology || []
      });
    },
    finalize(lineCount) {
      return finalizeServers(entries, warnings, groupDefs, lineCount, lineText, this);
    }
  };
}

/** Transitive group membership from Ansible-style definitions. */
function groupMembership(groupDefs) {
  const parents = new Map(); // child group → Set(parent groups)
  for (const [g, def] of groupDefs) {
    for (const c of def.children) {
      if (!parents.has(c)) parents.set(c, new Set());
      parents.get(c).add(g);
    }
  }
  const expand = (groups) => {
    const out = new Set();
    const queue = [...groups];
    while (queue.length) {
      const g = queue.shift();
      if (out.has(g)) continue;
      out.add(g);
      for (const p of parents.get(g) || []) queue.push(p);
    }
    for (const g of IGNORED_GROUPS) out.delete(g);
    return [...out];
  };
  const direct = new Map(); // host(lower) → Set(groups)
  for (const [g, def] of groupDefs) {
    for (const h of def.hosts) {
      const key = String(h).toLowerCase();
      if (!direct.has(key)) direct.set(key, new Set());
      direct.get(key).add(g);
    }
  }
  return { expand, direct };
}

/**
 * `{ ip: ports }` for the addresses of `eps` written with a port at least once, in the order
 * seen; `null` in a list: the same address also appeared without a port (the CLI's `-p`).
 * @param {Array<{ ip: string, port?: number|null }>} eps
 * @returns {Object<string, Array<number|null>>}
 */
function portsOf(eps) {
  const explicit = new Set(eps.filter((e) => Number.isInteger(e.port)).map((e) => e.ip));
  const out = {};
  for (const e of eps) {
    if (!explicit.has(e.ip)) continue;
    const spec = out[e.ip] || (out[e.ip] = []);
    const port = Number.isInteger(e.port) ? e.port : null;
    if (!spec.includes(port)) spec.push(port);
  }
  return out;
}

/**
 * Add address `ip` on `port` (null: the `-p` ports) to a server draft, merging like the CLI's
 * `Server.add_ip`: an address first given bare and later with a port gets both.
 */
function addAddress(d, ip, port) {
  if (!d.ips.includes(ip)) {
    d.ips.push(ip);
    if (port !== null) d.ports[ip] = [port];
    return;
  }
  const spec = d.ports[ip];
  if (!spec) {
    if (port !== null) d.ports[ip] = [null, port];
  } else if (!spec.includes(port)) {
    spec.push(port);
  }
}

/** The port list of `ip` in an entry: its own ports, or `[null]` (the `-p` ports). */
const entryPorts = (e, ip) => (e.ports && e.ports[ip] ? e.ports[ip] : [null]);

const emptyTopology = () => ({ tlsPorts: [], terminatesTls: undefined, vips: [], nats: [], backendRefs: [] });

/** Merge an entry's topology into a draft; terminates_tls both ways: a 'conflict', yes kept. */
function mergeTopology(d, list, ctx) {
  const push = (arr, values) => {
    for (const v of values) if (!arr.includes(v)) arr.push(v);
  };
  for (const t of list || []) {
    if (isPortsKey(t.key)) push(d.topo.tlsPorts, t.value);
    else if (t.key === 'vip') push(d.topo.vips, t.value);
    else if (t.key === 'nat') push(d.topo.nats, t.value);
    else if (t.key === 'backends') for (const ref of t.value) d.topo.backendRefs.push({ ref, line: t.line });
    else if (t.key === 'terminates_tls') {
      if (d.topo.terminatesTls !== undefined && d.topo.terminatesTls !== t.value) {
        ctx.warn(t.line, 'TOPOLOGY', undefined, `terminates_tls=${t.raw}`, 'conflict');
        d.topo.terminatesTls = true;
      } else d.topo.terminatesTls = t.value;
    }
  }
}

/** `backends=` resolved to server names: by name, else by address. */
function linkBackends(drafts, ctx) {
  const byName = new Map(drafts.map((d) => [d.name.toLowerCase(), d]));
  for (const d of drafts) {
    const out = [];
    for (const { ref, line } of d.topo.backendRefs) {
      const named = byName.get(String(ref).toLowerCase());
      const ip = named ? null : normalizeIP(ref);
      const targets = named ? [named] : ip ? drafts.filter((x) => x.ips.includes(ip)) : [];
      if (!targets.length) {
        ctx.warn(line, 'TOPOLOGY', undefined, ref, 'unknownBackend');
        continue;
      }
      for (const target of targets) {
        if (target === d) ctx.warn(line, 'TOPOLOGY', undefined, ref, 'selfBackend');
        else if (!out.includes(target.name)) out.push(target.name);
      }
    }
    d.topo.backends = out;
  }
}

/** Checks over the linked inventory, as the CLI's topology_checks. */
function topologyChecks(drafts, ctx) {
  const byName = new Map(drafts.map((d) => [d.name, d]));
  const plain = (d) => d.topo.terminatesTls === false;
  for (const d of drafts) {
    if (!plain(d) || !d.topo.backends.length) continue;
    const seen = new Set([d]);
    const queue = [d];
    let ends = false;
    while (queue.length && !ends) {
      for (const b of queue.shift().topo.backends.map((n) => byName.get(n))) {
        if (!b || seen.has(b)) continue;
        seen.add(b);
        if (plain(b)) queue.push(b);
        else ends = true;
      }
    }
    if (!ends) ctx.warn(d.line, 'TOPOLOGY', undefined, d.name, 'noTermination');
  }
  const holders = new Map();
  for (const d of drafts) for (const ip of d.topo.vips) holders.set(ip, [...(holders.get(ip) || []), d]);
  for (const [ip, list] of holders) {
    const off = list.filter(plain);
    if (off.length && off.length < list.length) ctx.warn(off[0].line, 'TOPOLOGY', undefined, `vip=${ip}`, 'vipMixed');
  }
  const own = new Map();
  for (const d of drafts) {
    for (const ip of d.ips) if (!own.has(ip)) own.set(ip, d.name);
    const prev = new Map();
    const queue = [d.name];
    while (queue.length && !prev.has(d.name)) {
      const n = queue.shift();
      for (const b of byName.get(n)?.topo.backends || []) {
        if (!prev.has(b)) {
          prev.set(b, n);
          queue.push(b);
        }
      }
    }
    if (!prev.has(d.name)) continue;
    const loop = [d.name];
    for (let n = prev.get(d.name); n !== d.name; n = prev.get(n)) loop.unshift(n);
    ctx.warn(d.line, 'TOPOLOGY', undefined, [d.name, ...loop].join(' → '), 'cycle');
  }
  for (const d of drafts) {
    for (const [k, ips] of [['vip', d.topo.vips], ['nat', d.topo.nats]]) {
      for (const ip of ips) if (own.has(ip)) ctx.warn(d.line, 'TOPOLOGY', undefined, `${k}=${ip} (${own.get(ip)})`, 'ownedAddress');
    }
  }
}

function finalizeServers(entries, warnings, groupDefs, lineCount, lineText, ctx) {
  const byName = new Map(); // lower name → server draft
  const drafts = [];

  const draftFor = (key, name, line) => {
    let d = byName.get(key);
    if (!d) {
      d = { name, ips: [], ports: {}, groups: [], aliases: [], line, loud: false, named: true, topo: emptyTopology() };
      byName.set(key, d);
      drafts.push(d);
    }
    return d;
  };
  const push = (arr, values) => {
    for (const v of values) if (!arr.includes(v)) arr.push(v);
  };

  // 1) Named entries merge by case-insensitive name.
  for (const e of entries) {
    if (!e.name) continue;
    const d = draftFor(e.name.toLowerCase(), e.name, e.line);
    for (const ip of e.ips) for (const port of entryPorts(e, ip)) addAddress(d, ip, port);
    push(d.groups, e.groups);
    push(d.aliases, e.aliases.filter((a) => a.toLowerCase() !== d.name.toLowerCase()));
    mergeTopology(d, e.topology, ctx);
    if (!e.quiet) d.loud = true;
  }

  // 2) Unnamed entries: drop IPs already owned by a named server, merge by first IP. The
  //    ports they were written with (bare = the -p ports) go to that server, so targets.txt
  //    still scans every ip:port the CLI would scan reading this inventory itself.
  const namedIps = new Map();
  for (const d of drafts) for (const ip of d.ips) namedIps.set(ip, [...(namedIps.get(ip) || []), d]);
  const byIp = new Map();
  for (const e of entries) {
    if (e.name) continue;
    const owners = new Set();
    for (const ip of e.ips) {
      for (const owner of namedIps.get(ip) || []) {
        for (const port of entryPorts(e, ip)) addAddress(owner, ip, port);
        owners.add(owner);
      }
    }
    for (const owner of owners) mergeTopology(owner, e.topology, ctx);
    const ips = e.ips.filter((ip) => !namedIps.has(ip));
    if (ips.length === 0) {
      if (e.ips.length === 0 && !e.quiet) ctx.warn(e.line, 'NO_IP');
      continue;
    }
    let d = byIp.get(ips[0]);
    if (!d) {
      d = { name: ips[0], ips: [], ports: {}, groups: [], aliases: [], line: e.line, loud: true, named: false, topo: emptyTopology() };
      byIp.set(ips[0], d);
      drafts.push(d);
    }
    for (const ip of ips) for (const port of entryPorts(e, ip)) addAddress(d, ip, port);
    push(d.groups, e.groups);
    mergeTopology(d, e.topology, ctx);
  }

  // 3) Ansible group definitions (names and IPs as hosts), incl. parent groups.
  const { expand, direct } = groupMembership(groupDefs);
  for (const d of drafts) {
    const own = new Set(d.groups);
    for (const key of [d.name.toLowerCase(), ...d.aliases.map((a) => a.toLowerCase()), ...d.ips]) {
      for (const g of direct.get(key) || []) own.add(g);
    }
    d.groups = expand(own);
  }

  // 4) Servers without IPs → NO_IP (unless only referenced quietly).
  linkBackends(drafts, ctx);
  topologyChecks(drafts, ctx);
  const servers = [];
  for (const d of drafts) {
    if (d.ips.length === 0) {
      if (d.loud) ctx.warn(d.line, 'NO_IP', undefined, d.name);
      continue;
    }
    const server = { id: d.name, name: d.name, ips: d.ips, groups: d.groups, line: d.line, aliases: d.aliases };
    if (Object.keys(d.ports).length) server.ports = d.ports;
    if (d.topo.tlsPorts.length) server.tlsPorts = d.topo.tlsPorts;
    if (d.topo.terminatesTls !== undefined) server.terminatesTls = d.topo.terminatesTls;
    if (d.topo.vips.length) server.vips = d.topo.vips;
    if (d.topo.nats.length) server.nats = d.topo.nats;
    if (d.topo.backends.length) server.backends = d.topo.backends;
    servers.push(server);
  }

  // Hosts named in group definitions that never got a server (e.g. ansible_host is a DNS name).
  const known = new Set(drafts.map((d) => d.name.toLowerCase()));
  for (const [, def] of groupDefs) {
    for (const h of def.hosts) {
      const key = String(h).toLowerCase();
      if (known.has(key) || normalizeIP(h)) continue;
      known.add(key);
      const line = ctx.lineOf(h);
      ctx.warn(line, 'NO_IP', undefined, h);
    }
  }

  // 5) The same endpoint on several distinct servers (VIPs, copy-paste errors): an address on
  //    its own port, or bare (the CLI's -p ports). One address on different ports (a NAT
  //    forwarding each port to another machine) is no duplicate, as in the CLI.
  const owners = new Map(); // endpoint → its servers, in order
  const uniqueIps = new Set();
  for (const s of servers) {
    for (const ip of s.ips) {
      uniqueIps.add(ip);
      for (const endpoint of addressTargets(s, ip)) {
        if (!owners.has(endpoint)) owners.set(endpoint, []);
        owners.get(endpoint).push(s);
      }
    }
  }
  for (const s of servers) {
    for (const ip of s.ips) {
      // One warning per server and address: its first endpoint an earlier server has too.
      const endpoint = addressTargets(s, ip).find((e) => owners.get(e)[0] !== s);
      if (!endpoint) continue;
      warnings.push({
        line: s.line, code: 'DUPLICATE_IP', text: lineText(s.line),
        detail: `${endpoint} (${owners.get(endpoint).map((x) => x.name).join(', ')})`
      });
    }
  }

  warnings.sort((a, b) => a.line - b.line);
  return {
    servers,
    warnings,
    stats: { lines: lineCount, servers: servers.length, ips: uniqueIps.size }
  };
}

/* ------------------------------------------------------------------------ */
/* Structured data (JSON / YAML)                                            */
/* ------------------------------------------------------------------------ */

const NAME_KEYS = ['name', 'Name', 'hostname', 'host_name', 'hostName', 'HostName', 'inventory_hostname',
  'fqdn', 'server', 'server_name', 'serverName', 'instance_name', 'instanceName', 'display_name',
  'displayName', 'computer_name', 'computerName', 'vm_name', 'vmName', 'label', 'host'];
// Identifiers: used only when no real name (incl. tags.Name) exists.
const ID_KEYS = ['InstanceId', 'instance_id', 'instanceId', 'id'];
const NAME_KEY_SET = new Set([...NAME_KEYS, ...ID_KEYS]);

const STRUCTURAL_KEYS = new Set(['value', 'values', 'hosts', 'children', 'vars', 'hostvars', '_meta', 'all',
  'ungrouped', 'items', 'data', 'result', 'results', 'resources', 'resource', 'instances', 'attributes',
  'outputs', 'output', 'servers', 'nodes', 'machines', 'vms', 'droplets', 'reservations', 'list',
  'records', 'rows', 'entries', 'members', 'targets', 'inventory', 'spec', 'status', 'properties',
  'config', 'metadata', 'modules', 'module', 'objects', 'response', 'body', 'payload']);

// Keys whose (nested) IPs belong to the enclosing machine.
const IP_FIELD_KEY_RE = /(^|_)(ip|ips|ip\d+|ipv4|ipv6|addr|address|addresses|adres|host|ansible_host|ansible_ssh_host|public|private|nat|external|internal|v4|v6|network|networks|interface|interfaces|nic|nics|eth\d*|access_config|association|endpoint|endpoints)(_|$)/;

function validName(v) {
  if (typeof v !== 'string') return null;
  const s = v.trim();
  if (!s || s.length > 253 || /[\r\n]/.test(s) || cleanIpToken(s) || invalidReason(s)) return null;
  return s;
}

function pickName(obj) {
  for (const key of NAME_KEYS) {
    if (!(key in obj)) continue;
    const v = validName(obj[key]);
    if (v) return v;
  }
  const tags = obj.tags ?? obj.Tags ?? obj.labels;
  if (tags && typeof tags === 'object') {
    if (Array.isArray(tags)) {
      const t = tags.find((x) => x && typeof x === 'object' && /^name$/i.test(String(x.Key ?? x.key ?? '')));
      const v = t ? validName(t.Value ?? t.value) : null;
      if (v) return v;
    } else {
      const v = validName(tags.Name ?? tags.name);
      if (v) return v;
    }
  }
  const meta = obj.metadata;
  if (meta && typeof meta === 'object' && !Array.isArray(meta)) {
    const v = validName(meta.name);
    if (v) return v;
  }
  for (const key of ID_KEYS) {
    if (!(key in obj)) continue;
    const v = validName(obj[key]);
    if (v && v.length <= 64 && !/^\d+$/.test(v)) return v;
  }
  return null;
}

function isTerraformOutput(v) {
  if (!v || typeof v !== 'object' || Array.isArray(v) || !('value' in v)) return false;
  return Object.keys(v).every((k) => k === 'value' || k === 'type' || k === 'sensitive');
}

// Network, management and version attributes of a machine record: never its own
// address, never another server's name (cf. the CLI's _JSON_SKIP_KEY_RE). Unlike
// IP_KEY_EXCLUDE_RE it spares web / site / url / link, common group and output names.
const RECORD_ATTR_EXCLUDE_RE = /(^|_)(gateway|gw|netmask|mask|subnet|broadcast|cidr|routes?|dns|nameservers?|resolvers?|ntp|mac|ilo|idrac|ipmi|bmc|version|ver)(_|$)/;

/**
 * A key holding the enclosing machine's own address: `ip`, `ips`, `address`,
 * `ansible_host`, `public_ip`… or a name key holding an IP. Deliberately not the
 * broad IP_FIELD_KEY_RE (host / public / internal / endpoint…), which host names
 * such as docker-host-1, public-lb or vpn-endpoint also match.
 */
function isAddressKey(key) {
  return NAME_KEY_SET.has(key) || isIpKey(normalizeKey(key));
}

/** A key shaped like a host name (dns-1, mail-gw, ntp.example.com), not like a variable. */
const isHostLikeKey = (key) => /[-.]/.test(key);

function keyKind(key, value) {
  if (isTerraformOutput(value)) return 'name';
  if (NAME_KEY_SET.has(key)) return 'field'; // { name: '10.0.0.1' }: an unnamed server's IP, not a server "name"
  if (STRUCTURAL_KEYS.has(String(key).toLowerCase())) return 'structural';
  const nk = normalizeKey(key);
  if (!IP_KEY_EXCLUDE_RE.test(nk) && IP_FIELD_KEY_RE.test(nk)) return 'field';
  if (/^\d+$/.test(key)) return 'structural'; // array-like object
  return isNameToken(String(key)) ? 'name' : 'field';
}

const NO_HOSTS = new Set();

/**
 * May a host name with a port found under `key` stay a warning? Only where the CLI reads a
 * target (its `_json_host_values` and name-map entries): `ansible_host` / `ansible_ssh_host`,
 * or a name map's entry (`{ web01: "web01.example.net:8443" }`, a Terraform output) outside any
 * record or vars map. Every record and vars map on the way up drops it otherwise, so
 * `consul_addr`, `db_url`, a Terraform `endpoint` or a `health_url` never warn.
 */
function keepsHostPort(key, kind, record) {
  if (key === 'ansible_host' || key === 'ansible_ssh_host') return true;
  return !record && kind !== 'field';
}

/** `groups` without the host-name-with-a-port items, and without groups left empty. */
function withoutHostPort(groups) {
  if (!groups.some((g) => g.some((i) => i.bad === 'hostPort'))) return groups;
  return groups.map((g) => g.filter((i) => i.bad !== 'hostPort')).filter((g) => g.length);
}

/**
 * Walk a JSON/YAML value. Named objects claim every IP below them; unnamed
 * objects pass their IPs up (one group per object); keys that look like
 * names (terraform outputs, `{ web01: {...} }` maps) name what is below.
 * A listed Ansible host always names what is below it. In a machine record
 * (named, holding an address key, or an Ansible vars map) gateway / DNS / NTP /
 * iLO / version attributes are skipped.
 * Returns groups of { ip, raw } not claimed by any name.
 * A machine record's topology key is an item `{ topo, items, raw }` (in a group's vars: a warning).
 * @param {Set<string>} [hosts] host names listed in Ansible groups or `_meta.hostvars`
 * @param {boolean} [isVars] `node` is a vars map: one of those hosts' (hostvars) or a group's `vars`
 * @param {boolean} [groupVars] `node` is a group's `vars` map
 */
function visitStructured(node, depth, found, hosts = NO_HOSTS, isVars = false, groupVars = false) {
  if (depth > MAX_DEPTH || node === null || node === undefined) return [];
  if (typeof node === 'string') {
    const items = [];
    const parts = node.length <= 200 ? node.split(/[\s,;]+/) : [];
    for (const part of parts) {
      const hit = parseIpToken(part);
      const bad = hit ? null : invalidReason(part);
      if (hit) items.push({ ip: hit.ip, port: hit.port, raw: part });
      else if (bad) items.push({ bad, raw: part }); // 203.0.113.10:99999: a warning, never dropped silently
    }
    // A whole value that is a host name with a port ("web01": "web01.example.net:8443"), as a
    // line has it: the CLI resolves it, here it is a warning. Dotted only: "image": "redis:7" is none.
    // Kept only where a target is read (keepsHostPort): a record's other attributes and vars
    // (consul_addr, db_url, a Terraform endpoint) are not targets, in the CLI either.
    const words = parts.filter(Boolean);
    const value = words.length === 1 ? words[0] : '';
    if (!items.length && HOST_PORT_RE.test(value) && isDottedHost(value.slice(0, value.lastIndexOf(':')))) {
      items.push({ bad: 'hostPort', raw: value });
    }
    return items.length ? [items] : [];
  }
  if (Array.isArray(node)) {
    const out = [];
    for (const el of node) out.push(...visitStructured(el, depth + 1, found, hosts));
    return out;
  }
  if (typeof node !== 'object') return [];

  const name = pickName(node);
  // Visit every value first (what it names goes to `sub`): whether this is a
  // machine record, and so which keys are attributes, depends on all of them.
  const entries = [];
  const visit = (key, value) => {
    // A listed host (a `hosts:` / hostvars map, a plain YAML host map), however
    // it is named; a machine's own variables are never hosts.
    const host = !name && !isVars && hosts.has(key) && isNameToken(String(key));
    const kind = host ? 'name' : keyKind(key, value);
    const sub = [];
    const inVars = host || key === 'vars';
    const groups = visitStructured(value, depth + 1, sub, hosts, inVars, key === 'vars' && !host);
    return { key, kind, host, groups, sub };
  };
  const topology = [];
  for (const [key, value] of Object.entries(node)) {
    if (NAME_KEY_SET.has(key) && validName(value)) continue; // the name itself
    const tk = topologyKey(key, true);
    const items = tk ? topologyItems(value, true) : null;
    if (items) topology.push({ key, value, item: { topo: tk, items, raw: Array.isArray(value) ? value.join(',') : String(value ?? '') } });
    else entries.push(visit(key, value));
  }
  const strong = !!name || isVars;
  const record = strong || entries.some((e) => e.kind === 'field' && e.groups.length && isAddressKey(e.key));
  const own = [];
  const pass = [];
  for (const t of topology) {
    if (!record) entries.push(visit(t.key, t.value));
    else own.push(groupVars ? { bad: 'groupVars', raw: t.item.topo } : t.item);
  }
  for (const { key, kind, host, groups: all, sub } of entries) {
    const groups = keepsHostPort(key, kind, record) ? all : withoutHostPort(all);
    // gateway, dns, ntp, iLO, version… A record known only by its address key
    // may still be a name map ({ ip-10-0-0-1: …, dns-1: … }): there a key shaped
    // like a host name stays.
    if (record && !host && RECORD_ATTR_EXCLUDE_RE.test(normalizeKey(key)) && (strong || !isHostLikeKey(key))) continue;
    for (const f of sub) found.push(f); // not a spread: one key may hold 100k+ records
    if (groups.length === 0) continue;
    if (name) {
      own.push(...groups.flat());
      continue;
    }
    if (kind === 'field') own.push(...groups.flat());
    else if (kind === 'structural') pass.push(...groups);
    else found.push({ name: key, items: groups.flat() });
  }
  if (name) {
    if (own.length) found.push({ name, items: own });
    return [];
  }
  if (own.length) pass.push(own);
  return pass;
}

/**
 * Collect Ansible group definitions ({group: {hosts, children, vars}}).
 * @returns {Set<string>} every host listed under a group's `hosts` or in `_meta.hostvars`
 */
function collectGroupDefs(root, ctx) {
  const listed = new Set();
  if (!root || typeof root !== 'object' || Array.isArray(root)) return listed;
  const seen = new Set();
  const scan = (name, obj, depth) => {
    if (depth > MAX_DEPTH) return;
    const def = ctx.defineGroup(name);
    if (!obj || typeof obj !== 'object' || seen.has(obj)) return;
    seen.add(obj);
    const { hosts, children } = obj;
    if (Array.isArray(hosts)) {
      for (const h of hosts) if (typeof h === 'string' && h.trim()) def.hosts.add(h.trim());
    } else if (hosts && typeof hosts === 'object') {
      for (const h of Object.keys(hosts)) def.hosts.add(h);
    }
    for (const h of def.hosts) listed.add(h);
    if (Array.isArray(children)) {
      for (const c of children) {
        if (typeof c !== 'string') continue;
        def.children.add(c);
        ctx.defineGroup(c);
      }
    } else if (children && typeof children === 'object') {
      for (const [c, v] of Object.entries(children)) {
        def.children.add(c);
        scan(c, v, depth + 1);
      }
    }
  };
  for (const [key, value] of Object.entries(root)) {
    if (key === '_meta') continue;
    if (value && typeof value === 'object' && !Array.isArray(value)
      && ('hosts' in value || 'children' in value)) {
      scan(key, value, 0);
    }
  }
  // `ansible-inventory --list`: every host has an entry here, grouped or not.
  const hostvars = root._meta && root._meta.hostvars;
  if (hostvars && typeof hostvars === 'object' && !Array.isArray(hostvars)) {
    for (const h of Object.keys(hostvars)) listed.add(h);
  }
  return listed;
}

function extractStructured(root, ctx, fixedLine = null) {
  const hosts = collectGroupDefs(root, ctx);
  const found = [];
  const leftovers = visitStructured(root, 0, found, hosts);
  for (const items of leftovers) found.push({ name: null, items });
  for (const f of found) {
    // Values that cannot be used ({ bad, raw }): an INVALID_IP for a bad port or a zone id, a
    // PARSE for a host name with a port, as on a line (the CLI warns about the first two too).
    const good = f.items.filter((i) => i.ip);
    const bad = f.items.filter((i) => i.bad);
    for (const b of bad) {
      const code = b.bad === 'hostPort' ? 'PARSE' : b.bad === 'groupVars' ? 'TOPOLOGY' : 'INVALID_IP';
      ctx.warn(fixedLine ?? ctx.lineOf(b.raw), code, undefined, b.raw, b.bad);
    }
    const line = fixedLine ?? ctx.lineOf((good[0] || f.items[0])?.raw);
    const topology = [];
    for (const i of f.items) {
      if (!i.topo) continue;
      const t = readTopology(ctx, i.topo, i.items, i.raw, line);
      if (t) topology.push(t);
    }
    if (!good.length) {
      // A named server keeps its groups; a mistyped address is not warned about twice (NO_IP).
      if (f.name) ctx.add({ name: f.name, ips: [], line, quiet: bad.some((b) => b.bad !== 'hostPort'), topology });
      else if (f.items.some((i) => i.topo)) ctx.warn(line, 'TOPOLOGY', undefined, f.items.find((i) => i.topo).topo, 'noServer');
      continue;
    }
    ctx.add({ name: f.name, ips: [...new Set(good.map((i) => i.ip))], ports: portsOf(good), line, topology });
  }
}

function tryJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/* ------------------------------------------------------------------------ */
/* Minimal YAML subset                                                      */
/* ------------------------------------------------------------------------ */

const YAML_KEY_LINE_RE = /^("[^"]*"|'[^']*'|[^\s"'#\-[{][^#]*?|-[^\s][^#]*?):(\s|$)/;

function looksLikeYaml(lines) {
  let meaningful = 0;
  let nested = 0;
  for (const raw of lines) {
    const t = raw.trim();
    if (!t || t.startsWith('#') || t === '---' || t === '...') continue;
    meaningful += 1;
    if (/^\[[^\]]*\]$/.test(t) && !normalizeIP(t)) return false; // INI header
    const indented = /^\s/.test(raw);
    if (/^-(\s|$)/.test(t) || YAML_KEY_LINE_RE.test(t)) {
      if (indented) nested += 1;
      continue;
    }
    if (indented) continue; // block-scalar continuation
    return false;
  }
  return meaningful > 0 && nested > 0;
}

function stripYamlComment(s) {
  let quote = null;
  for (let i = 0; i < s.length; i += 1) {
    const c = s[i];
    if (quote) {
      if (c === quote) quote = null;
    } else if (c === '"' || c === "'") {
      if (i === 0 || /[\s:[{,-]/.test(s[i - 1])) quote = c;
    } else if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) {
      return s.slice(0, i);
    }
  }
  return s;
}

function yamlScalar(raw) {
  const s = raw.trim();
  if (s === '' || s === '~' || s === 'null' || s === 'Null' || s === 'NULL') return null;
  if (s.length >= 2 && s[0] === '"' && s.endsWith('"')) {
    return s.slice(1, -1).replace(/\\(["\\/nrt])/g, (_, c) => ({ n: '\n', r: '\r', t: '\t' }[c] || c));
  }
  if (s.length >= 2 && s[0] === "'" && s.endsWith("'")) return s.slice(1, -1).replace(/''/g, "'");
  if (s.startsWith('[') && s.endsWith(']')) return splitFlow(s.slice(1, -1)).map(yamlScalar);
  if (s.startsWith('{') && s.endsWith('}')) {
    const obj = {};
    for (const part of splitFlow(s.slice(1, -1))) {
      const kv = splitYamlKey(part.trim());
      if (kv) obj[kv.key] = yamlScalar(kv.rest);
    }
    return obj;
  }
  return s;
}

function splitFlow(s) {
  const out = [];
  let depth = 0;
  let quote = null;
  let cur = '';
  for (const c of s) {
    if (quote) {
      if (c === quote) quote = null;
      cur += c;
    } else if (c === '"' || c === "'") {
      quote = c;
      cur += c;
    } else if (c === '[' || c === '{') {
      depth += 1;
      cur += c;
    } else if (c === ']' || c === '}') {
      depth -= 1;
      cur += c;
    } else if (c === ',' && depth === 0) {
      out.push(cur.trim());
      cur = '';
    } else {
      cur += c;
    }
  }
  if (cur.trim()) out.push(cur.trim());
  return out;
}

function splitYamlKey(text) {
  if (text[0] === '"' || text[0] === "'") {
    const end = text.indexOf(text[0], 1);
    if (end === -1) return null;
    const after = text.slice(end + 1);
    const m = /^\s*:(\s|$)/.exec(after);
    if (!m) return null;
    return { key: text.slice(1, end), rest: after.slice(m[0].length).trim() };
  }
  const m = /:(\s|$)/.exec(text);
  if (!m || m.index === 0) return null;
  return { key: text.slice(0, m.index).trim(), rest: text.slice(m.index + m[0].length).trim() };
}

const isSeqItem = (t) => t === '-' || t.startsWith('- ');

/** Parse indentation-based YAML (maps, sequences, scalars, flow collections). */
function parseYamlSubset(lines) {
  const items = [];
  for (let i = 0; i < lines.length; i += 1) {
    const raw = lines[i].replace(/\s+$/, '');
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed === '---' || trimmed === '...') continue;
    const lead = /^[ \t]*/.exec(raw)[0];
    if (lead.includes('\t')) return null; // tabs are illegal YAML indentation
    const text = stripYamlComment(raw.slice(lead.length)).trimEnd();
    if (text) items.push({ indent: lead.length, text });
  }
  let pos = 0;

  const parseBlock = () => (isSeqItem(items[pos].text) ? parseSeq(items[pos].indent) : parseMap(items[pos].indent));

  function blockScalar(indent) {
    const parts = [];
    while (pos < items.length && items[pos].indent > indent) {
      parts.push(items[pos].text);
      pos += 1;
    }
    return parts.join('\n');
  }

  function parseMap(indent) {
    const obj = {};
    while (pos < items.length && items[pos].indent === indent && !isSeqItem(items[pos].text)) {
      const kv = splitYamlKey(items[pos].text);
      if (!kv) throw new Error('not a mapping line');
      pos += 1;
      let value = null;
      if (kv.rest === '') {
        const next = items[pos];
        if (next && (next.indent > indent || (next.indent === indent && isSeqItem(next.text)))) value = parseBlock();
      } else if (/^[|>][+-]?\d*$/.test(kv.rest)) {
        value = blockScalar(indent);
      } else {
        value = yamlScalar(kv.rest);
      }
      obj[kv.key] = value;
    }
    if (pos < items.length && items[pos].indent > indent) throw new Error('unexpected indentation');
    return obj;
  }

  function parseSeq(indent) {
    const arr = [];
    while (pos < items.length && items[pos].indent === indent && isSeqItem(items[pos].text)) {
      const item = items[pos];
      const rest = item.text.slice(1).trimStart();
      if (rest === '') {
        pos += 1;
        arr.push(pos < items.length && items[pos].indent > indent ? parseBlock() : null);
      } else if (!/^["'[{]/.test(rest) && splitYamlKey(rest)) {
        // "- key: value" starts a mapping whose keys align with `key`.
        const childIndent = indent + (item.text.length - rest.length);
        items[pos] = { indent: childIndent, text: rest };
        arr.push(parseMap(childIndent));
      } else {
        pos += 1;
        arr.push(yamlScalar(rest));
      }
    }
    return arr;
  }

  try {
    if (items.length === 0) return null;
    const value = parseBlock();
    return pos === items.length ? value : null;
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------------ */
/* CSV / TSV                                                                */
/* ------------------------------------------------------------------------ */

function countOutsideQuotes(line, ch) {
  let n = 0;
  let quote = false;
  for (const c of line) {
    if (c === '"') quote = !quote;
    else if (c === ch && !quote) n += 1;
  }
  return n;
}

function splitCsvLine(line, delimiter) {
  return parseCsvRecords(line, delimiter, 1)[0]?.cells || [];
}

function classifyHeader(cells) {
  const columns = cells.map((cell) => {
    const key = normalizeKey(cell);
    if (TOPOLOGY_KEY_SET.has(key)) return { role: 'topology', key };
    if (isIpKey(key)) return { role: 'ip', key };
    if (NAME_HEADER_RANK.has(key)) return { role: 'name', key, rank: NAME_HEADER_RANK.get(key) };
    if (GROUP_HEADERS.has(key)) return { role: 'group', key };
    return { role: 'other', key };
  });
  return columns;
}

/** Find a header row within the first few meaningful lines. */
function detectCsv(lines) {
  let forced = null;
  let checked = 0;
  for (let i = 0; i < lines.length && checked < 6; i += 1) {
    const line = lines[i].trim();
    if (!line || /^(#|\/\/)/.test(line)) continue;
    if (line[0] === '{' || line[0] === '[') return null; // JSON Lines / INI, never CSV
    const sep = /^sep=(.)$/i.exec(line);
    if (sep) {
      forced = sep[1];
      continue;
    }
    checked += 1;
    const candidates = forced ? [forced] : ['\t', ';', ',', '|'];
    let best = null;
    for (const d of candidates) {
      const n = countOutsideQuotes(line, d);
      if (n > 0 && (!best || n > best.n)) best = { d, n };
    }
    if (!best) continue;
    const cells = splitCsvLine(line, best.d).map((c) => c.trim());
    if (cells.length < 2 || cells.some((c) => cleanIpToken(c))) continue;
    // Header cells are short labels, not prose or data.
    if (cells.some((c) => c.length > 40 || c.split(/\s+/).length > 4 || /[:.!?]$/.test(c)
      || !/^[\p{L}\p{N} _\-./()#]*$/u.test(c))) continue;
    const columns = classifyHeader(cells);
    // an IP column, or a name and a topology one (`name,where,terminates_tls`, as the CLI reads it)
    const has = (role) => columns.some((c) => c.role === role);
    if (!has('ip') && !(has('name') && has('topology'))) continue;
    // At least one following data line must use the same delimiter.
    const following = lines.slice(i + 1, i + 8).filter((l) => l.trim() && !/^(#|\/\/)/.test(l.trim()));
    if (following.length && !following.some((l) => countOutsideQuotes(l, best.d) > 0)) continue;
    return { delimiter: best.d, headerLine: i, columns };
  }
  return null;
}

/** RFC 4180 records with 1-based start line numbers. */
function parseCsvRecords(text, delimiter, startLine) {
  const records = [];
  let cells = [];
  let cell = '';
  let quoted = false;
  let atCellStart = true;
  let line = startLine;
  let recordLine = startLine;
  const endCell = () => {
    cells.push(cell);
    cell = '';
    atCellStart = true;
  };
  const endRecord = () => {
    endCell();
    records.push({ cells, line: recordLine });
    cells = [];
  };
  for (let i = 0; i < text.length; i += 1) {
    const c = text[i];
    if (quoted) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        if (c === '\n') line += 1;
        cell += c;
      }
      continue;
    }
    if (c === '"' && atCellStart) {
      quoted = true;
      atCellStart = false;
    } else if (c === delimiter) {
      endCell();
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i += 1;
      endRecord();
      line += 1;
      recordLine = line;
    } else {
      if (!(atCellStart && (c === ' ' || c === '\t') && delimiter !== '\t')) atCellStart = false;
      cell += c;
    }
  }
  if (cell !== '' || cells.length > 0) endRecord();
  return records;
}

function splitCellValues(value) {
  return String(value).split(/[\s,;|]+/).map((v) => v.trim()).filter(Boolean);
}

/** Character offset where 0-based line `n` starts (CRLF / CR / LF aware). */
function offsetOfLine(text, n) {
  let line = 0;
  for (let i = 0; i < text.length && line < n; i += 1) {
    if (text[i] === '\r' && text[i + 1] === '\n') i += 1;
    if (text[i] === '\n' || text[i] === '\r') {
      line += 1;
      if (line === n) return i + 1;
    }
  }
  return n === 0 ? 0 : text.length;
}

function parseCsv(text, csv, ctx) {
  const body = text.slice(offsetOfLine(text, csv.headerLine + 1));
  const records = parseCsvRecords(body, csv.delimiter, csv.headerLine + 2);
  const { columns } = csv;
  const nameCols = columns
    .map((c, i) => ({ ...c, i }))
    .filter((c) => c.role === 'name')
    .sort((a, b) => a.rank - b.rank);
  for (const { key } of columns) if (NEAR_MISS.has(key)) ctx.warn(csv.headerLine + 1, 'TOPOLOGY', undefined, `${key} (${NEAR_MISS.get(key)}?)`, 'nearMiss');

  for (const rec of records) {
    const cells = rec.cells.map((c) => unwrap(c).trim());
    if (cells.every((c) => !c)) continue;
    if (/^(#|\/\/|;)/.test(cells[0] || '')) continue;
    const ips = [];
    const eps = [];
    let name = null;
    const aliases = [];
    const groups = [];
    let invalid = 0;
    const addIpValue = (value, strict) => {
      for (const part of splitCellValues(value)) {
        const hit = parseIpToken(part);
        if (hit) {
          ips.push(hit.ip);
          eps.push(hit);
        } else if (strict && looksLikeIp(part)) {
          invalid += 1;
          ctx.warn(rec.line, 'INVALID_IP', undefined, part, invalidReason(part));
        }
      }
    };
    const topoFound = [];
    columns.forEach((col, i) => {
      const value = cells[i] || '';
      if (!value) return;
      if (col.role === 'ip') addIpValue(value, true);
      else if (col.role === 'group') groups.push(...value.split(/[,;|]+/).map((g) => g.trim()).filter(Boolean));
      else if (col.role === 'topology') topoFound.push({ key: col.key, raw: value });
    });
    const topology = lineTopology(ctx, topoFound, rec.line, true);
    for (const col of nameCols) {
      const value = cells[col.i] || '';
      if (!value) continue;
      const hit = parseIpToken(value);
      if (hit) {
        ips.push(hit.ip);
        eps.push(hit);
        continue;
      }
      if (!name) name = value;
      else if (value.toLowerCase() !== name.toLowerCase()) aliases.push(value);
    }
    if (ips.length === 0) {
      // IPs in unexpected columns (only when the IP columns are empty).
      columns.forEach((col, i) => {
        if (col.role === 'other' && cells[i]) addIpValue(cells[i], false);
      });
    }
    ctx.add({ name, ips: [...new Set(ips)], ports: portsOf(eps), groups, aliases, line: rec.line, quiet: ips.length === 0 && invalid > 0, topology });
  }
}

/* ------------------------------------------------------------------------ */
/* Line-oriented formats (hosts, name ip, Ansible INI, garbage)             */
/* ------------------------------------------------------------------------ */

function stripInlineComment(line) {
  return line.replace(/\s(#|\/\/).*$/, '').trim();
}

/** A word no heading has: a dot, or a digit group other than ip2 / ipv4 / ipv6. */
function isHostWord(token) {
  return token.includes('.') || normalizeKey(token).split('_').some((p) => /\d/.test(p) && !/^ipv?\d+$/.test(p));
}

function isHeaderLike(tokens) {
  // "ip-10-0-1-23.ec2.internal", "ipv6.example.com": a host without an IP (NO_IP), not a heading
  if (tokens.length === 0 || tokens.some(isHostWord)) return false;
  const keys = tokens.map(normalizeKey);
  if (tokens.length === 1) return isIpKey(keys[0]) || NAME_HEADER_RANK.has(keys[0]);
  return keys.some(isIpKey) && keys.some((k) => NAME_HEADER_RANK.has(k) || GROUP_HEADERS.has(k));
}

function parseLines(lines, ctx) {
  let group = null;
  let section = 'hosts';
  for (let idx = 0; idx < lines.length; idx += 1) {
    const lineNo = idx + 1;
    let line = lines[idx].trim();
    if (!line || /^(#|;|\/\/)/.test(line) || line === '---' || line === '...') continue;

    // Ansible INI section header (but not a bracketed IPv6 literal).
    const header = /^\[([^\]]+)\]$/.exec(line);
    if (header && !cleanIpToken(line)) {
      const [g, kind = ''] = header[1].trim().split(':');
      if (/^[\p{L}\p{N}_.-]+$/u.test(g)) {
        group = g;
        section = kind === 'vars' ? 'vars' : kind === 'children' ? 'children' : 'hosts';
        ctx.defineGroup(g);
        continue;
      }
    }
    if (section === 'vars') {
      for (const t of splitTopology(stripInlineComment(line)).found) ctx.warn(lineNo, 'TOPOLOGY', undefined, t.key, 'groupVars');
      continue;
    }
    if (section === 'children') {
      const child = line.split(/\s+/)[0];
      if (group && child) {
        ctx.defineGroup(group).children.add(child);
        ctx.defineGroup(child);
      }
      continue;
    }

    // JSON Lines.
    if (line.startsWith('{') && line.endsWith('}')) {
      const obj = tryJson(line);
      if (obj !== undefined) {
        extractStructured(obj, ctx, lineNo);
        continue;
      }
    }

    line = stripInlineComment(line).replace(/^(?:[-*\u2022+]|\d{1,4}[.)])\s+/u, '');
    if (!line) continue;
    const warned = ctx.warned;
    const { rest, found, near } = splitTopology(line);
    for (const n of near) ctx.warn(lineNo, 'TOPOLOGY', undefined, n, 'nearMiss');
    const topology = lineTopology(ctx, found, lineNo);
    const added = rest.trim() ? parseHostLine(rest.trim(), lineNo, group, ctx, topology) : false;
    // keys without a server, when nothing else was said about the line
    if (!added && found.length && ctx.warned === warned) ctx.warn(lineNo, 'TOPOLOGY', undefined, found[0].key, 'noServer');
  }
}

/** One line; true when it added an entry, which carries `topology`. */
function parseHostLine(line, lineNo, group, ctx, topology = []) {
  const tokens = line.split(/[\s,;|]+/).filter(Boolean);
  const ips = [];
  const eps = [];
  const invalid = [];
  const names = [];
  const others = [];
  const hostPorts = [];
  let ipFirst = false;
  // Ansible INI: a line under a [group] header, or one with ansible_* variables. There a port
  // on the host pattern (the first token: `badwolf.example.com:5309`, `192.0.2.50:2222`,
  // `[2001:db8::1]:2222`) is Ansible's SSH port (ansible_port), never a TLS port: the host
  // stays on the CLI's -p ports, as cli/ssl_origin_scan.py reads it.
  const ansible = group !== null || tokens.some((t) => /^ansible_\w*=/i.test(unwrap(t)));

  tokens.forEach((raw, i) => {
    let tok = unwrap(raw);
    if (!tok) return;
    if (i === 0 && ansible && !tok.includes('=')) {
      const host = sshHostOf(tok);
      if (host) {
        ctx.warn(lineNo, 'PARSE', undefined, tok, 'sshPort');
        tok = host;
      }
    }
    const eq = tok.indexOf('=');
    if (eq > 0) {
      const key = tok.slice(0, eq);
      const value = unwrap(tok.slice(eq + 1));
      const hit = parseIpToken(value);
      const ip = hit ? hit.ip : null;
      const nk = normalizeKey(key);
      const addrKey = isIpKey(nk) || /(^|_)host$/.test(nk);
      // The first token "web01=…" names the server (NAME=TARGET, as the CLI's -t takes it).
      const nameKey = i === 0 && isNameToken(key) && !/^ansible_/.test(nk);
      if (ip && addrKey) {
        ips.push(ip);
        eps.push(hit);
      } else if (ip && nameKey) {
        names.push(key); // "web01=10.0.0.1"
        ips.push(ip);
        eps.push(hit);
      } else if (!ip && looksLikeIp(value) && (isIpKey(nk) || nameKey)) {
        invalid.push(value); // "web01=10.0.0.300", "web01=10.0.0.1:99999": a warning, never dropped silently
      } else if (!ip && (addrKey || nameKey) && HOST_PORT_RE.test(value)) {
        // "web01=web01.example.net:8443", "ansible_host=web01.example.net:8443": the CLI resolves it
        if (nameKey && !addrKey) names.push(key);
        hostPorts.push(value);
      } else if (!ip && nameKey && !addrKey && isDottedHost(value)) {
        names.push(key); // "web01=web01.example.net": the CLI resolves it, here the server has no IP
      }
      return;
    }
    const hit = parseIpToken(tok);
    if (hit) {
      if (i === 0) ipFirst = true;
      ips.push(hit.ip);
      eps.push(hit);
      return;
    }
    if (looksLikeIp(tok)) {
      invalid.push(tok);
      return;
    }
    if (HOST_PORT_RE.test(tok)) {
      hostPorts.push(tok);
      return;
    }
    if (tok.endsWith(':')) {
      const label = tok.slice(0, -1);
      if (FIELD_LABELS.has(normalizeKey(label))) return;
      if (isNameToken(label)) names.push(label);
      else others.push(tok);
      return;
    }
    const cleaned = tok.replace(/\.$/, '');
    if (isNameToken(cleaned)) names.push(cleaned);
    else others.push(tok);
  });

  for (const bad of invalid) ctx.warn(lineNo, 'INVALID_IP', undefined, bad, invalidReason(bad));
  for (const hp of hostPorts) ctx.warn(lineNo, 'PARSE', undefined, hp, 'hostPort');
  const groups = group && !IGNORED_GROUPS.has(group) ? [group] : [];
  const hostish = names.filter(isHostish);
  const plain = names.filter((n) => PLAIN_WORD_RE.test(n));

  if (ips.length === 0) {
    if (invalid.length) {
      // The IP was mistyped: keep group membership but do not double-warn.
      if (names.length) ctx.add({ name: hostish[0] || names[0], ips: [], groups, line: lineNo, quiet: true, topology });
      return true;
    }
    if (line.endsWith(':') || isHeaderLike(tokens.map(unwrap))) return false; // heading / table header
    if (names.length === 0) {
      if (others.length) ctx.warn(lineNo, 'PARSE');
      return false; // only key=value vars
    }
    if (others.length > 0 || plain.length >= 3 || names.length > 3) {
      ctx.warn(lineNo, 'PARSE');
      return false;
    }
    ctx.add({ name: hostish[0] || names[0], ips: [], groups, line: lineNo, topology });
    return true;
  }

  let name = null;
  if (hostish.length) name = hostish[0];
  else if (plain.length && plain.length <= 2 && others.length === 0) name = plain[0];
  else if (names.length === 1 && others.length === 0) name = names[0];

  if (!name) {
    // Prose around IPs ("please update 10.0.0.1 and 10.0.0.2"): each IP stands alone.
    for (const ip of new Set(ips)) ctx.add({ name: null, ips: [ip], ports: portsOf(eps.filter((e) => e.ip === ip)), groups, line: lineNo, topology });
    return true;
  }
  const aliases = ipFirst ? names.filter((n) => n !== name) : [];
  ctx.add({ name, ips: [...new Set(ips)], ports: portsOf(eps), groups, aliases, line: lineNo, topology });
  return true;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

function emptyResult(lines, warnings = []) {
  return { servers: [], warnings, stats: { lines, servers: 0, ips: 0 } };
}

/** The input as parseInventory reads it: size-capped, BOM stripped, split into lines. */
function prepareSource(text) {
  let source = typeof text === 'string' ? text : text === null || text === undefined ? '' : String(text);
  const truncated = source.length > MAX_INPUT;
  if (truncated) source = source.slice(0, MAX_INPUT);
  source = source.replace(/^\uFEFF/, '');
  const lines = source.split(/\r\n|\r|\n/);
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  return { source, lines, truncated };
}

/**
 * Which reader parseInventory hands the text to: one JSON document, the YAML subset, CSV with
 * a header row, else the line-oriented reader (name ip, hosts, Ansible INI, JSON Lines). May
 * throw on pathological input (parseInventory catches it).
 */
function detectFormat(source, lines) {
  const trimmed = source.trim();
  if (!trimmed) return { format: 'empty' };
  if (trimmed[0] === '{' || trimmed[0] === '[') {
    const data = tryJson(trimmed);
    if (data !== undefined) return { format: 'json', data };
  }
  if (looksLikeYaml(lines)) {
    const data = parseYamlSubset(lines);
    if (data !== null && typeof data === 'object') return { format: 'yaml', data };
  }
  const csv = detectCsv(lines);
  if (csv) return { format: 'csv', csv };
  return { format: 'lines' };
}

/**
 * The format parseInventory reads `text` as, for a tool that adds hosts to it in the same
 * format (the Reverse DNS view's "Add to Servers"). Never throws.
 * - 'json': one JSON document (`data`, parsed); 'yaml': the YAML subset (`data`, parsed);
 * - 'csv': a header row (`delimiter`, `header` = each column's `role` 'name' | 'ip' | 'group' |
 *   'other' and normalised `key`, `nameColumn` = the index of the column the name is read from,
 *   -1 without one);
 * - 'ini': line-oriented with an Ansible `[group]` header; 'jsonl': every line a JSON object;
 *   'lines': `name ip`, `ip name`, hosts file; 'empty'.
 * @param {string} text
 * @returns {{ format: 'empty'|'json'|'yaml'|'csv'|'ini'|'jsonl'|'lines', data?: unknown, delimiter?: string,
 *   header?: Array<{ role: 'name'|'ip'|'group'|'other', key: string }>, nameColumn?: number }}
 */
export function inventoryFormat(text) {
  const { source, lines } = prepareSource(text);
  let found;
  try {
    found = detectFormat(source, lines);
  } catch {
    return { format: 'lines' };
  }
  if (found.format === 'csv') {
    const header = found.csv.columns.map((c) => ({ role: c.role, key: c.key }));
    const names = found.csv.columns.map((c, i) => ({ ...c, i })).filter((c) => c.role === 'name').sort((a, b) => a.rank - b.rank);
    return { format: 'csv', delimiter: found.csv.delimiter, header, nameColumn: names.length ? names[0].i : -1 };
  }
  if (found.format !== 'lines') return found;
  const meaningful = lines.map((l) => l.trim()).filter((l) => l && !/^(#|;|\/\/)/.test(l) && l !== '---' && l !== '...');
  // The section headers parseLines takes (a bracketed IPv6 literal is no header).
  const isHeader = (l) => {
    const m = /^\[([^\]]+)\]$/.exec(l);
    return !!m && !cleanIpToken(l) && /^[\p{L}\p{N}_.-]+$/u.test(m[1].trim().split(':')[0]);
  };
  if (meaningful.some(isHeader)) return { format: 'ini' };
  if (meaningful.length && meaningful.every((l) => l.startsWith('{') && l.endsWith('}') && tryJson(l) !== undefined)) return { format: 'jsonl' };
  return { format: 'lines' };
}

/**
 * Parse a server inventory in any supported format. Never throws.
 * @param {string} text
 * @returns {{ servers: Server[], warnings: InventoryWarning[],
 *   stats: { lines: number, servers: number, ips: number } }}
 */
export function parseInventory(text) {
  const { source, lines, truncated } = prepareSource(text);
  const warnings = [];
  if (truncated) warnings.push({ line: 0, code: 'PARSE', text: `Input truncated to ${MAX_INPUT} characters` });
  const lineCount = source.trim() ? lines.length : 0;
  if (!source.trim()) return emptyResult(lineCount, warnings);

  try {
    const ctx = createCollector(source, lines);
    const found = detectFormat(source, lines);
    if (found.format === 'json' || found.format === 'yaml') extractStructured(found.data, ctx);
    else if (found.format === 'csv') parseCsv(source, found.csv, ctx);
    else parseLines(lines, ctx);
    const result = ctx.finalize(lineCount);
    result.warnings.unshift(...warnings);
    return result;
  } catch (err) {
    warnings.push({ line: 0, code: 'PARSE', text: String(err && err.message ? err.message : err).slice(0, 200) });
    return emptyResult(lineCount, warnings);
  }
}

/**
 * An address as a CLI target: `203.0.113.10:8443`, `[2001:db8::1]:8443`, or the bare address
 * when `port` is null / not an integer 1–65535. Null when `ip` is not an IP address.
 * @param {string} ip
 * @param {number|null} [port]
 * @returns {string|null}
 */
export function formatEndpoint(ip, port = null) {
  const addr = normalizeIP(String(ip ?? ''));
  if (!addr) return null;
  if (!Number.isInteger(port) || port < 1 || port > 65535) return addr;
  return addr.includes(':') ? `[${addr}]:${port}` : `${addr}:${port}`;
}

/**
 * The `-t` tokens of address `ip` of `server`, as the CLI reads them back: the bare address, or
 * one `ip:port` per port it was written with (`Server.ports`; `null` there keeps the bare
 * address as well). [] when `ip` is not an IP address. Without a port: `tlsPorts`, else `-p`.
 * @param {{ ports?: Object<string, Array<number|null>>, tlsPorts?: number[] }|null} server
 * @param {string} ip canonical, as in `Server.ips`
 * @returns {string[]}
 */
export function addressTargets(server, ip) {
  const ports = server && server.ports && typeof server.ports === 'object' ? server.ports : {};
  const spec = Array.isArray(ports[ip]) && ports[ip].length ? ports[ip] : [null];
  const own = server && Array.isArray(server.tlsPorts) ? server.tlsPorts.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535) : [];
  const out = [];
  for (const port of spec.flatMap((p) => (p === null && own.length ? own : [p]))) {
    const token = formatEndpoint(ip, port);
    if (token && !out.includes(token)) out.push(token);
  }
  return out;
}

/**
 * The `-t` tokens of one server ({@link addressTargets} of each of its addresses, in order).
 * @param {{ ips?: string[], ports?: Object<string, Array<number|null>> }} server
 * @returns {string[]}
 */
export function serverTargets(server) {
  const out = [];
  for (const ip of Array.isArray(server?.ips) ? server.ips : []) {
    for (const token of addressTargets(server, ip)) if (!out.includes(token)) out.push(token);
  }
  return out;
}

/**
 * Index servers by canonical IP (their own, `vip=` and `nat=` addresses).
 * @param {Server[]} servers
 * @returns {Map<string, Server[]>}
 */
export function buildIpIndex(servers) {
  const index = new Map();
  for (const server of Array.isArray(servers) ? servers : []) {
    if (!server || !Array.isArray(server.ips)) continue;
    const vips = Array.isArray(server.vips) ? server.vips : [];
    const nats = Array.isArray(server.nats) ? server.nats : [];
    for (const raw of [...server.ips, ...vips, ...nats]) {
      const ip = normalizeIP(raw);
      if (!ip) continue;
      const list = index.get(ip);
      if (!list) index.set(ip, [server]);
      else if (!list.includes(server)) list.push(server);
    }
  }
  return index;
}

function reachedThrough(server, key) {
  if (server.ips.some((ip) => normalizeIP(ip) === key)) return null;
  if ((server.vips || []).some((ip) => normalizeIP(ip) === key)) return 'vip';
  return (server.nats || []).some((ip) => normalizeIP(ip) === key) ? 'nat' : null;
}

/**
 * Servers owning any of `ips` (a `vip=` / `nat=` one: `through`). IPv4-mapped IPv6
 * (`::ffff:1.2.3.4`) also matches servers listed with the plain IPv4.
 * @param {string[]|string} ips
 * @param {Map<string, Server[]>} index From {@link buildIpIndex}.
 * @returns {Array<{ server: Server, ip: string, through?: 'vip'|'nat' }>} unique (server, ip) pairs, input order.
 */
export function lookupServers(ips, index) {
  const out = [];
  if (!index || typeof index.get !== 'function') return out;
  const seen = new Set();
  const list = Array.isArray(ips) ? ips : typeof ips === 'string' ? [ips] : [];
  for (const raw of list) {
    const ip = normalizeIP(raw);
    if (!ip) continue;
    const keys = [ip];
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(ip);
    if (mapped) keys.push(mapped[1]);
    for (const key of keys) {
      for (const server of index.get(key) || []) {
        const k = `${server.id}\u0000${ip}`;
        if (seen.has(k)) continue;
        seen.add(k);
        const through = Array.isArray(server.ips) ? reachedThrough(server, key) : null;
        out.push(through ? { server, ip, through } : { server, ip });
      }
    }
  }
  return out;
}
