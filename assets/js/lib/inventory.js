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
 */

import { normalizeIP, parseCidr, ipInCidr } from './netinfo.js';

/**
 * @typedef {object} Server
 * @property {string} id        Stable id: the name, or the first IP for unnamed servers.
 * @property {string} name      Server name (the first IP for unnamed servers).
 * @property {string[]} ips     Canonical IPs (normalizeIP), unique, input order.
 * @property {string[]} groups  Groups/roles (Ansible groups incl. parents, CSV group columns).
 * @property {number} line      1-based line where the server first appears.
 * @property {string[]} aliases Extension: other names (hosts-file aliases, secondary name columns).
 */

/**
 * @typedef {object} InventoryWarning
 * @property {number} line 1-based line (approximate for JSON/YAML; 0 = whole input).
 * @property {'NO_IP'|'INVALID_IP'|'DUPLICATE_IP'|'PARSE'} code
 * @property {string} text  The offending line (trimmed, ≤ 200 chars).
 * @property {string} [detail] Extension: offending token / IP / server name.
 */

const MAX_INPUT = 10 * 1024 * 1024;
const MAX_DEPTH = 64;
const IGNORED_GROUPS = new Set(['all', 'ungrouped']);

/* ------------------------------------------------------------------------ */
/* Token helpers                                                            */
/* ------------------------------------------------------------------------ */

// Addresses that never identify a server: loopback, unspecified, multicast,
// broadcast and the /etc/hosts "fe00::0 ip6-localnet" boilerplate.
const NON_HOST_RANGES = ['127.0.0.0/8', '0.0.0.0/32', '224.0.0.0/4', '255.255.255.255/32',
  '::1/128', '::/128', 'ff00::/8', 'fe00::/16'].map(parseCidr);

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
 * Parse one token as an IP: accepts brackets, `ip:port`, `[v6]:port`,
 * `ip/32`, `ip/128`, a trailing sentence dot; returns the canonical IP or null.
 */
function cleanIpToken(token) {
  if (typeof token !== 'string') return null;
  let t = unwrap(token);
  if (!t || t.length > 64) return null;
  if (t.endsWith('.') && !t.includes(':')) t = t.slice(0, -1);
  let m = /^\[([^\]]+)\](?::\d{1,5})?$/.exec(t);
  if (m) return normalizeIP(m[1]);
  m = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{0,5}$/.exec(t);
  if (m) return normalizeIP(m[1]);
  m = /^([^/]+)\/(\d{1,3})$/.exec(t);
  if (m) {
    const ip = normalizeIP(m[1]);
    if (!ip) return null;
    return Number(m[2]) === (ip.includes(':') ? 128 : 32) ? ip : null;
  }
  return normalizeIP(t);
}

/** Token that is *meant* to be an IP but is not valid (10.0.0.256, 1::2::3, a CIDR…). */
function looksLikeIp(token) {
  let t = unwrap(token).replace(/\/\d{1,3}$/, '');
  t = t.replace(/^\[/, '').replace(/\](?::\d+)?$/, '');
  if (t.endsWith('.') && !t.includes(':')) t = t.slice(0, -1);
  if (/^\d+\.\d+\.\d+\.\d+(?::\d+)?$/.test(t)) return true;
  const colons = (t.match(/:/g) || []).length;
  return colons >= 2
    && /^[0-9a-f:.%]+$/i.test(t)
    && /[0-9a-f]/i.test(t)
    && !/^\d{1,2}:\d{2}(?::\d{2})?$/.test(t); // clock times
}

const NAME_TOKEN_RE = /^[\p{L}\p{N}_](?:[\p{L}\p{N}_.-]*[\p{L}\p{N}_])?$/u;
const ANSIBLE_RANGE_RE = /^[\p{L}\p{N}_.-]*\[[^\]\s]+:[^\]\s]+\][\p{L}\p{N}_.-]*$/u;
const PLAIN_WORD_RE = /^\p{L}+$/u;

function isNameToken(t) {
  if (!t || t.length > 253) return false;
  if (/^[\d.]+$/.test(t)) return false; // numbers / version-ish
  return NAME_TOKEN_RE.test(t) || ANSIBLE_RANGE_RE.test(t);
}

const isHostish = (t) => /[\d._-]/.test(t);

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
/* Collector: entries → merged servers                                     */
/* ------------------------------------------------------------------------ */

function createCollector(text, lines) {
  const entries = [];
  const warnings = [];
  /** @type {Map<string, { hosts: Set<string>, children: Set<string> }>} */
  const groupDefs = new Map();
  let lineStarts = null;

  const lineText = (n) => (n >= 1 && n <= lines.length ? lines[n - 1].trim().slice(0, 200) : '');

  return {
    lines,
    warn(line, code, textOverride, detail) {
      const w = { line, code, text: textOverride !== undefined ? String(textOverride).slice(0, 200) : lineText(line) };
      if (detail !== undefined) w.detail = String(detail).slice(0, 200);
      warnings.push(w);
    },
    lineText,
    /** Approximate 1-based line of the first occurrence of `needle`. */
    lineOf(needle) {
      if (!needle) return 1;
      const idx = text.indexOf(needle);
      if (idx === -1) return 1;
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
     * @param {{ name: string|null, ips: string[], groups?: string[], aliases?: string[], line: number,
     *   quiet?: boolean }} e quiet: never emit NO_IP for this entry alone.
     */
    add(e) {
      const all = e.ips || [];
      const ips = all.filter((ip) => !isNonHostIP(ip));
      if (all.length > 0 && ips.length === 0) return; // loopback/boilerplate only
      entries.push({
        name: e.name ? String(e.name).trim().replace(/\.$/, '') || null : null,
        ips,
        groups: (e.groups || []).filter(Boolean),
        aliases: (e.aliases || []).filter(Boolean),
        line: e.line || 1,
        quiet: !!e.quiet
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

function finalizeServers(entries, warnings, groupDefs, lineCount, lineText, ctx) {
  const byName = new Map(); // lower name → server draft
  const drafts = [];

  const draftFor = (key, name, line) => {
    let d = byName.get(key);
    if (!d) {
      d = { name, ips: [], groups: [], aliases: [], line, loud: false, named: true };
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
    push(d.ips, e.ips);
    push(d.groups, e.groups);
    push(d.aliases, e.aliases.filter((a) => a.toLowerCase() !== d.name.toLowerCase()));
    if (!e.quiet) d.loud = true;
  }

  // 2) Unnamed entries: drop IPs already owned by a named server, merge by first IP.
  const namedIps = new Set();
  for (const d of drafts) for (const ip of d.ips) namedIps.add(ip);
  const byIp = new Map();
  for (const e of entries) {
    if (e.name) continue;
    const ips = e.ips.filter((ip) => !namedIps.has(ip));
    if (ips.length === 0) {
      if (e.ips.length === 0 && !e.quiet) ctx.warn(e.line, 'NO_IP');
      continue;
    }
    let d = byIp.get(ips[0]);
    if (!d) {
      d = { name: ips[0], ips: [], groups: [], aliases: [], line: e.line, loud: true, named: false };
      byIp.set(ips[0], d);
      drafts.push(d);
    }
    push(d.ips, ips);
    push(d.groups, e.groups);
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
  const servers = [];
  for (const d of drafts) {
    if (d.ips.length === 0) {
      if (d.loud) ctx.warn(d.line, 'NO_IP', undefined, d.name);
      continue;
    }
    servers.push({ id: d.name, name: d.name, ips: d.ips, groups: d.groups, line: d.line, aliases: d.aliases });
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

  // 5) The same IP on several distinct servers (VIPs, NAT, copy-paste errors).
  const owners = new Map();
  for (const s of servers) {
    for (const ip of s.ips) {
      if (!owners.has(ip)) owners.set(ip, []);
      owners.get(ip).push(s);
    }
  }
  for (const [ip, list] of owners) {
    for (const s of list.slice(1)) {
      warnings.push({
        line: s.line, code: 'DUPLICATE_IP', text: lineText(s.line),
        detail: `${ip} (${list.map((x) => x.name).join(', ')})`
      });
    }
  }

  warnings.sort((a, b) => a.line - b.line);
  return {
    servers,
    warnings,
    stats: { lines: lineCount, servers: servers.length, ips: owners.size }
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
  if (!s || s.length > 253 || /[\r\n]/.test(s) || cleanIpToken(s)) return null;
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

function keyKind(key, value) {
  if (isTerraformOutput(value)) return 'name';
  if (STRUCTURAL_KEYS.has(String(key).toLowerCase())) return 'structural';
  const nk = normalizeKey(key);
  if (!IP_KEY_EXCLUDE_RE.test(nk) && IP_FIELD_KEY_RE.test(nk)) return 'field';
  if (/^\d+$/.test(key)) return 'structural'; // array-like object
  return isNameToken(String(key)) ? 'name' : 'field';
}

/**
 * Walk a JSON/YAML value. Named objects claim every IP below them; unnamed
 * objects pass their IPs up (one group per object); keys that look like
 * names (terraform outputs, `{ web01: {...} }` maps) name what is below.
 * Returns groups of { ip, raw } not claimed by any name.
 */
function visitStructured(node, depth, found) {
  if (depth > MAX_DEPTH || node === null || node === undefined) return [];
  if (typeof node === 'string') {
    const items = [];
    const parts = node.length <= 200 ? node.split(/[\s,;]+/) : [];
    for (const part of parts) {
      const ip = cleanIpToken(part);
      if (ip) items.push({ ip, raw: part });
    }
    return items.length ? [items] : [];
  }
  if (Array.isArray(node)) {
    const out = [];
    for (const el of node) out.push(...visitStructured(el, depth + 1, found));
    return out;
  }
  if (typeof node !== 'object') return [];

  const name = pickName(node);
  const own = [];
  const pass = [];
  for (const [key, value] of Object.entries(node)) {
    if (NAME_KEY_SET.has(key) && validName(value)) continue; // the name itself
    const groups = visitStructured(value, depth + 1, found);
    if (groups.length === 0) continue;
    if (name) {
      own.push(...groups.flat());
      continue;
    }
    const kind = keyKind(key, value);
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

/** Collect Ansible group definitions ({group: {hosts, children, vars}}). */
function collectGroupDefs(root, ctx) {
  if (!root || typeof root !== 'object' || Array.isArray(root)) return;
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
}

function extractStructured(root, ctx, fixedLine = null) {
  collectGroupDefs(root, ctx);
  const found = [];
  const leftovers = visitStructured(root, 0, found);
  for (const items of leftovers) found.push({ name: null, items });
  for (const f of found) {
    const ips = [...new Set(f.items.map((i) => i.ip))];
    const line = fixedLine ?? ctx.lineOf(f.items[0]?.raw);
    ctx.add({ name: f.name, ips, line });
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
    if (!columns.some((c) => c.role === 'ip')) continue;
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

  for (const rec of records) {
    const cells = rec.cells.map((c) => unwrap(c).trim());
    if (cells.every((c) => !c)) continue;
    if (/^(#|\/\/|;)/.test(cells[0] || '')) continue;
    const ips = [];
    let name = null;
    const aliases = [];
    const groups = [];
    let invalid = 0;
    const addIpValue = (value, strict) => {
      for (const part of splitCellValues(value)) {
        const ip = cleanIpToken(part);
        if (ip) ips.push(ip);
        else if (strict && looksLikeIp(part)) {
          invalid += 1;
          ctx.warn(rec.line, 'INVALID_IP', undefined, part);
        }
      }
    };
    columns.forEach((col, i) => {
      const value = cells[i] || '';
      if (!value) return;
      if (col.role === 'ip') addIpValue(value, true);
      else if (col.role === 'group') groups.push(...value.split(/[,;|]+/).map((g) => g.trim()).filter(Boolean));
    });
    for (const col of nameCols) {
      const value = cells[col.i] || '';
      if (!value) continue;
      const ip = cleanIpToken(value);
      if (ip) {
        ips.push(ip);
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
    ctx.add({ name, ips: [...new Set(ips)], groups, aliases, line: rec.line, quiet: ips.length === 0 && invalid > 0 });
  }
}

/* ------------------------------------------------------------------------ */
/* Line-oriented formats (hosts, name ip, Ansible INI, garbage)             */
/* ------------------------------------------------------------------------ */

function stripInlineComment(line) {
  return line.replace(/\s(#|\/\/).*$/, '').trim();
}

function isHeaderLike(tokens) {
  if (tokens.length === 0) return false;
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
    if (section === 'vars') continue;
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
    parseHostLine(line, lineNo, group, ctx);
  }
}

function parseHostLine(line, lineNo, group, ctx) {
  const tokens = line.split(/[\s,;|]+/).filter(Boolean);
  const ips = [];
  const invalid = [];
  const names = [];
  const others = [];
  let ipFirst = false;

  tokens.forEach((raw, i) => {
    const tok = unwrap(raw);
    if (!tok) return;
    const eq = tok.indexOf('=');
    if (eq > 0) {
      const key = tok.slice(0, eq);
      const value = unwrap(tok.slice(eq + 1));
      const ip = cleanIpToken(value);
      const nk = normalizeKey(key);
      if (ip && (isIpKey(nk) || /(^|_)host$/.test(nk))) ips.push(ip);
      else if (ip && i === 0 && isNameToken(key) && !/^ansible_/.test(nk)) {
        names.push(key); // "web01=10.0.0.1"
        ips.push(ip);
      } else if (!ip && looksLikeIp(value) && isIpKey(nk)) invalid.push(value);
      return;
    }
    const ip = cleanIpToken(tok);
    if (ip) {
      if (i === 0) ipFirst = true;
      ips.push(ip);
      return;
    }
    if (looksLikeIp(tok)) {
      invalid.push(tok);
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

  for (const bad of invalid) ctx.warn(lineNo, 'INVALID_IP', undefined, bad);
  const groups = group && !IGNORED_GROUPS.has(group) ? [group] : [];
  const hostish = names.filter(isHostish);
  const plain = names.filter((n) => PLAIN_WORD_RE.test(n));

  if (ips.length === 0) {
    if (invalid.length) {
      // The IP was mistyped: keep group membership but do not double-warn.
      if (names.length) ctx.add({ name: hostish[0] || names[0], ips: [], groups, line: lineNo, quiet: true });
      return;
    }
    if (line.endsWith(':') || isHeaderLike(tokens.map(unwrap))) return; // heading / table header
    if (names.length === 0) {
      if (others.length) ctx.warn(lineNo, 'PARSE');
      return; // only key=value vars
    }
    if (others.length > 0 || plain.length >= 3 || names.length > 3) {
      ctx.warn(lineNo, 'PARSE');
      return;
    }
    ctx.add({ name: hostish[0] || names[0], ips: [], groups, line: lineNo });
    return;
  }

  let name = null;
  if (hostish.length) name = hostish[0];
  else if (plain.length && plain.length <= 2 && others.length === 0) name = plain[0];
  else if (names.length === 1 && others.length === 0) name = names[0];

  if (!name) {
    // Prose around IPs ("please update 10.0.0.1 and 10.0.0.2"): each IP stands alone.
    for (const ip of new Set(ips)) ctx.add({ name: null, ips: [ip], groups, line: lineNo });
    return;
  }
  const aliases = ipFirst ? names.filter((n) => n !== name) : [];
  ctx.add({ name, ips: [...new Set(ips)], groups, aliases, line: lineNo });
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

function emptyResult(lines, warnings = []) {
  return { servers: [], warnings, stats: { lines, servers: 0, ips: 0 } };
}

/**
 * Parse a server inventory in any supported format. Never throws.
 * @param {string} text
 * @returns {{ servers: Server[], warnings: InventoryWarning[],
 *   stats: { lines: number, servers: number, ips: number } }}
 */
export function parseInventory(text) {
  let source = typeof text === 'string' ? text : text === null || text === undefined ? '' : String(text);
  const warnings = [];
  if (source.length > MAX_INPUT) {
    source = source.slice(0, MAX_INPUT);
    warnings.push({ line: 0, code: 'PARSE', text: `Input truncated to ${MAX_INPUT} characters` });
  }
  source = source.replace(/^\uFEFF/, '');
  const lines = source.split(/\r\n|\r|\n/);
  if (lines.length && lines[lines.length - 1] === '') lines.pop();
  const lineCount = source.trim() ? lines.length : 0;
  if (!source.trim()) return emptyResult(lineCount, warnings);

  try {
    const ctx = createCollector(source, lines);
    const trimmed = source.trim();
    let handled = false;
    if (trimmed[0] === '{' || trimmed[0] === '[') {
      const data = tryJson(trimmed);
      if (data !== undefined) {
        extractStructured(data, ctx);
        handled = true;
      }
    }
    if (!handled && looksLikeYaml(lines)) {
      const data = parseYamlSubset(lines);
      if (data !== null && typeof data === 'object') {
        extractStructured(data, ctx);
        handled = true;
      }
    }
    if (!handled) {
      const csv = detectCsv(lines);
      if (csv) {
        parseCsv(source, csv, ctx);
        handled = true;
      }
    }
    if (!handled) parseLines(lines, ctx);
    const result = ctx.finalize(lineCount);
    result.warnings.unshift(...warnings);
    return result;
  } catch (err) {
    warnings.push({ line: 0, code: 'PARSE', text: String(err && err.message ? err.message : err).slice(0, 200) });
    return emptyResult(lineCount, warnings);
  }
}

/**
 * Index servers by canonical IP.
 * @param {Server[]} servers
 * @returns {Map<string, Server[]>}
 */
export function buildIpIndex(servers) {
  const index = new Map();
  for (const server of Array.isArray(servers) ? servers : []) {
    if (!server || !Array.isArray(server.ips)) continue;
    for (const raw of server.ips) {
      const ip = normalizeIP(raw);
      if (!ip) continue;
      const list = index.get(ip);
      if (!list) index.set(ip, [server]);
      else if (!list.includes(server)) list.push(server);
    }
  }
  return index;
}

/**
 * Servers owning any of `ips`. IPv4-mapped IPv6 (`::ffff:1.2.3.4`) also
 * matches servers listed with the plain IPv4.
 * @param {string[]|string} ips
 * @param {Map<string, Server[]>} index From {@link buildIpIndex}.
 * @returns {Array<{ server: Server, ip: string }>} unique (server, ip) pairs, input order.
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
        out.push({ server, ip });
      }
    }
  }
  return out;
}
