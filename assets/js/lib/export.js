/**
 * export.js — CSV / JSON serialization and the helper files for the
 * companion CLI (cli/ssl_origin_scan.py). Pure string builders; DOM-free.
 * (Triggering a download is the UI's job: assets/js/ui/download.js.)
 */

import { sortHostnames } from './domain.js';
import { addressTargets } from './inventory.js';
import { normalizeIP } from './netinfo.js';

/* ------------------------------------------------------------------------ */
/* CSV                                                                      */
/* ------------------------------------------------------------------------ */

const FORMULA_START = /^[=+\-@\t\r]/;

/** Plain-text form of a cell value. Arrays are joined with a space. */
function cellText(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? '' : value.toISOString();
  if (Array.isArray(value)) return value.map(cellText).filter((s) => s !== '').join(' ');
  if (typeof value === 'object') {
    if (value instanceof Set) return cellText([...value]);
    try {
      return JSON.stringify(value);
    } catch {
      return String(value);
    }
  }
  return String(value);
}

/**
 * Serialize rows as CSV (RFC 4180): CRLF line endings, fields containing the
 * delimiter, a double quote, CR or LF are quoted and quotes doubled. A UTF-8
 * BOM is prepended by default so Excel shows Turkish characters correctly.
 *
 * Values: null/undefined → empty, Date → ISO 8601, arrays → space-joined,
 * objects → JSON. Extension `safe` (default true): string cells starting with
 * = + - @ TAB or CR get a leading apostrophe so spreadsheet apps never
 * evaluate data from CT logs / DNS as a formula (CSV injection). Numbers are
 * left untouched. Extension: `columns` may be omitted (keys of the rows).
 *
 * @param {object[]} rows
 * @param {Array<{ key: string, header?: string, get?: (row: object) => any }>} [columns]
 * @param {{ bom?: boolean, delimiter?: string, safe?: boolean, eol?: string }} [opts]
 * @returns {string}
 */
export function toCsv(rows, columns, { bom = true, delimiter = ',', safe = true, eol = '\r\n' } = {}) {
  const list = Array.isArray(rows) ? rows : [];
  const delim = typeof delimiter === 'string' && delimiter.length === 1 && !/["\r\n]/.test(delimiter) ? delimiter : ',';
  let cols = Array.isArray(columns) && columns.length ? columns : null;
  if (!cols) {
    const keys = [];
    for (const row of list) {
      if (row && typeof row === 'object') for (const k of Object.keys(row)) if (!keys.includes(k)) keys.push(k);
    }
    cols = keys.map((key) => ({ key }));
  }
  const needsQuote = (s) => s.includes(delim) || s.includes('"') || s.includes('\r') || s.includes('\n')
    || /^\s|\s$/.test(s);
  const field = (value, isHeader = false) => {
    let s = cellText(value);
    if (safe && !isHeader && typeof value !== 'number' && typeof value !== 'bigint' && FORMULA_START.test(s)) s = `'${s}`;
    return needsQuote(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = [cols.map((c) => field(c.header ?? c.key, true)).join(delim)];
  for (const row of list) {
    lines.push(cols.map((c) => {
      let value;
      try {
        value = typeof c.get === 'function' ? c.get(row) : row == null ? undefined : row[c.key];
      } catch {
        value = '';
      }
      return field(value);
    }).join(delim));
  }
  return `${bom ? '﻿' : ''}${lines.join(eol)}${eol}`;
}

/* ------------------------------------------------------------------------ */
/* JSON                                                                     */
/* ------------------------------------------------------------------------ */

function isBinary(v) {
  return v instanceof ArrayBuffer || ArrayBuffer.isView(v)
    || (typeof SharedArrayBuffer !== 'undefined' && v instanceof SharedArrayBuffer);
}

/**
 * Convert a value to a JSON-safe structure: Dates → ISO strings (invalid →
 * null), Map → object, Set → array, typed arrays / ArrayBuffers → omitted,
 * BigInt → decimal string, RegExp → its source, Error → { name, message },
 * functions / symbols → omitted, objects with toJSON() → its result, cyclic
 * references → '[Circular]'.
 */
function toPlain(value, stack) {
  if (value === null) return null;
  const t = typeof value;
  if (t === 'string' || t === 'boolean') return value;
  if (t === 'number') return Number.isFinite(value) ? value : null;
  if (t === 'bigint') return value.toString();
  if (t === 'undefined' || t === 'function' || t === 'symbol') return undefined;
  if (value instanceof Date) return Number.isNaN(value.getTime()) ? null : value.toISOString();
  if (isBinary(value)) return undefined;
  if (value instanceof RegExp) return value.source;
  if (stack.includes(value)) return '[Circular]';
  stack.push(value);
  try {
    if (typeof value.toJSON === 'function' && !(value instanceof Map) && !(value instanceof Set)) {
      return toPlain(value.toJSON(), stack);
    }
    if (value instanceof Error) {
      return { name: value.name, message: value.message };
    }
    if (value instanceof Map) {
      const out = {};
      for (const [k, v] of value) {
        const plain = toPlain(v, stack);
        if (plain !== undefined) out[typeof k === 'string' ? k : String(toPlain(k, stack) ?? k)] = plain;
      }
      return out;
    }
    if (Array.isArray(value)) {
      // Omitting an element would shift positions: use null like JSON.stringify.
      return value.map((v) => {
        const plain = toPlain(v, stack);
        return plain === undefined ? null : plain;
      });
    }
    if (value instanceof Set) {
      const out = [];
      for (const v of value) {
        const plain = toPlain(v, stack);
        if (plain !== undefined) out.push(plain);
      }
      return out;
    }
    const out = {};
    for (const k of Object.keys(value)) {
      const plain = toPlain(value[k], stack);
      if (plain !== undefined) out[k] = plain;
    }
    return out;
  } finally {
    stack.pop();
  }
}

/**
 * Pretty JSON (2 spaces) that handles Dates (ISO), Map (object), Set (array),
 * Uint8Array / binary (omitted), BigInt (string) and cycles.
 * @param {any} value
 * @returns {string}
 */
export function toJson(value) {
  const plain = toPlain(value, []);
  return JSON.stringify(plain === undefined ? null : plain, null, 2);
}

/* ------------------------------------------------------------------------ */
/* Scan tables                                                              */
/* ------------------------------------------------------------------------ */

/**
 * Default columns for {@link scanHostRows} rows (extension). Headers are
 * English; the UI may pass its own translated column list.
 */
export const HOST_COLUMNS = Object.freeze([
  { key: 'name', header: 'Hostname' },
  { key: 'status', header: 'DNS status' },
  { key: 'kind', header: 'Classification' },
  { key: 'provider', header: 'Provider' },
  { key: 'hidesOrigin', header: 'Origin hidden' },
  { key: 'dangling', header: 'Dangling CNAME' },
  { key: 'ipv4', header: 'IPv4' },
  { key: 'ipv6', header: 'IPv6' },
  { key: 'cnames', header: 'CNAME chain' },
  { key: 'ttl', header: 'TTL' },
  { key: 'covered', header: 'Covered by certificate' },
  { key: 'coveredBy', header: 'Covered by name' },
  { key: 'servers', header: 'Servers' },
  { key: 'origins', header: 'Found by' },
  { key: 'wildcardSuspect', header: 'Wildcard suspect' },
  { key: 'historicalIps', header: 'Historical IPs' },
  { key: 'resolver', header: 'Resolver' },
  { key: 'error', header: 'Error' }
].map((c) => Object.freeze(c)));

/** Default columns for {@link scanServerRows} rows (extension). */
export const SERVER_COLUMNS = Object.freeze([
  { key: 'server', header: 'Server' },
  { key: 'serverIps', header: 'Server IPs' },
  { key: 'groups', header: 'Groups' },
  { key: 'needsCert', header: 'Needs certificate' },
  { key: 'host', header: 'Hostname' },
  { key: 'ip', header: 'IP' },
  { key: 'via', header: 'Matched via' },
  { key: 'covered', header: 'Covered by certificate' }
].map((c) => Object.freeze(c)));

/**
 * One flat row per host of a ScanResult (list fields stay arrays; toCsv joins
 * them with spaces).
 * @param {object} scan ScanResult
 * @returns {object[]}
 */
export function scanHostRows(scan) {
  const hosts = scan && Array.isArray(scan.hosts) ? scan.hosts : [];
  return hosts.map((h) => {
    const res = h.resolution || {};
    const cls = h.classification || {};
    return {
      name: h.name,
      status: res.status ?? null,
      kind: cls.kind ?? null,
      provider: cls.provider ? cls.provider.name : null,
      providerId: cls.provider ? cls.provider.id : null,
      hidesOrigin: !!cls.hidesOrigin,
      certManagedByProvider: !!cls.certManagedByProvider,
      dangling: !!cls.dangling,
      reasonKey: cls.reasonKey ?? null,
      ipv4: [...(res.ipv4 || [])],
      ipv6: [...(res.ipv6 || [])],
      cnames: [...(res.cnames || [])],
      ttl: Number.isFinite(res.ttl) ? res.ttl : null,
      resolver: res.resolver ?? null,
      covered: h.cert ? !!h.cert.covered : null,
      coveredBy: h.cert && h.cert.by ? h.cert.by : null,
      servers: (h.servers || []).map((s) => `${s.name} (${s.ip})`),
      serverIds: [...new Set((h.servers || []).map((s) => s.serverId))],
      origins: [...(h.origins || [])],
      wildcardSuspect: !!h.wildcardSuspect,
      historicalIps: [...new Set((h.ipHints || []).map((x) => x.ip))],
      error: res.error ?? null
    };
  });
}

/**
 * One row per (server, host) pair of the scan's server groups, followed by
 * one row per unmatched direct IP (`server` empty, `matched: false`).
 * @param {object} scan ScanResult
 * @returns {object[]}
 */
export function scanServerRows(scan) {
  const rows = [];
  for (const g of scan && Array.isArray(scan.servers) ? scan.servers : []) {
    const s = g.server || {};
    const base = {
      server: s.name ?? s.id ?? '',
      serverId: s.id ?? null,
      serverIps: [...(s.ips || [])],
      groups: [...(s.groups || [])],
      needsCert: !!g.needsCert,
      maybeNeedsCert: !!g.maybeNeedsCert,
      matched: true
    };
    const hosts = Array.isArray(g.hosts) && g.hosts.length ? g.hosts : [null];
    for (const h of hosts) {
      rows.push({
        ...base,
        host: h ? h.name : null,
        ip: h ? h.ip : null,
        via: h ? h.via : null,
        covered: h ? h.covered : null
      });
    }
  }
  for (const u of scan && Array.isArray(scan.unmatchedIps) ? scan.unmatchedIps : []) {
    for (const host of u.hosts && u.hosts.length ? u.hosts : [null]) {
      const hr = scan.hosts ? scan.hosts.find((x) => x.name === host) : null;
      rows.push({
        server: '',
        serverId: null,
        serverIps: [],
        groups: [],
        needsCert: false,
        maybeNeedsCert: false,
        matched: false,
        host,
        ip: u.ip,
        via: 'dns',
        covered: hr && hr.cert ? !!hr.cert.covered : null
      });
    }
  }
  return rows;
}

/* ------------------------------------------------------------------------ */
/* CLI helper files                                                         */
/* ------------------------------------------------------------------------ */

/**
 * Hostnames for `ssl_origin_scan.py -n names.txt`, one per line (sorted, with
 * a trailing newline; '' when empty). Wildcard-suspect names are excluded.
 * @param {object} scan ScanResult
 * @param {{ onlyCovered?: boolean }} [opts] onlyCovered: only names the scanned certificate covers
 * @returns {string}
 */
export function namesForCli(scan, { onlyCovered = false } = {}) {
  const hosts = scan && Array.isArray(scan.hosts) ? scan.hosts : [];
  const names = new Set();
  for (const h of hosts) {
    if (!h || typeof h.name !== 'string' || h.wildcardSuspect) continue;
    if (onlyCovered && !(h.cert && h.cert.covered)) continue;
    names.add(h.name);
  }
  const list = sortHostnames([...names]);
  return list.length ? `${list.join('\n')}\n` : '';
}

/**
 * A server name as ONE token of a `-t targets.txt` line, or '' when nothing usable is left (the
 * IPs are then written bare). The CLI splits a line on whitespace, ',' and ';', drops `#`, `;` and
 * `//` comments (also after a space), skips `key=value` Ansible variables and, like Python's
 * `splitlines()`, breaks lines on control characters — so every run of those becomes '_'; so does
 * ':', or a name such as `ansible_host: web` would make the CLI read the file as YAML. A name
 * that is itself an IP address or an IP range (`192.0.2.50-60`) is dropped: the CLI would probe
 * it as one.
 * @param {unknown} name
 * @returns {string}
 */
export function cliServerName(name) {
  const raw = String(name ?? '').trim();
  // eslint-disable-next-line no-control-regex
  const token = raw.replace(/[\s\x00-\x1f\x7f\x85,;#=/:]+/g, '_');
  return token && !normalizeIP(raw) && !isIpRangeToken(token) ? token : '';
}

/** An IP range as the CLI's is_ip_block reads one: `first-last` or `a.b.c.d-e`. */
function isIpRangeToken(token) {
  const dash = token.indexOf('-');
  if (dash < 1) return false;
  const start = normalizeIP(token.slice(0, dash));
  const end = token.slice(dash + 1);
  return !!start && (!!normalizeIP(end) || (/^\d+$/.test(end) && start.includes('.')));
}

/**
 * Targets for `ssl_origin_scan.py -t targets.txt`: "name ip" lines.
 * Accepts inventory Servers, ServerGroups ({ server }), origin hints
 * ({ ip, servers }), unmatched IP entries ({ ip, hosts }), or plain IP
 * strings; IPs without a server name are written bare. An inventory address
 * written with its own port (`Server.ports`) keeps it, as the CLI would scan it
 * reading the inventory: "web01 203.0.113.10:8443" (inventory.addressTargets).
 * De-duplicated by endpoint, in input order, with a trailing newline: a
 * server's address keeps only the endpoints no earlier line wrote (the first
 * name wins), so another server on the same address with a port of its own
 * still gets its line ("web02 203.0.113.10" after "web01 203.0.113.10:8443",
 * as the CLI scans both reading the inventory); a hint or an unmatched IP is
 * left out when any line has its address.
 * @param {Array<object|string>} servers
 * @returns {string}
 */
export function targetsForCli(servers) {
  const seenIps = new Set();
  const seenTargets = new Set();
  const lines = [];
  const add = (name, rawIp, server = null) => {
    const ip = normalizeIP(String(rawIp ?? ''));
    if (!ip) return;
    const targets = server
      ? addressTargets(server, ip).filter((target) => !seenTargets.has(target))
      : seenIps.has(ip) ? [] : [ip];
    if (!targets.length) return;
    seenIps.add(ip);
    for (const target of targets) seenTargets.add(target);
    lines.push([cliServerName(name), ...targets].filter(Boolean).join(' '));
  };
  for (const item of Array.isArray(servers) ? servers : []) {
    if (!item) continue;
    if (typeof item === 'string') {
      add('', item);
      continue;
    }
    const server = item.server && typeof item.server === 'object' ? item.server : item;
    if (Array.isArray(server.ips) && server.ips.length) {
      for (const ip of server.ips) add(server.name ?? server.id, ip, server);
      continue;
    }
    if (item.ip) {
      const named = Array.isArray(item.servers) && item.servers.length ? item.servers[0].name : '';
      add(named, item.ip);
    }
  }
  return lines.length ? `${lines.join('\n')}\n` : '';
}

/** Quote a path for POSIX shells and PowerShell alike when needed. */
function shellArg(s) {
  const v = String(s);
  return /^[A-Za-z0-9_.,/:\\-]+$/.test(v) ? v : `'${v.replace(/'/g, "'\\''")}'`;
}

/**
 * The CLI invocation for the downloaded helper files, e.g.
 * `python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem`.
 * Extensions: `certFile: null` omits --cert; `python`, `script`, `ports`,
 * `json`, `csv` options.
 * @param {{ namesFile?: string, targetsFile?: string, certFile?: string|null, python?: string,
 *   script?: string, ports?: number[]|string|null, json?: string|null, csv?: string|null }} [opts]
 * @returns {string}
 */
export function cliCommand({
  namesFile = 'names.txt', targetsFile = 'targets.txt', certFile = 'new-cert.pem',
  python = 'python3', script = 'ssl_origin_scan.py', ports = null, json = null, csv = null
} = {}) {
  const parts = [python, shellArg(script), '-t', shellArg(targetsFile), '-n', shellArg(namesFile)];
  if (certFile) parts.push('--cert', shellArg(certFile));
  const portList = Array.isArray(ports) ? ports.join(',') : ports;
  if (portList) parts.push('--ports', shellArg(portList));
  if (json) parts.push('--json', shellArg(json));
  if (csv) parts.push('--csv', shellArg(csv));
  return parts.join(' ');
}
