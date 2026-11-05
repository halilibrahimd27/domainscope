/**
 * ipscan.js — the IP Scan view's model: an IPv4 range as a map of addresses, each used,
 * claimed, free, reserved or not scanned, from the JSON reports of the companion CLI
 * (cli/ip_scan.py --json) and the workspace's server inventory. DOM-free; runs in browsers and
 * Node 22. Nothing is sent: a browser can neither ping nor reach an internal network, so the
 * probing is the CLI's, run from a machine on that network, and this module only reads.
 *
 * - {@link parseScanRange}: what the user typed → the addresses of the map: IPv4 networks
 *   (`10.0.5.0/24`; /30 and wider mark their network and broadcast address), ranges
 *   (`10.0.5.10-10.0.5.50` or `10.0.5.10-50`) and addresses, at most
 *   {@link IPSCAN_MAX_ADDRESSES} together. Private ranges are the point here (unlike
 *   lib/ptrsweep.js, whose public resolvers cannot see them).
 * - {@link readScanReport}: one file of the CLI → a checked report (what is not one says
 *   why, {@link REPORT_ERRORS}); every value is validated, nothing of the file is trusted.
 * - {@link mergeScanReports}: several reports (two jump hosts, last week and today) → one
 *   answer per address, the newest report's.
 * - {@link addressMap}: the range, the merged reports and the inventory index → one row per
 *   address with its state ({@link IPSCAN_STATES}), the reasons ({@link IPSCAN_REASONS}),
 *   the evidence and the servers of the inventory on it; the counts; the /24 groups of the
 *   map; the free runs.
 * - {@link suggestFree}, {@link freeRuns}, {@link ipscanCsvRows}, {@link freeListText},
 *   {@link cliCommand}, {@link ipscanSummaryFacts}: what the view offers.
 *
 * States: `used` — something answered the scan (a ping, a TCP port open or closed with a
 * reset, a MAC address in the ARP table); `claimed` — nothing answered (or no scan covers it),
 * but the inventory lists a server on it or it has a reverse DNS name that is not a provider's
 * template: taken on record, check before use; `free` — the scan saw nothing and nothing claims
 * it (`confirmed` when no device answered ARP or a router called it unreachable); `reserved` —
 * the network or broadcast address of a /30 or wider network; `unscanned` — no report covers it.
 */

import { parseIP, formatIP, parseCidr, normalizeIP } from './ip.js';
import { lookupServers } from './inventory.js';

/* ------------------------------------------------------------------------ */
/* Limits and vocabularies (frozen; the i18n coverage test derives keys)    */
/* ------------------------------------------------------------------------ */

/** Most addresses one map shows (a /20: 16 groups of 256). */
export const IPSCAN_MAX_ADDRESSES = 4096;
/** Largest report file read (a /16 of the CLI is about 25 MB of JSON; the map shows a /20). */
export const IPSCAN_MAX_BYTES = 16 * 1048576;
/** Reports open at once. */
export const IPSCAN_MAX_REPORTS = 10;
/** The CLI report's schema, and the CLI's file name. */
export const IPSCAN_SCHEMA = 'domainscope.ip-scan/1';
export const CLI_FILE = 'ip_scan.py';
/** Where the published site serves the CLI (tools/assemble-site.mjs copies cli/). */
export const CLI_PATH = 'cli/ip_scan.py';

/** Per-address states, in the order the counts show them. */
export const IPSCAN_STATES = Object.freeze(['used', 'claimed', 'free', 'reserved', 'unscanned']);
/** What the list and the map can show ('taken' = used or claimed; 'confirmed' = free and confirmed). */
export const IPSCAN_FILTERS = Object.freeze(['all', 'taken', 'used', 'claimed', 'free', 'confirmed', 'unscanned', 'reserved']);
/** The evidence behind a state (the CLI's reasons, and the inventory's). */
export const IPSCAN_REASONS = Object.freeze(['icmp', 'tcp-open', 'tcp-refused', 'arp', 'ptr', 'inventory', 'arp-incomplete', 'unreachable']);
/** Problems of the typed range. */
export const RANGE_ISSUES = Object.freeze(['invalid', 'v6', 'reversed', 'too-large', 'host-bits', 'nothing']);
export const RANGE_ISSUE_SEVERITY = Object.freeze({
  invalid: 'error', v6: 'error', reversed: 'error', 'too-large': 'error', 'host-bits': 'info', nothing: 'error'
});
/** Why a file is not read. */
export const REPORT_ERRORS = Object.freeze(['too-large', 'not-json', 'not-report', 'version', 'no-results']);

const CLI_STATES = new Set(['used', 'claimed', 'free', 'reserved']);
const CLI_REASONS = new Set(['icmp', 'tcp-open', 'tcp-refused', 'arp', 'ptr', 'arp-incomplete', 'unreachable']);
const MAX_RESULTS = 65536;
const MAX_PORTS = 64;
const MAX_NAMES = 4;
const MAX_TEXT = 253;
const MAX_SERVER = 120;
const MAC_RE = /^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/;
const NAME_RE = /^[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?$/i;

/* ------------------------------------------------------------------------ */
/* The range                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ScanBlock
 * @property {string} input the token as typed
 * @property {'cidr'|'range'|'ip'} kind
 * @property {string} label canonical: '10.0.5.0/24', '10.0.5.10-10.0.5.50' or the address
 * @property {bigint} first
 * @property {bigint} last
 * @property {bigint|null} network a /30 or wider network: its network address
 * @property {bigint|null} broadcast ... and its broadcast address
 */

/**
 * @typedef {object} ScanRange
 * @property {ScanBlock[]} blocks
 * @property {string[]} addresses every address, block order, each once (none while an error stands)
 * @property {number} total distinct addresses
 * @property {Array<{ code: string, severity: string, params: object }>} issues
 * @property {boolean} ok
 * @property {string} label short text for the heading and the CLI command
 */

const issue = (code, params = {}) => ({ code, severity: RANGE_ISSUE_SEVERITY[code], params });
const listText = (items, max = 4) => (items.length > max ? `${items.slice(0, max).join(', ')} (+${items.length - max})` : items.join(', '));
const RANGE_RE = /^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$/;

/**
 * Tokens of the typed text: `#` starts a comment, whitespace / commas / semicolons split, and
 * a range typed with spaces or an en dash (`10.0.5.10 - 10.0.5.20`, `10.0.5.10–20`) is one.
 * @param {string} text
 * @returns {string[]}
 */
export function rangeTokens(text) {
  return String(text ?? '').split(/\r?\n/)
    .map((line) => line.replace(/#.*$/, ''))
    .join(' ')
    .replace(/(\d)[ \t]*[-–][ \t]*(\d)/g, '$1-$2')
    .split(/[\s,;]+/)
    .filter(Boolean);
}

/**
 * Read what the user typed.
 * @param {string} text
 * @param {{ max?: number }} [opts]
 * @returns {ScanRange}
 */
export function parseScanRange(text, { max = IPSCAN_MAX_ADDRESSES } = {}) {
  const out = { blocks: [], addresses: [], total: 0, issues: [], ok: false, label: '' };
  const tokens = rangeTokens(text);
  if (!tokens.length) return out;
  const invalid = [];
  const v6 = [];
  const reversed = [];
  for (const token of tokens) {
    if (token.includes(':')) {
      v6.push(token);
      continue;
    }
    if (token.includes('/')) {
      const c = parseCidr(token);
      if (!c || c.version !== 4) {
        invalid.push(token);
        continue;
      }
      const last = c.network + (1n << BigInt(32 - c.prefix)) - 1n;
      const label = c.prefix === 32 ? formatIP(c.network, 4) : `${formatIP(c.network, 4)}/${c.prefix}`;
      const typed = parseIP(token.slice(0, token.indexOf('/')));
      if (typed && typed.value !== c.network) out.issues.push(issue('host-bits', { input: token, cidr: label }));
      const wide = c.prefix <= 30;
      out.blocks.push({
        input: token, kind: c.prefix === 32 ? 'ip' : 'cidr', label, first: c.network, last,
        network: wide ? c.network : null, broadcast: wide ? last : null
      });
      continue;
    }
    const m = RANGE_RE.exec(token);
    if (m) {
      const start = parseIP(m[1]);
      let end = m[2].includes('.') ? parseIP(m[2]) : null;
      if (!end && start && !m[2].includes('.') && Number(m[2]) <= 255) {
        end = { version: 4, value: (start.value & ~0xffn) | BigInt(Number(m[2])) };
      }
      if (!start || !end || start.version !== 4 || end.version !== 4) {
        invalid.push(token);
      } else if (end.value < start.value) {
        reversed.push(token);
      } else {
        const one = end.value === start.value;
        out.blocks.push({
          input: token, kind: one ? 'ip' : 'range',
          label: one ? formatIP(start.value, 4) : `${formatIP(start.value, 4)}-${formatIP(end.value, 4)}`,
          first: start.value, last: end.value, network: null, broadcast: null
        });
      }
      continue;
    }
    const ip = parseIP(token);
    if (!ip || ip.version !== 4) {
      invalid.push(token);
      continue;
    }
    out.blocks.push({ input: token, kind: 'ip', label: formatIP(ip.value, 4), first: ip.value, last: ip.value, network: null, broadcast: null });
  }
  if (invalid.length) out.issues.push(issue('invalid', { items: listText(invalid), count: invalid.length }));
  if (v6.length) out.issues.push(issue('v6', { items: listText(v6), count: v6.length }));
  if (reversed.length) out.issues.push(issue('reversed', { items: listText(reversed), count: reversed.length }));
  // the same block typed twice is one
  const seen = new Set();
  out.blocks = out.blocks.filter((b) => (seen.has(b.label) ? false : seen.add(b.label)));
  if (!out.blocks.length) {
    if (!out.issues.some((i) => i.severity === 'error')) out.issues.push(issue('nothing'));
    return out;
  }
  out.label = listText(out.blocks.map((b) => b.label), 3);
  out.total = distinctCount(out.blocks);
  if (out.total > max) {
    const wide = out.blocks.find((b) => b.kind === 'cidr' && b.last - b.first + 1n > BigInt(max));
    const suggestion = wide ? `${formatIP(wide.first, 4)}/${32 - Math.floor(Math.log2(max))}` : '';
    out.issues.push(issue('too-large', { count: out.total, max, suggestion }));
  }
  if (out.issues.some((i) => i.severity === 'error')) return out;
  out.addresses = addressesOf(out.blocks);
  out.ok = true;
  return out;
}

function distinctCount(blocks) {
  const spans = blocks.map((b) => [b.first, b.last]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  let count = 0n;
  let end = -1n;
  for (const [first, last] of spans) {
    if (last <= end) continue;
    count += last - (first > end ? first : end + 1n) + 1n;
    end = last;
  }
  return Number(count);
}

/** Every address of the blocks, block order, each once. */
function addressesOf(blocks) {
  const seen = new Set();
  const out = [];
  for (const b of blocks) {
    for (let v = b.first; v <= b.last; v += 1n) {
      const ip = formatIP(v, 4);
      if (seen.has(ip)) continue;
      seen.add(ip);
      out.push(ip);
    }
  }
  return out;
}

/**
 * 'network' / 'broadcast' when the address is that of a /30 or wider block of the range.
 * @param {string} ip
 * @param {ScanBlock[]} blocks
 * @returns {'network'|'broadcast'|null}
 */
export function reservedRole(ip, blocks) {
  const p = parseIP(ip);
  if (!p) return null;
  for (const b of blocks || []) {
    if (b.network !== null && p.value === b.network) return 'network';
    if (b.broadcast !== null && p.value === b.broadcast) return 'broadcast';
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* The CLI's reports                                                         */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ScanRow one address of a report, every value checked
 * @property {string} ip
 * @property {'used'|'claimed'|'free'|'reserved'} state
 * @property {boolean} confirmed
 * @property {string[]} reasons
 * @property {'network'|'broadcast'|null} reserved
 * @property {number|null} rttMs
 * @property {number[]} open
 * @property {number[]} refused
 * @property {string|null} mac
 * @property {boolean|null} onLink
 * @property {string[]} ptr
 * @property {boolean} ptrTemplated
 * @property {Record<string, string>} web port → Server header
 */

/**
 * @typedef {object} ScanReport
 * @property {string} id the same scan read twice has the same id
 * @property {string} name the file name
 * @property {Date|null} startedAt
 * @property {Date|null} finishedAt
 * @property {string[]} targets
 * @property {{ icmp: string, arp: string, ports: number[], ptr: boolean, web: boolean }} methods
 * @property {Map<string, ScanRow>} rows
 * @property {string[]} warnings
 */

const asDate = (v) => {
  if (typeof v !== 'string') return null;
  const d = new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};
const text = (v, max = MAX_TEXT) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, '').trim().slice(0, max) : '');
const ports = (v) => (Array.isArray(v) ? [...new Set(v.filter((p) => Number.isInteger(p) && p >= 1 && p <= 65535))].sort((a, b) => a - b).slice(0, MAX_PORTS) : []);

/**
 * One result row of the file → a checked row, or null when it is not one.
 * @param {any} r
 * @returns {ScanRow|null}
 */
function readRow(r) {
  if (!r || typeof r !== 'object') return null;
  const ip = typeof r.ip === 'string' ? normalizeIP(r.ip) : null;
  if (!ip || ip.includes(':') || !CLI_STATES.has(r.state)) return null;
  const mac = typeof r.mac === 'string' && MAC_RE.test(r.mac.toLowerCase()) ? r.mac.toLowerCase() : null;
  const ptr = Array.isArray(r.ptr) ? [...new Set(r.ptr.map((n) => text(n).toLowerCase().replace(/\.$/, '')).filter((n) => NAME_RE.test(n) && n.split('.').every((l) => l.length <= 63)))].slice(0, MAX_NAMES) : [];
  const web = {};
  if (r.web && typeof r.web === 'object' && !Array.isArray(r.web)) {
    for (const [port, server] of Object.entries(r.web).slice(0, 8)) {
      const p = Number(port);
      const s = text(server, MAX_SERVER);
      if (Number.isInteger(p) && p >= 1 && p <= 65535 && s) web[String(p)] = s;
    }
  }
  const rtt = typeof r.rttMs === 'number' && Number.isFinite(r.rttMs) && r.rttMs >= 0 && r.rttMs < 60000 ? r.rttMs : null;
  return {
    ip,
    state: r.state,
    confirmed: r.state === 'free' && r.confirmed === true,
    reasons: Array.isArray(r.reasons) ? [...new Set(r.reasons.filter((x) => CLI_REASONS.has(x)))] : [],
    reserved: r.reserved === 'network' || r.reserved === 'broadcast' ? r.reserved : null,
    rttMs: rtt,
    open: ports(r.open),
    refused: ports(r.refused),
    mac,
    onLink: typeof r.onLink === 'boolean' ? r.onLink : null,
    ptr,
    ptrTemplated: r.ptrTemplated === true,
    web
  };
}

/**
 * Read one file of the CLI (`ip_scan.py --json`).
 * @param {string} body
 * @param {{ name?: string }} [opts]
 * @returns {{ ok: true, report: ScanReport }|{ ok: false, error: string, detail?: string }}
 */
export function readScanReport(body, { name = '' } = {}) {
  const raw = typeof body === 'string' ? body : '';
  if (raw.length > IPSCAN_MAX_BYTES) return { ok: false, error: 'too-large' };
  let doc;
  try {
    doc = JSON.parse(raw.replace(/^﻿/, ''));
  } catch {
    return { ok: false, error: 'not-json' };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || typeof doc.schema !== 'string' || !doc.schema.startsWith('domainscope.ip-scan/')) {
    return { ok: false, error: 'not-report' };
  }
  if (doc.schema !== IPSCAN_SCHEMA) return { ok: false, error: 'version', detail: text(doc.schema.slice('domainscope.ip-scan/'.length), 16) };
  const rows = new Map();
  for (const r of Array.isArray(doc.results) ? doc.results.slice(0, MAX_RESULTS) : []) {
    const row = readRow(r);
    if (row && !rows.has(row.ip)) rows.set(row.ip, row);
  }
  if (!rows.size) return { ok: false, error: 'no-results' };
  const m = doc.methods && typeof doc.methods === 'object' ? doc.methods : {};
  const finishedAt = asDate(doc.finishedAt);
  const targets = Array.isArray(doc.targets) ? doc.targets.map((x) => text(x, 64)).filter(Boolean).slice(0, 64) : [];
  return {
    ok: true,
    report: {
      id: `${finishedAt ? finishedAt.toISOString() : ''}|${targets.join(',')}|${rows.size}`,
      name: text(name, 200),
      startedAt: asDate(doc.startedAt),
      finishedAt,
      targets,
      methods: {
        icmp: text(m.icmp, 24) || 'unknown',
        arp: text(m.arp, 24) || 'unknown',
        ports: ports(m.tcpPorts),
        ptr: m.ptr !== false,
        web: m.web !== false
      },
      rows,
      warnings: Array.isArray(doc.warnings) ? doc.warnings.map((w) => text(w, 300)).filter(Boolean).slice(0, 10) : []
    }
  };
}

/**
 * Several reports → one row per address: the newest report's (by finishedAt; a report without
 * a date counts as oldest, then the order they were opened).
 * @param {ScanReport[]} reports
 * @returns {Map<string, { row: ScanRow, report: number }>} report = index in `reports`
 */
export function mergeScanReports(reports) {
  const order = (reports || []).map((r, i) => ({ r, i }))
    .sort((a, b) => ((a.r.finishedAt ? a.r.finishedAt.getTime() : -Infinity) - (b.r.finishedAt ? b.r.finishedAt.getTime() : -Infinity)) || a.i - b.i);
  const out = new Map();
  for (const { r, i } of order) {
    for (const [ip, row] of r.rows) out.set(ip, { row, report: i });
  }
  return out;
}

/**
 * The range the reports cover, as text for the range field when the user typed none: the
 * targets of the reports (each a network, a range or an address), else their addresses folded.
 * @param {ScanReport[]} reports
 * @returns {string}
 */
export function reportsRange(reports) {
  const targets = [...new Set((reports || []).flatMap((r) => r.targets))];
  if (targets.length && parseScanRange(targets.join(' ')).ok) return targets.join(' ');
  const ips = [...new Set((reports || []).flatMap((r) => [...r.rows.keys()]))];
  return foldAddresses(ips).join(' ');
}

/**
 * Consecutive addresses folded into ranges ('10.0.5.2-10.0.5.4').
 * @param {string[]} ips
 * @returns {string[]}
 */
export function foldAddresses(ips) {
  const values = [...new Set((ips || []).map((ip) => parseIP(ip)).filter((p) => p && p.version === 4).map((p) => p.value))]
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  const out = [];
  for (let i = 0; i < values.length;) {
    let j = i;
    while (j + 1 < values.length && values[j + 1] === values[j] + 1n) j += 1;
    out.push(i === j ? formatIP(values[i], 4) : `${formatIP(values[i], 4)}-${formatIP(values[j], 4)}`);
    i = j + 1;
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* The map                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} AddressRow
 * @property {string} ip
 * @property {number} octet the last octet (the map's cell text)
 * @property {'used'|'claimed'|'free'|'reserved'|'unscanned'} state
 * @property {boolean} confirmed free, and no device answered ARP / a router called it unreachable
 * @property {string[]} reasons
 * @property {'network'|'broadcast'|null} reserved
 * @property {ScanRow|null} scan
 * @property {number|null} report index of the report the scan row came from
 * @property {Array<{ id: string, name: string }>} servers the inventory's servers on the address
 * @property {string[]} names the reverse DNS names that claim it (not a provider's template)
 */

/**
 * The map of a range.
 * @param {{ range: ScanRange, reports?: ScanReport[], index?: Map<string, object[]>|null }} input
 * @returns {{ rows: AddressRow[], counts: Record<string, number>, groups: Array<{ label: string, rows: AddressRow[] }>,
 *   scanned: number, outside: number }}
 *   `outside`: addresses the reports hold that the range does not show
 */
export function addressMap({ range, reports = [], index = null }) {
  const merged = mergeScanReports(reports);
  const counts = { total: 0, freeConfirmed: 0 };
  for (const s of IPSCAN_STATES) counts[s] = 0;
  const rows = [];
  let scanned = 0;
  const shown = new Set();
  for (const ip of (range && range.ok ? range.addresses : [])) {
    shown.add(ip);
    const hit = merged.get(ip) || null;
    const scan = hit ? hit.row : null;
    const servers = index && index.size ? lookupServers([ip], index).map((m) => ({ id: m.server.id, name: m.server.name })) : [];
    const uniqServers = servers.filter((s, i) => servers.findIndex((x) => x.id === s.id) === i);
    const names = scan && scan.ptr.length && !scan.ptrTemplated ? scan.ptr : [];
    const reserved = reservedRole(ip, range.blocks) || (scan && scan.reserved) || null;
    let state;
    let reasons = [];
    let confirmed = false;
    if (reserved) {
      state = 'reserved';
    } else if (scan && scan.state === 'used') {
      state = 'used';
      reasons = [...scan.reasons];
    } else if (scan && scan.state === 'claimed') {
      state = 'claimed';
      reasons = [...scan.reasons];
    } else if (uniqServers.length) {
      state = 'claimed';
      reasons = scan ? scan.reasons.filter((r) => r !== 'arp-incomplete' && r !== 'unreachable') : [];
    } else if (scan) {
      state = scan.state === 'reserved' ? 'reserved' : 'free';
      confirmed = state === 'free' && scan.confirmed;
      reasons = state === 'free' ? [...scan.reasons] : [];
    } else {
      state = 'unscanned';
    }
    if (uniqServers.length && state !== 'reserved') reasons.push('inventory');
    if (scan) scanned += 1;
    counts[state] += 1;
    counts.total += 1;
    if (confirmed) counts.freeConfirmed += 1;
    rows.push({
      ip, octet: Number(ip.slice(ip.lastIndexOf('.') + 1)), state, confirmed, reasons, reserved,
      scan, report: hit ? hit.report : null, servers: uniqServers, names
    });
  }
  let outside = 0;
  for (const ip of merged.keys()) if (!shown.has(ip)) outside += 1;
  return { rows, counts, groups: groupsOf(rows), scanned, outside };
}

/** The rows by /24, in address order of their first row ('10.0.5.0/24'). */
function groupsOf(rows) {
  const map = new Map();
  for (const row of rows) {
    const key = `${row.ip.slice(0, row.ip.lastIndexOf('.'))}.0/24`;
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  }
  return [...map].map(([label, list]) => ({ label, rows: list }));
}

/**
 * Does a row pass a filter of the list / map?
 * @param {AddressRow} row
 * @param {string} filter one of {@link IPSCAN_FILTERS}
 * @returns {boolean}
 */
export function ipscanMatches(row, filter) {
  switch (filter) {
    case 'taken': return row.state === 'used' || row.state === 'claimed';
    case 'confirmed': return row.state === 'free' && row.confirmed;
    case 'used': case 'claimed': case 'free': case 'unscanned': case 'reserved': return row.state === filter;
    default: return true;
  }
}

/**
 * The free addresses to suggest, best first: confirmed free ones before the rest, address order
 * within each; never a reserved, claimed or unscanned address.
 * @param {AddressRow[]} rows
 * @param {{ count?: number }} [opts]
 * @returns {AddressRow[]}
 */
export function suggestFree(rows, { count = 8 } = {}) {
  const free = (rows || []).filter((r) => r.state === 'free');
  return [...free.filter((r) => r.confirmed), ...free.filter((r) => !r.confirmed)].slice(0, Math.max(0, count));
}

/**
 * Runs of consecutive free addresses, longest first (ties: address order): for a cluster that
 * needs several neighbouring addresses.
 * @param {AddressRow[]} rows
 * @param {{ min?: number, max?: number }} [opts]
 * @returns {Array<{ first: string, last: string, length: number, confirmed: number }>}
 */
export function freeRuns(rows, { min = 2, max = 5 } = {}) {
  const sorted = (rows || []).filter((r) => r.state === 'free')
    .map((r) => ({ r, v: parseIP(r.ip).value }))
    .sort((a, b) => (a.v < b.v ? -1 : a.v > b.v ? 1 : 0));
  const runs = [];
  for (let i = 0; i < sorted.length;) {
    let j = i;
    while (j + 1 < sorted.length && sorted[j + 1].v === sorted[j].v + 1n) j += 1;
    const length = j - i + 1;
    if (length >= min) {
      runs.push({ first: sorted[i].r.ip, last: sorted[j].r.ip, length, confirmed: sorted.slice(i, j + 1).filter((x) => x.r.confirmed).length, at: i });
    }
    i = j + 1;
  }
  return runs.sort((a, b) => b.length - a.length || a.at - b.at).slice(0, Math.max(0, max)).map(({ at, ...run }) => run);
}

/** The CSV columns of the list ({@link ipscanCsvRows}). */
export const IPSCAN_CSV_COLUMNS = Object.freeze(['ip', 'state', 'confirmed', 'reasons', 'ping_ms', 'open_ports', 'refused_ports', 'mac', 'ptr', 'web', 'servers', 'reserved']);

/**
 * The rows as CSV records (lib/export.js toCsv makes the file, spreadsheet-safe).
 * @param {AddressRow[]} rows
 * @returns {object[]}
 */
export function ipscanCsvRows(rows) {
  return (rows || []).map((r) => ({
    ip: r.ip,
    state: r.state,
    confirmed: r.state === 'free' ? (r.confirmed ? 'yes' : 'no') : '',
    reasons: r.reasons.join(' '),
    ping_ms: r.scan && r.scan.rttMs !== null ? r.scan.rttMs : '',
    open_ports: r.scan ? r.scan.open.join(' ') : '',
    refused_ports: r.scan ? r.scan.refused.join(' ') : '',
    mac: r.scan && r.scan.mac ? r.scan.mac : '',
    ptr: r.scan ? r.scan.ptr.join(' ') : '',
    web: r.scan ? Object.entries(r.scan.web).map(([p, s]) => `${p}=${s}`).join(' ') : '',
    servers: r.servers.map((s) => s.name).join(' '),
    reserved: r.reserved || ''
  }));
}

/**
 * The free addresses, one a line (confirmed ones only when `confirmedOnly`).
 * @param {AddressRow[]} rows
 * @param {{ confirmedOnly?: boolean }} [opts]
 * @returns {string}
 */
export function freeListText(rows, { confirmedOnly = false } = {}) {
  const list = (rows || []).filter((r) => r.state === 'free' && (!confirmedOnly || r.confirmed)).map((r) => r.ip);
  return list.length ? `${list.join('\n')}\n` : '';
}

/**
 * The CLI command that scans the range (the label of a parsed range; a placeholder without one).
 * @param {ScanRange|null} range
 * @param {{ file?: string }} [opts]
 * @returns {string}
 */
export function cliCommand(range, { file = 'scan.json' } = {}) {
  const targets = range && range.ok ? range.blocks.map((b) => b.label) : ['10.0.5.0/24'];
  return `python3 ${CLI_FILE} ${targets.join(' ')} --json ${file}`;
}

/**
 * The Copy summary's facts (lib/summary.js ipscanSummary): the range, the counts, the free
 * addresses folded, the taken ones (address and state only — never a server name, MAC address or
 * DNS name of the reports: a summary goes into tickets and chats), when the newest scan ran.
 * @param {{ range: ScanRange, map: ReturnType<typeof addressMap>, reports: ScanReport[] }} input
 * @returns {object}
 */
export function ipscanSummaryFacts({ range, map, reports = [] }) {
  const times = reports.map((r) => r.finishedAt).filter((d) => d instanceof Date);
  return {
    range: range && range.ok ? range.label : '',
    counts: { ...map.counts },
    scanned: map.scanned,
    free: foldAddresses(map.rows.filter((r) => r.state === 'free').map((r) => r.ip)),
    confirmed: foldAddresses(map.rows.filter((r) => r.state === 'free' && r.confirmed).map((r) => r.ip)),
    taken: map.rows.filter((r) => r.state === 'used' || r.state === 'claimed').map((r) => ({ ip: r.ip, state: r.state })),
    reports: reports.length,
    at: times.length ? new Date(Math.max(...times.map((d) => d.getTime()))) : null
  };
}
