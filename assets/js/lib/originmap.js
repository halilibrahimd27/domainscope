/**
 * lib/originmap.js — a workspace's origin map: which server and port really serves a proxied
 * name, remembered once a CLI sweep, a zone file, a Verify origin check or a server comparison
 * found it. The workspace part 'origins' (lib/workspace.js): `{ v: 1, remember, entries }`.
 *
 * `remember` is the opt-in "Remember origins in this workspace" (off by default; while it is off
 * lib/originfill.js writes nothing). An entry: `{ name, ip, port, source, firstSeen,
 * lastConfirmed, server, stale }` — `source` where it was last confirmed ({@link ORIGIN_SOURCES}),
 * `server` an inventory name or null, `stale` null or `{ reason, at, ip?, port? }` once a later
 * run contradicted it ({@link STALE_REASONS}; ip / port: where the name was found instead).
 * Stale entries are kept and shown, never a scan's known origin ({@link knownForScan}).
 *
 * This module is the model and how it is read (it loads with the workspace store); the merge
 * rules and the sources' observations are lib/originfill.js. DOM-free and pure.
 */

import { normalizeHostname } from './domain.js';
import { normalizeIP } from './netinfo.js';

/** Where an entry was found / last confirmed. */
export const ORIGIN_SOURCES = Object.freeze(['cli-json', 'zone', 'verify', 'compare', 'manual']);
/** Why an entry is stale: the source that contradicted it, and how. */
export const STALE_REASONS = Object.freeze(['cli-elsewhere', 'cli-not-hosted', 'verify-elsewhere', 'verify-not-hosted', 'zone-other']);
/** Caps: entries in all, entries of one name (a pool), the server name's length. */
export const ORIGIN_MAP_LIMITS = Object.freeze({ entries: 2000, perName: 16, server: 80 });
/** The port an entry gets when its source names none (a zone file). */
export const ORIGIN_DEFAULT_PORT = 443;

// eslint-disable-next-line no-control-regex
const JUNK_RE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;

/** An ISO time of a date or a parseable value, else null. */
export const originTime = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
};
const ms = (v) => (v ? Date.parse(v) || 0 : 0);

/** A server name as an entry keeps it (controls removed, at most 80 characters), or null. */
export const originServer = (v) => (typeof v === 'string'
  ? v.normalize('NFC').replace(JUNK_RE, ' ').replace(/\s+/g, ' ').trim().slice(0, ORIGIN_MAP_LIMITS.server).trim() || null : null);

/** A name as the map keeps it (domain.js normalizeHostname, `*.x` allowed), or null. */
export function originName(input) {
  return typeof input === 'string' ? normalizeHostname(input, { allowWildcard: true }) : null;
}

/** A port 1–65535; empty → {@link ORIGIN_DEFAULT_PORT}; anything else → null. */
export function originPort(v) {
  if (v === null || v === undefined || v === '') return ORIGIN_DEFAULT_PORT;
  const n = typeof v === 'number' ? v : (/^\s*\d{1,5}\s*$/.test(String(v)) ? Number(v) : NaN);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null;
}

/** An entry's key: `name|ip|port`. */
export const originKey = (e) => `${e.name}|${e.ip}|${e.port}`;

/** The CLI target of an entry: the address on 443, `ip:port` / `[v6]:port` on another port. */
export function originTarget(e) {
  if (e.port === ORIGIN_DEFAULT_PORT) return e.ip;
  return e.ip.includes(':') ? `[${e.ip}]:${e.port}` : `${e.ip}:${e.port}`;
}

/** One stored entry, checked; null when it is not one. */
function sanitizeEntry(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const name = originName(raw.name);
  const ip = normalizeIP(String(raw.ip ?? ''));
  const port = originPort(raw.port);
  const last = originTime(raw.lastConfirmed) || originTime(raw.firstSeen);
  if (!name || !ip || !port || !last) return null;
  const first = originTime(raw.firstSeen);
  let stale = null;
  const s = raw.stale;
  if (s && typeof s === 'object' && STALE_REASONS.includes(s.reason) && originTime(s.at)) {
    stale = { reason: s.reason, at: originTime(s.at) };
    const byIp = normalizeIP(String(s.ip ?? ''));
    const byPort = originPort(s.port);
    if (byIp && byPort) Object.assign(stale, { ip: byIp, port: byPort });
  }
  return {
    name, ip, port, source: ORIGIN_SOURCES.includes(raw.source) ? raw.source : 'manual',
    firstSeen: first && ms(first) <= ms(last) ? first : last, lastConfirmed: last, server: originServer(raw.server), stale
  };
}

/** Active before stale, then the most recently confirmed first. */
const rank = (a, b) => Number(!!a.stale) - Number(!!b.stale) || ms(b.lastConfirmed) - ms(a.lastConfirmed);

/**
 * The map as the workspace keeps it: every entry checked, one per key (the latest
 * confirmation), at most {@link ORIGIN_MAP_LIMITS} (active and recent entries kept first), by
 * name; null when remembering is off and there is no entry (an empty part is not stored).
 * @param {unknown} value
 * @returns {{ v: 1, remember: boolean, entries: object[] }|null}
 */
export function sanitizeOriginMap(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const byKey = new Map();
  for (const raw of Array.isArray(value.entries) ? value.entries.slice(0, ORIGIN_MAP_LIMITS.entries * 4) : []) {
    const e = sanitizeEntry(raw);
    const prev = e && byKey.get(originKey(e));
    if (e && (!prev || ms(e.lastConfirmed) > ms(prev.lastConfirmed))) byKey.set(originKey(e), e);
  }
  const perName = new Map();
  const entries = [];
  for (const e of [...byKey.values()].sort(rank)) {
    const n = perName.get(e.name) || 0;
    if (n >= ORIGIN_MAP_LIMITS.perName || entries.length >= ORIGIN_MAP_LIMITS.entries) continue;
    perName.set(e.name, n + 1);
    entries.push(e);
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0) || rank(a, b) || (originKey(a) < originKey(b) ? -1 : 1));
  const remember = value.remember === true;
  return remember || entries.length ? { v: 1, remember, entries } : null;
}

/**
 * A name's entries: its own and a `*.parent` one covering it, active first, newest first.
 * @param {object|null} map
 * @param {string} name
 * @returns {object[]}
 */
export function originsFor(map, name) {
  const n = originName(name);
  const m = sanitizeOriginMap(map);
  if (!n || !m) return [];
  const dot = n.indexOf('.');
  const wild = dot > 0 && !n.startsWith('*.') ? `*.${n.slice(dot + 1)}` : null;
  return m.entries.filter((e) => e.name === n || e.name === wild).sort(rank);
}

/**
 * The active (not stale) entries as a scan's known origins (lib/scanner.js `knownOrigins`).
 * @param {object|null} map
 * @returns {Array<{ name: string, ip: string, port: number, server: string|null, source: string, lastConfirmed: string }>}
 */
export function knownForScan(map) {
  const m = sanitizeOriginMap(map);
  return m ? m.entries.filter((e) => !e.stale)
    .map(({ name, ip, port, server, source, lastConfirmed }) => ({ name, ip, port, server, source, lastConfirmed })) : [];
}
