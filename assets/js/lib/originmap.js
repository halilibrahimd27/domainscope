/**
 * lib/originmap.js — a workspace's origin map: which server and port really serves a proxied
 * name, remembered once a CLI sweep, a zone file, a Verify origin check or a server comparison
 * found it. The workspace part 'origins' (lib/workspace.js): `{ v: 1, remember, entries }`.
 *
 * `remember` is the opt-in "Remember origins in this workspace" (off by default; while it is off
 * lib/originfill.js writes nothing). An entry: `{ name, ip, port, source, firstSeen,
 * lastConfirmed, server, stale }` — `source` where it was last confirmed ({@link ORIGIN_SOURCES}),
 * `server` an inventory name or null, `stale` null or `{ reason, at, ip?, port? }` once a later
 * run contradicted it ({@link STALE_REASONS}; ip / port: where the name was found instead; the
 * newest contradiction, always newer than `lastConfirmed`).
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

/**
 * The clock the map is read against, in ms: a Date, a number or a parseable string; anything else
 * (absent) is the real clock. Every date the map keeps or a run brings is at most this: a fast
 * clock or an edited file never dates an entry in the future, where no later check could reach it.
 * @param {Date|number|string|null|undefined} [now]
 * @returns {number}
 */
export function originNow(now) {
  const n = now instanceof Date ? now.getTime() : typeof now === 'number' ? now : typeof now === 'string' ? Date.parse(now) : NaN;
  return Number.isFinite(n) ? n : Date.now();
}

/** An ISO time of `v` (see {@link originTime}), never later than `nowMs`; null when `v` is no time. */
export function originTimeAt(v, nowMs) {
  const t = originTime(v);
  return t && Date.parse(t) > nowMs ? new Date(nowMs).toISOString() : t;
}

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

/** The `*.parent` name that covers a host name (one label under it), or null (a wildcard or a bare label). */
export function originWildcard(name) {
  const n = typeof name === 'string' ? name : '';
  const dot = n.indexOf('.');
  return dot > 0 && !n.startsWith('*.') ? `*.${n.slice(dot + 1)}` : null;
}

/** An entry's key: `name|ip|port`. */
export const originKey = (e) => `${e.name}|${e.ip}|${e.port}`;

/** The CLI target of an entry: the address on 443, `ip:port` / `[v6]:port` on another port. */
export function originTarget(e) {
  if (e.port === ORIGIN_DEFAULT_PORT) return e.ip;
  return e.ip.includes(':') ? `[${e.ip}]:${e.port}` : `${e.ip}:${e.port}`;
}

/** One stored entry, checked, its dates at most `nowMs`; null when it is not one. */
function sanitizeEntry(raw, nowMs) {
  if (!raw || typeof raw !== 'object') return null;
  const name = originName(raw.name);
  const ip = normalizeIP(String(raw.ip ?? ''));
  const port = originPort(raw.port);
  const last = originTimeAt(raw.lastConfirmed, nowMs) || originTimeAt(raw.firstSeen, nowMs);
  if (!name || !ip || !port || !last) return null;
  const first = originTimeAt(raw.firstSeen, nowMs);
  let stale = null;
  const s = raw.stale;
  const markedAt = s && typeof s === 'object' ? originTimeAt(s.at, nowMs) : null;
  // A mark stands only while it is newer than the last confirmation (a confirmation as new as the
  // mark, or newer, cleared it: lib/originfill.js).
  if (markedAt && STALE_REASONS.includes(s.reason) && ms(markedAt) > ms(last)) {
    stale = { reason: s.reason, at: markedAt };
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
 * name, no date later than `now` (the real clock unless given: {@link originNow}); null when
 * remembering is off and there is no entry (an empty part is not stored).
 * @param {unknown} value
 * @param {{ now?: Date|number|string }} [opts]
 * @returns {{ v: 1, remember: boolean, entries: object[] }|null}
 */
export function sanitizeOriginMap(value, { now } = {}) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const nowMs = originNow(now);
  const byKey = new Map();
  for (const raw of Array.isArray(value.entries) ? value.entries.slice(0, ORIGIN_MAP_LIMITS.entries * 4) : []) {
    const e = sanitizeEntry(raw, nowMs);
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

/** The indexes {@link originIndex} made (an index passed where a map is expected is used as is). */
const INDEXES = new WeakSet();

/**
 * The map read once for many lookups — a view's render, the scan's list: sanitized once, its
 * entries by name. Every reader here takes the map or its index; give a render the index, so a
 * full map (2,000 entries) is not checked again for each proxied host.
 * @param {object|null} map the workspace part, or an index (returned as is)
 * @returns {{ map: object|null, byName: Map<string, object[]> }}
 */
export function originIndex(map) {
  if (map && typeof map === 'object' && INDEXES.has(map)) return map;
  const m = sanitizeOriginMap(map);
  const byName = new Map();
  for (const e of m ? m.entries : []) {
    if (!byName.has(e.name)) byName.set(e.name, []);
    byName.get(e.name).push(e);
  }
  const index = Object.freeze({ map: m, byName });
  INDEXES.add(index);
  return index;
}

/**
 * A name's entries: its own and a `*.parent` one covering it, active first, newest first. A
 * wildcard entry at an address and port the name has an entry of its own for is left out: that
 * entry (a stale one masks the wildcard for this name) speaks for it.
 * @param {object|null} map the map, or its {@link originIndex} (for many names)
 * @param {string} name
 * @returns {object[]}
 */
export function originsFor(map, name) {
  const n = originName(name);
  const { map: m, byName } = originIndex(map);
  if (!n || !m) return [];
  const mine = byName.get(n) || [];
  const wild = originWildcard(n);
  const covering = ((wild && byName.get(wild)) || []).filter((w) => !mine.some((e) => e.ip === w.ip && e.port === w.port));
  return [...mine, ...covering].sort(rank);
}

/**
 * The active (not stale) entries as a scan's known origins (lib/scanner.js `knownOrigins`). A
 * wildcard entry lists in `except` the names it does not apply to: those with an entry of their
 * own at its address and port (a stale one masks it, an active one speaks for itself).
 * @param {object|null} map the map, or its {@link originIndex}
 * @returns {Array<{ name: string, ip: string, port: number, server: string|null, source: string, lastConfirmed: string, except?: string[] }>}
 */
export function knownForScan(map) {
  const { map: m } = originIndex(map);
  if (!m) return [];
  // The names with an entry of their own, by address and port.
  const at = new Map();
  for (const e of m.entries) {
    if (e.name.startsWith('*.')) continue;
    const k = `${e.ip}|${e.port}`;
    if (!at.has(k)) at.set(k, []);
    at.get(k).push(e.name);
  }
  return m.entries.filter((e) => !e.stale).map(({ name, ip, port, server, source, lastConfirmed }) => {
    const out = { name, ip, port, server, source, lastConfirmed };
    if (name.startsWith('*.')) {
      const except = [...new Set((at.get(`${ip}|${port}`) || []).filter((n) => originWildcard(n) === name))].sort();
      if (except.length) out.except = except;
    }
    return out;
  });
}
