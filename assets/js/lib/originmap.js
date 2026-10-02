/**
 * lib/originmap.js — the workspace part 'origins' `{ v: 1, remember, entries }`: which server and
 * port really serves a proxied name. Entry: `{ name, ip, port, source, firstSeen, lastConfirmed,
 * server, stale }`, `stale` null or the newest contradiction `{ reason, at, ip?, port? }`. The
 * model and readers (start route); merge rules: lib/originfill.js. Pure. Spec §5.61.
 */

import { normalizeHostname } from './domain.js';
import { normalizeIP } from './netinfo.js';

/** Where an entry was last confirmed. */
export const ORIGIN_SOURCES = Object.freeze(['cli-json', 'zone', 'verify', 'compare', 'manual']);
/** Why an entry is stale. */
export const STALE_REASONS = Object.freeze(['cli-elsewhere', 'cli-not-hosted', 'verify-elsewhere', 'verify-not-hosted', 'zone-other']);
/** Caps: entries, entries per name, server name length. */
export const ORIGIN_MAP_LIMITS = Object.freeze({ entries: 2000, perName: 16, server: 80 });
/** The port when a source names none (a zone file). */
export const ORIGIN_DEFAULT_PORT = 443;

// eslint-disable-next-line no-control-regex
const JUNK_RE = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u2028-\u202e\u2060-\u2064\ufeff]/g;

/** An ISO time of a date or a parseable value, at most `nowMs`; else null. */
export const originTime = (v, nowMs = Infinity) => {
  if (v === null || v === undefined || v === '') return null;
  const d = v instanceof Date ? v : new Date(v);
  return Number.isNaN(d.getTime()) ? null : new Date(Math.min(d.getTime(), nowMs)).toISOString();
};
const ms = (v) => (v ? Date.parse(v) || 0 : 0);

/** The clock in ms (a Date, number or date string; else the real one): no date the map keeps is later. */
export function originNow(now) {
  const n = now instanceof Date ? now.getTime() : typeof now === 'number' ? now : typeof now === 'string' ? Date.parse(now) : NaN;
  return Number.isFinite(n) ? n : Date.now();
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

/** The `*.parent` that covers a host name (one label under it), or null. */
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
  const last = originTime(raw.lastConfirmed, nowMs) || originTime(raw.firstSeen, nowMs);
  if (!name || !ip || !port || !last) return null;
  const first = originTime(raw.firstSeen, nowMs);
  let stale = null;
  const s = raw.stale;
  const markedAt = s && typeof s === 'object' ? originTime(s.at, nowMs) : null;
  // A mark stands only while newer than the last confirmation.
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
 * The map as the workspace keeps it: every entry checked, one per key (the latest confirmation),
 * capped (active and recent kept first), by name, no date after `now`; null when off and empty.
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
  const refuted = ((value.refuted && sanitizeOriginMap({ entries: value.refuted }, { now })) || { entries: [] }).entries.filter((e) => e.stale);
  return remember || entries.length ? { v: 1, remember, entries, ...(refuted.length && { refuted }) } : null;
}

const INDEXES = new WeakSet();

/**
 * The map read once for many lookups (a render): sanitized, entries by name. The readers below
 * take the map or this index.
 * @param {object|null} map the part, or an index (returned as is)
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
 * A name's entries, active and newest first: its own, and a covering `*.parent` one unless the
 * name has its own at that address and port (a stale one masks the wildcard for the name).
 * @param {object|null} map the map, or its {@link originIndex}
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
 * A host's remembered origins as a result shows them now: the ones it used (stale in place), then
 * its other stale entries; one row per address and port.
 * @param {object|null} map the map, or its {@link originIndex}
 * @param {string} name
 * @param {Array<{ ip: string, port: number }>} used
 * @returns {Array<{ ip: string, port: number, target: string, entry: object|null, stale: boolean, used: boolean }>}
 */
export function rememberedRows(map, name, used) {
  const entries = originsFor(map, name);
  const rows = [];
  const add = (ip, port, entry, isUsed) => {
    if (rows.some((r) => r.ip === ip && r.port === port)) return;
    rows.push({ ip, port, target: originTarget({ ip, port }), entry, stale: !!(entry && entry.stale), used: isUsed });
  };
  for (const u of used || []) add(u.ip, u.port, entries.find((e) => e.ip === u.ip && e.port === u.port) || null, true);
  for (const e of entries) if (e.stale) add(e.ip, e.port, e, false);
  return rows;
}

/**
 * The active entries as a scan's `knownOrigins` (lib/scanner.js); a wildcard's `except` lists the
 * names with their own entry at its address and port.
 * @param {object|null} map the map, or its {@link originIndex}
 * @returns {Array<{ name: string, ip: string, port: number, server: string|null, source: string, lastConfirmed: string, except?: string[] }>}
 */
export function knownForScan(map) {
  const { map: m } = originIndex(map);
  if (!m) return [];
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
