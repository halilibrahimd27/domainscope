/**
 * lib/originfill.js — how the origin map (lib/originmap.js) is written: the merge rules
 * ({@link applyObservations}: what one run confirms, adds and marks stale), the edits by hand
 * ({@link addManualOrigin}, {@link removeOrigins}, {@link setRemember}) and what each source
 * observes. DOM-free and pure; nothing is sent. Not on the start route (the views that write the
 * map load it).
 *
 * - {@link zoneObservations}: Zone File › Origins & servers — every exact address the file gives a
 *   proxied name (no port: the map keeps 443 for a new entry). A host-name, Tunnel or provider
 *   origin is no address and is left out. Source 'zone' (a zone naming another origin marks the
 *   name's other entries stale).
 * - {@link cliReportObservations}: the CLI's `--json` reports, read with lib/estate.js
 *   readEstateReport (the Certificate estate view's reader): per name asked and endpoint,
 *   UPDATED / NEEDS_UPDATE / ORIGIN_CERT = it serves the name, NOT_HOSTED = it does not, anything
 *   else (PRIVATE_CERT, TLS_ERROR, TIMEOUT, CLOSED) says nothing. Source 'cli-json'.
 * - {@link verifyObservations}: SSL Targets › Verify — the origin checks (a proxied name on an
 *   inventory origin, `via` hint / zone / known) with a verdict, read the same way. Source 'verify'.
 * - {@link compareObservations}: Retire an IP › the old and the new server — the new address
 *   serves the name when it answered with a certificate covering it (not 'broken', not
 *   'unreachable'). Source 'compare' (it never marks anything stale).
 *
 * @example
 *   const { observations, at } = cliReportObservations(report.doc);
 *   applyObservations(map, observations, { source: 'cli-json', at, proxied });
 */

import { readEstateReport, ESTATE_MAX_REPORTS } from './estate.js';
import { normalizeIP } from './netinfo.js';
import {
  sanitizeOriginMap, originName, originPort, originKey, originServer, originTime, ORIGIN_SOURCES, ORIGIN_MAP_LIMITS, ORIGIN_DEFAULT_PORT
} from './originmap.js';

/* ------------------------------------------------------------------------ */
/* Writing the map                                                          */
/* ------------------------------------------------------------------------ */

/** The stale reasons each source gives: [found on another server, no longer served here]. */
const CONTRADICTS = Object.freeze({
  'cli-json': ['cli-elsewhere', 'cli-not-hosted'], verify: ['verify-elsewhere', 'verify-not-hosted'], zone: ['zone-other', null]
});
const ms = (v) => (v ? Date.parse(v) || 0 : 0);
/** A copy of the map to change (remembering off and no entry when there is none). */
const working = (map) => {
  const m = sanitizeOriginMap(map) || { v: 1, remember: false, entries: [] };
  return { ...m, entries: m.entries.map((e) => ({ ...e, stale: e.stale && { ...e.stale } })) };
};
/** The changed copy as the workspace keeps it (one per key, capped, by name). */
const finish = (m) => sanitizeOriginMap(m);

/**
 * Remembering on or off. Turning it off keeps the entries (they are still used; remove them
 * with {@link removeOrigins}).
 * @param {object|null} map
 * @param {boolean} on
 * @returns {object|null}
 */
export function setRemember(map, on) {
  return finish({ ...working(map), remember: !!on });
}

/**
 * Apply what one run saw to the map. Every observation is one name at one address:
 * `outcome` 'hosted' (it serves the name), 'not-hosted' (it answered without it) or 'unknown'
 * (no answer, an error: nothing changes). `port` null matches any port of the address (a zone
 * file names no port) and adds {@link ORIGIN_DEFAULT_PORT}.
 *
 * - 'hosted' confirms the matching entries (`lastConfirmed`, `source`; a stale mark older than
 *   the run goes) or adds one — only for a proxied name: one the map has, or `proxied(name)`
 *   (absent: every name); the others are listed in `skipped`.
 * - A run that found a name hosted marks the name's other entries stale (`<src>-elsewhere`,
 *   `zone-other`), and 'not-hosted' the entry at that address (`<src>-not-hosted`) — the CLI
 *   JSON, Verify and a zone file contradict; a comparison or a manual entry never does. An entry
 *   confirmed by the same run, or after it, is never marked.
 * - With remembering off nothing changes (`off: true`).
 * @param {object|null} map
 * @param {Array<{ name: string, ip: string, port?: number|null, outcome: 'hosted'|'not-hosted'|'unknown', server?: string|null }>} observations
 * @param {{ source: string, at: Date|string, proxied?: ((name: string) => boolean)|null, serverOf?: ((ip: string) => (string|null))|null }} opts
 * @returns {{ map: object|null, off: boolean, added: string[], confirmed: string[], staled: string[], skipped: string[] }}
 *   keys added, confirmed and marked stale; names skipped as not known to be proxied
 */
export function applyObservations(map, observations, { source, at, proxied = null, serverOf = null } = {}) {
  const m = working(map);
  const out = { map: sanitizeOriginMap(map), off: !m.remember, added: [], confirmed: [], staled: [], skipped: [] };
  const when = originTime(at);
  if (out.off || !when || !ORIGIN_SOURCES.includes(source)) return out;
  const t = ms(when);
  const names = new Set(m.entries.map((e) => e.name));
  const isProxied = (name) => names.has(name) || typeof proxied !== 'function' || !!proxied(name);
  const lookup = (ip) => (typeof serverOf === 'function' ? originServer(serverOf(ip)) : null);
  const obs = [];
  for (const o of Array.isArray(observations) ? observations : []) {
    if (!o || typeof o !== 'object') continue;
    const name = originName(o.name);
    const ip = normalizeIP(String(o.ip ?? ''));
    const anyPort = o.port === null || o.port === undefined;
    const port = anyPort ? null : originPort(o.port);
    if (!name || !ip || (!anyPort && !port) || !['hosted', 'not-hosted'].includes(o.outcome)) continue;
    obs.push({ name, ip, port, outcome: o.outcome, server: originServer(o.server) });
  }
  const matches = (e, o) => e.name === o.name && e.ip === o.ip && (o.port === null || e.port === o.port);
  const confirmed = new Set();
  const skipped = new Set();
  const foundAt = new Map();
  for (const o of obs.filter((x) => x.outcome === 'hosted')) {
    if (!foundAt.has(o.name)) foundAt.set(o.name, o);
    const hits = m.entries.filter((e) => matches(e, o));
    for (const e of hits) {
      if (t >= ms(e.lastConfirmed)) Object.assign(e, { lastConfirmed: when, source });
      if (t < ms(e.firstSeen)) e.firstSeen = when;
      if (e.stale && ms(e.stale.at) <= t) e.stale = null;
      e.server = o.server || e.server || lookup(e.ip);
      confirmed.add(originKey(e));
    }
    if (hits.length) continue;
    if (!isProxied(o.name)) {
      skipped.add(o.name);
      continue;
    }
    const e = { name: o.name, ip: o.ip, port: o.port ?? ORIGIN_DEFAULT_PORT, source, firstSeen: when, lastConfirmed: when, server: o.server || lookup(o.ip), stale: null };
    m.entries.push(e);
    confirmed.add(originKey(e));
    out.added.push(originKey(e));
  }
  const [elsewhere, notHosted] = CONTRADICTS[source] || [null, null];
  const mark = (e, reason, by = null) => {
    if (!reason || e.stale || confirmed.has(originKey(e)) || t <= ms(e.lastConfirmed)) return;
    e.stale = { reason, at: when, ...(by ? { ip: by.ip, port: by.port ?? ORIGIN_DEFAULT_PORT } : {}) };
    out.staled.push(originKey(e));
  };
  for (const e of m.entries) if (foundAt.has(e.name)) mark(e, elsewhere, foundAt.get(e.name));
  for (const o of obs.filter((x) => x.outcome === 'not-hosted')) for (const e of m.entries) if (matches(e, o)) mark(e, notHosted);
  out.confirmed = [...confirmed].filter((k) => !out.added.includes(k));
  out.skipped = [...skipped].sort();
  out.map = finish(m);
  return out;
}

/**
 * Add an entry by hand, or change one (`replace`: the key of the entry it replaces). The same
 * key again confirms it. Refused: 'off' (remembering is off), 'name', 'ip', 'port', 'limit'.
 * @param {object|null} map
 * @param {{ name: string, ip: string, port?: number|string|null, server?: string|null }} input
 * @param {{ at: Date|string, replace?: string|null, serverOf?: ((ip: string) => (string|null))|null }} opts
 * @returns {{ map: object|null, error: string|null, key: string|null }}
 */
export function addManualOrigin(map, input, { at, replace = null, serverOf = null } = {}) {
  const m = working(map);
  const fail = (error) => ({ map: sanitizeOriginMap(map), error, key: null });
  if (!m.remember) return fail('off');
  const src = input || {};
  const name = originName(String(src.name ?? '').trim());
  if (!name) return fail('name');
  const ip = normalizeIP(String(src.ip ?? '').trim());
  if (!ip) return fail('ip');
  const port = originPort(typeof src.port === 'string' ? src.port.trim() : src.port);
  if (!port) return fail('port');
  const when = originTime(at) || new Date(0).toISOString();
  const entry = { name, ip, port };
  const key = originKey(entry);
  const entries = m.entries.filter((e) => originKey(e) !== replace || replace === key);
  const prev = entries.find((e) => originKey(e) === key);
  const server = originServer(src.server) || (prev && prev.server) || (typeof serverOf === 'function' ? originServer(serverOf(ip)) : null);
  if (prev) {
    Object.assign(prev, { source: 'manual', lastConfirmed: when, stale: null, server });
  } else {
    if (entries.filter((e) => e.name === name).length >= ORIGIN_MAP_LIMITS.perName || entries.length >= ORIGIN_MAP_LIMITS.entries) return fail('limit');
    entries.push({ ...entry, source: 'manual', firstSeen: when, lastConfirmed: when, server, stale: null });
  }
  return { map: finish({ ...m, entries }), error: null, key };
}

/**
 * Remove entries by key (always allowed, remembering on or off).
 * @param {object|null} map
 * @param {Iterable<string>} keys
 * @returns {object|null}
 */
export function removeOrigins(map, keys) {
  const drop = new Set(keys || []);
  const m = working(map);
  return finish({ ...m, entries: m.entries.filter((e) => !drop.has(originKey(e))) });
}

/* ------------------------------------------------------------------------ */
/* What each source observes                                                */
/* ------------------------------------------------------------------------ */

/** The CLI / Verify statuses that say a server serves the name. */
export const HOSTED_STATUSES = Object.freeze(['UPDATED', 'NEEDS_UPDATE', 'ORIGIN_CERT']);
/** The status that says it does not. */
export const NOT_HOSTED_STATUS = 'NOT_HOSTED';
/** The `via` of a Verify origin check (lib/verify.js isOriginPair). */
const ORIGIN_VIAS = new Set(['hint', 'zone', 'known']);

/** 'hosted' / 'not-hosted' / 'unknown' of a CLI or Verify status. */
export function outcomeOf(status) {
  if (HOSTED_STATUSES.includes(status)) return 'hosted';
  return status === NOT_HOSTED_STATUS ? 'not-hosted' : 'unknown';
}

/**
 * Zone File › Origins & servers: the proxied names' exact addresses (lib/zoneorigins.js
 * proxiedOriginMap rows of kind 'ip').
 * @param {Array<{ name: string, kind: string, ips?: string[] }>} origins
 * @returns {Array<{ name: string, ip: string, port: null, outcome: 'hosted' }>}
 */
export function zoneObservations(origins) {
  const out = [];
  for (const row of Array.isArray(origins) ? origins : []) {
    if (!row || row.kind !== 'ip' || !Array.isArray(row.ips)) continue;
    for (const ip of row.ips) out.push({ name: row.name, ip, port: null, outcome: 'hosted' });
  }
  return out;
}

/**
 * One CLI `--json` report (the parsed document): its observations, when it ran (finishedAt, else
 * startedAt) and the names an endpoint answered with a Cloudflare Origin CA certificate (an
 * origin behind Cloudflare: proxied whatever this page knows).
 * @param {object} doc
 * @returns {{ observations: Array<{ name: string, ip: string, port: number, outcome: string, server: string|null }>,
 *   at: string|null, originCertNames: string[] }}
 */
export function cliReportObservations(doc) {
  const d = doc && typeof doc === 'object' ? doc : {};
  const observations = [];
  const originCert = new Set();
  const seen = new Set();
  for (const row of Array.isArray(d.results) ? d.results : []) {
    if (!row || typeof row !== 'object' || (row.probe !== 'sni' && row.probe !== 'wildcard')) continue;
    const ip = normalizeIP(String(row.ip ?? ''));
    if (!ip || typeof row.name !== 'string' || !row.name || !Number.isInteger(row.port)) continue;
    const key = `${row.name}|${ip}|${row.port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // The CLI names a bare-address target after its address: that is no server name.
    const server = typeof row.server === 'string' && row.server && normalizeIP(row.server) !== ip ? row.server : null;
    observations.push({ name: row.name, ip, port: row.port, outcome: outcomeOf(row.status), server });
    if (row.status === 'ORIGIN_CERT') originCert.add(row.name);
  }
  const at = [d.finishedAt, d.startedAt].find((v) => typeof v === 'string' && !Number.isNaN(Date.parse(v))) || null;
  return { observations, at, originCertNames: [...originCert] };
}

/**
 * Several report files (`{ name, text }`, at most ESTATE_MAX_REPORTS): each read with the
 * Certificate estate's reader, the readable ones oldest first (so a newer run has the last word).
 * @param {Array<{ name: string, text: string }>} files
 * @returns {{ reports: Array<{ name: string, observations: object[], at: string|null, originCertNames: string[] }>,
 *   errors: Array<{ name: string, error: string, detail?: string }> }}
 */
export function readCliReports(files) {
  const reports = [];
  const errors = [];
  for (const f of (Array.isArray(files) ? files : []).slice(0, ESTATE_MAX_REPORTS)) {
    const read = readEstateReport(f && f.text, { name: f && f.name });
    if (!read.ok) {
      errors.push({ name: String((f && f.name) || ''), error: read.error, ...(read.detail ? { detail: read.detail } : {}) });
      continue;
    }
    reports.push({ name: read.report.name, ...cliReportObservations(read.report.doc) });
  }
  reports.sort((a, b) => (Date.parse(a.at) || 0) - (Date.parse(b.at) || 0));
  return { reports, errors };
}

/**
 * SSL Targets › Verify: the origin checks of a batch that got a verdict (lib/verify.js rows).
 * @param {object[]} rows
 * @returns {Array<{ name: string, ip: string, port: number, outcome: string, server: string|null }>}
 */
export function verifyObservations(rows) {
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!r || r.state !== 'done' || r.stale || !r.proxied || !ORIGIN_VIAS.has(r.via) || !r.status) continue;
    out.push({ name: r.name, ip: r.ip, port: r.port, outcome: outcomeOf(r.status), server: r.server ? r.server.name : null });
  }
  return out;
}

/**
 * Retire an IP › the old and the new server: the new address serves the name when it answered
 * with a certificate covering it and the comparison is neither 'broken' nor 'unreachable'.
 * @param {{ host: string, port: number|string, new: object, comparison: { verdict: string } }|null} result
 * @returns {Array<{ name: string, ip: string, port: number, outcome: 'hosted' }>}
 */
export function compareObservations(result) {
  const r = result || {};
  const side = r.new;
  const verdict = r.comparison && r.comparison.verdict;
  if (!side || !side.ok || !side.cert || side.cert.covers !== true || verdict === 'broken' || verdict === 'unreachable') return [];
  return [{ name: r.host, ip: side.ip, port: Number(r.port) || 443, outcome: 'hosted' }];
}
