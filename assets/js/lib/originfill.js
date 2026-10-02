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
 *   UPDATED / NEEDS_UPDATE / ORIGIN_CERT / PRIVATE_CERT (a covering certificate) = it serves the
 *   name, NOT_HOSTED = it does not, anything else (TLS_ERROR, TIMEOUT, CLOSED) = asked, no answer;
 *   a port that did not open (a `connect` row) was asked for every name of the run. Source 'cli-json'.
 * - {@link verifyObservations}: SSL Targets › Verify — the checks of exact origins (a proxied name
 *   on an inventory origin the origin map or the zone file names, `via` known / zone) with a
 *   verdict, read the same way. A hint's candidate is never one. Source 'verify'.
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
  sanitizeOriginMap, originName, originPort, originKey, originServer, originNow, originTime, originWildcard,
  ORIGIN_SOURCES, ORIGIN_MAP_LIMITS, ORIGIN_DEFAULT_PORT
} from './originmap.js';

/* ------------------------------------------------------------------------ */
/* Writing the map                                                          */
/* ------------------------------------------------------------------------ */

/** What an observation says, the strongest first: served, answered without the name, no answer. */
const OUTCOMES = Object.freeze(['hosted', 'not-hosted', 'unknown']);
/** The stale reasons each source gives: [found on another server, no longer served here]. */
const CONTRADICTS = Object.freeze({
  'cli-json': ['cli-elsewhere', 'cli-not-hosted'], verify: ['verify-elsewhere', 'verify-not-hosted'], zone: ['zone-other', null]
});
/** Marks from a probe of one address and port (the CLI, Verify): a zone file, naming no port, never clears them. */
const PROBE_MARKS = new Set(['cli-elsewhere', 'cli-not-hosted', 'verify-elsewhere', 'verify-not-hosted']);
/** The mark an entry added from an older run gets when a newer run of this source found the name elsewhere. */
const FOUND_ELSEWHERE = Object.freeze({ 'cli-json': 'cli-elsewhere', verify: 'verify-elsewhere', zone: 'zone-other' });
const ms = (v) => (v ? Date.parse(v) || 0 : 0);
/** A copy of the map to change (remembering off and no entry when there is none), read against `nowMs`. */
const working = (map, nowMs) => {
  const m = sanitizeOriginMap(map, { now: nowMs }) || { v: 1, remember: false, entries: [] };
  return { ...m, entries: m.entries.map((e) => ({ ...e, stale: e.stale && { ...e.stale } })) };
};
/** The changed copy as the workspace keeps it (one per key, capped, by name). */
const finish = (m, nowMs) => sanitizeOriginMap(m, { now: nowMs });

/**
 * Remembering on or off. Turning it off keeps the entries (they are still used; remove them
 * with {@link removeOrigins}).
 * @param {object|null} map
 * @param {boolean} on
 * @returns {object|null}
 */
export function setRemember(map, on) {
  const nowMs = originNow();
  return finish({ ...working(map, nowMs), remember: !!on }, nowMs);
}

/**
 * Apply what one run saw to the map. Every observation is one name at one address:
 * `outcome` 'hosted' (it serves the name), 'not-hosted' (it answered without it) or 'unknown'
 * (no answer, an error: it was asked, and said nothing). `port` null (a zone file names no port)
 * is the address: it confirms the address's entry on {@link ORIGIN_DEFAULT_PORT} unless a probe
 * of that port marked it, leaves an entry on another port as it is (no new 443 entry next to it),
 * and adds one on 443 when the address has none.
 *
 * - 'hosted' confirms the matching entries (`lastConfirmed`, `source`; a stale mark not newer than
 *   the run goes, a newer one stays) or adds one — only for a proxied name: one the map has, or
 *   `proxied(name)` (absent: every name); the others are listed in `skipped`. An entry added from
 *   a run older than another entry of the name at another address, which the CLI JSON, Verify or
 *   a zone file confirmed, starts stale (that newer run found the name elsewhere), so the order
 *   reports are imported in does not matter.
 * - Contradictions (the CLI JSON, Verify, a zone file; a comparison or a manual entry never
 *   contradicts): a run marks an entry `<src>-elsewhere` only when it asked that entry's address
 *   and port and got no answer or an answer without the name while it found the name on another
 *   address (another port of an address it found the name at is the same server); an entry it
 *   did not ask is left alone (a name may have several origins). 'not-hosted' at an entry's
 *   address and port, with the name found nowhere else, marks it `<src>-not-hosted`. A zone file
 *   names a proxied name's origins: its other entries are `zone-other`. An entry confirmed by the
 *   same run, or at or after its time, is never marked; a stale entry takes the newer of two marks.
 * - A `*.parent` entry covers every name one label under it: such a name counts as proxied, and
 *   'hosted' at the wildcard's address and port adds nothing of its own. A probe that contradicts
 *   the wildcard for one name (as above, at its address and port) masks it for that name only: the
 *   name gets its own stale entry there (the wildcard's dates and source), and the wildcard stands
 *   for the other names.
 * - With remembering off nothing changes (`off: true`).
 * - A run is never later than `now` (the real clock unless given): a report dated in the future (a
 *   fast clock, an edited file) counts as now, and so cannot outrank every later check.
 * @param {object|null} map
 * @param {Array<{ name: string, ip: string, port?: number|null, outcome: 'hosted'|'not-hosted'|'unknown', server?: string|null }>} observations
 * @param {{ source: string, at: Date|string, now?: Date|number|string, proxied?: ((name: string) => boolean)|null, serverOf?: ((ip: string) => (string|null))|null }} opts
 * @returns {{ map: object|null, off: boolean, added: string[], confirmed: string[], staled: string[], skipped: string[] }}
 *   keys added, confirmed and marked stale; names skipped as not known to be proxied
 */
export function applyObservations(map, observations, { source, at, now, proxied = null, serverOf = null } = {}) {
  const nowMs = originNow(now);
  const m = working(map, nowMs);
  const out = { map: sanitizeOriginMap(map, { now: nowMs }), off: !m.remember, added: [], confirmed: [], staled: [], skipped: [] };
  const when = originTime(at, nowMs);
  if (out.off || !when || !ORIGIN_SOURCES.includes(source)) return out;
  const t = ms(when);
  // The entries by name, kept up to date as the run adds some (a report can hold 200,000 rows).
  const byName = new Map();
  const index = (e) => {
    if (!byName.has(e.name)) byName.set(e.name, []);
    byName.get(e.name).push(e);
  };
  for (const e of m.entries) index(e);
  const own = (name) => byName.get(name) || [];
  /** The active `*.parent` entries that cover a name (a wildcard name has none). */
  const wildcards = (name) => {
    const w = originWildcard(name);
    return w ? own(w).filter((e) => !e.stale) : [];
  };
  const sits = (e, ip, port) => e.ip === ip && e.port === port;
  const isProxied = (name) => byName.has(name) || wildcards(name).length > 0 || typeof proxied !== 'function' || !!proxied(name);
  const lookup = (ip) => (typeof serverOf === 'function' ? originServer(serverOf(ip)) : null);
  const obs = [];
  for (const o of Array.isArray(observations) ? observations : []) {
    if (!o || typeof o !== 'object') continue;
    const name = originName(o.name);
    const ip = normalizeIP(String(o.ip ?? ''));
    const anyPort = o.port === null || o.port === undefined;
    const port = anyPort ? null : originPort(o.port);
    if (!name || !ip || (!anyPort && !port) || !OUTCOMES.includes(o.outcome)) continue;
    // Only a zone file names no port, and it only says where a name is served.
    if (anyPort && o.outcome !== 'hosted') continue;
    obs.push({ name, ip, port, outcome: o.outcome, server: originServer(o.server) });
  }
  // What the run asked, per name: each address and port with its answer (served, then not served,
  // then no answer wins when it was asked twice).
  const asked = new Map();
  for (const o of obs) {
    if (o.port === null) continue;
    if (!asked.has(o.name)) asked.set(o.name, new Map());
    const answers = asked.get(o.name);
    const k = `${o.ip}|${o.port}`;
    if (!answers.has(k) || OUTCOMES.indexOf(o.outcome) < OUTCOMES.indexOf(answers.get(k))) answers.set(k, o.outcome);
  }
  const confirmed = new Set();
  const skipped = new Set();
  // Per name: where the run found it hosted, in order.
  const foundAt = new Map();
  for (const o of obs) {
    if (o.outcome !== 'hosted') continue;
    if (!foundAt.has(o.name)) foundAt.set(o.name, []);
    foundAt.get(o.name).push(o);
    const hits = own(o.name).filter((e) => e.ip === o.ip && (o.port === null || e.port === o.port));
    for (const e of hits) {
      // A zone file names no port: never a confirmation of another port, nor of an answer a probe
      // of this one gave (the address is known: no new entry either).
      if (o.port === null && (e.port !== ORIGIN_DEFAULT_PORT || (e.stale && PROBE_MARKS.has(e.stale.reason)))) continue;
      if (t >= ms(e.lastConfirmed)) Object.assign(e, { lastConfirmed: when, source });
      if (t < ms(e.firstSeen)) e.firstSeen = when;
      if (e.stale && ms(e.stale.at) <= t) e.stale = null;
      e.server = o.server || e.server || lookup(e.ip);
      confirmed.add(originKey(e));
    }
    if (hits.length) continue;
    // A wildcard entry already says this address serves the name: nothing of its own to add.
    if (wildcards(o.name).some((w) => sits(w, o.ip, o.port ?? ORIGIN_DEFAULT_PORT))) continue;
    if (!isProxied(o.name)) {
      skipped.add(o.name);
      continue;
    }
    const e = { name: o.name, ip: o.ip, port: o.port ?? ORIGIN_DEFAULT_PORT, source, firstSeen: when, lastConfirmed: when, server: o.server || lookup(o.ip), stale: null };
    // An older run than one that found the name on another address: its finding is already superseded.
    const newer = own(e.name)
      .filter((x) => x.ip !== e.ip && !x.stale && FOUND_ELSEWHERE[x.source] && ms(x.lastConfirmed) > t)
      .sort((a, b) => ms(b.lastConfirmed) - ms(a.lastConfirmed))[0];
    if (newer) {
      e.stale = { reason: FOUND_ELSEWHERE[newer.source], at: newer.lastConfirmed, ip: newer.ip, port: newer.port };
      out.staled.push(originKey(e));
    }
    m.entries.push(e);
    index(e);
    confirmed.add(originKey(e));
    out.added.push(originKey(e));
  }
  const [elsewhere, notHosted] = CONTRADICTS[source] || [null, null];
  const stamp = (reason, by) => ({ reason, at: when, ...(by ? { ip: by.ip, port: by.port ?? ORIGIN_DEFAULT_PORT } : {}) });
  const mark = (e, reason, by = null) => {
    if (!reason || confirmed.has(originKey(e)) || t <= ms(e.lastConfirmed)) return;
    // The newest contradiction is kept: an older run's mark never replaces a newer one.
    if (e.stale && ms(e.stale.at) >= t) return;
    e.stale = stamp(reason, by);
    out.staled.push(originKey(e));
  };
  /**
   * A probe contradicted a wildcard entry for one name: the name gets its own entry at the
   * wildcard's address and port, stale, which masks the wildcard for that name only
   * (lib/originmap.js originsFor / knownForScan). It carries the wildcard's dates and source.
   */
  const mask = (name, w, reason, by = null) => {
    if (!reason || t <= ms(w.lastConfirmed)) return;
    const e = { name, ip: w.ip, port: w.port, source: w.source, firstSeen: w.firstSeen, lastConfirmed: w.lastConfirmed, server: w.server, stale: stamp(reason, by) };
    m.entries.push(e);
    index(e);
    out.staled.push(originKey(e));
  };
  if (source === 'zone') {
    // A zone file names the proxied name's origins: an entry at another address is not one.
    for (const [name, found] of foundAt) {
      for (const e of own(name)) if (!found.some((o) => o.ip === e.ip)) mark(e, elsewhere, found[0]);
    }
  } else if (elsewhere) {
    // The CLI and Verify contradict only what they asked: an address and port without the name
    // (or without an answer while the name was found on another address).
    for (const [name, answers] of asked) {
      const found = foundAt.get(name) || [];
      const verdict = (ip, answer) => {
        if (!answer || answer === 'hosted') return null;
        const by = found.find((o) => o.ip !== ip);
        if (by && !found.some((o) => o.ip === ip)) return [elsewhere, by];
        return answer === 'not-hosted' ? [notHosted, null] : null;
      };
      for (const e of own(name)) {
        const v = verdict(e.ip, answers.get(`${e.ip}|${e.port}`));
        if (v) mark(e, v[0], v[1]);
      }
      for (const w of wildcards(name)) {
        if (own(name).some((e) => sits(e, w.ip, w.port))) continue;
        const v = verdict(w.ip, answers.get(`${w.ip}|${w.port}`));
        if (v) mask(name, w, v[0], v[1]);
      }
    }
  }
  out.skipped = [...skipped].sort();
  out.map = finish(m, nowMs);
  // Counted against what the map kept: the caps (per name, in all) can drop a new entry.
  const kept = new Set(out.map ? out.map.entries.map(originKey) : []);
  const added = new Set(out.added);
  out.added = out.added.filter((k) => kept.has(k));
  out.confirmed = [...confirmed].filter((k) => !added.has(k) && kept.has(k));
  out.staled = [...new Set(out.staled)].filter((k) => kept.has(k));
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
export function addManualOrigin(map, input, { at, now, replace = null, serverOf = null } = {}) {
  const nowMs = originNow(now);
  const m = working(map, nowMs);
  const fail = (error) => ({ map: sanitizeOriginMap(map, { now: nowMs }), error, key: null });
  if (!m.remember) return fail('off');
  const src = input || {};
  const name = originName(String(src.name ?? '').trim());
  if (!name) return fail('name');
  const ip = normalizeIP(String(src.ip ?? '').trim());
  if (!ip) return fail('ip');
  const port = originPort(typeof src.port === 'string' ? src.port.trim() : src.port);
  if (!port) return fail('port');
  const when = originTime(at, nowMs) || new Date(nowMs).toISOString();
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
  return { map: finish({ ...m, entries }, nowMs), error: null, key };
}

/**
 * Remove entries by key (always allowed, remembering on or off).
 * @param {object|null} map
 * @param {Iterable<string>} keys
 * @returns {object|null}
 */
export function removeOrigins(map, keys) {
  const drop = new Set(keys || []);
  const nowMs = originNow();
  const m = working(map, nowMs);
  return finish({ ...m, entries: m.entries.filter((e) => !drop.has(originKey(e))) }, nowMs);
}

/* ------------------------------------------------------------------------ */
/* What each source observes                                                */
/* ------------------------------------------------------------------------ */

/**
 * The CLI / Verify statuses that say a server serves the name: every covering certificate, the new
 * one or not — a Cloudflare Origin CA certificate (ORIGIN_CERT) and a self-signed or private-CA one
 * (PRIVATE_CERT: a Cloudflare "Full" origin, an internal host) included.
 */
export const HOSTED_STATUSES = Object.freeze(['UPDATED', 'NEEDS_UPDATE', 'ORIGIN_CERT', 'PRIVATE_CERT']);
/** The status that says it does not. */
export const NOT_HOSTED_STATUS = 'NOT_HOSTED';
/**
 * The `via` of a Verify origin check that names an exact origin (lib/verify.js isOriginPair):
 * the origin map's own entry or the zone file's origin. A 'hint' pair is only a candidate (an SPF,
 * MX or sibling address paired with every proxied name): a server answering for the name with a
 * covering certificate (a shared wildcard, say) is not shown to be its origin, so it never
 * confirms, adds or contradicts an entry.
 */
const EXACT_VIAS = new Set(['known', 'zone']);

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
 * origin behind Cloudflare: proxied whatever this page knows). An endpoint whose port did not open
 * (a `connect` row: CLOSED, TIMEOUT — a server switched off) was asked for every name of the run
 * (`names`, else the names its rows probed): one 'unknown' observation per name there.
 * @param {object} doc
 * @returns {{ observations: Array<{ name: string, ip: string, port: number, outcome: string, server: string|null }>,
 *   at: string|null, originCertNames: string[] }}
 */
export function cliReportObservations(doc) {
  const d = doc && typeof doc === 'object' ? doc : {};
  const observations = [];
  const originCert = new Set();
  const seen = new Set();
  const rows = (Array.isArray(d.results) ? d.results : []).filter((row) => row && typeof row === 'object');
  // The names the run asked: its `names`, else what its rows probed (as the CLI reads a report).
  const asked = (Array.isArray(d.names) ? d.names : []).map((n) => n && n.name).filter((n) => typeof n === 'string' && n);
  const names = asked.length ? asked : rows.map((row) => row.name).filter((n) => typeof n === 'string' && n);
  for (const row of rows) {
    const connect = row.probe === 'connect';
    if (!connect && row.probe !== 'sni' && row.probe !== 'wildcard') continue;
    const ip = normalizeIP(String(row.ip ?? ''));
    if (!ip || !Number.isInteger(row.port) || (!connect && (typeof row.name !== 'string' || !row.name))) continue;
    // The CLI names a bare-address target after its address: that is no server name.
    const server = typeof row.server === 'string' && row.server && normalizeIP(row.server) !== ip ? row.server : null;
    for (const name of connect ? names : [row.name]) {
      const key = `${name}|${ip}|${row.port}`;
      if (seen.has(key)) continue;
      seen.add(key);
      observations.push({ name, ip, port: row.port, outcome: connect ? 'unknown' : outcomeOf(row.status), server });
    }
    if (row.status === 'ORIGIN_CERT') originCert.add(row.name);
  }
  const at = [d.finishedAt, d.startedAt].find((v) => typeof v === 'string' && !Number.isNaN(Date.parse(v))) || null;
  return { observations, at, originCertNames: [...originCert] };
}

/**
 * Several report files (`{ name, text }`, at most ESTATE_MAX_REPORTS): each read with the
 * Certificate estate's reader, the readable ones oldest first (so a newer run has the last word),
 * an undated one last (it is applied as now).
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
  const order = (r) => (r.at ? Date.parse(r.at) : Infinity);
  reports.sort((a, b) => order(a) - order(b));
  return { reports, errors };
}

/**
 * SSL Targets › Verify: the exact-origin checks of a batch that got a verdict (lib/verify.js rows,
 * `via` known or zone), an unanswered one included: it was asked.
 * @param {object[]} rows
 * @returns {Array<{ name: string, ip: string, port: number, outcome: string, server: string|null }>}
 */
export function verifyObservations(rows) {
  const out = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!r || r.state !== 'done' || r.stale || !r.proxied || !EXACT_VIAS.has(r.via) || !r.status) continue;
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
