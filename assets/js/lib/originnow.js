/**
 * lib/originnow.js — a scan's remembered origins as the workspace's origin map reads them now.
 * A scan ranks a remembered origin (`via` known, lib/originmap.js knownForScan) first and counts
 * it where TLS terminates. Once a later CLI report, Verify check or zone file marks it stale
 * (lib/originfill.js), the result on screen and its exports flag it (`stale`: the map's mark) and
 * it no longer makes its server need the certificate: SSL Targets' Servers tab, summary and
 * exports, the Verify rows of such origins, the Subdomains JSON export's `origin.hints`.
 * DOM-free and pure (spec §5.70); the map or its lib/originmap.js originIndex is read as given.
 */

import { originIndex, rememberedRows } from './originmap.js';
import { rankServerGroups } from './topology.js';

const portOf = (v) => Number(v) || 443;
const keyOf = (name, ip, port) => `${name}|${ip}|${portOf(port)}`;
const isKnown = (r) => !!r && r.kind === 'known' && typeof r.host === 'string';

/**
 * The stale mark the map now has for one remembered origin of a name (its own entry at that
 * address and port, which also masks a covering `*.parent` one), or null.
 * @param {object|null} map the map, or its originIndex
 * @param {string} name
 * @param {string} ip canonical
 * @param {number|string|null} [port] 443 when absent
 * @returns {{ reason: string, at: string, ip?: string, port?: number }|null}
 */
export function originStaleMark(map, name, ip, port) {
  const [row] = rememberedRows(map, name, [{ ip, port: portOf(port) }]);
  return row && row.stale && row.entry && row.entry.stale ? { ...row.entry.stale } : null;
}

/**
 * Every remembered origin a scan used (its origin hints' reasons of kind 'known') that the map
 * now marks stale.
 * @param {object|null} result ScanResult
 * @param {object|null} map the map, or its originIndex
 * @returns {Map<string, object>} `name|ip|port` → the stale mark
 */
export function staleKnownUses(result, map) {
  const out = new Map();
  const index = originIndex(map);
  if (!index.map) return out;
  for (const hint of result && Array.isArray(result.originHints) ? result.originHints : []) {
    for (const r of Array.isArray(hint && hint.reasons) ? hint.reasons : []) {
      if (!isKnown(r)) continue;
      const key = keyOf(r.host, hint.ip, r.port);
      if (out.has(key)) continue;
      const mark = originStaleMark(index, r.host, hint.ip, r.port);
      if (mark) out.set(key, mark);
    }
  }
  return out;
}

/**
 * The origin hints of a scan with each remembered origin the map now marks stale carrying the
 * mark (`reason.stale`); the scan's own array when none is.
 * @param {object|null} result ScanResult
 * @param {object|null} map the map, or its originIndex
 * @param {Map<string, object>} [stale] {@link staleKnownUses} of the same result and map
 * @returns {object[]}
 */
export function hintsNow(result, map, stale = staleKnownUses(result, map)) {
  const hints = result && Array.isArray(result.originHints) ? result.originHints : [];
  if (!stale.size) return hints;
  return hints.map((hint) => {
    const reasons = Array.isArray(hint && hint.reasons) ? hint.reasons : [];
    const next = reasons.map((r) => {
      const mark = isKnown(r) ? stale.get(keyOf(r.host, hint.ip, r.port)) : null;
      return mark ? { ...r, stale: mark } : r;
    });
    return next.some((r, i) => r !== reasons[i]) ? { ...hint, reasons: next } : hint;
  });
}

/**
 * The server groups of a scan with the map now: an entry `via` known the map marks stale — one
 * the scan matched directly, or one a load balancer passed on (`lbs`) when every entry of that
 * name it came from is such a stale origin — carries the mark (`stale`), and no longer counts
 * toward its group's `needsCert` (a group left with an origin hint only is `maybeNeedsCert`);
 * the groups are then ranked again as the scan ranks them (lib/topology.js rankServerGroups).
 * The scan's own array when nothing is stale.
 * @param {object|null} result ScanResult
 * @param {object|null} map the map, or its originIndex
 * @param {Map<string, object>} [stale] {@link staleKnownUses} of the same result and map
 * @returns {object[]}
 */
export function serversNow(result, map, stale = staleKnownUses(result, map)) {
  const groups = result && Array.isArray(result.servers) ? result.servers : [];
  if (!stale.size) return groups;
  const byName = new Map(groups.map((g) => [g && g.server ? g.server.name : null, g]));
  const markOf = (entry, seen) => {
    if (!entry || entry.via !== 'known') return null;
    if (!Array.isArray(entry.lbs)) return stale.get(keyOf(entry.name, entry.ip, entry.port)) || null;
    // Passed on by a load balancer: stale only when each tie of the name there is a stale origin.
    let mark = null;
    for (const lbName of entry.lbs) {
      const lb = byName.get(lbName);
      if (!lb || seen.has(lb)) return null;
      const ties = lb.hosts.filter((x) => x && x.name === entry.name && x.via !== 'hint');
      if (!ties.length) return null;
      for (const x of ties) {
        const m = markOf(x, new Set([...seen, lb]));
        if (!m) return null;
        mark = mark || m;
      }
    }
    return mark;
  };
  let changed = false;
  const next = groups.map((g) => {
    const hosts = Array.isArray(g && g.hosts) ? g.hosts : [];
    const marked = hosts.map((e) => {
      const mark = markOf(e, new Set([g]));
      return mark ? { ...e, stale: mark } : e;
    });
    if (!marked.some((e, i) => e !== hosts[i])) return g;
    changed = true;
    const counts = (e) => (e.via === 'dns' || e.via === 'zone' || (e.via === 'known' && !e.stale)) && e.covered !== false;
    const needsCert = !!g.needsCert && marked.some(counts);
    const maybeNeedsCert = g.needsCert ? !needsCert && marked.some((e) => e.via === 'hint' && e.covered !== false) : !!g.maybeNeedsCert;
    return { ...g, hosts: marked, needsCert, maybeNeedsCert };
  });
  return changed ? rankServerGroups(next) : groups;
}

/**
 * A scan's result with the map now ({@link hintsNow}, {@link serversNow}, `stats.needsCert` and
 * `stats.hintedServers` counted again); the result itself when the map marks none of its
 * remembered origins stale.
 * @param {object|null} result ScanResult
 * @param {object|null} map the map, or its originIndex
 * @returns {object|null}
 */
export function resultNow(result, map) {
  if (!result || typeof result !== 'object') return result ?? null;
  const stale = staleKnownUses(result, map);
  if (!stale.size) return result;
  const servers = serversNow(result, map, stale);
  // Tied by origin hints alone, as lib/scanner.js counts them: a now-stale remembered origin is no tie.
  const tied = (e) => e.via === 'dns' || e.via === 'zone' || (e.via === 'known' && !e.stale);
  return {
    ...result,
    originHints: hintsNow(result, map, stale),
    servers,
    stats: {
      ...(result.stats || {}),
      needsCert: servers.filter((g) => g.needsCert).length,
      hintedServers: servers.filter((g) => !(Array.isArray(g.hosts) ? g.hosts : []).some(tied)).length
    }
  };
}

/**
 * Mark the Verify rows of remembered origins (`via` known) with the map now: `originStale` is the
 * mark the map has for the row's name, address and port, else null (rows of other kinds are left
 * as they are). Returns how many rows are marked.
 * @param {object[]} rows VerifyRow[]
 * @param {object|null} map the map, or its originIndex
 * @returns {number}
 */
export function markStaleOrigins(rows, map) {
  const index = originIndex(map);
  let count = 0;
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || row.via !== 'known') continue;
    row.originStale = index.map ? originStaleMark(index, row.name, row.ip, row.port) : null;
    if (row.originStale) count += 1;
  }
  return count;
}
