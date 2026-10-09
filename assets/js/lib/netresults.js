/**
 * lib/netresults.js — the results of "Map IPs to servers" (IP Intel, Bulk Resolve, Reverse DNS) and
 * of Servers as the page template draws them (docs/DESIGN.md §5, §8 phase 5): the result title's
 * count, the status summary's items with the table filters they press, the metric strip's figures
 * and which zeros fold, the facts of the Copy summary builders of Bulk Resolve and Reverse DNS
 * (lib/summary.js bulkSummary, ptrSummary), the links a result hands over, and the columns the
 * result header's Export ▾ writes from a table's own column definitions.
 *
 * Pure: no DOM, no i18n (the views word the keys), no clock. lib/template.js orders and trims the
 * status items; ui/template.js draws them. Light on purpose: it imports lib/ip.js alone, so the
 * Servers view never pulls in a sweep's or a lookup's libraries through it.
 */

import { ipVersion, isPrivateIP } from './ip.js';

/** A count, or 0 (never negative, never a fraction). */
const n = (v) => (Number.isFinite(Number(v)) && Number(v) > 0 ? Math.floor(Number(v)) : 0);

/** The truthy strings of a list, each once, in order. */
const unique = (list) => [...new Set((Array.isArray(list) ? list : []).filter((x) => typeof x === 'string' && x))];

/* ------------------------------------------------------------------------ */
/* IP Intel                                                                 */
/* ------------------------------------------------------------------------ */

/** IP Intel's metric strip, in its order (views/ip.js). */
export const IP_METRICS = Object.freeze(['ips', 'cdn', 'mine', 'priv', 'nets', 'countries']);

/**
 * The metrics whose zero folds into one sentence ("None of these addresses is behind a CDN / proxy").
 * An address's classification, servers and private range are known as soon as its row exists; the
 * networks and countries grow while the lookups run, so they never fold.
 */
export const IP_FOLDABLE = Object.freeze(['cdn', 'mine', 'priv']);

/** The table filters IP Intel's status items press (an item pressed again shows every row). */
export const IP_FILTERS = Object.freeze(['cdn', 'mine', 'private']);

/**
 * The figures of IP Intel's rows: what the metric strip, the status summary and the result title
 * count.
 * @param {Array<{ ip: string, info?: object|null, pending?: boolean, classification?: object, servers?: object[] }>} rows
 * @returns {{ ips: number, v4: number, v6: number, cdn: number, providers: string[], mine: number, servers: string[],
 *   priv: number, nets: number, countries: string[], pending: number }}
 *   `providers`: the CDN / proxy names; `servers`: the names of the user's servers holding an
 *   address; `countries`: ISO codes; `pending`: rows still being looked up
 */
export function ipFigures(rows) {
  const list = (Array.isArray(rows) ? rows : []).filter((r) => r && typeof r.ip === 'string');
  const v6 = list.filter((r) => ipVersion(r.ip) === 6).length;
  const cdn = list.filter((r) => r.classification && r.classification.hidesOrigin);
  const mine = list.filter((r) => Array.isArray(r.servers) && r.servers.length);
  return {
    ips: list.length,
    v4: list.length - v6,
    v6,
    cdn: cdn.length,
    providers: unique(cdn.map((r) => r.classification.provider && r.classification.provider.name)),
    mine: mine.length,
    servers: unique(mine.flatMap((r) => r.servers.map((s) => s && s.name))),
    priv: list.filter((r) => isPrivateIP(r.ip)).length,
    nets: new Set(list.map((r) => r.info && r.info.asn).filter(Boolean)).size,
    countries: unique(list.map((r) => r.info && r.info.country)),
    pending: list.filter((r) => r.pending).length
  };
}

/**
 * The metrics IP Intel shows: "Your servers" only when the workspace has a server list to match
 * the addresses against (without one, 0 would claim nothing).
 * @param {{ inventory?: boolean }} [opts]
 * @returns {string[]} ids of {@link IP_METRICS}
 */
export function ipMetricIds({ inventory = false } = {}) {
  return IP_METRICS.filter((id) => id !== 'mine' || inventory);
}

/**
 * IP Intel's status summary (docs/DESIGN.md §5.4, §5.6: "· networks · countries ⓘ behind CDN ·
 * in your servers · private"), with the services whose failure left cells empty first ("1 source
 * failed", §5.2). An item's `filter` is the table filter it presses ({@link ipRowMatches}).
 * @param {{ figures?: ReturnType<typeof ipFigures>, failedSources?: number, inventory?: boolean }} [input]
 * @returns {Array<{ key: string, severity: string, count: number, filter: string|null }>}
 */
export function ipStatus({ figures = null, failedSources = 0, inventory = false } = {}) {
  const f = figures || ipFigures([]);
  return [
    { key: 'sources', severity: 'error', count: n(failedSources), filter: null },
    { key: 'cdn', severity: 'info', count: n(f.cdn), filter: 'cdn' },
    { key: 'nets', severity: 'neutral', count: n(f.nets), filter: null },
    { key: 'countries', severity: 'neutral', count: n(f.countries.length), filter: null },
    { key: 'mine', severity: 'neutral', count: inventory ? n(f.mine) : 0, filter: 'mine' },
    { key: 'priv', severity: 'neutral', count: n(f.priv), filter: 'private' }
  ];
}

/**
 * Does an IP Intel row pass a status filter ({@link IP_FILTERS})? Any other filter passes every row.
 * @param {{ ip: string, classification?: object, servers?: object[] }} row
 * @param {string|null} filter
 * @returns {boolean}
 */
export function ipRowMatches(row, filter) {
  if (!row) return false;
  switch (filter) {
    case 'cdn': return !!(row.classification && row.classification.hidesOrigin);
    case 'mine': return Array.isArray(row.servers) && row.servers.length > 0;
    case 'private': return isPrivateIP(row.ip);
    default: return true;
  }
}

/* ------------------------------------------------------------------------ */
/* Bulk Resolve                                                             */
/* ------------------------------------------------------------------------ */

/** Bulk Resolve's metric strip over the host names (views/bulk.js), in its order. */
export const BULK_METRICS = Object.freeze(['names', 'hidden', 'direct', 'unresolved']);

/** The host-name metrics whose zero folds once a job has ended (they grow while it runs). */
export const BULK_FOLDABLE = Object.freeze(['hidden', 'direct', 'unresolved']);

/** At most this many addresses go to IP Intel ("Use in IP Intel": views/ip.js MAX_IPS). */
export const HANDOFF_MAX_IPS = 250;

/** A Bulk Resolve link carries the job's host names only up to this many (like IP Intel's 40 entries). */
export const BULK_LINK_MAX_NAMES = 40;

/**
 * Bulk Resolve's status summary (docs/DESIGN.md §5.6: "· resolving ⓘ behind CDN · direct ⚠ not
 * resolving · your servers"), with the lookups that failed first (a resolver error is never a
 * silent "not resolving"). Each item's `filter` is the host table's "Show" filter it presses
 * (views/bulk.js BULK_FILTERS).
 * @param {{ resolved?: number, hidden?: number, direct?: number, unresolved?: number, errors?: number, mine?: number }} [stats]
 *   views/bulk.js bulkStats; `mine`: the host names that point at one of your servers
 * @param {{ inventory?: boolean }} [opts] `inventory`: the job matched a server list
 * @returns {Array<{ key: string, severity: string, count: number, filter: string }>}
 */
export function bulkStatus(stats, { inventory = false } = {}) {
  const s = stats || {};
  return [
    { key: 'errors', severity: 'error', count: n(s.errors), filter: 'errors' },
    { key: 'unresolved', severity: 'warn', count: n(s.unresolved), filter: 'unresolved' },
    { key: 'hidden', severity: 'info', count: n(s.hidden), filter: 'hidden' },
    { key: 'resolving', severity: 'neutral', count: n(s.resolved), filter: 'resolving' },
    { key: 'direct', severity: 'neutral', count: n(s.direct), filter: 'direct' },
    { key: 'mine', severity: 'neutral', count: inventory ? n(s.mine) : 0, filter: 'mine' }
  ];
}

/**
 * The route params of a Bulk Resolve job's link (`names=`): its host names, comma-joined, when
 * there are at most {@link BULK_LINK_MAX_NAMES}; null for a longer list, which no link carries
 * (Copy link then hides). A link pre-fills the list and waits for a click.
 * @param {string[]} names
 * @returns {{ names: string }|null}
 */
export function bulkLinkParams(names) {
  const list = unique(names);
  return list.length && list.length <= BULK_LINK_MAX_NAMES ? { names: list.join(',') } : null;
}

/**
 * The addresses "Use in IP Intel" hands over: a job's unique addresses, in their order, at most
 * {@link HANDOFF_MAX_IPS} (IP Intel looks up no more). The link only fills IP Intel's box.
 * @param {Iterable<string>} ips
 * @returns {string[]}
 */
export function handoffIps(ips) {
  return unique([...(ips || [])]).slice(0, HANDOFF_MAX_IPS);
}

/**
 * The facts of Bulk Resolve's Copy summary (lib/summary.js bulkSummary) of a finished or
 * cancelled job: what the result header and the tables show, never a server's name (how many
 * addresses are in the server list, as IP Intel says it).
 * @param {{ names: string[], status: string, done?: number, rows: object[], ips: Map<string, object>|object[], finishedAt?: Date|null }} job
 *   views/bulk.js createJob: `rows` (name, resolution.status, classification, ips, servers),
 *   `ips` (ip, version, servers)
 * @param {{ inventory?: boolean }} [opts]
 * @returns {object|null} null while the job runs (nothing to copy yet)
 */
export function bulkSummaryFacts(job, { inventory = false } = {}) {
  if (!job || job.status === 'running' || !Array.isArray(job.names)) return null;
  const rows = Array.isArray(job.rows) ? job.rows : [];
  const ipRows = job.ips instanceof Map ? [...job.ips.values()] : Array.isArray(job.ips) ? job.ips : [];
  const failed = (r) => r.resolution && r.resolution.status !== 'NOERROR' && r.resolution.status !== 'NXDOMAIN';
  const resolving = rows.filter((r) => Array.isArray(r.ips) && r.ips.length);
  const kind = (r) => (r.classification ? r.classification.kind : null);
  const notResolving = rows.filter((r) => !(Array.isArray(r.ips) && r.ips.length));
  const v6 = ipRows.filter((r) => r.version === 6 || ipVersion(r.ip) === 6).length;
  return {
    names: job.names.length,
    one: job.names.length === 1 ? job.names[0] : null,
    status: job.status,
    done: n(job.done ?? rows.length),
    resolved: resolving.length,
    cloudflare: rows.filter((r) => kind(r) === 'cloudflare').length,
    cdn: rows.filter((r) => r.classification && r.classification.hidesOrigin && kind(r) !== 'cloudflare').length,
    direct: rows.filter((r) => kind(r) === 'direct' || kind(r) === 'private').length,
    private: rows.filter((r) => kind(r) === 'private').length,
    notFound: notResolving.filter((r) => !failed(r)).map((r) => r.name),
    failed: notResolving.filter(failed).map((r) => r.name),
    ips: ipRows.length,
    v4: ipRows.length - v6,
    v6,
    mine: inventory ? ipRows.filter((r) => Array.isArray(r.servers) && r.servers.length).length : null,
    at: job.finishedAt || null
  };
}

/* ------------------------------------------------------------------------ */
/* Reverse DNS                                                              */
/* ------------------------------------------------------------------------ */

/** Reverse DNS's metric strip, in its order (views/ptr.js); `focus` or `servers` is the last. */
export const PTR_METRICS = Object.freeze(['addresses', 'named', 'confirmed', 'none', 'failed', 'focus', 'servers']);

/** The Reverse DNS metrics whose zero folds once a sweep has ended. */
export const PTR_FOLDABLE = Object.freeze(['none', 'failed']);

/**
 * Reverse DNS's status summary (docs/DESIGN.md §5.6: "· named ✓ confirmed ⚠ not confirmed · no
 * PTR ✕ failed"). Each item's `filter` is the table's "Show" filter it presses (lib/ptrsweep.js
 * SWEEP_FILTERS).
 * @param {{ withPtr?: number, noReverse?: number, failed?: number, byStatus?: Record<string, number> }} [summary]
 *   lib/ptrsweep.js sweepSummary
 * @returns {Array<{ key: string, severity: string, count: number, filter: string }>}
 */
export function ptrStatus(summary) {
  const s = summary || {};
  const by = s.byStatus || {};
  return [
    { key: 'failed', severity: 'error', count: n(s.failed), filter: 'failed' },
    { key: 'mismatch', severity: 'warn', count: n(by.mismatch), filter: 'mismatch' },
    { key: 'confirmed', severity: 'ok', count: n(by.confirmed), filter: 'confirmed' },
    { key: 'named', severity: 'neutral', count: n(s.withPtr), filter: 'ptr' },
    { key: 'none', severity: 'neutral', count: n(s.noReverse), filter: 'none' }
  ];
}

/**
 * The status item a Reverse DNS filter stands for (pressed while it applies), or null ('all',
 * 'focus': no item).
 * @param {string} filter lib/ptrsweep.js SWEEP_FILTERS
 * @returns {string|null}
 */
export function ptrStatusOfFilter(filter) {
  const item = ptrStatus({}).find((x) => x.filter === filter);
  return item ? item.key : null;
}

/**
 * The facts of Reverse DNS's Copy summary (lib/summary.js ptrSummary) of a finished or stopped
 * sweep: the counts of the result header, the addresses whose name does not resolve back and the
 * names under the focus domain. Nothing from the server list: the summary's link carries the
 * swept target as typed, so it says nothing about which addresses are the user's servers.
 * @param {{ label: string, planned: number, status: string, results: object[], finishedAt?: Date|null }} job
 *   views/ptr.js startJob
 * @param {{ summary: object, focus?: string|null, focusNames?: string[] }} input `summary`:
 *   lib/ptrsweep.js sweepSummary of the job's results; `focusNames`: the PTR names under the focus domain
 * @returns {object|null} null while the sweep runs
 */
export function ptrSummaryFacts(job, { summary, focus = null, focusNames = [] } = {}) {
  if (!job || job.status === 'running' || !summary) return null;
  const results = Array.isArray(job.results) ? job.results : [];
  const by = summary.byStatus || {};
  return {
    label: String(job.label || ''),
    planned: n(job.planned),
    status: job.status,
    done: n(summary.done),
    withPtr: n(summary.withPtr),
    templated: n(summary.templated),
    noReverse: n(summary.noReverse),
    failed: n(summary.failed),
    confirmed: n(by.confirmed),
    mismatch: n(by.mismatch),
    mismatches: results.filter((r) => r && r.status === 'mismatch').map((r) => ({ ip: r.ip, name: (r.names || [])[0] || '' })),
    focus: focus || null,
    focusNames: focus ? unique(focusNames) : [],
    at: job.finishedAt || null
  };
}

/* ------------------------------------------------------------------------ */
/* Servers                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * The figures of a parsed server list (lib/inventory.js parseInventory): what the result header's
 * title, meta line and status summary say.
 * @param {{ servers?: Array<{ ips?: string[], groups?: string[] }>, warnings?: object[], stats?: { lines?: number } }} [parsed]
 * @returns {{ servers: number, lines: number, ips: number, v4: number, v6: number, priv: number, groups: string[], warnings: number }}
 */
export function inventoryFigures(parsed) {
  const p = parsed || {};
  const servers = Array.isArray(p.servers) ? p.servers : [];
  const ips = servers.flatMap((s) => (Array.isArray(s.ips) ? s.ips : []));
  const v6 = ips.filter((ip) => ipVersion(ip) === 6).length;
  return {
    servers: servers.length,
    lines: n(p.stats && p.stats.lines),
    ips: ips.length,
    v4: ips.length - v6,
    v6,
    priv: ips.filter((ip) => isPrivateIP(ip)).length,
    groups: unique(servers.flatMap((s) => (Array.isArray(s.groups) ? s.groups : []))),
    warnings: Array.isArray(p.warnings) ? p.warnings.length : 0
  };
}

/**
 * Servers' status summary (docs/DESIGN.md §5.6: "· IPs · groups ⚠ warnings"): a press on the
 * warnings takes the focus to the first of them (the view).
 * @param {ReturnType<typeof inventoryFigures>} figures
 * @returns {Array<{ key: string, severity: string, count: number }>}
 */
export function inventoryStatus(figures) {
  const f = figures || inventoryFigures(null);
  return [
    { key: 'warnings', severity: 'warn', count: n(f.warnings) },
    { key: 'ips', severity: 'neutral', count: n(f.ips) },
    { key: 'groups', severity: 'neutral', count: n(f.groups.length) }
  ];
}

/* ------------------------------------------------------------------------ */
/* Export ▾ of a table                                                      */
/* ------------------------------------------------------------------------ */

/**
 * The columns a table exports, for lib/export.js toCsv, from its own column definitions
 * (ui/components.js DataTableColumn): every column but `export: false` (an export-only column,
 * `display: false`, included), headed by `exportHeader` or its label, its value read as the
 * table's own buttons read it — `exportValue`, else `searchValue`, else `sortValue`, else
 * `row[key]`; a list is joined with spaces. The result header's Export ▾ writes the rows the
 * table lists (filter and search applied, in its order: DataTable getVisibleRows) with them.
 * @param {Array<{ key: string, label?: string, exportHeader?: string, export?: boolean, exportValue?: Function,
 *   searchValue?: Function, sortValue?: Function }|null>} columns
 * @returns {Array<{ key: string, header: string, get: (row: object) => any }>}
 */
export function exportColumns(columns) {
  return (Array.isArray(columns) ? columns : []).filter((c) => c && c.key && c.export !== false).map((c) => ({
    key: c.key,
    header: String(c.exportHeader || (typeof c.label === 'string' ? c.label : c.key)),
    get: (row) => {
      const read = c.exportValue || c.searchValue || c.sortValue;
      const value = typeof read === 'function' ? read(row) : row == null ? undefined : row[c.key];
      return Array.isArray(value) ? value.filter((v) => v !== null && v !== undefined && v !== '').join(' ') : value;
    }
  }));
}

/**
 * The JSON rows of a table's export: one object per row, keyed by column ({@link exportColumns}).
 * @param {object[]} rows
 * @param {ReturnType<typeof exportColumns>} cols
 * @returns {Array<Record<string, any>>}
 */
export function exportObjects(rows, cols) {
  return (Array.isArray(rows) ? rows : []).map((row) => Object.fromEntries(cols.map((c) => [c.key, c.get(row)])));
}
