/**
 * dirmap.js — the Endpoint map view's model: the directories and endpoints a web host serves,
 * from the JSON reports of the companion CLI (cli/dir_scan.py --json). DOM-free; runs in
 * browsers and Node 22. Nothing is sent: a browser cannot read a cross-origin response's status
 * code, so the probing is the CLI's (run from a machine that reaches your hosts), and this
 * module only reads its reports.
 *
 * - {@link readDirReport}: one file of the CLI → a checked report (what is not one says why,
 *   {@link REPORT_ERRORS}); every value is validated, nothing of the file is trusted.
 * - {@link mergeDirReports}: several reports → one host per URL, the newest report answering
 *   for a path.
 * - {@link dirMap}: the merged reports → one entry per host with its paths, the counts and the
 *   verdicts as filters.
 * - {@link foundPaths}, {@link dirmapCsvRows}, {@link dirmapSummaryFacts}: what the view offers.
 *
 * Verdicts, per path: `found` — the path answers, unlike a random path (a real directory or
 * endpoint); `listing` — a directory listing is served; `protected` — behind auth (401 / 403);
 * `redirect` — it redirects elsewhere; `not-found` — 404, or indistinguishable from the server's
 * catch-all page; `blocked` / `timeout` / `error` — not checked. A path that answers is a fact
 * about the site, not a vulnerability; leaked secret files are the Exposure audit's and
 * content_audit.py's job.
 */

const MAX_BYTES = 16 * 1048576;
const MAX_REPORTS = 10;
const MAX_HOSTS = 2048;
const MAX_RESULTS = 20000;
const MAX_TEXT = 2048;

/** Largest report file read. */
export const DIRMAP_MAX_BYTES = MAX_BYTES;
/** Reports open at once. */
export const DIRMAP_MAX_REPORTS = MAX_REPORTS;
/** The CLI report's schema, the CLI's file name and where the site serves it. */
export const DIRMAP_SCHEMA = 'domainscope.dir-scan/1';
export const CLI_FILE = 'dir_scan.py';
export const CLI_PATH = 'cli/dir_scan.py';

/** Per-path verdicts, in the order the counts and the list show them. */
export const DIRMAP_VERDICTS = Object.freeze(['found', 'listing', 'protected', 'redirect', 'not-found', 'blocked', 'timeout', 'error']);
/** The verdicts that are a path on the site (what the map is). */
export const DIRMAP_HITS = Object.freeze(['found', 'listing']);
/** What the list can filter by ('answered' = found/listing/protected/redirect; 'unchecked' = blocked/timeout/error). */
export const DIRMAP_FILTERS = Object.freeze(['all', 'answered', 'found', 'listing', 'protected', 'redirect', 'unchecked', 'not-found']);
/** Why a file is not read. */
export const REPORT_ERRORS = Object.freeze(['too-large', 'not-json', 'not-report', 'version', 'no-hosts']);

const CLI_VERDICTS = new Set(['FOUND', 'LISTING', 'PROTECTED', 'REDIRECT', 'NOT_FOUND', 'BLOCKED', 'TIMEOUT', 'ERROR']);
const UNCHECKED = new Set(['blocked', 'timeout', 'error']);
const VERDICT_LC = { FOUND: 'found', LISTING: 'listing', PROTECTED: 'protected', REDIRECT: 'redirect', NOT_FOUND: 'not-found', BLOCKED: 'blocked', TIMEOUT: 'timeout', ERROR: 'error' };

const text = (v, max = MAX_TEXT) => (typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, '').trim().slice(0, max) : '');
const int = (v, lo, hi) => (Number.isInteger(v) && v >= lo && v <= hi ? v : null);

/**
 * @typedef {object} DirPath one result of a report, every value checked
 * @property {string} path the relative path (always starting with '/')
 * @property {string} verdict one of {@link DIRMAP_VERDICTS}
 * @property {number|null} status the HTTP status
 * @property {string} contentType
 * @property {number|null} length bytes (found / listing only)
 * @property {string} location a redirect's target origin
 * @property {string} detail why this verdict, in the CLI's words
 */

/**
 * @typedef {object} DirHost
 * @property {string} url the base URL ('https://host[:port]/base/')
 * @property {string} host
 * @property {boolean} reachable
 * @property {string} error when unreachable
 * @property {{ kind: string, status: number|null, note: string }} baseline
 * @property {string} notMapped when every path redirected away
 * @property {DirPath[]} paths
 */

function readResult(r) {
  if (!r || typeof r !== 'object' || !CLI_VERDICTS.has(r.verdict)) return null;
  const path = text(r.path, 512);
  if (!path) return null;
  return {
    path: path.startsWith('/') ? path : `/${path}`,
    verdict: VERDICT_LC[r.verdict],
    status: int(r.status, 100, 599),
    contentType: text(r.contentType, 128),
    length: Number.isInteger(r.length) && r.length >= 0 && r.length <= 1e9 ? r.length : null,
    location: text(r.location, 256),
    detail: text(r.detail, 300)
  };
}

function readHost(h) {
  if (!h || typeof h !== 'object') return null;
  const url = text(h.url, 512);
  const host = text(h.host, 253);
  if (!url || !host) return null;
  const b = h.baseline && typeof h.baseline === 'object' ? h.baseline : {};
  const paths = [];
  const seen = new Set();
  for (const r of Array.isArray(h.results) ? h.results.slice(0, MAX_RESULTS) : []) {
    const res = readResult(r);
    if (res && !seen.has(res.path)) {
      seen.add(res.path);
      paths.push(res);
    }
  }
  return {
    url,
    host,
    reachable: h.reachable !== false,
    error: text(h.error, 300),
    baseline: { kind: text(b.kind, 24), status: int(b.status, 100, 599), note: text(b.note, 300) },
    notMapped: text(h.notMapped, 300),
    paths
  };
}

/**
 * Read one file of the CLI (`dir_scan.py --json`).
 * @param {string} body
 * @param {{ name?: string }} [opts]
 * @returns {{ ok: true, report: { id, name, generatedAt: Date|null, hosts: DirHost[], warnings: string[] } }|{ ok: false, error: string, detail?: string }}
 */
export function readDirReport(body, { name = '' } = {}) {
  const raw = typeof body === 'string' ? body : '';
  if (raw.length > MAX_BYTES) return { ok: false, error: 'too-large' };
  let doc;
  try {
    doc = JSON.parse(raw.replace(/^﻿/, ''));
  } catch {
    return { ok: false, error: 'not-json' };
  }
  if (!doc || typeof doc !== 'object' || Array.isArray(doc) || typeof doc.schema !== 'string' || !doc.schema.startsWith('domainscope.dir-scan/')) {
    return { ok: false, error: 'not-report' };
  }
  if (doc.schema !== DIRMAP_SCHEMA) return { ok: false, error: 'version', detail: text(doc.schema.slice('domainscope.dir-scan/'.length), 16) };
  const hosts = [];
  const seen = new Set();
  for (const h of Array.isArray(doc.hosts) ? doc.hosts.slice(0, MAX_HOSTS) : []) {
    const host = readHost(h);
    if (host && !seen.has(host.url)) {
      seen.add(host.url);
      hosts.push(host);
    }
  }
  if (!hosts.length) return { ok: false, error: 'no-hosts' };
  const at = typeof doc.generatedAt === 'string' ? new Date(doc.generatedAt) : null;
  const generatedAt = at && !Number.isNaN(at.getTime()) ? at : null;
  return {
    ok: true,
    report: {
      id: `${generatedAt ? generatedAt.toISOString() : ''}|${hosts.map((h) => h.url).join(',').slice(0, 200)}|${hosts.length}`,
      name: text(name, 200),
      generatedAt,
      hosts,
      warnings: Array.isArray(doc.warnings) ? doc.warnings.map((w) => text(w, 300)).filter(Boolean).slice(0, 25) : []
    }
  };
}

/**
 * Several reports → one host per URL, the newest report (by generatedAt) answering for it.
 * @param {Array<{ generatedAt: Date|null, hosts: DirHost[] }>} reports
 * @returns {Map<string, { host: DirHost, report: number }>}
 */
export function mergeDirReports(reports) {
  const order = (reports || []).map((r, i) => ({ r, i }))
    .sort((a, b) => ((a.r.generatedAt ? a.r.generatedAt.getTime() : -Infinity) - (b.r.generatedAt ? b.r.generatedAt.getTime() : -Infinity)) || a.i - b.i);
  const out = new Map();
  for (const { r, i } of order) {
    for (const host of r.hosts) out.set(host.url, { host, report: i });
  }
  return out;
}

/**
 * @typedef {object} DirEntry
 * @property {string} url
 * @property {string} host
 * @property {boolean} reachable
 * @property {string} error
 * @property {{ kind: string, status: number|null, note: string }} baseline
 * @property {string} notMapped
 * @property {DirPath[]} paths
 * @property {Record<string, number>} counts
 * @property {number} report index of the report this host came from
 */

/**
 * The map of the open reports.
 * @param {{ reports?: Array<{ generatedAt: Date|null, hosts: DirHost[] }> }} input
 * @returns {{ entries: DirEntry[], counts: Record<string, number>, hosts: number, reachable: number }}
 */
export function dirMap({ reports = [] } = {}) {
  const merged = mergeDirReports(reports);
  const entries = [];
  const totals = countsObject();
  totals.paths = 0;
  let reachable = 0;
  for (const { host, report } of merged.values()) {
    const counts = countsObject();
    for (const p of host.paths) {
      counts[p.verdict] += 1;
      totals[p.verdict] += 1;
    }
    counts.answered = counts.found + counts.listing + counts.protected + counts.redirect;
    counts.unchecked = counts.blocked + counts.timeout + counts.error;
    counts.all = host.paths.length;
    totals.paths += host.paths.length;
    if (host.reachable) reachable += 1;
    entries.push({ ...host, counts, report });
  }
  entries.sort((a, b) => (b.counts.found + b.counts.listing) - (a.counts.found + a.counts.listing) || a.host.localeCompare(b.host));
  totals.answered = totals.found + totals.listing + totals.protected + totals.redirect;
  totals.unchecked = totals.blocked + totals.timeout + totals.error;
  return { entries, counts: totals, hosts: entries.length, reachable };
}

function countsObject() {
  const out = {};
  for (const v of DIRMAP_VERDICTS) out[v] = 0;
  return out;
}

/**
 * Does a path pass a filter of the list?
 * @param {DirPath} path
 * @param {string} filter one of {@link DIRMAP_FILTERS}
 * @returns {boolean}
 */
export function dirmapMatches(path, filter) {
  switch (filter) {
    case 'answered': return path.verdict === 'found' || path.verdict === 'listing' || path.verdict === 'protected' || path.verdict === 'redirect';
    case 'unchecked': return UNCHECKED.has(path.verdict);
    case 'found': case 'listing': case 'protected': case 'redirect': case 'not-found': return path.verdict === filter;
    default: return true;
  }
}

/**
 * The paths that answer (found + listing), host by host, for a copy list.
 * @param {DirEntry[]} entries
 * @param {{ includeProtected?: boolean }} [opts]
 * @returns {string[]} full URLs
 */
export function foundPaths(entries, { includeProtected = false } = {}) {
  const out = [];
  for (const entry of entries || []) {
    for (const p of entry.paths) {
      if (p.verdict === 'found' || p.verdict === 'listing' || (includeProtected && p.verdict === 'protected')) {
        out.push(entry.url.replace(/\/$/, '') + p.path);
      }
    }
  }
  return out;
}

/** The CSV columns of the list. */
export const DIRMAP_CSV_COLUMNS = Object.freeze(['host', 'path', 'verdict', 'status', 'length', 'content_type', 'location', 'detail']);

/**
 * The paths as CSV records (lib/export.js toCsv makes the file).
 * @param {DirEntry[]} entries
 * @param {(p: DirPath) => boolean} [match]
 * @returns {object[]}
 */
export function dirmapCsvRows(entries, match = () => true) {
  const rows = [];
  for (const entry of entries || []) {
    for (const p of entry.paths) {
      if (!match(p)) continue;
      rows.push({
        host: entry.host,
        path: p.path,
        verdict: p.verdict,
        status: p.status === null ? '' : p.status,
        length: p.length === null ? '' : p.length,
        content_type: p.contentType,
        location: p.location,
        detail: p.detail
      });
    }
  }
  return rows;
}

/**
 * The reports' hosts as text for the empty range (unused by the view, kept for symmetry).
 * @param {Array<{ hosts: DirHost[] }>} reports
 * @returns {string[]}
 */
export function reportHosts(reports) {
  return [...new Set((reports || []).flatMap((r) => r.hosts.map((h) => h.host)))];
}

/**
 * The Copy summary's facts (lib/dirmapsummary.js): the hosts, the counts, the paths that answer
 * (host and path only — never a response body or header of the reports), what could not be
 * checked, when the newest scan ran.
 * @param {{ map: ReturnType<typeof dirMap>, reports: Array<{ generatedAt: Date|null }> }} input
 * @returns {object}
 */
export function dirmapSummaryFacts({ map, reports = [] }) {
  const times = reports.map((r) => r.generatedAt).filter((d) => d instanceof Date);
  const found = [];
  for (const entry of map.entries) {
    for (const p of entry.paths) {
      if (p.verdict === 'found' || p.verdict === 'listing') found.push({ host: entry.host, path: p.path, listing: p.verdict === 'listing' });
    }
  }
  return {
    hosts: map.hosts,
    reachable: map.reachable,
    counts: { ...map.counts },
    found,
    protectedCount: map.counts.protected,
    redirectCount: map.counts.redirect,
    unchecked: map.counts.unchecked,
    reports: reports.length,
    at: times.length ? new Date(Math.max(...times.map((d) => d.getTime()))) : null
  };
}
