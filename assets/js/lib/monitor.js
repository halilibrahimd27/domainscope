/**
 * monitor.js — the Monitoring view over the headless runner's results (views/monitor.js): the
 * `--json` reports a nightly repository keeps (results/NAME.json, tools/ds.mjs) and the runner's
 * history (`--history DIR`: results/history/YYYY-MM.jsonl), read into one row per target, the
 * change timeline, the sparkline series and the tiles. The history line is written here too, so
 * the runner (tools/ds/history.mjs) and the page share one definition of it.
 *
 * - A report is checked with the runner's own shape rules (lib/runreport.js reportProblem, the
 *   rules a `--baseline` must meet): what the runner would refuse to compare is never drawn.
 * - A history line (`v: 1`): `{ v, at, command, target, ok, score?, grade?, minDaysLeft?,
 *   counts: { bad, info }, changes: [{ tag, tone, item }] ≤ 20, run?, gone? }` — one per target of
 *   a run (`gone`: a target of the baseline no longer checked, for its changes), `at` the run's end.
 *   `ok`: the check read what it needed ({@link checkCompleted}); `score` / `grade`: Domain Health's;
 *   `minDaysLeft`: the soonest expiry of the certificates the run saw (tls: served; ct: the current
 *   ones logged); `counts.bad`: the changes that count with a bad tone, `counts.info` every other one
 *   listed; `run`: the GitHub Actions run, when the runner ran in one. A line that is not one of
 *   these is skipped and counted, never fatal: the rest of the file is read.
 * - Rows: per target, the latest check of each command, from the newest report naming it (its
 *   history lines stand in for a command whose report is not open); a report older than the newest
 *   one by more than {@link STALE_MS} did not run since (a nightly check that failed leaves last
 *   night's file in place), so its checks count as not completed.
 * - Days left are counted from `now` for what the reports hold (the certificates' expiry dates);
 *   the history keeps them as of each run.
 *
 * DOM-free, no I/O; runs in browsers and Node 22 (the runner imports it).
 */

import { DS_TOOL, DS_VERSION, reportProblem } from './runreport.js';
import { toCsv } from './export.js';

/** The history line's format version. */
export const HISTORY_VERSION = 1;
/** Changes a history line keeps at most (the ones that count first). */
export const HISTORY_MAX_CHANGES = 20;
/** Month files the runner keeps: this month and the twelve before it. */
export const HISTORY_KEEP_MONTHS = 13;
/** A month file of the history: `YYYY-MM.jsonl`. */
export const HISTORY_FILE_RE = /^(\d{4})-(0[1-9]|1[0-2])\.jsonl$/;
/** A change's tone (tools/ds/diff.mjs). */
export const CHANGE_TONES = Object.freeze(['bad', 'good', 'info', 'quiet']);
/** The commands this view knows, in the order its rows show them (an unknown one goes last, by name). */
export const MONITOR_COMMANDS = Object.freeze(['health', 'ct', 'tls', 'takeover', 'audit', 'subdomains', 'drift', 'renew', 'dane']);
/** The largest file read (a big domain's subdomains report runs to megabytes). */
export const MONITOR_MAX_BYTES = 64 * 1024 * 1024;
/** Reports open at once at most. */
export const MONITOR_MAX_REPORTS = 60;
/** History lines kept at most (the newest; a year of nightly checks of 200 targets is about 220,000). */
export const MONITOR_MAX_LINES = 250000;
/** "Bad changes in N days": the window of the first tile. */
export const MONITOR_RECENT_DAYS = 7;
/** "Certificates under N days": the second tile. */
export const MONITOR_WARN_DAYS = 21;
/** A report this much older than the newest one open did not run since (a missed night and some). */
export const STALE_MS = 36 * 3600000;
/** Points a sparkline draws at most (the newest). */
export const SPARK_MAX_POINTS = 60;
/** Why a file was not read (`mon.error.<code>`). */
export const MONITOR_FILE_ERRORS = Object.freeze(['too-large', 'not-json', 'not-report', 'version', 'damaged', 'not-results', 'empty-history']);
/** Why a history line was skipped. */
export const HISTORY_LINE_PROBLEMS = Object.freeze(['not-json', 'not-object', 'version', 'at', 'command', 'target', 'ok', 'counts', 'changes', 'value']);
/** The columns of the timeline's CSV. */
export const TIMELINE_CSV_COLUMNS = Object.freeze(['at', 'command', 'target', 'tag', 'tone', 'counts', 'item', 'text', 'run']
  .map((key) => Object.freeze({ key, header: key })));

const DAY_MS = 86400000;
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const major = (v) => String(v).split('.')[0];
const COMMAND_RE = /^[a-z][a-z0-9-]{0,31}$/;
const TAG_RE = /^[A-Z][A-Z-]{0,15}$/;
const GRADE_RE = /^[A-F]$/;
/** Statuses of a source that answered (lib/sourceinfo.js OK_STATES). */
const SOURCE_OK = new Set(['ok', 'empty', 'partial']);
/** `tls` endpoint statuses, worst first (tools/ds/tlsdiff.mjs; a failed handshake below a certificate's own problem). */
export const TLS_WORST = Object.freeze(['EXPIRED', 'UNTRUSTED', 'NAME_MISMATCH', 'TLS_ERROR', 'TIMEOUT', 'CLOSED', 'OK', 'SKIPPED']);
/** Takeover risk severities, worst first (lib/takeover.js TAKEOVER_SEVERITIES); medium and worse are open problems. */
const RISK_ORDER = Object.freeze(['critical', 'high', 'medium', 'low', 'info']);
const RISK_COUNTED = new Set(['critical', 'high', 'medium']);

/** A time as milliseconds, or null. */
function msOf(v) {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? null : v.getTime();
  if (!isStr(v)) return null;
  const ms = Date.parse(v);
  return Number.isNaN(ms) ? null : ms;
}
const isoOf = (v) => {
  const ms = msOf(v);
  return ms === null ? null : new Date(ms).toISOString();
};
/** Whole days from `now` to `iso` (negative: past), as the runner counts them. */
const daysFrom = (iso, now) => {
  const ms = msOf(iso);
  return ms === null ? null : Math.floor((ms - now) / DAY_MS);
};
const minOf = (list) => {
  const n = list.filter((x) => Number.isFinite(x));
  return n.length ? Math.min(...n) : null;
};

/* ------------------------------------------------------------------------ */
/* What one target's check says                                             */
/* ------------------------------------------------------------------------ */

/**
 * Did one target's check read what it needed? health: no lookup failed; subdomains: the DNS
 * answered and a passive source did (an exact run asks none); ct: a source answered; drift: the
 * budget lasted and no record set's lookup failed; renew: a verdict; dane: no endpoint's lookup
 * failed; audit: every rule could be checked; tls: the host's DNS answered; takeover: every lookup
 * answered. A command this module does not know: null.
 * @param {string} command
 * @param {object} x a report's target
 * @returns {boolean|null}
 */
export function checkCompleted(command, x) {
  const t = isObj(x) ? x : {};
  switch (command) {
    case 'health': return !(Array.isArray(t.failedLookups) && t.failedLookups.length);
    case 'subdomains': {
      if (Array.isArray(t.warnings) && t.warnings.includes('DNS_UNREACHABLE')) return false;
      return t.mode === 'exact' || (Array.isArray(t.sources) && t.sources.some((s) => isObj(s) && !s.skipped && SOURCE_OK.has(s.state)));
    }
    case 'ct': return t.answered !== false;
    case 'drift': return !t.aborted && (Array.isArray(t.rows) ? t.rows : []).every((r) => !isObj(r) || r.status !== 'error');
    case 'renew': return t.verdict !== 'unknown';
    case 'dane': return (Array.isArray(t.endpoints) ? t.endpoints : []).every((e) => !isObj(e) || e.status !== 'error');
    case 'audit': return !(Number(t.unknown) > 0);
    case 'tls': return !t.carried;
    case 'takeover': return !(Array.isArray(t.failures) && t.failures.length);
    default: return null;
  }
}

/** The current certificates of a `ct` target (the CT watch's `current`; without it, the ones still valid at `now`). */
function ctCurrent(x, now) {
  const certs = (Array.isArray(x.certificates) ? x.certificates : []).filter(isObj);
  if (certs.some((c) => typeof c.current === 'boolean')) return certs.filter((c) => c.current === true);
  return certs.filter((c) => (msOf(c.notAfter) ?? -Infinity) > now);
}

/** The certificates a `tls` target was served (this run's, not the ones a failed handshake carried). */
const tlsCerts = (x) => (Array.isArray(x.endpoints) ? x.endpoints : []).filter((e) => isObj(e) && isObj(e.cert)).map((e) => e.cert);

/**
 * The soonest expiry, in whole days from `now`, of the certificates a target's check saw: tls the
 * ones served, ct the current ones logged; null for the other commands or none.
 * @param {string} command
 * @param {object} x
 * @param {number} now ms
 * @returns {number|null}
 */
export function minDaysLeftOf(command, x, now) {
  if (!isObj(x)) return null;
  if (command === 'tls') return minOf(tlsCerts(x).map((c) => daysFrom(c.notAfter, now)));
  if (command === 'ct') return minOf(ctCurrent(x, now).map((c) => daysFrom(c.notAfter, now)));
  return null;
}

/**
 * The facts a history line keeps of one target's check, as of the run's end `at`.
 * @param {string} command
 * @param {object} x a report's target
 * @param {number} at ms
 * @returns {{ ok: boolean, score?: number, grade?: string, minDaysLeft?: number }}
 */
export function targetFacts(command, x, at) {
  const out = { ok: checkCompleted(command, x) !== false };
  if (command === 'health' && isObj(x)) {
    if (Number.isFinite(x.score)) out.score = x.score;
    if (isStr(x.grade) && GRADE_RE.test(x.grade)) out.grade = x.grade;
  }
  const days = minDaysLeftOf(command, x, at);
  if (days !== null) out.minDaysLeft = days;
  return out;
}

/* ------------------------------------------------------------------------ */
/* The history line (written by the runner, read here)                      */
/* ------------------------------------------------------------------------ */

/** The changes of a report, grouped by their target, in the report's order (the ones that count first). */
function changesByTarget(doc) {
  const by = new Map();
  for (const c of Array.isArray(doc.changes) ? doc.changes : []) {
    if (!isObj(c) || !isStr(c.target) || !isStr(c.tag) || !TAG_RE.test(c.tag)) continue;
    if (!by.has(c.target)) by.set(c.target, []);
    by.get(c.target).push(c);
  }
  return by;
}

/** A change's counts: the bad ones that count, and every other one listed. */
function changeCounts(list) {
  const bad = list.filter((c) => c.counts !== false && c.tone === 'bad').length;
  return { bad, info: list.length - bad };
}

const lineChange = (c) => ({ tag: c.tag, tone: CHANGE_TONES.includes(c.tone) ? c.tone : 'info', item: isStr(c.item) ? c.item : null });

/**
 * The history lines of one run: one per target of the report, and one (`gone: true`) per target of
 * the baseline it no longer checks whose changes it lists. `at` is the run's end.
 * @param {object} doc the runner's report (tools/ds.mjs; `changes` only with --baseline)
 * @param {{ run?: string|null }} [opts] the GitHub Actions run (tools/ds/notify.mjs runUrl)
 * @returns {object[]} lines as JSON values
 */
export function historyLines(doc, { run = null } = {}) {
  if (!isObj(doc) || !Array.isArray(doc.targets)) return [];
  const at = isoOf(doc.finishedAt) || isoOf(doc.startedAt);
  if (!at || !isStr(doc.command) || !COMMAND_RE.test(doc.command)) return [];
  const atMs = msOf(at);
  const byTarget = changesByTarget(doc);
  const link = runLink(run);
  const line = (target, facts, changes, extra = {}) => ({
    v: HISTORY_VERSION,
    at,
    command: doc.command,
    target,
    ...facts,
    counts: changeCounts(changes),
    changes: changes.slice(0, HISTORY_MAX_CHANGES).map(lineChange),
    ...(link ? { run: link } : {}),
    ...extra
  });
  const out = [];
  const seen = new Set();
  for (const x of doc.targets) {
    if (!isObj(x) || !isStr(x.target) || seen.has(x.target)) continue;
    seen.add(x.target);
    out.push(line(x.target, targetFacts(doc.command, x, atMs), byTarget.get(x.target) || []));
  }
  for (const [target, changes] of byTarget) {
    if (!seen.has(target)) out.push(line(target, { ok: true }, changes, { gone: true }));
  }
  return out;
}

/**
 * The month file a time's line goes to: `YYYY-MM.jsonl` (UTC).
 * @param {Date|number|string} at
 * @returns {string}
 */
export function historyFileName(at) {
  const ms = msOf(at instanceof Date ? at.toISOString() : typeof at === 'number' ? new Date(at).toISOString() : at);
  const d = new Date(ms ?? Date.now());
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}.jsonl`;
}

/** A month as one number (year × 12 + month − 1), of a time or of a month file's name; null for neither. */
export function monthIndex(value) {
  if (isStr(value)) {
    const m = HISTORY_FILE_RE.exec(value);
    if (m) return Number(m[1]) * 12 + Number(m[2]) - 1;
  }
  const ms = typeof value === 'number' ? value : msOf(value);
  if (ms === null || !Number.isFinite(ms)) return null;
  const d = new Date(ms);
  return d.getUTCFullYear() * 12 + d.getUTCMonth();
}

/**
 * The month files of a directory listing the runner deletes: older than {@link HISTORY_KEEP_MONTHS}
 * months (this month and the twelve before it stay). Other names are never touched.
 * @param {string[]} names
 * @param {Date|number} now
 * @param {number} [keep]
 * @returns {string[]}
 */
export function staleHistoryFiles(names, now, keep = HISTORY_KEEP_MONTHS) {
  const current = monthIndex(now instanceof Date ? now.getTime() : now);
  return (names || []).filter((n) => {
    const i = isStr(n) && HISTORY_FILE_RE.test(n) ? monthIndex(n) : null;
    return i !== null && current - i >= keep;
  }).sort();
}

/**
 * The month files of the last `months` months (this one included), newest first: what the page
 * reads from a repository by default.
 * @param {string[]} names
 * @param {Date|number} now
 * @param {number} months
 * @returns {string[]}
 */
export function recentHistoryFiles(names, now, months) {
  const current = monthIndex(now instanceof Date ? now.getTime() : now);
  return [...new Set((names || []).filter((n) => isStr(n) && HISTORY_FILE_RE.test(n)))]
    .filter((n) => current - monthIndex(n) < months && monthIndex(n) <= current)
    .sort().reverse();
}

/**
 * A GitHub Actions run's link as the runner writes it, or null: https, `<owner>/<repo>/actions/runs/<id>`.
 * @param {unknown} value
 * @returns {string|null}
 */
export function runLink(value) {
  if (!isStr(value) || value.length > 300) return null;
  return /^https:\/\/[a-z0-9.-]+(?::\d{1,5})?\/[\w.-]+\/[\w.-]+\/actions\/runs\/\d{1,20}$/i.test(value) ? value : null;
}

/**
 * The repository of a run's link: `{ server, owner, repo }`, or null.
 * @param {string|null} link
 */
export function repoOfRun(link) {
  const ok = runLink(link);
  if (!ok) return null;
  const u = new URL(ok);
  const [owner, repo] = u.pathname.split('/').slice(1, 3);
  return { server: u.origin, owner, repo };
}

/**
 * Read one parsed history line, or why it is skipped.
 * @param {unknown} v
 * @returns {{ line: object }|{ why: string }}
 */
export function readHistoryLine(v) {
  if (!isObj(v)) return { why: 'not-object' };
  if (v.v !== HISTORY_VERSION) return { why: 'version' };
  const ms = msOf(v.at);
  if (ms === null) return { why: 'at' };
  if (!isStr(v.command) || !COMMAND_RE.test(v.command)) return { why: 'command' };
  if (!isStr(v.target) || !v.target.trim() || v.target.length > 300) return { why: 'target' };
  if (typeof v.ok !== 'boolean') return { why: 'ok' };
  const natural = (n) => Number.isInteger(n) && n >= 0;
  if (!isObj(v.counts) || !natural(v.counts.bad) || !natural(v.counts.info)) return { why: 'counts' };
  if (!Array.isArray(v.changes) || !v.changes.every((c) => isObj(c) && isStr(c.tag) && TAG_RE.test(c.tag)
    && CHANGE_TONES.includes(c.tone) && (c.item === null || c.item === undefined || isStr(c.item)))) return { why: 'changes' };
  if ((v.score !== undefined && !(Number.isFinite(v.score) && v.score >= 0 && v.score <= 100))
    || (v.grade !== undefined && !(isStr(v.grade) && GRADE_RE.test(v.grade)))
    || (v.minDaysLeft !== undefined && !Number.isInteger(v.minDaysLeft))
    || (v.run !== undefined && !runLink(v.run))
    || (v.gone !== undefined && v.gone !== true)) return { why: 'value' };
  return {
    line: {
      v: HISTORY_VERSION,
      at: new Date(ms).toISOString(),
      ms,
      command: v.command,
      target: v.target,
      ok: v.ok,
      ...(v.score !== undefined ? { score: v.score } : {}),
      ...(v.grade !== undefined ? { grade: v.grade } : {}),
      ...(v.minDaysLeft !== undefined ? { minDaysLeft: v.minDaysLeft } : {}),
      counts: { bad: v.counts.bad, info: v.counts.info },
      changes: v.changes.slice(0, HISTORY_MAX_CHANGES).map(lineChange),
      ...(v.run !== undefined ? { run: v.run } : {}),
      ...(v.gone ? { gone: true } : {})
    }
  };
}

/**
 * The lines of a history file (JSON Lines; a UTF-8 BOM and CRLF line ends are fine). A line that is
 * not a history line is skipped and counted with its number and why; empty lines are no lines.
 * @param {string} text
 * @returns {{ lines: object[], skipped: Array<{ line: number, why: string }> }}
 */
export function parseHistory(text) {
  const lines = [];
  const skipped = [];
  String(text ?? '').replace(/^﻿/, '').split(/\r?\n/).forEach((raw, i) => {
    const s = raw.trim();
    if (!s) return;
    let v;
    try {
      v = JSON.parse(s);
    } catch {
      skipped.push({ line: i + 1, why: 'not-json' });
      return;
    }
    const r = readHistoryLine(v);
    if (r.line) lines.push(r.line);
    else skipped.push({ line: i + 1, why: r.why });
  });
  return { lines, skipped };
}

/** The key one run's line of one target and command has: the same line read twice is one. */
export const lineKey = (l) => `${l.at}|${l.command}|${l.target}`;

/**
 * Lists of lines as one, oldest first: a line read twice (the same month file again, or a report's
 * own lines next to the history's) is kept once, the first one given winning; past `max` the
 * oldest go.
 * @param {...object[]} lists
 * @returns {object[]}
 */
export function mergeLines(...lists) {
  const by = new Map();
  for (const list of lists) for (const l of list || []) if (l && !by.has(lineKey(l))) by.set(lineKey(l), l);
  const out = [...by.values()].sort((a, b) => a.ms - b.ms || (a.command < b.command ? -1 : a.command > b.command ? 1 : 0)
    || (a.target < b.target ? -1 : a.target > b.target ? 1 : 0));
  return out.length > MONITOR_MAX_LINES ? out.slice(out.length - MONITOR_MAX_LINES) : out;
}

/**
 * The lines at `since` or later.
 * @param {object[]} lines
 * @param {number} since ms
 * @returns {object[]}
 */
export function pruneLines(lines, since) {
  return (lines || []).filter((l) => l.ms >= since);
}

/* ------------------------------------------------------------------------ */
/* Reading the files of a results folder                                   */
/* ------------------------------------------------------------------------ */

/**
 * Read one `--json` report of the runner: `{ ok: true, report }` or `{ ok: false, error, detail? }`
 * ({@link MONITOR_FILE_ERRORS}). `report`: `{ name, id, command, startedAt, finishedAt (ms), doc,
 * lines }`, `lines` its own history lines (a folder without history still draws one point).
 * @param {string} text
 * @param {{ name?: string }} [opts]
 */
export function readReport(text, { name = '' } = {}) {
  const source = String(text ?? '');
  if (source.length > MONITOR_MAX_BYTES) return { ok: false, error: 'too-large' };
  let doc;
  try {
    doc = JSON.parse(source.replace(/^﻿/, ''));
  } catch {
    return { ok: false, error: 'not-json' };
  }
  if (!isObj(doc) || doc.tool !== DS_TOOL) return { ok: false, error: 'not-report' };
  if (!isStr(doc.version) || major(doc.version) !== major(DS_VERSION)) return { ok: false, error: 'version', detail: isStr(doc.version) ? doc.version.slice(0, 20) : '?' };
  const problem = reportProblem(doc);
  if (problem) return { ok: false, error: 'damaged', detail: problem.slice(0, 200) };
  const finishedAt = msOf(doc.finishedAt) ?? msOf(doc.startedAt);
  if (finishedAt === null) return { ok: false, error: 'damaged', detail: 'it has no "finishedAt" time' };
  const lines = historyLines(doc).map((l) => readHistoryLine(l).line).filter(Boolean);
  return {
    ok: true,
    report: {
      name: String(name || ''),
      id: `${doc.command}|${doc.startedAt}|${doc.finishedAt}|${doc.targets.length}`,
      command: doc.command,
      startedAt: msOf(doc.startedAt),
      finishedAt,
      doc,
      lines
    }
  };
}

/**
 * An empty dataset: the reports open, the history lines, what each file gave.
 * @returns {{ reports: object[], lines: object[], files: object[] }}
 */
export function emptyMonitor() {
  return { reports: [], lines: [], files: [] };
}

/**
 * What a file of a results folder is: `report` (`*.json`), `history` (`*.jsonl`), `summary` (the
 * `*.md` next to each report: left alone without a word), else `other`. Pasted text is a report
 * when it is one JSON value, else history lines.
 * @param {{ name?: string, text?: string|null, source?: string }} file
 * @returns {'report'|'history'|'summary'|'other'}
 */
export function fileKind(file) {
  const name = String((file && file.name) || '');
  if (/\.jsonl$/i.test(name)) return 'history';
  if (/\.json$/i.test(name)) return 'report';
  if (/\.md$/i.test(name)) return 'summary';
  if (file && file.source === 'paste') {
    try {
      JSON.parse(String(file.text ?? ''));
      return 'report';
    } catch {
      return 'history';
    }
  }
  return 'other';
}

/**
 * Read dropped or fetched files into a dataset (a new one: `data` is not changed): `*.json` are
 * reports, `*.jsonl` history files ({@link fileKind}); the Markdown summaries of a results folder
 * are left alone without a word, any other file is a problem. The same report again is a
 * duplicate; past {@link MONITOR_MAX_REPORTS} the rest are not read (`capped`).
 * @param {{ reports: object[], lines: object[], files: object[] }} data
 * @param {Array<{ name: string, text: string|null, source?: string }>} files
 * @returns {{ data: object, added: { reports: number, lines: number, history: number }, problems: Array<{ name: string, error: string, detail?: string }>,
 *   duplicates: string[], capped: boolean, skippedLines: number }}
 */
export function readMonitorFiles(data, files) {
  const base = data || emptyMonitor();
  const reports = [...base.reports];
  const fileList = [...base.files];
  const problems = [];
  const duplicates = [];
  const historyLists = [];
  let capped = false;
  let skippedLines = 0;
  let history = 0;
  let added = 0;
  for (const file of files || []) {
    const name = String((file && file.name) || '');
    const text = file && isStr(file.text) ? file.text : '';
    const kind = fileKind(file);
    if (kind === 'summary') continue;
    if (kind === 'other') {
      problems.push({ name, error: 'not-results' });
      continue;
    }
    if (kind === 'history') {
      if (text.length > MONITOR_MAX_BYTES) {
        problems.push({ name, error: 'too-large' });
        continue;
      }
      const parsed = parseHistory(text);
      if (!parsed.lines.length && parsed.skipped.length) {
        problems.push({ name, error: 'empty-history', detail: String(parsed.skipped.length) });
        continue;
      }
      historyLists.push(parsed.lines);
      skippedLines += parsed.skipped.length;
      history += 1;
      // the same month again (read after another night's run): its entry takes the newer counts
      const entry = { name, kind: 'history', lines: parsed.lines.length, skipped: parsed.skipped.length };
      const at = fileList.findIndex((f) => f.kind === 'history' && f.name === name);
      if (at === -1) fileList.push(entry);
      else fileList[at] = entry;
      continue;
    }
    const read = readReport(text, { name });
    if (!read.ok) {
      problems.push({ name, error: read.error, ...(read.detail ? { detail: read.detail } : {}) });
      continue;
    }
    if (reports.some((r) => r.id === read.report.id)) {
      duplicates.push(name);
      continue;
    }
    if (reports.length >= MONITOR_MAX_REPORTS) {
      capped = true;
      continue;
    }
    reports.push(read.report);
    added += 1;
    fileList.push({ name, kind: 'report', command: read.report.command, targets: read.report.doc.targets.length, finishedAt: read.report.finishedAt });
  }
  const before = base.lines.length;
  const lines = mergeLines(base.lines, ...historyLists);
  return {
    data: { reports, lines, files: fileList },
    added: { reports: added, lines: Math.max(0, lines.length - before), history },
    problems,
    duplicates,
    capped,
    skippedLines
  };
}

/**
 * Every line of a dataset: the history files' first, then each report's own (which only add the runs
 * the history does not have yet).
 * @param {{ reports: object[], lines: object[] }} data
 * @returns {object[]}
 */
export function allLines(data) {
  return mergeLines(data.lines, ...data.reports.map((r) => r.lines));
}

/* ------------------------------------------------------------------------ */
/* Rows                                                                     */
/* ------------------------------------------------------------------------ */

/** Commands in this view's order: the known ones first, then the rest by name. */
export function commandOrder(a, b) {
  const ia = MONITOR_COMMANDS.indexOf(a);
  const ib = MONITOR_COMMANDS.indexOf(b);
  if (ia !== ib) return (ia === -1 ? MONITOR_COMMANDS.length : ia) - (ib === -1 ? MONITOR_COMMANDS.length : ib);
  return a < b ? -1 : a > b ? 1 : 0;
}

/** The worst `tls` status of a list, or null. */
export function worstTlsStatus(statuses) {
  const ranked = (statuses || []).filter((s) => TLS_WORST.includes(s)).sort((a, b) => TLS_WORST.indexOf(a) - TLS_WORST.indexOf(b));
  return ranked[0] || null;
}

/**
 * The facts of one target's latest check of one command, from its report (`now`: when days left
 * are counted from).
 * @param {string} command
 * @param {object} x the report's target
 * @param {object} report readReport's report
 * @param {number} now ms
 * @param {object[]} changes the report's changes of this target
 * @returns {object}
 */
export function cellFacts(command, x, report, now, changes = []) {
  const cell = { command, ms: report.finishedAt, ok: checkCompleted(command, x), stale: false, from: 'report', report: report.name, changes: changeCounts(changes) };
  switch (command) {
    case 'health': {
      const checks = Array.isArray(x.checks) ? x.checks.filter(isObj) : [];
      return {
        ...cell,
        score: Number.isFinite(x.score) ? x.score : null,
        grade: isStr(x.grade) && GRADE_RE.test(x.grade) ? x.grade : null,
        errors: checks.filter((c) => c.severity === 'error').length,
        warnings: checks.filter((c) => c.severity === 'warn').length
      };
    }
    case 'ct': {
      const watch = isObj(x.watch) && isObj(x.watch.counts) ? x.watch.counts : {};
      const n = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
      return {
        ...cell,
        current: ctCurrent(x, now).length,
        minDaysLeft: minDaysLeftOf('ct', x, now),
        newIssuers: [...new Set(changes.filter((c) => c.tag === 'ISSUER' && c.kind === 'appeared' && isStr(c.item)).map((c) => c.item))],
        unexpected: n(watch.unexpected),
        revoked: n(watch.revoked)
      };
    }
    case 'tls': {
      const endpoints = (Array.isArray(x.endpoints) ? x.endpoints : []).filter(isObj);
      return {
        ...cell,
        endpoints: endpoints.length,
        worst: worstTlsStatus(endpoints.map((e) => e.status)),
        problems: endpoints.filter((e) => e.status !== 'OK' && e.status !== 'SKIPPED').length,
        minDaysLeft: minDaysLeftOf('tls', x, now)
      };
    }
    case 'takeover': {
      const risks = (Array.isArray(x.risks) ? x.risks : []).filter(isObj);
      const worst = risks.map((r) => r.severity).filter((s) => RISK_ORDER.includes(s)).sort((a, b) => RISK_ORDER.indexOf(a) - RISK_ORDER.indexOf(b))[0] || null;
      return { ...cell, risks: risks.filter((r) => RISK_COUNTED.has(r.severity)).length, low: risks.filter((r) => r.severity === 'low').length, worst };
    }
    case 'audit': {
      const rules = (Array.isArray(x.rules) ? x.rules : []).filter(isObj);
      const carriedFail = (r) => r.status === 'unknown' && isObj(r.last) && r.last.status === 'fail';
      const security = isObj(x.security) && Number.isFinite(x.security.score) ? { score: x.security.score, max: Number.isFinite(x.security.max) ? x.security.max : 8 } : null;
      return {
        ...cell,
        fail: rules.filter((r) => r.status === 'fail' || carriedFail(r)).length,
        unknown: rules.filter((r) => r.status === 'unknown' && !carriedFail(r)).length,
        pass: rules.filter((r) => r.status === 'pass').length,
        security
      };
    }
    default:
      return cell;
  }
}

/** A cell from a history line, for a command whose report is not open. */
function lineCell(l) {
  return {
    command: l.command, ms: l.ms, ok: l.ok, stale: false, from: 'history', report: null, changes: { ...l.counts },
    ...(l.score !== undefined ? { score: l.score } : {}),
    ...(l.grade !== undefined ? { grade: l.grade } : {}),
    ...(l.minDaysLeft !== undefined ? { minDaysLeft: l.minDaysLeft } : {})
  };
}

/**
 * The certificates the open reports say expire soonest: tls's served ones, ct's current ones,
 * each once (by SHA-256, else by its CT id), days counted from `now`, soonest first.
 * @param {object[]} reports
 * @param {number} now ms
 * @param {number} [days] only those with fewer days left (Infinity: all)
 * @returns {Array<{ target: string, command: string, name: string, notAfter: string, daysLeft: number }>}
 */
export function expiringCertificates(reports, now, days = MONITOR_WARN_DAYS) {
  const latest = latestTargets(reports);
  const by = new Map();
  for (const [target, cmds] of latest) {
    for (const command of ['tls', 'ct']) {
      const hit = cmds.get(command);
      if (!hit) continue;
      const certs = command === 'tls' ? tlsCerts(hit.x) : ctCurrent(hit.x, now);
      for (const c of certs) {
        const left = daysFrom(c.notAfter, now);
        if (left === null || !(left < days)) continue;
        const key = isStr(c.sha256) && c.sha256 ? `sha:${c.sha256.toLowerCase()}` : `ct:${c.id}`;
        const names = Array.isArray(c.names) ? c.names.filter(isStr) : [];
        const name = (isStr(c.subject) && c.subject) || names[0] || target;
        const prev = by.get(key);
        if (!prev || (command === 'tls' && prev.command !== 'tls')) by.set(key, { target, command, name, notAfter: isoOf(c.notAfter), daysLeft: left });
      }
    }
  }
  return [...by.values()].sort((a, b) => a.daysLeft - b.daysLeft || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
}

/** Per target, the newest report of each command naming it: Map<target, Map<command, { report, x }>>. */
function latestTargets(reports) {
  const out = new Map();
  for (const r of reports || []) {
    for (const x of r.doc.targets) {
      if (!out.has(x.target)) out.set(x.target, new Map());
      const cmds = out.get(x.target);
      const prev = cmds.get(r.command);
      if (!prev || prev.report.finishedAt < r.finishedAt) cmds.set(r.command, { report: r, x });
    }
  }
  return out;
}

/**
 * Sparkline series of a target from its lines: the health score, and the soonest certificate expiry
 * (tls's served certificates when it is checked, else ct's), oldest first, the newest
 * {@link SPARK_MAX_POINTS} of each.
 * @param {object[]} lines the target's lines
 * @returns {{ score: Array<{ ms: number, value: number }>, days: Array<{ ms: number, value: number }> }}
 */
export function seriesOf(lines) {
  const sorted = [...(lines || [])].filter((l) => !l.gone).sort((a, b) => a.ms - b.ms);
  const score = sorted.filter((l) => l.command === 'health' && Number.isFinite(l.score)).map((l) => ({ ms: l.ms, value: l.score }));
  const daysOf = (command) => sorted.filter((l) => l.command === command && Number.isFinite(l.minDaysLeft)).map((l) => ({ ms: l.ms, value: l.minDaysLeft }));
  const tls = daysOf('tls');
  const days = tls.length ? tls : daysOf('ct');
  return { score: score.slice(-SPARK_MAX_POINTS), days: days.slice(-SPARK_MAX_POINTS) };
}

/**
 * The points of a sparkline in a `width` × `height` box (2 px inside its edges): "x,y x,y …" for an
 * SVG polyline, oldest left; a flat series sits in the middle. `domain` fixes the value range (a
 * score: 0 … 100).
 * @param {number[]} values
 * @param {{ width?: number, height?: number, domain?: [number, number]|null }} [opts]
 * @returns {{ points: string, last: { x: number, y: number }|null }}
 */
export function sparkPoints(values, { width = 96, height = 24, domain = null } = {}) {
  const v = (values || []).filter((n) => Number.isFinite(n));
  if (!v.length) return { points: '', last: null };
  const lo = domain ? Math.min(domain[0], ...v) : Math.min(...v);
  const hi = domain ? Math.max(domain[1], ...v) : Math.max(...v);
  const pad = 2;
  const w = width - pad * 2;
  const h = height - pad * 2;
  const round = (n) => Math.round(n * 10) / 10;
  const pts = v.map((n, i) => {
    const x = v.length === 1 ? width / 2 : pad + (w * i) / (v.length - 1);
    const y = hi === lo ? height / 2 : pad + h - (h * (n - lo)) / (hi - lo);
    return { x: round(x), y: round(y) };
  });
  return { points: pts.map((p) => `${p.x},${p.y}`).join(' '), last: pts[pts.length - 1] };
}

/**
 * One row per target: the latest check of each command (its report, else its newest history line),
 * whether every one of them completed, the bad changes of the last {@link MONITOR_RECENT_DAYS} days,
 * the soonest certificate expiry, the newest change and the sparkline series.
 * @param {{ reports: object[], lines: object[] }} data
 * @param {{ now?: number, recentDays?: number }} [opts]
 * @returns {object[]} worst first: did not complete, bad changes, soonest expiry, then by name
 */
export function monitorRows(data, { now = Date.now(), recentDays = MONITOR_RECENT_DAYS } = {}) {
  const reports = data.reports || [];
  const lines = allLines(data);
  const latest = latestTargets(reports);
  // the newest check of any kind: a report or a line older than it by STALE_MS did not run since
  const newest = Math.max(-Infinity, ...reports.map((r) => r.finishedAt), lines.length ? lines[lines.length - 1].ms : -Infinity);
  const linesBy = new Map();
  for (const l of lines) {
    if (!linesBy.has(l.target)) linesBy.set(l.target, []);
    linesBy.get(l.target).push(l);
  }
  /** A target's newest line of each command; a command whose newest line is "no longer checked" has none. */
  const lastLines = (list) => {
    const by = new Map();
    for (const l of list) if (!by.has(l.command) || by.get(l.command).ms <= l.ms) by.set(l.command, l);
    return [...by.values()].filter((l) => !l.gone);
  };
  const changesOf = new Map(reports.map((r) => [r, changesByTarget(r.doc)]));
  const since = now - recentDays * DAY_MS;
  const rows = [];
  for (const target of new Set([...latest.keys(), ...linesBy.keys()])) {
    const cells = {};
    for (const [command, { report, x }] of latest.get(target) || new Map()) {
      cells[command] = cellFacts(command, x, report, now, changesOf.get(report).get(target) || []);
    }
    const own = linesBy.get(target) || [];
    // the history stands in for a command whose report is not open (or is older than its last line)
    for (const l of lastLines(own)) if (!cells[l.command] || cells[l.command].ms < l.ms) cells[l.command] = lineCell(l);
    for (const cell of Object.values(cells)) if (newest - cell.ms > STALE_MS) cell.stale = true;
    const commands = Object.keys(cells).sort(commandOrder);
    if (!commands.length) continue;
    const incomplete = commands.filter((c) => cells[c].ok === false || cells[c].stale);
    const recent = own.filter((l) => l.ms >= since);
    const changes = own.flatMap((l) => l.changes.map((c) => ({ ...c, ms: l.ms, command: l.command })));
    const lastChange = changes.length ? changes.reduce((a, b) => (b.ms >= a.ms ? b : a)) : null;
    const days = minOf(['tls', 'ct'].map((c) => (cells[c] ? cells[c].minDaysLeft : null)));
    rows.push({
      target,
      cells,
      commands,
      ms: Math.max(...commands.map((c) => cells[c].ms)),
      incomplete,
      bad7: recent.reduce((n, l) => n + l.counts.bad, 0),
      minDaysLeft: days,
      lastChange,
      series: seriesOf(own)
    });
  }
  const rank = (r) => [r.incomplete.length ? 0 : 1, r.bad7 > 0 ? 0 : 1, r.minDaysLeft !== null && r.minDaysLeft < MONITOR_WARN_DAYS ? 0 : 1];
  return rows.sort((a, b) => {
    const ra = rank(a);
    const rb = rank(b);
    for (let i = 0; i < ra.length; i += 1) if (ra[i] !== rb[i]) return ra[i] - rb[i];
    if (a.minDaysLeft !== b.minDaysLeft) return (a.minDaysLeft ?? Infinity) - (b.minDaysLeft ?? Infinity);
    return a.target < b.target ? -1 : a.target > b.target ? 1 : 0;
  });
}

/**
 * The three tiles: the targets with a bad change in the last {@link MONITOR_RECENT_DAYS} days, the
 * certificates with under {@link MONITOR_WARN_DAYS} days left, the checks that did not complete
 * (their target and command; `stale`: the report is older than the newest one: it did not run since).
 * @param {object[]} rows monitorRows
 * @param {{ reports: object[] }} data
 * @param {{ now?: number }} [opts]
 */
export function monitorTiles(rows, data, { now = Date.now() } = {}) {
  return {
    targets: rows.length,
    bad: rows.filter((r) => r.bad7 > 0).map((r) => r.target),
    expiring: expiringCertificates(data.reports, now),
    incomplete: rows.flatMap((r) => r.incomplete.map((command) => ({ target: r.target, command, stale: r.cells[command].stale })))
  };
}

/** Does a row pass a tile's filter (`all`, `bad`, `expiring`, `incomplete`)? */
export function rowMatches(row, filter) {
  if (filter === 'bad') return row.bad7 > 0;
  if (filter === 'expiring') return row.minDaysLeft !== null && row.minDaysLeft < MONITOR_WARN_DAYS;
  if (filter === 'incomplete') return row.incomplete.length > 0;
  return true;
}

/* ------------------------------------------------------------------------ */
/* The timeline                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Every change of the dataset's lines, newest first (within one run, the report's order: the ones
 * that count first). A change of a run whose report is open carries its words (`text`) and whether
 * it counted; a line from the history alone has the tag, the tone and the item.
 * @param {{ reports: object[], lines: object[] }} data
 * @returns {Array<{ ms: number, at: string, command: string, target: string, tag: string, tone: string, item: string|null,
 *   counts: boolean|null, text: string|null, run: string|null }>}
 */
export function timelineEntries(data) {
  const runs = new Map();
  for (const r of data.reports || []) runs.set(`${new Date(r.finishedAt).toISOString()}|${r.command}`, changesByTarget(r.doc));
  const out = [];
  for (const l of allLines(data)) {
    const words = runs.get(`${l.at}|${l.command}`);
    const pool = words ? [...(words.get(l.target) || [])] : [];
    l.changes.forEach((c, i) => {
      const at = pool.findIndex((w) => w.tag === c.tag && (isStr(w.item) ? w.item : null) === c.item);
      const w = at === -1 ? null : pool.splice(at, 1)[0];
      out.push({
        ms: l.ms, at: l.at, command: l.command, target: l.target, tag: c.tag, tone: c.tone, item: c.item, order: i,
        counts: w ? w.counts !== false : null, text: w && isStr(w.text) ? w.text : null, run: l.run || null
      });
    });
  }
  return out.sort((a, b) => b.ms - a.ms || commandOrder(a.command, b.command) || (a.target < b.target ? -1 : a.target > b.target ? 1 : 0) || a.order - b.order);
}

/** The tone filters of the timeline: every change, the bad ones, the good ones, the rest. */
export const TIMELINE_TONES = Object.freeze(['all', 'bad', 'good', 'info']);

/**
 * The entries of a command, a target and a tone (`info`: info and quiet ones); '' or 'all' for any.
 * @param {object[]} entries
 * @param {{ command?: string, target?: string, tone?: string }} [filter]
 */
export function filterTimeline(entries, { command = '', target = '', tone = '' } = {}) {
  return (entries || []).filter((e) => (!command || e.command === command) && (!target || e.target === target)
    && (!tone || tone === 'all' || (tone === 'info' ? e.tone === 'info' || e.tone === 'quiet' : e.tone === tone)));
}

/**
 * The timeline as CSV (lib/export.js toCsv: a BOM, CRLF, spreadsheet-safe cells), the entries as given.
 * @param {object[]} entries
 * @returns {string}
 */
export function timelineCsv(entries) {
  const rows = (entries || []).map((e) => ({
    at: e.at, command: e.command, target: e.target, tag: e.tag, tone: e.tone,
    counts: e.counts === null || e.counts === undefined ? '' : e.counts ? 'yes' : 'no',
    item: e.item ?? '', text: e.text ?? '', run: e.run ?? ''
  }));
  return toCsv(rows, TIMELINE_CSV_COLUMNS);
}

/* ------------------------------------------------------------------------ */
/* Links and the summary                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The newest run link of the dataset's lines, or null.
 * @param {{ reports: object[], lines: object[] }} data
 * @returns {string|null}
 */
export function latestRun(data) {
  const lines = allLines(data);
  for (let i = lines.length - 1; i >= 0; i -= 1) if (lines[i].run) return lines[i].run;
  return null;
}

/**
 * The Copy summary's facts (lib/monitorsummary.js): the counts of the tiles, the targets with bad
 * changes and the checks that did not complete (by name), the certificates expiring first, when the
 * newest check ran. Names only: never an address of a report.
 * @param {object[]} rows
 * @param {object} tiles monitorTiles
 * @param {{ reports: object[], lines: object[] }} data
 */
export function monitorSummaryFacts(rows, tiles, data) {
  const lines = allLines(data);
  const times = [...(data.reports || []).map((r) => r.finishedAt), ...lines.map((l) => l.ms)].filter(Number.isFinite);
  const first = lines.length ? lines[0].ms : null;
  return {
    targets: rows.length,
    reports: (data.reports || []).length,
    runs: new Set(lines.map((l) => `${l.at}|${l.command}`)).size,
    since: first === null ? null : new Date(first),
    bad: tiles.bad.map((target) => ({ target, count: (rows.find((r) => r.target === target) || { bad7: 0 }).bad7 })),
    expiring: tiles.expiring.map((c) => ({ name: c.name, daysLeft: c.daysLeft })),
    incomplete: tiles.incomplete.map((x) => ({ target: x.target, command: x.command, stale: !!x.stale })),
    grades: rows.filter((r) => r.cells.health && r.cells.health.grade).map((r) => ({ target: r.target, grade: r.cells.health.grade, score: r.cells.health.score ?? null })),
    at: times.length ? new Date(Math.max(...times)) : null
  };
}
