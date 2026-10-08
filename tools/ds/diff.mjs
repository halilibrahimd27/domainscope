/**
 * tools/ds/diff.mjs — "Changes since the baseline": a run of the headless runner compared with
 * its previous `--json` report of the same subcommand, in the Python CLI's terms
 * (cli/ssl_origin_scan.py baseline_problem / compare_reports / order_changes / counts_as_change).
 *
 * A change is `{ tag, tone, counts, target, item, kind, before, after, parts }`:
 * - `tag`: render.mjs CHANGE_TAGS (NEW, GONE, WORSE, BETTER, CHANGED, FAILED, RECOVERED, FAILING,
 *   SCORE, ISSUER, NAME, CERT, CA, EXPIRING, REVOKED, EXPOSED, DANGLING); `tone`: 'bad' | 'good' |
 *   'info' | 'quiet';
 * - `counts`: false for what is listed but never counted by --fail-on-change (nor opens the
 *   nightly issue): a move from one failure state to another (FAILING: nothing was read either
 *   way), CT sources that could not be read (FAILED / RECOVERED: the source's outage, not the
 *   domain's change), what a failed lookup may hide (a finding "gone" while its lookup failed, a
 *   finding "new" in an area no earlier run read, a score moved by a failed lookup), a CT issuer
 *   or name that may only have been missed before (see surelyNew), a renewed certificate from a
 *   known issuer for known names (CERT), a certificate crossing a radar threshold while its
 *   automatic renewal is not overdue yet (EXPIRING, tools/ds/ctwatch.mjs radarCrossing) and a
 *   revoked certificate that was not the one in use. What a run could not read, its report carries
 *   from the last run that read it (tools/ds/carry.mjs): the run after is compared with that;
 * - `target` / `item`: the domain, name, zone or certificate, and what inside it moved (a
 *   finding id, a host, an RRset key, an issuer, an endpoint), null for the target itself;
 * - `parts`: the line as lib/summary.js parts, its untrusted values as code parts.
 * Pure: no I/O. The previous report is checked by {@link baselineProblem} before it is used.
 */

import { DS_TOOL, DS_VERSION } from './args.mjs';
import { code, isoDay, localYesNo, sourceName, certCount } from './render.mjs';
import { isLookupError, checkAreas, failedAreas, knownChecks, carriedFrom, lastFullTimes, lookupFailed } from './carry.mjs';
import { seenOf, radarCrossing } from './ctwatch.mjs';
import { textParts } from '../../assets/js/lib/summary.js';
import { DRIFT_SEVERITY } from '../../assets/js/lib/zonedrift.js';
import { DANE_SEVERITY } from '../../assets/js/lib/dane.js';

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const isStrOrNull = (v) => v === null || v === undefined || typeof v === 'string';
const isStrList = (v) => Array.isArray(v) && v.every(isStr);
const major = (v) => String(v).split('.')[0];

/* ------------------------------------------------------------------------ */
/* Baseline validation                                                      */
/* ------------------------------------------------------------------------ */

/** Why one item of a list is not what the comparison walks, or null. */
function itemsProblem(list, name, check) {
  if (!Array.isArray(list)) return `has no "${name}" list`;
  for (const [i, item] of list.entries()) {
    const p = isObj(item) ? check(item) : 'is not an object';
    if (p) return `${name}[${i}] ${p}`;
  }
  return null;
}

const checkProblem = (c) => (!isStr(c.id) ? 'has no "id"' : !isStr(c.severity) ? 'has no "severity"' : null);

/** Why a host (or the answer it carried, `lastGood`) is not what the comparison reads, or null. */
function answerProblem(h) {
  if (!isStrList(h.ipv4 || []) || !isStrList(h.ipv6 || [])) return 'has addresses that are not lists of text';
  if (!isStrList(h.cnames || [])) return 'has "cnames" that are not a list of text';
  if (!isStrOrNull(h.status) || !isStrOrNull(h.kind) || !isStrOrNull(h.provider)) return 'has a "status", "kind" or "provider" that is not text';
  return null;
}

const TARGET_CHECKS = Object.freeze({
  health: (x) => {
    if (x.score !== undefined && !Number.isFinite(x.score)) return 'has a "score" that is not a number';
    if (x.failedLookups !== undefined && !isStrList(x.failedLookups)) return 'has a "failedLookups" that is not a list of text';
    if (x.carried !== undefined) {
      const p = itemsProblem(x.carried, 'carried', (c) => (!isStr(c.area) ? 'has no "area"' : !isStrOrNull(c.from) ? 'has a "from" that is not text'
        : itemsProblem(c.checks, 'checks', checkProblem)));
      if (p) return p;
    }
    return itemsProblem(x.checks, 'checks', checkProblem);
  },
  subdomains: (x) => {
    if (!isStr(x.mode)) return 'has no "mode"';
    return itemsProblem(x.hosts, 'hosts', (h) => {
      if (!isStr(h.name)) return 'has no "name"';
      const p = answerProblem(h);
      if (p) return p;
      if (h.lastGood === undefined) return null;
      if (!isObj(h.lastGood) || !isStrOrNull(h.lastGood.at)) return 'has a "lastGood" that is not an answer';
      const q = answerProblem(h.lastGood);
      return q ? `lastGood ${q}` : null;
    });
  },
  ct: (x) => {
    if (!isStrList(x.names)) return 'has no "names" list';
    if (!isStrOrNull(x.readAt)) return 'has a "readAt" that is not text';
    if (x.sources !== undefined) {
      const p = itemsProblem(x.sources, 'sources', (s) => (!isStr(s.source) ? 'has no "source"' : !isStrOrNull(s.lastFullAt) ? 'has a "lastFullAt" that is not text' : null));
      if (p) return p;
    }
    if (x.seen !== undefined && !(isObj(x.seen) && isStr(x.seen.at) && isObj(x.seen.ids))) return 'has a "seen" that is not a store of certificate ids ({ at, ids })';
    const p = itemsProblem(x.issuers, 'issuers', (g) => (isStr(g.name) ? null : 'has no "name"'));
    if (p) return p;
    return itemsProblem(x.certificates, 'certificates', (c) => {
      if (!isStr(c.id)) return 'has no "id"';
      if (!isStr(c.ca)) return 'has no "ca"';
      if (!isStrList(c.names)) return 'has no "names" list';
      if (c.sources !== undefined && !isStrList(c.sources)) return 'has a "sources" that is not a list of text';
      if (c.carried !== undefined && !(isObj(c.carried) && isStrOrNull(c.carried.from))) return 'has a "carried" without a "from"';
      return null;
    });
  },
  drift: (x) => {
    if (x.preflight !== undefined && x.preflight !== null && !isObj(x.preflight)) return 'has a "preflight" that is not an object';
    return itemsProblem(x.rows, 'rows', (r) => (!isStr(r.key) ? 'has no "key"' : !isStr(r.status) ? 'has no "status"' : !isStrList(r.reasons || []) ? 'has "reasons" that are not a list of text' : null));
  },
  renew: (x) => {
    if (!isStr(x.verdict)) return 'has no "verdict"';
    return itemsProblem(x.findings, 'findings', (f) => (!isStr(f.id) ? 'has no "id"' : !isStr(f.severity) ? 'has no "severity"' : null));
  },
  dane: (x) => {
    if (!isStrOrNull(x.serialHex)) return 'has a "serialHex" that is not text';
    return itemsProblem(x.endpoints, 'endpoints', (e) => (!isStr(e.key) ? 'has no "key"' : !isStr(e.status) ? 'has no "status"' : null));
  },
  audit: (x) => itemsProblem(x.rules, 'rules', (r) => (!isStr(r.id) ? 'has no "id"' : !AUDIT_STATUSES.includes(r.status) ? 'has no "status" (pass, fail or unknown)' : null))
});

/** A cell's outcome in an audit report (lib/policy.js POLICY_STATUSES). */
const AUDIT_STATUSES = Object.freeze(['pass', 'fail', 'unknown']);

/**
 * Why `doc` cannot be the baseline of a `command` run, or null: it must be a `--json` report of
 * this runner, of the same subcommand, written by a version with the same major number, with
 * the lists the comparison walks well-formed.
 * @param {any} doc parsed JSON
 * @param {string} command
 * @returns {string|null}
 */
export function baselineProblem(doc, command) {
  if (!isObj(doc) || doc.tool !== DS_TOOL) return `it is not a --json report of ${DS_TOOL} (no "tool": "${DS_TOOL}")`;
  if (!isStr(doc.version) || major(doc.version) !== major(DS_VERSION)) {
    return `it was written by version ${JSON.stringify(doc.version ?? null)}, which this version (${DS_VERSION}) cannot compare`;
  }
  if (doc.command !== command) return `it is a report of "${doc.command}", not of "${command}"`;
  if (doc.options !== undefined && !isObj(doc.options)) return 'its "options" is not an object';
  if (!Array.isArray(doc.targets)) return 'it has no "targets" list';
  const check = TARGET_CHECKS[command];
  for (const [i, x] of doc.targets.entries()) {
    if (!isObj(x)) return `targets[${i}] is not an object`;
    if (!isStr(x.target)) return `targets[${i}] has no "target"`;
    const p = check ? check(x) : null;
    if (p) return `targets[${i}] ${p}`;
  }
  return null;
}

/**
 * The report's `baseline` block: the file (its base name), and the baseline's version and times.
 * @param {object} before the baseline report
 * @param {string|null} file
 */
export function baselineInfo(before, file) {
  const text = (v) => (isStr(v) ? v : null);
  return { file: file ? String(file).split(/[\\/]/).pop() : null, missing: false, version: text(before.version), startedAt: text(before.startedAt), finishedAt: text(before.finishedAt) };
}

/* ------------------------------------------------------------------------ */
/* The change model                                                         */
/* ------------------------------------------------------------------------ */

/**
 * @param {string} tag
 * @param {string} target
 * @param {string|null} item
 * @param {Array} what the parts after "target: "
 * @param {{ tone?: string, counts?: boolean, kind?: string, before?: any, after?: any }} [opts]
 */
function change(tag, target, item, what, { tone = 'info', counts = true, kind = 'changed', before = null, after = null } = {}) {
  return { tag, tone, counts, target, item, kind, before, after, parts: [code(target), ': ', ...what] };
}

/** Targets of a report by their `target`, in report order. */
const byTarget = (doc) => new Map((doc.targets || []).map((x) => [x.target, x]));

/** Severity ranks (lib/health, lib/renewal, lib/zonedrift DRIFT_SEVERITY, lib/dane DANE_SEVERITY). */
const SEVERITY_RANK = Object.freeze({ neutral: 0, ok: 0, info: 1, unknown: 1, warn: 2, error: 3 });
const notable = (severity) => severity === 'warn' || severity === 'error';

/**
 * Changes that count first, then the ones listed only, each group in its order (the CLI's
 * order_changes): every cap cuts what does not count first.
 * @param {object[]} changes
 */
export function orderChanges(changes) {
  return [...changes.filter((c) => c.counts), ...changes.filter((c) => !c.counts)];
}

/** The changes that count (--fail-on-change, the nightly issue). */
export function notableChanges(changes) {
  return (changes || []).filter((c) => c.counts);
}

/* ------------------------------------------------------------------------ */
/* health                                                                   */
/* ------------------------------------------------------------------------ */

/** The worst severity of each check id (a check id may appear more than once). */
function checksById(checks) {
  const out = new Map();
  for (const c of checks || []) {
    const prev = out.get(c.id);
    if (!prev || (SEVERITY_RANK[c.severity] ?? 0) > (SEVERITY_RANK[prev.severity] ?? 0)) out.set(c.id, c);
  }
  return out;
}

function healthTitle(t, c) {
  return textParts(t, c.titleKey || `health.${c.id}.title`, localYesNo(t, c.params));
}

function diffHealth(before, after, { t }) {
  const out = [];
  const old = byTarget(before);
  const now = byTarget(after);
  for (const [domain, a] of now) {
    const b = old.get(domain);
    if (!b) {
      out.push(change('NEW', domain, null, [`now checked: score ${a.score}`], { kind: 'appeared', after: { score: a.score } }));
      continue;
    }
    // A lookup that failed hides what it would have found, by area (carry.mjs failedAreas). This
    // run's failure: the findings of that area gone are listed, not counted, and the report
    // carries them to the next run. The baseline's: it carried the area as last read, and this
    // run is compared with that; an area no earlier run read makes its findings "new" listed
    // only. The failed lookup is a finding of its own, and counts. A score moved by a failed
    // lookup in either run is listed only: its findings say what moved.
    const failedNow = failedAreas(a);
    const unreadBefore = new Set([...carriedFrom(b)].filter(([, from]) => from === null).map(([area]) => area));
    const failedWhen = failedNow.size ? ' (a lookup failed this run)' : failedAreas(b).size ? ' (a lookup failed in the baseline run)' : '';
    if (Number.isFinite(b.score) && Number.isFinite(a.score) && b.score !== a.score) {
      out.push(change('SCORE', domain, null, [`health score ${b.score} → ${a.score}`, ...(failedWhen ? [failedWhen] : [])],
        { tone: failedWhen ? 'quiet' : a.score < b.score ? 'bad' : 'good', counts: !failedWhen, before: b.score, after: a.score }));
    }
    const bc = checksById(knownChecks(b));
    const ac = checksById(a.checks);
    for (const [id, x] of ac) {
      const y = bc.get(id);
      if (!y) {
        if (!notable(x.severity)) continue;
        const unsure = checkAreas(id).some((area) => unreadBefore.has(area));
        out.push(change('NEW', domain, id, [`${x.severity} `, code(id), ' — ', ...healthTitle(t, x), ...(unsure ? [' (its lookup failed in the baseline run: it may not be new)'] : [])],
          { tone: unsure ? 'quiet' : 'bad', counts: !unsure, kind: 'appeared', after: x.severity }));
        continue;
      }
      if (y.severity === x.severity || !(notable(x.severity) || notable(y.severity))) continue;
      const worse = (SEVERITY_RANK[x.severity] ?? 0) > (SEVERITY_RANK[y.severity] ?? 0);
      out.push(change(worse ? 'WORSE' : 'BETTER', domain, id, [code(id), `: ${y.severity} → ${x.severity} — `, ...healthTitle(t, x)],
        { tone: worse ? 'bad' : 'good', before: y.severity, after: x.severity }));
    }
    const readBefore = new Set((b.checks || []).map((c) => c.id));
    for (const [id, y] of bc) {
      if (ac.has(id) || !notable(y.severity)) continue;
      const hidden = !isLookupError(id) && checkAreas(id).some((area) => failedNow.has(area));
      // Carried by the baseline and carried again: nothing was read either night.
      if (hidden && !readBefore.has(id)) continue;
      out.push(change('GONE', domain, id, [`${y.severity} `, code(id), ' no longer reported — ', ...healthTitle(t, y),
        ...(hidden ? [' (its lookup failed this run: it may still be there)'] : [])], { tone: hidden ? 'quiet' : 'good', counts: !hidden, kind: 'disappeared', before: y.severity }));
    }
  }
  for (const [domain, b] of old) {
    if (!now.has(domain)) out.push(change('GONE', domain, null, [`no longer checked; score was ${b.score}`], { kind: 'disappeared', before: { score: b.score } }));
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* subdomains                                                               */
/* ------------------------------------------------------------------------ */

const resolves = (h) => (h.ipv4 || []).length > 0 || (h.ipv6 || []).length > 0;
const addresses = (h) => [...(h.ipv4 || []), ...(h.ipv6 || [])];
const DIRECT = new Set(['direct', 'private']);

/** "Cloudflare", "direct 192.0.2.10", "NXDOMAIN" … for a host line. */
function hostState(h) {
  if (lookupFailed(h)) return [`lookup failed (${h.status}${h.error ? `: ${h.error}` : ''})`];
  if (h.dangling) return ['dangling CNAME to ', code((h.cnames || []).slice(-1)[0] || '?')];
  if (!resolves(h)) return [h.status && h.status !== 'NOERROR' ? String(h.status) : 'no address (NODATA)'];
  const who = h.provider ? [code(h.provider)] : [String(h.kind || 'resolves')];
  const ips = addresses(h);
  return DIRECT.has(h.kind) || !h.provider
    ? [...who, ' ', ...ips.slice(0, 3).flatMap((ip, i) => (i ? [', ', code(ip)] : [code(ip)])), ...(ips.length > 3 ? [` +${ips.length - 3}`] : [])]
    : who;
}

/**
 * The change from one answer of a host to another, neither a failed lookup, or null.
 * @param {string} domain
 * @param {string} name
 * @param {object} y the earlier answer (a host, or the `lastGood` a failed one carried)
 * @param {object} x this run's
 * @param {Array} [note] parts after the line
 */
function hostMove(domain, name, y, x, note = []) {
  const where = [code(name), ' — '];
  if (!y.dangling && x.dangling) {
    return change('DANGLING', domain, name, [...where, ...hostState(x), '; was ', ...hostState(y), ...note], { tone: 'bad', before: y.status, after: x.status });
  }
  if (resolves(y) && !resolves(x)) {
    return change('GONE', domain, name, [...where, 'no longer resolves: ', ...hostState(x), ...note], { tone: 'bad', kind: 'disappeared', before: addresses(y), after: x.status });
  }
  if (!resolves(y) && resolves(x)) return change('NEW', domain, name, [...where, 'now resolves: ', ...hostState(x), ...note], { kind: 'appeared', before: y.status, after: addresses(x) });
  if (y.dangling && !x.dangling) {
    return change('BETTER', domain, name, [...where, 'no longer a dangling CNAME: ', ...hostState(x), ...note], { tone: 'good', before: y.status, after: x.status });
  }
  if (!resolves(x)) return null;
  const moved = y.kind !== x.kind || (y.providerId || y.provider) !== (x.providerId || x.provider);
  if (moved && y.hidesOrigin && !x.hidesOrigin && DIRECT.has(x.kind)) {
    return change('EXPOSED', domain, name, [...where, 'no longer behind ', code(y.provider || y.kind), ': now ', ...hostState(x), ...note], { tone: 'bad', before: y.kind, after: x.kind });
  }
  if (moved) return change('CHANGED', domain, name, [...where, ...hostState(y), ' → ', ...hostState(x), ...note], { before: y.kind, after: x.kind });
  if (DIRECT.has(x.kind) && addresses(x).join(',') !== addresses(y).join(',')) {
    return change('CHANGED', domain, name, [...where, 'addresses ', ...hostState(y), ' → ', ...hostState(x), ...note], { before: addresses(y), after: addresses(x) });
  }
  return null;
}

function diffHosts(domain, b, a) {
  const out = [];
  const old = new Map((b.hosts || []).filter((h) => !h.wildcardSuspect).map((h) => [h.name, h]));
  const now = new Map((a.hosts || []).filter((h) => !h.wildcardSuspect).map((h) => [h.name, h]));
  const exact = a.mode === 'exact';
  for (const [name, x] of now) {
    const y = old.get(name);
    const where = [code(name), ' — '];
    if (!y) {
      if (x.dangling) out.push(change('DANGLING', domain, name, ['new host ', ...where, ...hostState(x)], { tone: 'bad', kind: 'appeared', after: x.status }));
      else if (resolves(x)) out.push(change('NEW', domain, name, ['new host ', ...where, ...hostState(x)], { kind: 'appeared', after: x.status }));
      continue;
    }
    const yFail = lookupFailed(y);
    const xFail = lookupFailed(x);
    if (xFail && yFail) {
      if (x.status !== y.status) out.push(change('FAILING', domain, name, [...where, `${y.status} → ${x.status}`], { tone: 'quiet', counts: false, before: y.status, after: x.status }));
      continue;
    }
    if (xFail) {
      out.push(change('FAILED', domain, name, [...where, ...hostState(x), '; was ', ...hostState(y)], { tone: 'bad', before: y.status, after: x.status }));
      continue;
    }
    if (yFail) {
      // Answered again: compared with its last answer before the failed lookup (carry.mjs
      // carryHosts), so a host that left its proxy or moved meanwhile says so.
      const last = isObj(y.lastGood) ? y.lastGood : null;
      const moved = last && hostMove(domain, name, last, x, [` (compared with its answer ${last.at ? `of ${isoDay(last.at)}` : 'of an earlier run'}, before the lookup failed)`]);
      out.push(moved || change('RECOVERED', domain, name, [...where, `answers again${last ? ' as before' : ''}: `, ...hostState(x)],
        { tone: last || (resolves(x) && !x.dangling) ? 'good' : 'bad', before: y.status, after: x.status }));
      continue;
    }
    const moved = hostMove(domain, name, y, x);
    if (moved) out.push(moved);
  }
  for (const [name, y] of old) {
    if (now.has(name) || !(resolves(y) || y.dangling || lookupFailed(y))) continue;
    // A discovery run seeds the previous run's names (commands.mjs baselineSeeds), so a host
    // missing entirely was cut (a host cap, out of scope), not found gone: listed, not counted.
    out.push(exact
      ? change('GONE', domain, name, [code(name), ' — no longer in the names file'], { kind: 'disappeared', before: addresses(y) })
      : change('GONE', domain, name, [code(name), ' — not in this run\'s result (not looked up again)'], { tone: 'quiet', counts: false, kind: 'disappeared', before: addresses(y) }));
  }
  return out;
}

function diffSubdomains(before, after) {
  const out = [];
  const old = byTarget(before);
  const now = byTarget(after);
  for (const [domain, a] of now) {
    const b = old.get(domain);
    if (!b) out.push(change('NEW', domain, null, [`now scanned: ${(a.hosts || []).filter((h) => !h.wildcardSuspect && resolves(h)).length} hosts resolve`], { kind: 'appeared' }));
    else out.push(...diffHosts(domain, b, a));
  }
  for (const [domain] of old) if (!now.has(domain)) out.push(change('GONE', domain, null, ['no longer scanned'], { kind: 'disappeared' }));
  return out;
}

/* ------------------------------------------------------------------------ */
/* ct                                                                       */
/* ------------------------------------------------------------------------ */

/**
 * Is a certificate of this run surely absent from what the baseline `b` knew, so an issuer or a
 * name it brings is new? Per source, as the sources answer on different nights (Cert Spotter's
 * hourly quota runs out on a list of domains; crt.sh is often down), and with each source's last
 * full read (carry.mjs lastFullTimes: a night a source could not read carried that read on): yes
 * when a source that lists it now has read the domain in full before (it was not listed then, and
 * what it listed then is still known), or when it was issued after the earliest of those full
 * reads (a certificate that did not exist yet cannot have been missed). A baseline without
 * per-source states (never written by this version) falls back to its `complete`.
 * @param {object} b the baseline's target
 * @param {Map<string, string|null>} full source → the time of its last full read
 * @returns {(c: object) => boolean}
 */
function surelyNew(b, full) {
  if (!Array.isArray(b.sources)) return () => b.complete !== false;
  const times = [...full.values()].map((at) => Date.parse(at)).filter(Number.isFinite);
  const first = times.length ? Math.min(...times) : NaN;
  return (c) => (c.sources || []).some((s) => full.has(s)) || (Number.isFinite(first) && Date.parse(c.notBefore) > first);
}

function diffCt(before, after) {
  const out = [];
  const old = byTarget(before);
  const now = byTarget(after);
  // A source that could not be read is the source's outage, not the domain's change: FAILED and
  // RECOVERED are listed only. The report of a night that could not read carried the last read
  // (carry.mjs carryCt), so the night after is compared with that.
  const failedText = (x) => (x.sources || []).filter((s) => !s.ok)
    .map((s) => `${sourceName(s.source)} ${String(s.state || 'error').replace('-', ' ')}${s.skipped ? ' (not asked)' : ''}`).join(', ');
  for (const [domain, a] of now) {
    const b = old.get(domain);
    const read = (a.certificates || []).filter((c) => !c.carried).length;
    if (!b) {
      out.push(change('NEW', domain, null, [a.answered === false ? 'now watched (Certificate Transparency could not be read this run)' : `now watched: ${certCount(read)}`], { kind: 'appeared' }));
      continue;
    }
    const full = lastFullTimes(b, before.startedAt);
    const known = b.answered || full.size > 0 || (b.certificates || []).length > 0;
    if (!a.answered) {
      // Said once: a second night without a read has nothing new to say.
      if (b.answered) {
        out.push(change('FAILED', domain, null, [`Certificate Transparency could not be read this run (${failedText(a)}): nothing compared; the next run compares with the last read`],
          { tone: 'quiet', counts: false }));
      }
      continue;
    }
    if (!b.answered) {
      if (!known) {
        out.push(change('RECOVERED', domain, null, [`Certificate Transparency read again: ${certCount(read)} (not compared: no earlier run read it)`], { tone: 'quiet', counts: false }));
        continue;
      }
      const last = [...full.values()].filter(Boolean).sort().at(-1);
      out.push(change('RECOVERED', domain, null, [`Certificate Transparency read again: ${certCount(read)}, compared with the last read${last ? ` (${isoDay(last)})` : ''}`],
        { tone: 'quiet', counts: false }));
    }
    // A new issuer or name counts only when one of its certificates is surely new (surelyNew):
    // one a source missed before may have been there all along.
    const isNew = surelyNew(b, full);
    const unsure = [' (listed only by a source no earlier run read in full: it may not be new)'];
    const certs = (a.certificates || []).filter((c) => !c.carried);
    const oldIssuers = new Set((b.issuers || []).map((g) => g.name));
    const newIssuers = new Set();
    for (const g of a.issuers || []) {
      if (oldIssuers.has(g.name)) continue;
      newIssuers.add(g.name);
      const sure = certs.some((c) => c.ca === g.name && isNew(c));
      // Not one of the expected CAs (--expected-ca): it counts even when it may only have been
      // missed before, since no earlier run said it.
      const odd = certs.some((c) => c.ca === g.name && c.unexpected === true);
      out.push(change('ISSUER', domain, g.name, ['new issuer ', code(g.name),
        ...(g.intermediates && g.intermediates.length ? [' (', ...g.intermediates.slice(0, 3).flatMap((n, i) => (i ? [', ', code(n)] : [code(n)])), ')'] : []),
        `: ${certCount(g.count)}, newest ${isoDay(g.newest)}`, ...(odd ? [', not one of the expected CAs'] : []), ...(sure ? [] : unsure)],
      { tone: sure || odd ? 'bad' : 'quiet', counts: sure || odd, kind: 'appeared', after: g.count }));
    }
    const oldNames = new Set(b.names || []);
    const newNames = new Set((a.names || []).filter((n) => !oldNames.has(n)));
    for (const name of newNames) {
      const holders = certs.filter((c) => c.names.includes(name));
      const first = holders.slice(-1)[0];
      const sure = holders.some(isNew);
      out.push(change('NAME', domain, name, ['first certificate for ', code(name), ...(first ? [' (', code(first.ca), `, ${isoDay(first.notBefore)})`] : []), ...(sure ? [] : unsure)],
        { tone: sure ? 'info' : 'quiet', counts: sure, kind: 'appeared' }));
    }
    // New since the baseline: not among the ids the last runs that read the domain saw (the store
    // its report keeps, ctwatch.mjs; a baseline written before it: its certificates).
    const seenIds = new Set([...Object.keys((seenOf(b, before.startedAt) || { ids: {} }).ids), ...(b.certificates || []).map((c) => c.id)]);
    const names = (c) => [...c.names.slice(0, 3).flatMap((n, i) => (i ? [', ', code(n)] : [code(n)])), ...(c.names.length > 3 ? [` +${c.names.length - 3}`] : [])];
    const intermediate = (c) => (c.intermediate ? [' (', code(c.intermediate), ')'] : []);
    const also = (c) => [...(c.precert === true ? [' (precertificate only)'] : []), ...(c.revoked === true ? [' (revoked)'] : [])];
    for (const c of certs) {
      if (seenIds.has(c.id) || newIssuers.has(c.ca)) continue;
      if (c.unexpected === true) {
        // A certificate from a CA the run was told not to expect: the CT watch's "Unexpected CA".
        out.push(change('CA', domain, c.id, ['certificate from ', code(c.ca), ...intermediate(c), ', not one of the expected CAs, issued ',
          `${isoDay(c.notBefore)}: `, ...names(c), ...also(c)], { tone: 'bad', kind: 'appeared' }));
        continue;
      }
      if (c.names.every((n) => newNames.has(n))) continue;
      out.push(change('CERT', domain, c.id, ['new certificate from ', code(c.ca), ...intermediate(c), `, ${isoDay(c.notBefore)}: `, ...names(c), ...also(c)],
        { tone: 'quiet', counts: false, kind: 'appeared' }));
    }
    // The expiry radar: a current certificate within a threshold it was outside at the last read
    // of the domain (its time in the store), counted once its automatic renewal is overdue.
    const store = seenOf(b, before.startedAt);
    const lastRead = store ? Date.parse(store.at) : Date.parse(b.readAt || before.startedAt);
    const radar = isObj(a.watch) && Array.isArray(a.watch.radar) ? a.watch.radar : [];
    const prevById = new Map((b.certificates || []).map((c) => [c.id, c]));
    for (const c of a.certificates || []) {
      // known before: listed in the baseline, or in its store (a source missed it that night)
      const known = prevById.get(c.id) || (store && store.ids[c.id] ? { id: c.id } : undefined);
      const crossed = radarCrossing(c, known, { radar, lastRead });
      if (!crossed) continue;
      out.push(change('EXPIRING', domain, c.id, [...names(c), `: ${crossed.daysLeft} day${crossed.daysLeft === 1 ? '' : 's'} left (expires ${isoDay(c.notAfter)}), within the radar's ${crossed.threshold} days; `,
        code(c.ca), ...intermediate(c), crossed.overdue ? ' — its automatic renewal is overdue' : ' (an automatic renewal is not overdue yet)'],
      { tone: crossed.overdue ? 'bad' : 'quiet', counts: crossed.overdue, before: null, after: crossed.threshold }));
    }
    // Revoked since the baseline: counted when it was the certificate in use for its names.
    for (const c of certs) {
      const p = prevById.get(c.id);
      if (c.revoked !== true || !p || p.revoked === true) continue;
      const inUse = p.current === true && p.revoked === false;
      out.push(change('REVOKED', domain, c.id, ['certificate from ', code(c.ca), ...intermediate(c), ' revoked by its CA: ', ...names(c),
        inUse ? ' (it was the current certificate of these names)' : ' (a newer certificate covered these names, or the baseline did not know)'],
      { tone: inUse ? 'bad' : 'quiet', counts: inUse }));
    }
    if (a.complete) {
      const nowIssuers = new Set((a.issuers || []).map((g) => g.name));
      for (const g of b.issuers || []) {
        if (!nowIssuers.has(g.name)) out.push(change('GONE', domain, g.name, ['no current certificate from ', code(g.name), ' any more'], { tone: 'quiet', counts: false, kind: 'disappeared' }));
      }
    }
  }
  for (const [domain] of old) if (!now.has(domain)) out.push(change('GONE', domain, null, ['no longer watched'], { kind: 'disappeared' }));
  return out;
}

/* ------------------------------------------------------------------------ */
/* drift                                                                    */
/* ------------------------------------------------------------------------ */

const driftSev = (status) => DRIFT_SEVERITY[status] || 'unknown';
const needsLook = (status) => ['warn', 'error', 'unknown'].includes(driftSev(status));

function rowWhere(r) {
  return [code(`${r.name} ${r.type}`), ' — '];
}

function diffDrift(before, after, { t }) {
  const out = [];
  const old = byTarget(before);
  const now = byTarget(after);
  const label = (s) => t(`zone.drift.${s}`);
  for (const [origin, a] of now) {
    const b = old.get(origin);
    if (!b) {
      out.push(change('NEW', origin, null, [`zone now checked: ${(a.rows || []).filter((r) => needsLook(r.status)).length} record sets need a look`], { kind: 'appeared' }));
      continue;
    }
    const bp = b.preflight || {};
    const ap = a.preflight || {};
    if (bp.nsMatch && ap.nsMatch && bp.nsMatch !== ap.nsMatch && bp.nsMatch !== 'unknown' && ap.nsMatch !== 'unknown') {
      const worse = ['same', 'overlap', 'disjoint'].indexOf(ap.nsMatch) > ['same', 'overlap', 'disjoint'].indexOf(bp.nsMatch);
      out.push(change(worse ? 'WORSE' : 'BETTER', origin, 'NS', [`the file's name servers and the live ones: ${bp.nsMatch} → ${ap.nsMatch}`], { tone: worse ? 'bad' : 'good', before: bp.nsMatch, after: ap.nsMatch }));
    }
    const oldRows = new Map((b.rows || []).map((r) => [r.key, r]));
    const newKeys = new Set((a.rows || []).map((r) => r.key));
    for (const x of a.rows || []) {
      const y = oldRows.get(x.key);
      if (!y) {
        if (needsLook(x.status)) {
          const failed = x.status === 'error';
          out.push(change('NEW', origin, x.key, ['new in the file ', ...rowWhere(x), label(x.status)], { tone: failed ? 'quiet' : 'bad', counts: !failed, kind: 'appeared', after: x.status }));
        }
        continue;
      }
      if (x.status === y.status) {
        // sets, not lists: `added` is in the resolver's answer order, and a rotating answer order is no change
        const vals = (r) => JSON.stringify([r.added, r.removed, r.reasons].map((list) => [...(list || [])].sort()));
        if (needsLook(x.status) && x.status !== 'error' && vals(x) !== vals(y)) {
          out.push(change('CHANGED', origin, x.key, [...rowWhere(x), label(x.status), ', live values changed: ', ...((x.added || []).length ? ['now also ', ...x.added.slice(0, 3).flatMap((v, i) => (i ? [', ', code(v)] : [code(v)]))] : ['values moved'])],
            { before: y.added || [], after: x.added || [] }));
        }
        continue;
      }
      const move = [...rowWhere(x), `${label(y.status)} → ${label(x.status)}`];
      if (x.status === 'error') out.push(change('FAILED', origin, x.key, move, { tone: 'bad', before: y.status, after: x.status }));
      else if (y.status === 'error') out.push(change('RECOVERED', origin, x.key, move, { tone: notable(driftSev(x.status)) ? 'bad' : 'good', before: y.status, after: x.status }));
      else if (x.status === 'skipped' || y.status === 'skipped') {
        out.push(change('CHANGED', origin, x.key, [...move, x.status === 'skipped' ? ' (not checked this run)' : ' (checked again this run)'], { tone: 'quiet', counts: false, before: y.status, after: x.status }));
      } else {
        const rb = SEVERITY_RANK[driftSev(y.status)];
        const ra = SEVERITY_RANK[driftSev(x.status)];
        const tag = ra > rb ? 'WORSE' : ra < rb ? 'BETTER' : 'CHANGED';
        out.push(change(tag, origin, x.key, move, { tone: tag === 'WORSE' ? 'bad' : tag === 'BETTER' ? 'good' : 'info', before: y.status, after: x.status }));
      }
    }
    for (const y of b.rows || []) {
      if (newKeys.has(y.key) || !needsLook(y.status) || y.status === 'error') continue;
      out.push(change('GONE', origin, y.key, ['no longer in the file ', ...rowWhere(y), `was ${label(y.status)}`], { tone: 'quiet', counts: false, kind: 'disappeared', before: y.status }));
    }
  }
  for (const [origin] of old) if (!now.has(origin)) out.push(change('GONE', origin, null, ['zone no longer checked'], { kind: 'disappeared' }));
  return out;
}

/* ------------------------------------------------------------------------ */
/* renew                                                                    */
/* ------------------------------------------------------------------------ */

/** lib/renewal.js RENEWAL_VERDICTS, worst first. */
const VERDICT_RANK = Object.freeze({ fail: 0, unknown: 1, warnings: 2, ready: 3 });
/** The tone of a name checked again after "could not be checked": what it is now, never good news by itself. */
const RECOVERED_TONE = Object.freeze({ fail: 'bad', warnings: 'info', ready: 'good' });

function diffRenew(before, after, { t, localParams }) {
  const out = [];
  const old = byTarget(before);
  const now = byTarget(after);
  const verdict = (v) => t(`renew.v.${v}`);
  const title = (f) => textParts(t, `renew.f.${f.id}.title`, localParams({ params: f.params || {} }, t));
  const problems = (x) => new Map((x.findings || []).filter((f) => notable(f.severity) && !f.unchecked).map((f) => [f.id, f]));
  for (const [name, a] of now) {
    const b = old.get(name);
    if (!b) {
      out.push(change('NEW', name, null, [`now checked: ${verdict(a.verdict)}`], { tone: VERDICT_RANK[a.verdict] <= 1 ? 'bad' : 'info', kind: 'appeared', after: a.verdict }));
      continue;
    }
    const pb = problems(b);
    const pa = problems(a);
    const added = [...pa.values()].filter((f) => !pb.has(f.id));
    const gone = [...pb.values()].filter((f) => !pa.has(f.id));
    const detail = [
      ...added.slice(0, 3).flatMap((f) => ['; new: ', ...title(f)]),
      ...gone.slice(0, 3).flatMap((f) => ['; gone: ', ...title(f)]),
      ...(added.length + gone.length > 6 ? [` (+${added.length + gone.length - 6} more)`] : [])
    ];
    if (a.verdict === b.verdict) {
      if (!added.length && !gone.length) continue;
      const failing = a.verdict === 'unknown';
      out.push(change(failing ? 'FAILING' : 'CHANGED', name, null, [verdict(a.verdict), ...detail],
        { tone: failing ? 'quiet' : 'info', counts: !failing, before: b.verdict, after: a.verdict }));
      continue;
    }
    const move = [`${verdict(b.verdict)} → ${verdict(a.verdict)}`, ...detail];
    if (a.verdict === 'unknown') out.push(change('FAILED', name, null, move, { tone: 'bad', before: b.verdict, after: a.verdict }));
    else if (b.verdict === 'unknown') out.push(change('RECOVERED', name, null, move, { tone: RECOVERED_TONE[a.verdict] || 'info', before: b.verdict, after: a.verdict }));
    else {
      const worse = VERDICT_RANK[a.verdict] < VERDICT_RANK[b.verdict];
      out.push(change(worse ? 'WORSE' : 'BETTER', name, null, move, { tone: worse ? 'bad' : 'good', before: b.verdict, after: a.verdict }));
    }
  }
  for (const [name, b] of old) {
    if (!now.has(name)) out.push(change('GONE', name, null, [`no longer checked; was ${verdict(b.verdict)}`], { kind: 'disappeared', before: b.verdict }));
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* dane                                                                     */
/* ------------------------------------------------------------------------ */

function diffDane(before, after, { t }) {
  const out = [];
  // One certificate per run: compared whatever its name, so a renewed certificate is compared
  // with the one before it (a note says the certificate differs).
  const b = (before.targets || [])[0];
  const a = (after.targets || [])[0];
  if (!a || !b) return out;
  const label = (s) => t(`dane.st.${s}`);
  const target = a.target;
  const old = new Map((b.endpoints || []).map((e) => [e.key, e]));
  const keys = new Set((a.endpoints || []).map((e) => e.key));
  for (const x of a.endpoints || []) {
    const y = old.get(x.key);
    const where = [code(x.qname || x.key), ' — '];
    if (!y) {
      out.push(change('NEW', target, x.key, ['new endpoint ', ...where, label(x.status)], { tone: notable(DANE_SEVERITY[x.status]) ? 'bad' : 'info', kind: 'appeared', after: x.status }));
      continue;
    }
    if (x.status === y.status) continue;
    const move = [...where, `${label(y.status)} → ${label(x.status)}`];
    if (x.status === 'error') out.push(change('FAILED', target, x.key, move, { tone: 'bad', before: y.status, after: x.status }));
    else if (y.status === 'error') out.push(change('RECOVERED', target, x.key, move, { tone: notable(DANE_SEVERITY[x.status]) ? 'bad' : 'good', before: y.status, after: x.status }));
    else {
      const rb = SEVERITY_RANK[DANE_SEVERITY[y.status]] ?? 0;
      const ra = SEVERITY_RANK[DANE_SEVERITY[x.status]] ?? 0;
      const tag = ra > rb ? 'WORSE' : ra < rb ? 'BETTER' : 'CHANGED';
      out.push(change(tag, target, x.key, move, { tone: tag === 'WORSE' ? 'bad' : tag === 'BETTER' ? 'good' : 'info', before: y.status, after: x.status }));
    }
  }
  for (const y of b.endpoints || []) {
    if (!keys.has(y.key)) out.push(change('GONE', target, y.key, [code(y.qname || y.key), ` — no longer checked; was ${label(y.status)}`], { kind: 'disappeared', before: y.status }));
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* audit                                                                    */
/* ------------------------------------------------------------------------ */

/**
 * The policy audit: per domain and rule, a status that moved — pass → fail WORSE, fail → pass
 * BETTER; to "could not be checked" FAILED (listed only, the status it had is carried: `last`),
 * and checked again RECOVERED when no run had checked it before (counted when it lands on a fail),
 * else compared with the carried status, so a rule that failed before and after a night it could
 * not be checked is no change —, a rule new, gone or with another requirement (a policy changed:
 * the note says so), a domain new or gone. The evidence alone moving (one day fewer left) is no
 * change.
 */
function diffAudit(before, after, { t }) {
  const out = [];
  const old = byTarget(before);
  const now = byTarget(after);
  const word = (s) => (s === 'unknown' ? 'not known' : s);
  const what = (r) => [code(`${r.id} ${r.required || ''}`.trim()), ': '];
  // The evidence quotes values from DNS and the registry (a registrar's name, CAA issuers): code parts.
  const evidence = (r) => (r.key ? [' — ', ...textParts(t, r.key, r.params)] : r.evidence ? [' — ', code(r.evidence)] : []);
  const checked = (s) => s === 'pass' || s === 'fail';
  for (const [domain, a] of now) {
    const b = old.get(domain);
    if (!b) {
      const failing = (a.rules || []).filter((r) => r.status === 'fail');
      // counted only when a rule fails: a domain added that meets every rule is no news to act on
      out.push(change('NEW', domain, null, [`now audited: ${failing.length} rule${failing.length === 1 ? '' : 's'} failed`],
        { tone: failing.length ? 'bad' : 'info', counts: failing.length > 0, kind: 'appeared', after: failing.map((r) => r.id) }));
      continue;
    }
    const prev = new Map((b.rules || []).map((r) => [r.id, r]));
    for (const r of a.rules || []) {
      const p = prev.get(r.id);
      if (!p || (p.required || '') !== (r.required || '')) {
        // A rule new to the policy, or with another requirement: what it says now.
        out.push(change('NEW', domain, r.id, ['new rule ', ...what(r), word(r.status), ...evidence(r)],
          { tone: r.status === 'fail' ? 'bad' : 'info', counts: r.status === 'fail', kind: 'appeared', after: r.status }));
        continue;
      }
      if (r.status === 'unknown') {
        // Not checked this run: said once, never counted; its last status is carried.
        if (checked(p.status)) {
          out.push(change('FAILED', domain, r.id, [...what(r), `${word(p.status)} → not known`, ...evidence(r)], { tone: 'quiet', counts: false, before: p.status, after: r.status }));
        }
        continue;
      }
      const carried = !checked(p.status) && p.last && checked(p.last.status) ? p.last : null;
      const was = carried ? carried.status : p.status;
      if (was === r.status) continue;
      const since = carried ? ` (last checked ${isoDay(carried.from) || 'in an earlier run'})` : '';
      const move = [...what(r), `${word(was)}${since} → ${word(r.status)}`, ...evidence(r)];
      if (!checked(was)) {
        out.push(change('RECOVERED', domain, r.id, move, { tone: r.status === 'fail' ? 'bad' : 'good', counts: r.status === 'fail', before: was, after: r.status }));
      } else {
        const worse = r.status === 'fail';
        out.push(change(worse ? 'WORSE' : 'BETTER', domain, r.id, move, { tone: worse ? 'bad' : 'good', before: was, after: r.status }));
      }
    }
    const ids = new Set((a.rules || []).map((r) => r.id));
    for (const p of b.rules || []) {
      if (!ids.has(p.id)) out.push(change('GONE', domain, p.id, [...what(p), `no longer a rule; was ${word(p.status)}`], { tone: 'quiet', counts: false, kind: 'disappeared', before: p.status }));
    }
  }
  for (const [domain] of old) {
    if (!now.has(domain)) out.push(change('GONE', domain, null, ['no longer audited'], { kind: 'disappeared' }));
  }
  return out;
}

/* ------------------------------------------------------------------------ */
/* Notes and dispatch                                                       */
/* ------------------------------------------------------------------------ */

const listText = (v) => (Array.isArray(v) ? v.join(',') : v === null || v === undefined ? 'default' : String(v));

/**
 * What the two runs did differently, as sentences (the CLI's baseline_notes): a change can come
 * from that rather than from DNS.
 * @param {string} command
 * @param {object} before
 * @param {object} after
 * @returns {string[]}
 */
export function baselineNotes(command, before, after) {
  const o = isObj(before.options) ? before.options : {};
  const n = isObj(after.options) ? after.options : {};
  const notes = [];
  const differs = (key) => listText(o[key]) !== listText(n[key]);
  if (o.resolvers && n.resolvers && differs('resolvers')) notes.push(`The resolvers differ from the baseline's (${listText(o.resolvers)} → ${listText(n.resolvers)}).`);
  if (command === 'subdomains') {
    if (differs('mode')) notes.push(`The mode differs from the baseline's (${listText(o.mode)} → ${listText(n.mode)}): hosts can appear or go because of that rather than because of DNS.`);
    else if (differs('level') || differs('sources')) notes.push(`The wordlist level or the sources differ from the baseline's (${listText(o.level)} / ${listText(o.sources)} → ${listText(n.level)} / ${listText(n.sources)}): hosts can appear because of that rather than because of DNS.`);
  }
  if (command === 'ct' && differs('sources')) notes.push(`The sources differ from the baseline's (${listText(o.sources)} → ${listText(n.sources)}): issuers and names can appear because of that.`);
  if (command === 'ct' && Array.isArray(o.expectedCas) && differs('expectedCas')) {
    notes.push(`The expected CAs differ from the baseline's (${listText(o.expectedCas) || 'none'} → ${listText(n.expectedCas) || 'none'}): a certificate seen before is not said again, though the summary marks it.`);
  }
  if (command === 'ct' && Array.isArray(o.radar) && differs('radar')) notes.push(`The expiry radar differs from the baseline's (${listText(o.radar)} → ${listText(n.radar)} days).`);
  if (command === 'drift') {
    if (differs('maxQueries')) notes.push(`The query budget differs from the baseline's (${listText(o.maxQueries)} → ${listText(n.maxQueries)}).`);
    if (o.includeOrigins !== undefined && o.includeOrigins !== n.includeOrigins) notes.push('Origin addresses were hidden in one run and kept in the other (--include-origins): value changes can come from that.');
  }
  if (command === 'renew' && (differs('ca') || differs('challenge'))) {
    notes.push(`The CA or the challenge differs from the baseline's (${listText(o.ca)} / ${listText(o.challenge)} → ${listText(n.ca)} / ${listText(n.challenge)}): verdicts can move because of that rather than because of DNS.`);
  }
  if (command === 'audit' && JSON.stringify((o.policy && o.policy.rules) || null) !== JSON.stringify((n.policy && n.policy.rules) || null)) {
    notes.push('The policy differs from the baseline\'s: rules can pass or fail because of that rather than because of DNS or the registry.');
  }
  if (command === 'audit' && o.dkim !== undefined && o.dkim !== n.dkim) notes.push('DKIM was checked in one run and not in the other (--no-dkim): the dkim rule can move because of that.');
  if (command === 'dane' && differs('serialHex')) notes.push(`The certificate differs from the baseline's (serial ${listText(o.serialHex)} → ${listText(n.serialHex)}): statuses can move because of that rather than because of DNS.`);
  return notes;
}

const DIFFS = Object.freeze({ health: diffHealth, subdomains: diffSubdomains, ct: diffCt, drift: diffDrift, renew: diffRenew, dane: diffDane, audit: diffAudit });

/**
 * What changed from the baseline report `before` to the report `after` of the same subcommand,
 * the changes that count first ({@link orderChanges}).
 * @param {string} command
 * @param {object} before a report that passed {@link baselineProblem}
 * @param {object} after this run's report
 * @param {{ t: Function, localParams?: Function }} kit `t` for the finding titles and status
 *   labels (render.mjs setupStrings); `localParams` views/renew.js' param wording (renew)
 * @returns {object[]}
 */
export function diffReports(command, before, after, { t, localParams = (f) => ({ ...f.params }) } = {}) {
  const fn = DIFFS[command];
  if (!fn) throw new RangeError(`diff: unknown command "${command}"`);
  if (typeof t !== 'function') throw new TypeError('diff: kit.t (translate) is required');
  return orderChanges(fn(before, after, { t, localParams }));
}
