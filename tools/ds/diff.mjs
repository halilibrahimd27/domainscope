/**
 * tools/ds/diff.mjs — "Changes since the baseline": a run of the headless runner compared with
 * its previous `--json` report of the same subcommand, in the Python CLI's terms
 * (cli/ssl_origin_scan.py baseline_problem / compare_reports / order_changes / counts_as_change).
 *
 * A change is `{ tag, tone, counts, target, item, kind, before, after, parts }`:
 * - `tag`: render.mjs CHANGE_TAGS (NEW, GONE, WORSE, BETTER, CHANGED, FAILED, RECOVERED, FAILING,
 *   SCORE, ISSUER, NAME, CERT, EXPOSED, DANGLING); `tone`: 'bad' | 'good' | 'info' | 'quiet';
 * - `counts`: false for what is listed but never counted by --fail-on-change (nor opens the
 *   nightly issue): a move from one failure state to another (FAILING: nothing was read either
 *   way), what a failed lookup may hide (a finding "gone" while that lookup failed), a CT issuer
 *   or name that may only have been missed the night before (see surelyNew), and a renewed
 *   certificate from a known issuer for known names (CERT);
 * - `target` / `item`: the domain, name, zone or certificate, and what inside it moved (a
 *   finding id, a host, an RRset key, an issuer, an endpoint), null for the target itself;
 * - `parts`: the line as lib/summary.js parts, its untrusted values as code parts.
 * Pure: no I/O. The previous report is checked by {@link baselineProblem} before it is used.
 */

import { DS_TOOL, DS_VERSION } from './args.mjs';
import { code, isoDay, localYesNo } from './render.mjs';
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

const TARGET_CHECKS = Object.freeze({
  health: (x) => {
    if (x.score !== undefined && !Number.isFinite(x.score)) return 'has a "score" that is not a number';
    if (x.failedLookups !== undefined && !isStrList(x.failedLookups)) return 'has a "failedLookups" that is not a list of text';
    return itemsProblem(x.checks, 'checks', (c) => (!isStr(c.id) ? 'has no "id"' : !isStr(c.severity) ? 'has no "severity"' : null));
  },
  subdomains: (x) => {
    if (!isStr(x.mode)) return 'has no "mode"';
    return itemsProblem(x.hosts, 'hosts', (h) => {
      if (!isStr(h.name)) return 'has no "name"';
      if (!isStrList(h.ipv4 || []) || !isStrList(h.ipv6 || [])) return 'has addresses that are not lists of text';
      if (!isStrOrNull(h.status) || !isStrOrNull(h.kind) || !isStrOrNull(h.provider)) return 'has a "status", "kind" or "provider" that is not text';
      return null;
    });
  },
  ct: (x) => {
    if (!isStrList(x.names)) return 'has no "names" list';
    const p = itemsProblem(x.issuers, 'issuers', (g) => (isStr(g.name) ? null : 'has no "name"'));
    if (p) return p;
    return itemsProblem(x.certificates, 'certificates', (c) => (!isStr(c.id) ? 'has no "id"' : !isStr(c.ca) ? 'has no "ca"' : !isStrList(c.names) ? 'has no "names" list' : null));
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
  }
});

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

/**
 * A check that says a lookup failed: `<area>.error` (soa, ns, mx, spf, dmarc, dkim, caa, dnssec,
 * wildcard, rdap), `spf.dns-error`, `mail-identity.fcrdns-error` — not `spf.include-error`, which
 * is a broken SPF record that was read.
 */
const isLookupError = (id) => /^[a-z-]+\.(?:error|dns-error|fcrdns-error)$/.test(id);

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
    // A lookup that failed this run hides what it would have found: the score and the findings
    // gone with it are listed, not counted (the failed lookup is a finding of its own, and counts).
    const failed = (a.failedLookups || []).length > 0 || (a.checks || []).some((c) => isLookupError(c.id));
    if (Number.isFinite(b.score) && Number.isFinite(a.score) && b.score !== a.score) {
      out.push(change('SCORE', domain, null, [`health score ${b.score} → ${a.score}`, ...(failed ? [' (a lookup failed this run)'] : [])],
        { tone: failed ? 'quiet' : a.score < b.score ? 'bad' : 'good', counts: !failed, before: b.score, after: a.score }));
    }
    const bc = checksById(b.checks);
    const ac = checksById(a.checks);
    for (const [id, x] of ac) {
      const y = bc.get(id);
      if (!y) {
        if (notable(x.severity)) out.push(change('NEW', domain, id, [`${x.severity} `, code(id), ' — ', ...healthTitle(t, x)], { tone: 'bad', kind: 'appeared', after: x.severity }));
        continue;
      }
      if (y.severity === x.severity || !(notable(x.severity) || notable(y.severity))) continue;
      const worse = (SEVERITY_RANK[x.severity] ?? 0) > (SEVERITY_RANK[y.severity] ?? 0);
      out.push(change(worse ? 'WORSE' : 'BETTER', domain, id, [code(id), `: ${y.severity} → ${x.severity} — `, ...healthTitle(t, x)],
        { tone: worse ? 'bad' : 'good', before: y.severity, after: x.severity }));
    }
    for (const [id, y] of bc) {
      if (ac.has(id) || !notable(y.severity)) continue;
      out.push(change('GONE', domain, id, [`${y.severity} `, code(id), ' no longer reported — ', ...healthTitle(t, y),
        ...(failed ? [' (a lookup failed this run: it may still be there)'] : [])], { tone: failed ? 'quiet' : 'good', counts: !failed, kind: 'disappeared', before: y.severity }));
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

const FAILED_STATUSES = new Set(['SERVFAIL', 'REFUSED', 'ERROR']);
const resolves = (h) => (h.ipv4 || []).length > 0 || (h.ipv6 || []).length > 0;
const addresses = (h) => [...(h.ipv4 || []), ...(h.ipv6 || [])];
const DIRECT = new Set(['direct', 'private']);

/** "Cloudflare", "direct 192.0.2.10", "NXDOMAIN" … for a host line. */
function hostState(h) {
  if (FAILED_STATUSES.has(h.status)) return [`lookup failed (${h.status}${h.error ? `: ${h.error}` : ''})`];
  if (h.dangling) return ['dangling CNAME to ', code((h.cnames || []).slice(-1)[0] || '?')];
  if (!resolves(h)) return [h.status && h.status !== 'NOERROR' ? String(h.status) : 'no address (NODATA)'];
  const who = h.provider ? [code(h.provider)] : [String(h.kind || 'resolves')];
  const ips = addresses(h);
  return DIRECT.has(h.kind) || !h.provider
    ? [...who, ' ', ...ips.slice(0, 3).flatMap((ip, i) => (i ? [', ', code(ip)] : [code(ip)])), ...(ips.length > 3 ? [` +${ips.length - 3}`] : [])]
    : who;
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
    const yFail = FAILED_STATUSES.has(y.status);
    const xFail = FAILED_STATUSES.has(x.status);
    if (xFail && yFail) {
      if (x.status !== y.status) out.push(change('FAILING', domain, name, [...where, `${y.status} → ${x.status}`], { tone: 'quiet', counts: false, before: y.status, after: x.status }));
      continue;
    }
    if (xFail) {
      out.push(change('FAILED', domain, name, [...where, ...hostState(x), '; was ', ...hostState(y)], { tone: 'bad', before: y.status, after: x.status }));
      continue;
    }
    if (yFail) {
      out.push(change('RECOVERED', domain, name, [...where, ...hostState(x)], { tone: 'good', before: y.status, after: x.status }));
      continue;
    }
    if (!y.dangling && x.dangling) {
      out.push(change('DANGLING', domain, name, [...where, ...hostState(x), '; was ', ...hostState(y)], { tone: 'bad', before: y.status, after: x.status }));
    } else if (resolves(y) && !resolves(x)) {
      out.push(change('GONE', domain, name, [...where, 'no longer resolves: ', ...hostState(x)], { tone: 'bad', kind: 'disappeared', before: addresses(y), after: x.status }));
    } else if (!resolves(y) && resolves(x)) {
      out.push(change('NEW', domain, name, [...where, 'now resolves: ', ...hostState(x)], { kind: 'appeared', before: y.status, after: addresses(x) }));
    } else if (y.dangling && !x.dangling) {
      out.push(change('BETTER', domain, name, [...where, 'no longer a dangling CNAME: ', ...hostState(x)], { tone: 'good', before: y.status, after: x.status }));
    } else if (resolves(x)) {
      const moved = y.kind !== x.kind || (y.providerId || y.provider) !== (x.providerId || x.provider);
      if (moved && y.hidesOrigin && !x.hidesOrigin && DIRECT.has(x.kind)) {
        out.push(change('EXPOSED', domain, name, [...where, 'no longer behind ', code(y.provider || y.kind), ': now ', ...hostState(x)], { tone: 'bad', before: y.kind, after: x.kind }));
      } else if (moved) {
        out.push(change('CHANGED', domain, name, [...where, ...hostState(y), ' → ', ...hostState(x)], { before: y.kind, after: x.kind }));
      } else if (DIRECT.has(x.kind) && addresses(x).join(',') !== addresses(y).join(',')) {
        out.push(change('CHANGED', domain, name, [...where, 'addresses ', ...hostState(y), ' → ', ...hostState(x)], { before: addresses(y), after: addresses(x) }));
      }
    }
  }
  for (const [name, y] of old) {
    if (now.has(name) || !(resolves(y) || y.dangling)) continue;
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

/** The CT sources that read a domain in full in a report: answered, not in part, not cut at a page cap. */
function fullSources(x) {
  return new Set((x.sources || []).filter((s) => s && s.ok && s.state !== 'partial' && !s.truncated).map((s) => s.source));
}

/**
 * Is a certificate of this run surely absent from the baseline `b` (run at `since`), so an issuer
 * or a name it brings is new? Per source, as the sources answer on different nights (Cert
 * Spotter's hourly quota runs out on a list of domains; crt.sh is often down): yes when a source
 * that lists it now read the domain in full in the baseline too, or when it was issued after the
 * baseline run started while the baseline read at least one source in full (a certificate that
 * did not exist yet cannot have been missed). A baseline without per-source states (never written
 * by this version) falls back to its `complete`.
 * @param {object} b the baseline's target
 * @param {number} since the baseline run's start (ms), NaN when unknown
 * @returns {(c: object) => boolean}
 */
function surelyNew(b, since) {
  if (!Array.isArray(b.sources)) return () => b.complete !== false;
  const full = fullSources(b);
  return (c) => (c.sources || []).some((s) => full.has(s)) || (full.size > 0 && Number.isFinite(since) && Date.parse(c.notBefore) > since);
}

function diffCt(before, after) {
  const out = [];
  const old = byTarget(before);
  const now = byTarget(after);
  const since = Date.parse(before.startedAt);
  for (const [domain, a] of now) {
    const b = old.get(domain);
    if (!b) {
      out.push(change('NEW', domain, null, [`now watched: ${(a.certificates || []).length} current certificates`], { kind: 'appeared' }));
      continue;
    }
    const failedText = (x) => (x.sources || []).filter((s) => !s.ok).map((s) => `${s.source} ${s.state || 'error'}${s.skipped ? ' (not asked)' : ''}`).join(', ');
    if (!a.answered && !b.answered) continue;
    if (!a.answered) {
      out.push(change('FAILED', domain, null, [`Certificate Transparency could not be read this run (${failedText(a)}): nothing compared`], { tone: 'bad' }));
      continue;
    }
    if (!b.answered) {
      out.push(change('RECOVERED', domain, null, [`Certificate Transparency read again: ${(a.certificates || []).length} current certificates (not compared: the baseline has none)`], { tone: 'good' }));
      continue;
    }
    // A new issuer or name counts only when one of its certificates is surely new (surelyNew):
    // one a source missed in the baseline may have been there all along.
    const isNew = surelyNew(b, since);
    const unsure = [' (listed only by a source the baseline run did not read in full: it may not be new)'];
    const certs = a.certificates || [];
    const oldIssuers = new Set((b.issuers || []).map((g) => g.name));
    const newIssuers = new Set();
    for (const g of a.issuers || []) {
      if (oldIssuers.has(g.name)) continue;
      newIssuers.add(g.name);
      const sure = certs.some((c) => c.ca === g.name && isNew(c));
      out.push(change('ISSUER', domain, g.name, ['new issuer ', code(g.name),
        ...(g.intermediates && g.intermediates.length ? [' (', ...g.intermediates.slice(0, 3).flatMap((n, i) => (i ? [', ', code(n)] : [code(n)])), ')'] : []),
        `: ${g.count} current certificate${g.count === 1 ? '' : 's'}, newest ${isoDay(g.newest)}`, ...(sure ? [] : unsure)],
      { tone: sure ? 'bad' : 'quiet', counts: sure, kind: 'appeared', after: g.count }));
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
    const oldIds = new Set((b.certificates || []).map((c) => c.id));
    for (const c of a.certificates || []) {
      if (oldIds.has(c.id) || newIssuers.has(c.ca) || c.names.every((n) => newNames.has(n))) continue;
      out.push(change('CERT', domain, c.id, ['new certificate from ', code(c.ca), ...(c.intermediate ? [' (', code(c.intermediate), ')'] : []),
        `, ${isoDay(c.notBefore)}: `, ...c.names.slice(0, 3).flatMap((n, i) => (i ? [', ', code(n)] : [code(n)])), ...(c.names.length > 3 ? [` +${c.names.length - 3}`] : [])],
      { tone: 'quiet', counts: false, kind: 'appeared' }));
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
        const vals = (r) => JSON.stringify([r.added || [], r.removed || [], [...(r.reasons || [])].sort()]);
        if (needsLook(x.status) && x.status !== 'error' && vals(x) !== vals(y)) {
          out.push(change('CHANGED', origin, x.key, [...rowWhere(x), label(x.status), ', live values changed: ', ...((x.added || []).length ? ['now also ', ...x.added.slice(0, 3).flatMap((v, i) => (i ? [', ', code(v)] : [code(v)]))] : ['values moved'])],
            { before: y.added || [], after: x.added || [] }));
        }
        continue;
      }
      const move = [...rowWhere(x), `${label(y.status)} → ${label(x.status)}`];
      if (x.status === 'error') out.push(change('FAILED', origin, x.key, move, { tone: 'bad', before: y.status, after: x.status }));
      else if (y.status === 'error') out.push(change('RECOVERED', origin, x.key, move, { tone: 'good', before: y.status, after: x.status }));
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
    else if (b.verdict === 'unknown') out.push(change('RECOVERED', name, null, move, { tone: 'good', before: b.verdict, after: a.verdict }));
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
    else if (y.status === 'error') out.push(change('RECOVERED', target, x.key, move, { tone: 'good', before: y.status, after: x.status }));
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
  if (command === 'drift') {
    if (differs('maxQueries')) notes.push(`The query budget differs from the baseline's (${listText(o.maxQueries)} → ${listText(n.maxQueries)}).`);
    if (o.includeOrigins !== undefined && o.includeOrigins !== n.includeOrigins) notes.push('Origin addresses were hidden in one run and kept in the other (--include-origins): value changes can come from that.');
  }
  if (command === 'renew' && (differs('ca') || differs('challenge'))) {
    notes.push(`The CA or the challenge differs from the baseline's (${listText(o.ca)} / ${listText(o.challenge)} → ${listText(n.ca)} / ${listText(n.challenge)}): verdicts can move because of that rather than because of DNS.`);
  }
  if (command === 'dane' && differs('serialHex')) notes.push(`The certificate differs from the baseline's (serial ${listText(o.serialHex)} → ${listText(n.serialHex)}): statuses can move because of that rather than because of DNS.`);
  return notes;
}

const DIFFS = Object.freeze({ health: diffHealth, subdomains: diffSubdomains, ct: diffCt, drift: diffDrift, renew: diffRenew, dane: diffDane });

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
