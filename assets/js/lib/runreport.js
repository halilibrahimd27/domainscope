/**
 * runreport.js — the headless runner's `--json` report (tools/ds.mjs, SPEC §9) as data: its tool
 * name and version, and the shape rules a report must meet before anything reads it. One copy of
 * those rules for both readers: the runner, which checks a `--baseline` with them
 * (tools/ds/diff.mjs baselineProblem), and the Monitoring view, which checks every report it opens
 * (lib/monitor.js readReport) — so a report the runner would refuse as a baseline is never drawn
 * in the page either, and the reverse.
 *
 * A report: `{ tool: 'domainscope-ds', version, command, startedAt, finishedAt, options, warnings?,
 * targets: [{ target, ... }], baseline?, changes?, notify? }`; each command's targets hold the lists
 * its comparison walks, checked by {@link TARGET_CHECKS}. A command these rules do not know (a newer
 * runner's) is checked for the envelope and the targets' names only.
 *
 * DOM-free, no I/O; runs in browsers and Node 22.
 */

/** The runner's name in its reports and messages. */
export const DS_TOOL = 'domainscope-ds';
/** Version of the runner and of its `--json` report: a reader takes the reports of its own major number. */
export const DS_VERSION = '1.0.0';

/** A cell's outcome in an audit report (lib/policy.js POLICY_STATUSES). */
export const AUDIT_STATUSES = Object.freeze(['pass', 'fail', 'unknown', 'waived']);

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const isStrOrNull = (v) => v === null || v === undefined || typeof v === 'string';
const isStrList = (v) => Array.isArray(v) && v.every(isStr);
const major = (v) => String(v).split('.')[0];

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

/**
 * Why a `tls` target is not what the comparison reads, or null (tools/ds/tlsdiff.mjs).
 * @param {object} x
 * @returns {string|null}
 */
export function tlsTargetProblem(x) {
  if (!Array.isArray(x.endpoints)) return 'has no "endpoints" list';
  if (x.carried !== undefined && !(isObj(x.carried) && isStrOrNull(x.carried.from))) return 'has a "carried" without a "from"';
  if (x.ct !== undefined && !isObj(x.ct)) return 'has a "ct" that is not an object';
  for (const [i, e] of x.endpoints.entries()) {
    const where = `endpoints[${i}]`;
    if (!isObj(e)) return `${where} is not an object`;
    if (!isStr(e.address)) return `${where} has no "address"`;
    if (!Number.isInteger(e.port)) return `${where} has no "port"`;
    if (!isStr(e.status)) return `${where} has no "status"`;
    for (const [key, v] of [['cert', e.cert], ['lastGood', e.lastGood], ['ari', e.ari], ['revocation', e.revocation], ['newer', e.newer], ['http', e.http]]) {
      if (v !== undefined && v !== null && !isObj(v)) return `${where} has a "${key}" that is not an object`;
    }
    for (const c of [e.cert, e.lastGood && e.lastGood.cert]) {
      if (c && !isStr(c.sha256)) return `${where} has a certificate without "sha256"`;
      if (c && c.names !== undefined && !(Array.isArray(c.names) && c.names.every(isStr))) return `${where} has certificate names that are not a list of text`;
    }
    for (const a of [e.ari, e.lastGood && e.lastGood.ari]) {
      if (a && !(isStrOrNull(a.start) && isStrOrNull(a.end) && isStrOrNull(a.explanationURL) && isStrOrNull(a.checkedAt))) return `${where} has an "ari" whose times are not text`;
    }
    for (const r of [e.revocation, e.lastGood && e.lastGood.revocation]) {
      if (r && !isStr(r.status)) return `${where} has a "revocation" without "status"`;
    }
    if (e.http && e.http.plain !== undefined && e.http.plain !== null && !isObj(e.http.plain)) return `${where} has an "http.plain" that is not an object`;
  }
  return null;
}

/**
 * Is a `takeover` target's list of risks what the comparison walks (tools/ds/takeover.mjs
 * diffTakeover)? Null when it is, else why not.
 * @param {object} x
 * @returns {string|null}
 */
export function takeoverTargetProblem(x) {
  if (!Array.isArray(x.risks)) return 'has no "risks" list';
  for (const [i, r] of x.risks.entries()) {
    if (!isObj(r)) return `risks[${i}] is not an object`;
    for (const k of ['key', 'kind', 'host', 'target', 'severity']) if (!isStr(r[k])) return `risks[${i}] has no "${k}"`;
    if (r.chain !== undefined && !(Array.isArray(r.chain) && r.chain.every(isStr))) return `risks[${i}] has a "chain" that is not a list of text`;
    if (r.carried !== undefined && !(isObj(r.carried) && (r.carried.from === null || isStr(r.carried.from)))) return `risks[${i}] has a "carried" without a "from"`;
  }
  if (x.domains !== undefined && !(Array.isArray(x.domains) && x.domains.every((d) => isObj(d) && isStr(d.domain)))) return 'has a "domains" list that is not registrations';
  return null;
}

/**
 * Why a `watch` target is not what the comparison reads, or null (tools/ds/watchdiff.mjs).
 * @param {object} x
 * @returns {string|null}
 */
export function watchTargetProblem(x) {
  if (!isStrList(x.names)) return 'has no "names" list';
  if (!isStrList(x.types)) return 'has no "types" list';
  if (x.runs !== undefined && !isStrList(x.runs)) return 'has "runs" that are not a list of text';
  if (x.delegated !== undefined && !isStrList(x.delegated)) return 'has "delegated" that is not a list of text';
  if (x.nxdomain !== undefined && !isStrList(x.nxdomain)) return 'has "nxdomain" that is not a list of text';
  const r = x.registration;
  if (!isObj(r) || !isStr(r.state)) return 'has no "registration" with a "state"';
  for (const k of ['registrar', 'ianaId', 'expires', 'soon']) if (!isStrOrNull(r[k])) return `has a registration "${k}" that is not text`;
  for (const k of ['statuses', 'nameservers']) if (r[k] !== undefined && r[k] !== null && !isStrList(r[k])) return `has a registration "${k}" that is not a list of text`;
  if (r.carried !== undefined && !(isObj(r.carried) && isStrOrNull(r.carried.from))) return 'has a registration "carried" without a "from"';
  const d = x.delegation;
  if (!isObj(d)) return 'has no "delegation"';
  for (const k of ['ns', 'ds']) if (d[k] !== null && d[k] !== undefined && !isStrList(d[k])) return `has a delegation "${k}" that is not a list of text`;
  if (!Array.isArray(x.records)) return 'has no "records" list';
  for (const [i, rec] of x.records.entries()) {
    const where = `records[${i}]`;
    if (!isObj(rec)) return `${where} is not an object`;
    for (const k of ['key', 'name', 'type']) if (!isStr(rec[k])) return `${where} has no "${k}"`;
    if (!isStrList(rec.values)) return `${where} has "values" that are not a list of text`;
    if (rec.flips !== undefined && !isStrList(rec.flips)) return `${where} has "flips" that are not a list of text`;
    if (rec.carried !== undefined && !(isObj(rec.carried) && isStrOrNull(rec.carried.from))) return `${where} has a "carried" without a "from"`;
  }
  if (x.classes !== undefined && !(isObj(x.classes) && Object.values(x.classes).every(isStr))) return 'has "classes" that are not text by name';
  if (x.failures !== undefined && !(Array.isArray(x.failures) && x.failures.every((f) => isObj(f) && isStr(f.name) && isStr(f.type)))) return 'has "failures" that are not lookups';
  const a = x.authoritative;
  if (a !== undefined && a !== null) {
    if (!isObj(a) || !isStr(a.view)) return 'has an "authoritative" without a "view"';
    if (a.servers !== undefined && !(Array.isArray(a.servers) && a.servers.every((s) => isObj(s) && isStr(s.address) && isStr(s.status)))) return 'has "authoritative" servers without an address and a status';
    if (a.mismatches !== undefined && !(Array.isArray(a.mismatches) && a.mismatches.every((m) => isObj(m) && isStr(m.key)))) return 'has "authoritative" mismatches without a key';
    if (a.lagging !== undefined && !isStrList(a.lagging)) return 'has "authoritative" lagging servers that are not a list of text';
  }
  return null;
}

/** Per command: why one of its targets is not what the comparison walks, or null. */
export const TARGET_CHECKS = Object.freeze({
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
  audit: (x) => itemsProblem(x.rules, 'rules', (r) => (!isStr(r.id) ? 'has no "id"' : !AUDIT_STATUSES.includes(r.status) ? 'has no "status" (pass, fail, unknown or waived)' : null)),
  tls: tlsTargetProblem,
  takeover: takeoverTargetProblem,
  watch: watchTargetProblem
});

/**
 * Why `doc` is not a report this version reads, or null: it must be a `--json` report of this
 * runner, written by a version with the same major number, of `command` when one is given (else
 * of any command, named), with the lists the comparison walks well-formed.
 * @param {any} doc parsed JSON
 * @param {string|null} [command] the subcommand it must be a report of; null: its own
 * @returns {string|null}
 */
export function reportProblem(doc, command = null) {
  if (!isObj(doc) || doc.tool !== DS_TOOL) return `it is not a --json report of ${DS_TOOL} (no "tool": "${DS_TOOL}")`;
  if (!isStr(doc.version) || major(doc.version) !== major(DS_VERSION)) {
    return `it was written by version ${JSON.stringify(doc.version ?? null)}, which this version (${DS_VERSION}) cannot compare`;
  }
  if (command !== null && doc.command !== command) return `it is a report of "${doc.command}", not of "${command}"`;
  if (command === null && !(isStr(doc.command) && /^[a-z][a-z0-9-]{0,31}$/.test(doc.command))) return 'it names no command';
  if (doc.options !== undefined && !isObj(doc.options)) return 'its "options" is not an object';
  if (!Array.isArray(doc.targets)) return 'it has no "targets" list';
  const check = Object.hasOwn(TARGET_CHECKS, doc.command) ? TARGET_CHECKS[doc.command] : null;
  for (const [i, x] of doc.targets.entries()) {
    if (!isObj(x)) return `targets[${i}] is not an object`;
    if (!isStr(x.target)) return `targets[${i}] has no "target"`;
    const p = check ? check(x) : null;
    if (p) return `targets[${i}] ${p}`;
  }
  return null;
}
