/**
 * tools/ds/states.mjs — the states the runner compares, and where a problem PagerDuty was paged
 * for stands in a later report.
 *
 * - The vocabulary tools/ds/diff.mjs compares with: severity ranks (lib/health, lib/renewal,
 *   lib/zonedrift DRIFT_SEVERITY, lib/dane DANE_SEVERITY), a check id's worst severity, a host's
 *   answer.
 * - {@link problemStanding}: the evidence of a PagerDuty resolve (tools/ds/notify.mjs
 *   problemOver). A key's problem is over only when this run's report shows its item in a state
 *   better than the one it was paged at ({@link pagedState}, kept with the key) — never because
 *   another change came by: a lookup that failed, a source or a record set not read, a host not
 *   looked up again say nothing, and the key stays open.
 * Pure: no I/O. Kept apart from diff.mjs, which imports args.mjs, which imports notify.mjs.
 */

import { isLookupError, checkAreas, failedAreas, knownChecks, lookupFailed } from './carry.mjs';
import { TLS_FAILED } from './tlsdiff.mjs';
import { DRIFT_SEVERITY } from '../../assets/js/lib/zonedrift.js';
import { DANE_SEVERITY } from '../../assets/js/lib/dane.js';
import { TAKEOVER_SEVERITIES } from '../../assets/js/lib/takeover.js';

/** Severity ranks (lib/health, lib/renewal, lib/zonedrift DRIFT_SEVERITY, lib/dane DANE_SEVERITY). */
export const SEVERITY_RANK = Object.freeze({ neutral: 0, ok: 0, info: 1, unknown: 1, warn: 2, error: 3 });
/** A severity that needs a look. */
export const notable = (severity) => severity === 'warn' || severity === 'error';

/** The worst severity of each check id (a check id may appear more than once). */
export function checksById(checks) {
  const out = new Map();
  for (const c of checks || []) {
    const prev = out.get(c.id);
    if (!prev || (SEVERITY_RANK[c.severity] ?? 0) > (SEVERITY_RANK[prev.severity] ?? 0)) out.set(c.id, c);
  }
  return out;
}

/** Does a host answer with an address? */
export const resolves = (h) => (h.ipv4 || []).length > 0 || (h.ipv6 || []).length > 0;
/** Host kinds whose address is the server itself. */
export const DIRECT = new Set(['direct', 'private']);
/** A drift row status's severity (DRIFT_SEVERITY; a status of a later version: unknown). */
export const driftSev = (status) => DRIFT_SEVERITY[status] || 'unknown';

/* ------------------------------------------------------------------------ */
/* Where a problem stands                                                   */
/* ------------------------------------------------------------------------ */

/** The match of a zone file's name servers with the live ones, best first. */
const NS_MATCH_RANK = Object.freeze({ same: 0, overlap: 1, disjoint: 2 });
/** A renewal verdict, best first; `unknown` (not checked) is no verdict. */
const VERDICT_RANK = Object.freeze({ ready: 0, warnings: 1, fail: 2 });
/** An audit status that was checked. */
const auditChecked = (s) => s === 'pass' || s === 'fail';

const has = (map, key) => typeof key === 'string' && Object.prototype.hasOwnProperty.call(map, key);
const rankIn = (map, key) => (has(map, key) ? map[key] : NaN);

/**
 * Over when the item's rank (0 best) is below the one its problem was paged at; a key without
 * its paged state is over only at the best rank.
 */
const below = (rank, paged) => (rank < (Number.isFinite(paged) ? paged : 1) ? 'over' : 'bad');

/** A drift status's rank. */
const driftRank = (status) => SEVERITY_RANK[driftSev(status)];
/** A DANE status's rank (a status of a later version: NaN). */
const daneRank = (status) => (has(DANE_SEVERITY, status) ? SEVERITY_RANK[DANE_SEVERITY[status]] ?? 0 : NaN);

/** The tls changes about one certificate (their item is its SHA-256): the CA's renewal window, its notice, its revocation. */
const TLS_CERTIFICATE_TAGS = new Set(['RENEW-NOW', 'MOVED-UP', 'CA-NOTICE', 'REVOKED']);
/** The least takeover severity a change counts at (tools/ds/takeover.mjs COUNTED_SEVERITY). */
export const TAKEOVER_COUNTED = 'medium';
const takeoverRank = (severity) => {
  const i = TAKEOVER_SEVERITIES.indexOf(severity);
  return i === -1 ? TAKEOVER_SEVERITIES.length : i;
};

/** Per command: where the problem of an open key stands in this run's target `x`. */
const STANDINGS = Object.freeze({
  /**
   * A finding by its worst severity, read or carried; one a failed lookup may hide is not known gone; one a waiver accepts
   * (`--waivers`) is over while it does. The score: read with no lookup failed.
   */
  health(x, e) {
    const failed = failedAreas(x);
    if (e.item === null) {
      if (e.tag !== 'SCORE' || failed.size || !Number.isFinite(x.score) || !Number.isFinite(e.state)) return 'unknown';
      return x.score > e.state ? 'over' : 'bad';
    }
    if ((x.checks || []).some((y) => y && y.id === e.item && y.waiver && typeof y.waiver === 'object')) return 'over';
    const c = checksById(knownChecks(x)).get(e.item);
    if (!c && !isLookupError(e.item) && checkAreas(e.item).some((area) => failed.has(area))) return 'unknown';
    return below(c ? SEVERITY_RANK[c.severity] ?? 0 : 0, rankIn(SEVERITY_RANK, e.state));
  },

  /** A host's answer: a failed lookup says nothing (but that it fails); a host an exact run no longer lists left its names file, one a discovery run did not look up again is not known. */
  subdomains(x, e) {
    if (e.item === null) return 'unknown';
    const h = (x.hosts || []).find((y) => y && y.name === e.item);
    if (!h) return x.mode === 'exact' ? 'over' : 'unknown';
    if (lookupFailed(h)) return e.tag === 'FAILED' ? 'bad' : 'unknown';
    switch (e.tag) {
      case 'FAILED': return 'over';
      case 'DANGLING': return h.dangling ? 'bad' : 'over';
      case 'GONE': return resolves(h) ? 'over' : 'bad';
      case 'EXPOSED': return resolves(h) && !h.hidesOrigin && DIRECT.has(h.kind) ? 'bad' : 'over';
      case 'RECOVERED': return resolves(h) && !h.dangling ? 'over' : 'bad';
      default: return 'unknown';
    }
  },

  /**
   * A certificate renewed (superseded for every name; one no longer listed proves nothing) or made a known certificate
   * (`--waivers`, while its waiver lasts); an issuer gone from a complete read, or whose certificates are all known.
   */
  ct(x, e) {
    if (e.item === null) return 'unknown';
    if (e.tag === 'ISSUER') {
      const own = (x.certificates || []).filter((c) => c && c.ca === e.item);
      if (own.length && own.every((c) => c.known && typeof c.known === 'object')) return 'over';
      if ((x.issuers || []).some((g) => g && g.name === e.item)) return 'bad';
      return x.complete === true ? 'over' : 'unknown';
    }
    const cert = (x.certificates || []).find((c) => c && c.id === e.item);
    if (!cert) return 'unknown';
    if (e.tag !== 'EXPIRING' && e.tag !== 'REVOKED' && cert.known && typeof cert.known === 'object') return 'over';
    return Array.isArray(cert.flags) && cert.flags.includes('superseded') ? 'over' : 'bad';
  },

  /** A record set's status or the name servers' match; a row not checked (error) or skipped is not known, one out of the file is over. */
  drift(x, e) {
    if (e.item === null) return 'unknown';
    if (e.item === 'NS') {
      const match = x.preflight && x.preflight.nsMatch;
      if (!has(NS_MATCH_RANK, match)) return 'unknown';
      return below(NS_MATCH_RANK[match], rankIn(NS_MATCH_RANK, e.state));
    }
    const row = (x.rows || []).find((r) => r && r.key === e.item);
    if (!row) return 'over';
    if (row.status === 'error') return e.tag === 'FAILED' ? 'bad' : 'unknown';
    if (row.status === 'skipped') return 'unknown';
    if (e.tag === 'FAILED') return 'over';
    return below(driftRank(row.status), has(DRIFT_SEVERITY, e.state) ? driftRank(e.state) : NaN);
  },

  /** The verdict; one that could not be checked is no verdict — but the problem of a key paged for that. */
  renew(x, e) {
    if (e.item !== null) return 'unknown';
    const verdict = x.verdict;
    if (e.tag === 'FAILED' || e.state === 'unknown') return verdict === 'unknown' ? 'bad' : has(VERDICT_RANK, verdict) ? 'over' : 'unknown';
    if (!has(VERDICT_RANK, verdict)) return 'unknown';
    return below(VERDICT_RANK[verdict], rankIn(VERDICT_RANK, e.state));
  },

  /**
   * An endpoint's status; one that could not be checked (error) is not known, one no longer
   * checked is over — unless an MX lookup failed this run (the mail hosts come from it).
   */
  dane(x, e) {
    if (e.item === null) return 'unknown';
    const ep = (x.endpoints || []).find((p) => p && p.key === e.item);
    if (!ep) return (x.domains || []).some((d) => d && d.error) ? 'unknown' : 'over';
    if (ep.status === 'error') return e.tag === 'FAILED' ? 'bad' : 'unknown';
    if (e.tag === 'FAILED') return 'over';
    if (!Number.isFinite(daneRank(ep.status))) return 'unknown';
    return below(daneRank(ep.status), daneRank(e.state));
  },

  /**
   * A rule's status, one not checked this run as last checked (`last`), one a waiver accepts as over; a domain added that
   * failed a rule, until none fails.
   */
  audit(x, e) {
    const status = (r) => (r.status === 'waived' || (r.waiver && typeof r.waiver === 'object') ? 'pass'
      : auditChecked(r.status) ? r.status : r.last && auditChecked(r.last.status) ? r.last.status : 'unknown');
    if (e.item === null) return (x.rules || []).some((r) => r && status(r) === 'fail') ? 'bad' : 'over';
    const rule = (x.rules || []).find((r) => r && r.id === e.item);
    if (!rule) return 'over';
    const s = status(rule);
    return s === 'pass' ? 'over' : s === 'fail' ? 'bad' : 'unknown';
  },

  /**
   * A certificate's problem (RENEW-NOW, MOVED-UP, CA-NOTICE, REVOKED: the item is its SHA-256) is over
   * once no endpoint serves that certificate any more (renewed or replaced) — never while one does, and
   * not known while an endpoint that served it last time could not be read. An endpoint's (item
   * `address|port`): FAILED is over once a handshake completes there, WORSE and RECOVERED once its
   * status is OK, an endpoint no longer asked is over; a CERT (another certificate) is never known fixed.
   * The name no longer resolving (GONE) is over once it resolves again. A DNS lookup that failed
   * (`carried`: last night's endpoints) says nothing.
   */
  tls(x, e) {
    if (x.carried) return 'unknown';
    const endpoints = (Array.isArray(x.endpoints) ? x.endpoints : []).filter((p) => p && typeof p === 'object');
    if (e.item === null) {
      if (e.tag !== 'GONE') return 'unknown';
      const status = x.dns && x.dns.status;
      if (status === 'NXDOMAIN') return 'bad';
      return status === 'NOERROR' && endpoints.length ? 'over' : 'unknown';
    }
    if (TLS_CERTIFICATE_TAGS.has(e.tag)) {
      if (endpoints.some((p) => p.cert && p.cert.sha256 === e.item)) return 'bad';
      // an endpoint that served it last time and could not be read now may serve it still (an IPv6 address this machine cannot reach never counts)
      if (endpoints.some((p) => !p.cert && p.status !== 'SKIPPED' && p.lastGood && p.lastGood.cert && p.lastGood.cert.sha256 === e.item)) return 'unknown';
      return endpoints.some((p) => p.cert) ? 'over' : 'unknown';
    }
    const p = endpoints.find((y) => `${y.address}|${y.port}` === e.item);
    if (!p) return 'over';
    if (p.status === 'SKIPPED') return 'unknown';
    if (e.tag === 'FAILED') return TLS_FAILED.includes(p.status) ? 'bad' : 'over';
    if (e.tag === 'WORSE' || e.tag === 'RECOVERED') return TLS_FAILED.includes(p.status) ? 'unknown' : p.status === 'OK' ? 'over' : 'bad';
    return 'unknown';
  },

  /**
   * A risk (RISK, WORSE: the item is its key `kind|host|target`) is over once this run's report no
   * longer lists it (a risk whose lookup failed stays in it, `carried`: not known) or lists it at a
   * lesser severity than it was paged at. A domain watched for the first time with risks at medium
   * severity or above (NEW) is over once none is left.
   */
  takeover(x, e) {
    const risks = (Array.isArray(x.risks) ? x.risks : []).filter((r) => r && typeof r === 'object');
    if (e.item === null) {
      if (e.tag !== 'NEW' || risks.some((r) => r.carried)) return 'unknown';
      return risks.some((r) => takeoverRank(r.severity) <= takeoverRank(TAKEOVER_COUNTED)) ? 'bad' : 'over';
    }
    const risk = risks.find((r) => r.key === e.item);
    if (!risk) return 'over';
    if (risk.carried) return 'unknown';
    const paged = TAKEOVER_SEVERITIES.indexOf(e.state);
    return paged !== -1 && takeoverRank(risk.severity) > paged ? 'over' : 'bad';
  }
});

/**
 * Where the problem of an open PagerDuty key stands in this run's target: `'bad'` (it goes on),
 * `'over'` (the report shows the item better than it was paged at, or out of what the run checks:
 * a host out of an exact names file, a record set out of the zone file, an endpoint, a rule), or
 * `'unknown'` (this run could not tell: a failed lookup, a source or a record set not read, a
 * certificate no longer listed). Null for a command without a rule.
 * @param {string} command
 * @param {object} x this run's target of the key's target
 * @param {{ item: string|null, tag: string, state?: string|number|null }} e the open key
 * @returns {'bad'|'over'|'unknown'|null}
 */
export function problemStanding(command, x, e) {
  const fn = STANDINGS[command];
  return fn ? fn(x, { item: e.item ?? null, tag: e.tag, state: e.state ?? null }) : null;
}

/** The commands whose problems are a level that can go back down: a key keeps the level it was paged at. */
const LEVELLED = new Set(['health', 'drift', 'renew', 'dane', 'takeover']);

/**
 * The state a counted bad change pages its item at, kept with its key (`state`): the change's
 * `after` — a finding's severity or the health score, a record set's status or the name servers'
 * match, a verdict, an endpoint's status, a takeover risk's severity — for the commands whose
 * problems are levels; null for the others (a host, a certificate, a rule: bad or not).
 * @param {string} command
 * @param {{ after?: any }} change
 * @returns {string|number|null}
 */
export function pagedState(command, change) {
  if (!LEVELLED.has(command)) return null;
  const a = change.after;
  return (typeof a === 'string' && a.length > 0 && a.length <= 64) || Number.isFinite(a) ? a : null;
}
