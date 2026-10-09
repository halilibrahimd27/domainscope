/**
 * tools/ds/tlsdiff.mjs — "Changes since the baseline" of the runner's `tls` (tools/ds/tls.mjs), and
 * what a `tls` baseline must hold. Pure: no I/O. tools/ds/diff.mjs dispatches here.
 *
 * Per target (a host and port, or an address), per endpoint (address and port):
 * - NEW / GONE: a target checked now and not then, or the reverse (counted); an address new to a
 *   name or gone from it is listed only (DNS rotates the addresses of a CDN or a pool);
 * - FAILED / RECOVERED / FAILING: a handshake that stopped completing (counted), completes again
 *   (its tone is the new status's), or moved between two failures (listed only); SKIPPED (no IPv6
 *   route) is never a change;
 * - CERT: another certificate served — listed only when it renews the last one (the same CA, key
 *   type and every name kept), counted when it drops a name, changes the key type or the CA;
 * - a host whose DNS lookup failed, or that `--max-endpoints` left out, is listed once (FAILED, not
 *   counted: nothing was compared) and the next run is compared with the endpoints it carried;
 *   NXDOMAIN (the name went) is GONE, counted.
 * Per target, the problems of its addresses ({@link TLS_PROBLEMS}), counted: UNTRUSTED (a chain this
 * machine's root store does not trust, an expired intermediate too), MISMATCH (a certificate without
 * the name), NOT-LIVE (with --ct in both runs: an older certificate than the renewal CT logged), and
 * with --http in both runs HTTP (GET / answers 5xx) and REDIRECT (http:// no longer redirects to
 * https://) — said when an address read in both runs gets the problem, or a new address has it while
 * none of the target's had it before (a pool's rotating addresses repeat nothing); BETTER (good) once
 * no address has it and every one that had it was read again for it (a handshake — for UNTRUSTED with
 * a leaf that has not expired —, and for HTTP a GET / that answered, for REDIRECT a port 80 that
 * answered: no answer is no news), NOT-LIVE's saying whether the address serves another certificate
 * or CT no longer lists the renewal. The item is null: one PagerDuty incident per host and problem,
 * however many of its addresses share it. A weaker HSTS header is listed only (HSTS).
 * Per certificate (the item is its SHA-256), counted, tone bad, also for a target new to the list
 * (compared with nothing):
 * - EXPIRING: it entered --warn-days with its automatic renewal overdue (less than a quarter of its
 *   lifetime left, tools/ds/ctwatch.mjs overdueDays: a 90-day certificate at 21 days, a 47-day one at
 *   11) since the baseline last saw it served; entering --warn-days earlier is listed only, and a
 *   short-lived certificate first seen inside it says nothing;
 * - EXPIRED: it expired, still served;
 * - RENEW-NOW: the CA's ARI window has opened (or ended, the renewal overdue) since the baseline last
 *   saw that certificate served — the window it knew then, at that time (the target's check; the
 *   check a DNS outage carried; an endpoint's lastGood `at`), never at its answer's `checkedAt`: an
 *   answer carried past its Retry-After keeps that time —, or a certificate first seen in its window;
 * - MOVED-UP: its window starts more than {@link MOVED_UP_MS} earlier than the last answer said — a CA
 *   does that before a mass revocation;
 * - CA-NOTICE: an explanationURL the target's last answers did not carry;
 * - REVOKED: its CRL lists it now, and did not at the last check (or it is new).
 * The research notes named MOVED-UP and CA-NOTICE "WINDOW-MOVED" and "EXPLANATION", and NOT-LIVE
 * "NOT-DEPLOYED" (the endpoint status keeps that name: NOT_DEPLOYED); SPEC §9 has every tag at most
 * nine characters (tests/js/ds-runner.test.js), the change column of both tools.
 */

import { code, isoDay } from './render.mjs';
import { windowState } from './ari.mjs';
import { daysLeftAt, overdueDays } from './ctwatch.mjs';

/**
 * The endpoint statuses of `tls`, best first: a certificate was read (the first six), or none.
 * EXPIRING and EXPIRED come from the certificate's dates, the other three from the endpoint.
 */
export const TLS_STATUSES = Object.freeze(['OK', 'EXPIRING', 'NOT_DEPLOYED', 'NAME_MISMATCH', 'UNTRUSTED', 'EXPIRED', 'TLS_ERROR', 'TIMEOUT', 'CLOSED', 'SKIPPED']);
/** Statuses with no certificate read: the handshake did not complete. */
export const TLS_FAILED = Object.freeze(['TLS_ERROR', 'TIMEOUT', 'CLOSED']);
/** Node's codes for a certificate without the name asked (tls.checkServerIdentity), set only when the chain was trusted. */
export const NAME_ERRORS = Object.freeze(['ERR_TLS_CERT_ALTNAME_INVALID', 'ERR_TLS_CERT_ALTNAME_FORMAT']);
/** A trust error that is the certificate's dates (EXPIRED, said per certificate), not the chain. */
const EXPIRY_ERRORS = Object.freeze(['CERT_HAS_EXPIRED']);
/** A window start this much earlier than the last answer's is MOVED-UP. */
export const MOVED_UP_MS = 24 * 3600000;
const STATE_RANK = Object.freeze({ before: 0, open: 1, past: 2 });
/** A certificate's expiry states, in order ({@link expiryState}). */
const EXPIRY_RANK = Object.freeze({ ok: 0, soon: 1, expiring: 2, expired: 3 });
/** --warn-days of a report that does not say (written before it existed). */
const DEFAULT_WARN_DAYS = 21;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const isStrOrNull = (v) => v === null || v === undefined || typeof v === 'string';

/**
 * Does an endpoint record serve a chain this machine does not trust? Not for the leaf's dates
 * (EXPIRED says that) nor for Node's name error (MISMATCH); CERT_HAS_EXPIRED on an endpoint that is
 * not EXPIRED is a certificate above the leaf that expired (tools/ds/tls.mjs statusOf), so it is.
 */
export const isUntrusted = (e) => !!(e && e.cert) && e.trusted === false && isStr(e.trustError)
  && (!EXPIRY_ERRORS.includes(e.trustError) || e.status !== 'EXPIRED') && !NAME_ERRORS.includes(e.trustError);
/** Does it serve a certificate without the name asked? */
export const isMismatch = (e) => !!(e && e.cert) && e.nameMatch === false;
/** Does it serve an older certificate than the renewal CT logged (--ct)? */
export const isNotDeployed = (e) => !!(e && e.cert) && isObj(e.newer);
/** Does GET / answer 5xx (--http)? */
export const isHttpError = (e) => !!(e && e.cert) && isObj(e.http) && Number.isInteger(e.http.status) && e.http.status >= 500;
/** Does http:// answer without a redirect to https:// (--http, port 443)? */
export const isNoRedirect = (e) => !!(e && e.cert) && isObj(e.http) && isObj(e.http.plain) && Number.isInteger(e.http.plain.status) && e.http.plain.toHttps !== true;
/** A certificate read: the handshake completed. */
const certRead = (e) => !!(e && e.cert);
/** A chain whose trust was told: not an expired leaf, whose CERT_HAS_EXPIRED (Node's last error) hides the chain's. */
const trustRead = (e) => certRead(e) && e.status !== 'EXPIRED';
/** GET / answered (--http): a 5xx, or none, is known. */
const httpAnswered = (e) => certRead(e) && isObj(e.http) && Number.isInteger(e.http.status);
/** Port 80 answered (--http, port 443): a redirect to https://, or none, is known. */
const plainAnswered = (e) => certRead(e) && isObj(e.http) && isObj(e.http.plain) && Number.isInteger(e.http.plain.status);

/**
 * The problems of an endpoint the target-level changes are about: the tag, the endpoint status it
 * stands for, its test, what a run must have read for a comparison (`needs`: the target's CT
 * lookup, an endpoint's HTTP answer), and whether an endpoint was read for it this run (`read`: a
 * GET / or a port 80 that did not answer says nothing of a 5xx or a redirect).
 */
export const TLS_PROBLEMS = Object.freeze([
  Object.freeze({ tag: 'UNTRUSTED', status: 'UNTRUSTED', has: isUntrusted, needs: null, read: trustRead }),
  Object.freeze({ tag: 'MISMATCH', status: 'NAME_MISMATCH', has: isMismatch, needs: null, read: certRead }),
  Object.freeze({ tag: 'NOT-LIVE', status: 'NOT_DEPLOYED', has: isNotDeployed, needs: 'ct', read: certRead }),
  Object.freeze({ tag: 'HTTP', status: 'HTTP_ERROR', has: isHttpError, needs: 'http', read: httpAnswered }),
  Object.freeze({ tag: 'REDIRECT', status: 'NO_REDIRECT', has: isNoRedirect, needs: 'redirect', read: plainAnswered })
]);

/**
 * A certificate's expiry state at `at` (ms) with `warnDays`: `expired`; `expiring` with at most
 * `warnDays` days left and its automatic renewal overdue (fewer days left than a quarter of its
 * lifetime); `soon` within `warnDays` before that; `ok`.
 * @param {{ notBefore: string, notAfter: string }} cert
 * @param {number} at
 * @param {number} warnDays
 * @returns {'ok'|'soon'|'expiring'|'expired'}
 */
export function expiryState(cert, at, warnDays) {
  const end = Date.parse(cert && cert.notAfter);
  if (!Number.isFinite(end) || !Number.isFinite(at)) return 'ok';
  if (end < at) return 'expired';
  const left = daysLeftAt(cert.notAfter, at);
  if (left > warnDays) return 'ok';
  return left <= overdueDays(cert) ? 'expiring' : 'soon';
}

/** A report's --warn-days (the default for a report written before the option). */
export const warnDaysOf = (doc) => (doc && isObj(doc.options) && Number.isInteger(doc.options.warnDays) ? doc.options.warnDays : DEFAULT_WARN_DAYS);

/**
 * Why a `tls` baseline target is not what the comparison reads, or null.
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

function change(tag, target, item, what, { tone = 'info', counts = true, kind = 'changed', before = null, after = null } = {}) {
  return { tag, tone, counts, target, item, kind, before, after, parts: [code(target), ': ', ...what] };
}

const key = (e) => `${e.address}|${e.port}`;
const where = (e) => (e.port === 443 || e.address.includes(':') ? e.address : `${e.address}:${e.port}`);
const shortSha = (sha) => String(sha || '').slice(0, 16);
/** The certificate an endpoint record stands for: this run's, else the last one it carried. */
const certOf = (e) => (e && e.cert) || (e && e.lastGood && e.lastGood.cert) || null;
/** The ARI and revocation records of an endpoint's certificate, read now or carried. */
const extrasOf = (e) => (e && e.cert ? { ari: e.ari || null, revocation: e.revocation || null } : { ari: (e && e.lastGood && e.lastGood.ari) || null, revocation: (e && e.lastGood && e.lastGood.revocation) || null });
const certLabel = (c) => [code(c.subject || shortSha(c.sha256)), ' (', code(c.ca || '?'), `, expires ${isoDay(c.notAfter)})`];
const days = (n) => `${n} day${n === 1 ? '' : 's'}`;

/** Addresses as code parts, at most four, then "+N". */
function addressParts(list) {
  const out = [];
  list.slice(0, 4).forEach((e, i) => {
    if (i) out.push(', ');
    out.push(code(where(e)));
  });
  if (list.length > 4) out.push(` +${list.length - 4}`);
  return out;
}

/** What another certificate on the same endpoint changed: [] for a renewal of the same kind. */
function certDifferences(a, b) {
  const out = [];
  const dropped = (b.names || []).filter((n) => !(a.names || []).includes(n));
  if (dropped.length) out.push(`no longer covers ${dropped.slice(0, 3).join(', ')}${dropped.length > 3 ? ` +${dropped.length - 3}` : ''}`);
  if (a.keyType !== b.keyType) out.push(`key type ${b.keyType} → ${a.keyType}`);
  if ((a.caId || a.ca) !== (b.caId || b.ca)) out.push(`CA ${b.ca} → ${a.ca}`);
  return out;
}

/** The time of a target's check (ms), else the report's start. */
const checkedMs = (x, doc) => Date.parse((x && x.checkedAt) || (doc && doc.startedAt) || '') || NaN;
/** When a target's endpoints were read (ms): a DNS outage carried them from an earlier check. */
const servedMs = (x, doc) => (x && x.carried && Date.parse(x.carried.from)) || checkedMs(x, doc);
/** Why a target was carried: its DNS lookup failed (`dns`, the default of an older report) or --max-endpoints left it out. */
const carriedWhy = (x) => (x && x.carried && x.carried.why === 'max-endpoints' ? 'max-endpoints' : 'dns');

/**
 * @param {object} before the baseline report
 * @param {object} after this run's report
 * @returns {object[]} changes (tools/ds/diff.mjs orders them)
 */
export function diffTls(before, after) {
  const out = [];
  const old = new Map((before.targets || []).map((x) => [x.target, x]));
  const now = new Map((after.targets || []).map((x) => [x.target, x]));
  const http = !!(before.options && before.options.http) && !!(after.options && after.options.http);
  for (const [target, a] of now) {
    const b = old.get(target);
    if (!b) {
      const ok = (a.endpoints || []).filter((e) => e.cert).length;
      out.push(change('NEW', target, null, [a.carried ? `now listed, not checked this run (${carriedWhy(a) === 'dns' ? 'its DNS lookup failed' : '--max-endpoints'})`
        : `now checked: ${ok} endpoint${ok === 1 ? '' : 's'} served a certificate`], { kind: 'appeared' }));
      // what its certificates and addresses are in now (a window open, a revocation, an untrusted chain) is said once, as the CLI does
      if (!a.carried) {
        out.push(...diffProblems(target, a, { endpoints: [] }, { http: !!(after.options && after.options.http) }));
        out.push(...diffCertificates(target, a, { endpoints: [] }, before, after));
      }
      continue;
    }
    if (a.carried) {
      // said once: the endpoints of the last check are carried, the next run is compared with them
      if (!b.carried || carriedWhy(b) !== carriedWhy(a)) {
        out.push(change('FAILED', target, null, [carriedWhy(a) === 'dns'
          ? `DNS lookup failed this run (${a.dns ? a.dns.status : '?'}): nothing compared; the next run compares with the last check`
          : 'not checked this run (--max-endpoints: the run had checked as many endpoints as it may): the next run compares with the last check'],
        { tone: 'quiet', counts: false }));
      }
      continue;
    }
    if (b.carried) {
      out.push(change('RECOVERED', target, null, [`${carriedWhy(b) === 'dns' ? 'DNS answered again' : 'checked again'}; compared with the check of ${isoDay(b.carried.from) || 'an earlier run'}`],
        { tone: 'quiet', counts: false }));
    }
    const bDns = b.dns && b.dns.status;
    const aDns = a.dns && a.dns.status;
    if (aDns === 'NXDOMAIN' && bDns !== 'NXDOMAIN' && (b.endpoints || []).length) {
      out.push(change('GONE', target, null, ['the name no longer resolves (NXDOMAIN)'], { tone: 'bad', kind: 'disappeared', before: bDns, after: aDns }));
      continue;
    }
    out.push(...diffEndpoints(target, a, b));
    out.push(...diffProblems(target, a, b, { http }));
    out.push(...diffCertificates(target, a, b, before, after));
  }
  for (const [target] of old) if (!now.has(target)) out.push(change('GONE', target, null, ['no longer checked'], { kind: 'disappeared' }));
  return out;
}

function diffEndpoints(target, a, b) {
  const out = [];
  const prev = new Map((b.endpoints || []).map((e) => [key(e), e]));
  const keys = new Set((a.endpoints || []).map(key));
  for (const e of a.endpoints || []) {
    const p = prev.get(key(e));
    if (e.status === 'SKIPPED') continue;
    if (!p) {
      out.push(change('NEW', target, key(e), ['new address ', code(where(e)), ` — ${e.status}`, ...(e.cert ? [', ', ...certLabel(e.cert)] : [])],
        { tone: 'quiet', counts: false, kind: 'appeared', after: e.status }));
      continue;
    }
    if (p.status === 'SKIPPED') continue;
    const ef = TLS_FAILED.includes(e.status);
    const pf = TLS_FAILED.includes(p.status);
    const at = [code(where(e)), ': '];
    if (ef && pf) {
      if (e.status !== p.status) out.push(change('FAILING', target, key(e), [...at, `${p.status} → ${e.status}${e.error ? ` (${e.error})` : ''}`], { tone: 'quiet', counts: false, before: p.status, after: e.status }));
      continue;
    }
    if (ef) {
      out.push(change('FAILED', target, key(e), [...at, `${p.status} → ${e.status}${e.error ? ` (${e.error})` : ''}`], { tone: 'bad', before: p.status, after: e.status }));
      continue;
    }
    if (pf) {
      const last = p.lastGood && p.lastGood.cert;
      const moved = last && last.sha256 !== e.cert.sha256 ? [', another certificate than before it failed: ', ...certLabel(e.cert)] : [];
      out.push(change('RECOVERED', target, key(e), [...at, `answers again: ${e.status}`, ...moved], { tone: e.status === 'OK' ? 'good' : 'bad', before: p.status, after: e.status }));
    }
    const pc = certOf(p);
    if (e.cert && pc && pc.sha256 !== e.cert.sha256) {
      const diffs = certDifferences(e.cert, pc);
      out.push(change('CERT', target, key(e), [...at, diffs.length ? 'another certificate: ' : 'renewed: ', ...certLabel(e.cert), ', was ', ...certLabel(pc),
        ...(diffs.length ? [` — ${diffs.join('; ')}`] : [])], { tone: diffs.length ? 'bad' : 'quiet', counts: diffs.length > 0, before: pc.sha256, after: e.cert.sha256 }));
    }
  }
  for (const p of b.endpoints || []) {
    if (keys.has(key(p)) || p.status === 'SKIPPED') continue;
    out.push(change('GONE', target, key(p), ['address ', code(where(p)), ' no longer answered by DNS'], { tone: 'quiet', counts: false, kind: 'disappeared', before: p.status }));
  }
  return out;
}

/** The words of a problem on a target's addresses (bad), and of its end (good). */
function problemText(problem, list) {
  const first = list[0];
  switch (problem.tag) {
    case 'UNTRUSTED': {
      const missing = list.map((e) => e.missingIntermediate).find(Boolean);
      const outdated = list.map((e) => e.outOfDateIssuer).find(isObj);
      return [...addressParts(list), ` serve${list.length === 1 ? 's' : ''} a chain this machine does not trust (`, code(first.trustError), ')',
        ...(missing ? ['; the intermediate ', code(missing.name), ...(missing.owner ? [' (', code(missing.owner), ')'] : []), ' is not sent'] : []),
        ...(outdated ? ['; ', code(outdated.name || '?'), outdated.expired === false ? ` in it is not valid before ${isoDay(outdated.notBefore)}` : ` in it expired on ${isoDay(outdated.notAfter)}`] : [])];
    }
    case 'MISMATCH':
      return [...addressParts(list), ` serve${list.length === 1 ? 's' : ''} `, ...certLabel(first.cert), ', which does not cover the name'];
    case 'NOT-LIVE':
      return [...addressParts(list), ` still serve${list.length === 1 ? 's' : ''} the certificate of ${isoDay(first.cert.notBefore)} (expires ${isoDay(first.cert.notAfter)}); `,
        `CT logged its renewal of ${isoDay(first.newer.notBefore)} (`, code(first.newer.ca || '?'), '), not installed there'];
    case 'HTTP':
      return [...addressParts(list), `: GET / answers ${first.http.status}`];
    case 'REDIRECT':
      return [...addressParts(list), `: http:// answers ${first.http.plain.status} without a redirect to https://`];
    default:
      return [...addressParts(list)];
  }
}

const GOOD_TEXT = Object.freeze({
  UNTRUSTED: 'every address serves a trusted chain again',
  MISMATCH: 'every address serves a certificate for the name again',
  'NOT-LIVE': 'every address serves the renewed certificate now',
  HTTP: 'GET / no longer answers 5xx',
  REDIRECT: 'http:// redirects to https:// again'
});
/** NOT-LIVE over while an address still serves the certificate it had: CT no longer lists the renewal (revoked, say). */
const NOT_LIVE_UNLISTED = 'CT no longer lists a newer certificate than the one still served';

/**
 * The target-level problems ({@link TLS_PROBLEMS}) one run has and the other had not, and a weaker
 * HSTS header (listed only).
 * @param {string} target
 * @param {object} a this run's target
 * @param {object} b the baseline's (`{ endpoints: [] }` for a target new to the list)
 * @param {{ http: boolean }} opts both runs asked HTTP (a target new to the list: this run did)
 */
function diffProblems(target, a, b, { http }) {
  const out = [];
  const prev = new Map((b.endpoints || []).map((e) => [key(e), e]));
  const now = (a.endpoints || []).filter((e) => e.cert);
  const readBefore = (b.endpoints || []).filter((e) => e.cert);
  const present = new Map((a.endpoints || []).map((e) => [key(e), e]));
  for (const problem of TLS_PROBLEMS) {
    if (problem.needs === 'ct' && !(isObj(a.ct) && (isObj(b.ct) || !readBefore.length))) continue;
    if ((problem.needs === 'http' || problem.needs === 'redirect') && !http) continue;
    const had = readBefore.filter((e) => problem.has(e));
    const has = now.filter((e) => problem.has(e));
    // an address read in both runs that got the problem, or a new one while the target had none
    const newly = has.filter((e) => {
      const p = prev.get(key(e));
      if (p && p.cert) return !problem.has(p) && (problem.needs !== 'http' || isObj(p.http)) && (problem.needs !== 'redirect' || (isObj(p.http) && isObj(p.http.plain)));
      return !p && !had.length;
    });
    if (newly.length) {
      out.push(change(problem.tag, target, null, problemText(problem, newly), { tone: 'bad', after: problem.status }));
    } else if (had.length && !has.length && had.every((e) => {
      const n = present.get(key(e));
      // read again for the problem, or gone from DNS: a handshake that failed, a GET / or a port 80 that did not answer may have it still
      return !n || problem.read(n);
    })) {
      const unlisted = problem.tag === 'NOT-LIVE' && had.some((e) => {
        const n = present.get(key(e));
        return !!n && n.cert.sha256 === e.cert.sha256;
      });
      out.push(change('BETTER', target, null, [unlisted ? NOT_LIVE_UNLISTED : GOOD_TEXT[problem.tag]], { tone: 'good', before: problem.status }));
    }
  }
  if (http) {
    const weaker = now.filter((e) => {
      const p = prev.get(key(e));
      const was = p && p.cert && isObj(p.http) && isObj(p.http.hsts) && p.http.hsts.valid ? p.http.hsts.maxAge : null;
      if (!was || !isObj(e.http) || !Number.isInteger(e.http.status)) return false;
      const is = isObj(e.http.hsts) && e.http.hsts.valid ? e.http.hsts.maxAge : 0;
      return is < was;
    });
    if (weaker.length) {
      const p = prev.get(key(weaker[0]));
      const is = isObj(weaker[0].http.hsts) && weaker[0].http.hsts.valid ? `max-age=${weaker[0].http.hsts.maxAge}` : 'none';
      out.push(change('HSTS', target, null, [...addressParts(weaker), `: Strict-Transport-Security max-age=${p.http.hsts.maxAge} → ${is}`], { tone: 'info', counts: false }));
    }
  }
  return out;
}

/**
 * Every certificate a target's report knows, with its ARI and revocation and when it was last seen
 * served (ms: the target's check, or an endpoint's lastGood `at`): sha256 → { cert, ari, revocation,
 * seenAt }, the newest record of a certificate two endpoints know.
 */
function certificatesOf(x, doc) {
  const out = new Map();
  const served = servedMs(x, doc);
  for (const e of (x && x.endpoints) || []) {
    const c = certOf(e);
    if (!c) continue;
    const seenAt = e.cert ? served : Date.parse(e.lastGood.at) || served;
    const had = out.get(c.sha256);
    if (!had || seenAt > had.seenAt) out.set(c.sha256, { cert: c, ...extrasOf(e), seenAt });
  }
  return out;
}

function diffCertificates(target, a, b, before, after) {
  const out = [];
  const prev = certificatesOf(b, before);
  const at = checkedMs(a, after);
  const warnNow = warnDaysOf(after);
  const warnThen = warnDaysOf(before);
  const prevExplanations = new Set();
  let prevRead = false;
  for (const e of b.endpoints || []) {
    const { ari } = extrasOf(e);
    if (ari && !ari.error) {
      prevRead = true;
      if (ari.explanationURL) prevExplanations.add(ari.explanationURL);
    }
  }
  // this run's certificates only: what the endpoints serve now
  const current = new Map();
  for (const e of a.endpoints || []) {
    if (!e.cert) continue;
    if (!current.has(e.cert.sha256)) current.set(e.cert.sha256, { cert: e.cert, ari: e.ari || null, revocation: e.revocation || null, endpoints: [] });
    current.get(e.cert.sha256).endpoints.push(e);
  }
  for (const [sha, x] of current) {
    const p = prev.get(sha) || null;
    const label = certLabel(x.cert);
    // its expiry: entering --warn-days with the renewal overdue, expiring; the state the baseline saw when it last saw it served
    const state = expiryState(x.cert, at, warnNow);
    const pState = p ? expiryState(x.cert, p.seenAt, warnThen) : null;
    const rank = EXPIRY_RANK[state];
    const pRank = pState === null ? -1 : EXPIRY_RANK[pState];
    if (rank > pRank && state !== 'ok') {
      const left = daysLeftAt(x.cert.notAfter, at);
      if (state === 'expired') {
        out.push(change('EXPIRED', target, sha, [...label, `: expired on ${isoDay(x.cert.notAfter)}, still served by `, ...addressParts(x.endpoints)],
          { tone: 'bad', before: pState, after: 'EXPIRED' }));
      } else if (state === 'expiring') {
        out.push(change('EXPIRING', target, sha, [...label, `: ${days(left)} left and not renewed (served by `, ...addressParts(x.endpoints), ')'],
          { tone: 'bad', before: pState, after: 'EXPIRING' }));
      } else if (p) {
        // within --warn-days before its automatic renewal is due: listed (a short-lived certificate first seen there says nothing)
        out.push(change('EXPIRING', target, sha, [...label, `: ${days(left)} left; its automatic renewal is not overdue yet`],
          { tone: 'info', counts: false, before: pState, after: 'soon' }));
      }
    }
    const ari = x.ari && !x.ari.error ? x.ari : null;
    const pAri = p && p.ari && !p.ari.error ? p.ari : null;
    if (ari) {
      const windowNow = windowState(ari, at);
      // the window the baseline knew, when it last saw the certificate served (what its run said)
      const windowThen = pAri ? windowState(pAri, [p.seenAt, Date.parse(pAri.checkedAt), at].find(Number.isFinite)) : null;
      if ((windowNow === 'open' || windowNow === 'past') && STATE_RANK[windowNow] > (windowThen === null ? -1 : STATE_RANK[windowThen])) {
        out.push(change('RENEW-NOW', target, sha, [...label, windowNow === 'open'
          ? `: the CA's renewal window opened (${isoDay(ari.start)} – ${isoDay(ari.end)}): renew it now`
          : `: the CA's renewal window ended on ${isoDay(ari.end)}: the renewal is overdue`], { tone: 'bad', after: windowNow }));
      }
      if (pAri && Date.parse(ari.start) < Date.parse(pAri.start) - MOVED_UP_MS) {
        const ahead = Math.round((Date.parse(pAri.start) - Date.parse(ari.start)) / 86400000);
        out.push(change('MOVED-UP', target, sha, [...label, `: the CA moved its renewal window ${ahead} day${ahead === 1 ? '' : 's'} earlier (starts ${isoDay(ari.start)}, was ${isoDay(pAri.start)}), as CAs do before a mass revocation`],
          { tone: 'bad', before: pAri.start, after: ari.start }));
      }
      if (ari.explanationURL && prevRead && !prevExplanations.has(ari.explanationURL)) {
        out.push(change('CA-NOTICE', target, sha, [...label, ': the CA explains its renewal window: ', code(ari.explanationURL)], { tone: 'bad', after: ari.explanationURL }));
      }
    }
    const rev = x.revocation;
    if (rev && rev.status === 'revoked' && !(p && p.revocation && p.revocation.status === 'revoked')) {
      out.push(change('REVOKED', target, sha, [...label, `: revoked by its CA on ${isoDay(rev.time) || '?'} (${rev.reason || 'no reason given'}), still served`],
        { tone: 'bad', before: p && p.revocation ? p.revocation.status : null, after: 'revoked' }));
    }
  }
  return out;
}

/**
 * What two `tls` runs did differently.
 * @param {object} o the baseline's options
 * @param {object} n this run's
 * @returns {string[]}
 */
export function tlsNotes(o, n) {
  const notes = [];
  if (o.ari !== undefined && !!o.ari !== !!n.ari) notes.push(`ARI was asked in ${n.ari ? 'this run only' : 'the baseline run only'} (--ari): RENEW-NOW, MOVED-UP and CA-NOTICE compare runs that both asked it.`);
  if (o.revocation !== undefined && !!o.revocation !== !!n.revocation) notes.push(`Revocation was checked in ${n.revocation ? 'this run only' : 'the baseline run only'} (--revocation).`);
  const ow = Number.isInteger(o.warnDays) ? o.warnDays : DEFAULT_WARN_DAYS;
  const nw = Number.isInteger(n.warnDays) ? n.warnDays : DEFAULT_WARN_DAYS;
  if (ow !== nw) notes.push(`The warning days differ from the baseline's (${ow} → ${nw}, --warn-days): EXPIRING can come from that.`);
  if (!!o.ct !== !!n.ct) notes.push(`CT was read in ${n.ct ? 'this run only' : 'the baseline run only'} (--ct): NOT-LIVE compares runs that both read it.`);
  if (!!o.http !== !!n.http) notes.push(`HTTP was asked in ${n.http ? 'this run only' : 'the baseline run only'} (--http): HTTP and REDIRECT compare runs that both asked it.`);
  return notes;
}
