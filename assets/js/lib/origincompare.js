/**
 * origincompare.js — before DNS moves a name to a new server: does the new server answer like the
 * old one? One HTTPS GET of a path, with the name as the SNI and the Host header, against each
 * address through Globalping (lib/globalping.js httpsGetAtRequest); the second measurement reuses
 * the first one's probe (`locations: <id>`), so both answers come from the same place. The two
 * answers are compared field by field: reachability, HTTP status, redirect target, content type,
 * page title, body (SHA-256 of what the probe returned: the first 10,000 characters, decoded),
 * HSTS, the Server header, and the certificate (does it cover the name, did the probe trust it,
 * issuer, expiry, SHA-256 fingerprint). DOM-free; runs in browsers and Node 22.
 *
 * Addresses a probe cannot reach (private, documentation, reserved) go to the CLI instead:
 * `ssl_origin_scan.py --compare OLD NEW -n NAME` does the same from inside your network
 * ({@link buildCompareCommand}).
 *
 * What is sent: the two addresses, the name and the path, to Globalping, only after the caller's
 * consent; the results (the servers' response headers and the first 10,000 characters of each
 * body included) are public to anyone with a measurement id for about six months.
 */

import { httpsGetAtRequest, isProbeableHost, isProbeablePort, probeTarget, probeSummary } from './globalping.js';
import { servedCert, parseFailure } from './verify.js';
import { certCovers } from './domain.js';
import { normalizeIP, ipVersion } from './netinfo.js';
import { sha256 } from './sha.js';
import { quoteArg } from './cmdline.js';

/** Compared fields, in display order (`oc.field.<key>`). */
export const COMPARE_FIELDS = Object.freeze(['reach', 'status', 'location', 'contentType', 'title', 'body', 'hsts', 'server',
  'certCovers', 'certTrusted', 'certIssuer', 'certExpires', 'certFingerprint']);
/** What a comparison says overall (`oc.verdict.<v>`). */
export const COMPARE_VERDICTS = Object.freeze(['same', 'differs', 'broken', 'incomplete']);
/** Notes a field row can carry (`oc.note.<n>`). */
export const COMPARE_NOTES = Object.freeze(['new-unreachable', 'old-unreachable', 'both-unreachable', 'new-error-status', 'dynamic-body',
  'body-cut', 'hsts-lost', 'hsts-new', 'cert-name', 'cert-untrusted', 'cert-expiring', 'new-cert', 'same-cert']);
/** Problems of the form (`oc.issue.<code>`). */
export const COMPARE_ISSUES = Object.freeze(['host', 'old-ip', 'new-ip', 'same-ip', 'path', 'port']);
/** A new certificate that expires within this many days is a warning. */
export const COMPARE_EXPIRY_WARN_DAYS = 14;
/** Globalping cuts a body at this many characters (`truncated: true`). */
export const COMPARE_BODY_LIMIT = 10000;
/** Probes one comparison costs: one per address. */
export const COMPARE_PROBES = 2;

const PATH_RE = /^\/[\x21-\x22\x24-\x3e\x40-\x7e]{0,500}$/;
const FILE_SAFE_PATH = /^\/[A-Za-z0-9._~\/-]{0,200}$/;
const DAY_MS = 86400000;
const PYTHON = Object.freeze({ posix: 'python3', powershell: 'python' });

/* ------------------------------------------------------------------------ */
/* The form                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * Check the form: a host name Globalping accepts, two different addresses, a plain path and a
 * port. An address a probe cannot reach (private, documentation, reserved) is no error: the
 * comparison then goes to the CLI (`probeable: false`, `private` lists which).
 * @param {{ host?: string, oldIp?: string, newIp?: string, path?: string, port?: number|string }} input
 * @returns {{ ok: boolean, probeable: boolean, host: string, oldIp: string|null, newIp: string|null, path: string, port: number,
 *   issues: Array<{ code: string, value: string }>, private: string[] }}
 */
export function checkCompare({ host = '', oldIp = '', newIp = '', path = '/', port = 443 } = {}) {
  const issues = [];
  const h = String(host ?? '').trim().toLowerCase().replace(/\.$/, '');
  if (!isProbeableHost(h)) issues.push({ code: 'host', value: String(host ?? '') });
  const addr = (v, code) => {
    const s = String(v ?? '').trim().replace(/^\[|\]$/g, '');
    const ip = ipVersion(s) ? normalizeIP(s) : null;
    if (!ip) issues.push({ code, value: s });
    return ip;
  };
  const a = addr(oldIp, 'old-ip');
  const b = addr(newIp, 'new-ip');
  if (a && b && a === b) issues.push({ code: 'same-ip', value: a });
  const p = String(path ?? '').trim() || '/';
  if (!PATH_RE.test(p)) issues.push({ code: 'path', value: p });
  const n = typeof port === 'number' ? port : Number(String(port ?? '').trim() || 443);
  if (!Number.isInteger(n) || n < 1 || n > 65535) issues.push({ code: 'port', value: String(port) });
  const priv = [a, b].filter((ip) => ip && !probeTarget(ip));
  const probeable = !priv.length && Number.isInteger(n) && isProbeablePort(n);
  return { ok: !issues.length, probeable: !issues.length && probeable, host: h, oldIp: a, newIp: b, path: p, port: Number.isInteger(n) ? n : 443, issues, private: priv };
}

/**
 * The Globalping body for one side: a GET of `path` at `ip` with `host` as SNI / Host
 * ({@link httpsGetAtRequest}); `locations` = the first side's measurement id for the second side.
 * @param {{ ip: string, host: string, path?: string, port?: number, locations?: string|null }} opts
 * @returns {object}
 */
export function compareRequest({ ip, host, path = '/', port = 443, locations = null }) {
  return httpsGetAtRequest({ ip, host, path, port, timeoutS: 10, probes: 1, locations });
}

/* ------------------------------------------------------------------------ */
/* One side                                                                 */
/* ------------------------------------------------------------------------ */

const headerValue = (headers, name) => {
  if (!headers || typeof headers !== 'object') return null;
  const v = headers[name];
  if (Array.isArray(v)) return v.length ? String(v[0]) : null;
  return v === undefined || v === null ? null : String(v);
};

/**
 * The `<title>` of an HTML body (the first one, whitespace collapsed, the common entities
 * decoded, ≤ 200 characters), or null.
 * @param {string} body
 * @returns {string|null}
 */
export function pageTitle(body) {
  const m = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(typeof body === 'string' ? body : '');
  if (!m) return null;
  const text = m[1]
    .replace(/&#(\d{1,6});/g, (x, d) => (Number(d) > 0 && Number(d) < 0x110000 ? String.fromCodePoint(Number(d)) : x))
    .replace(/&#x([0-9a-f]{1,6});/gi, (x, d) => (parseInt(d, 16) > 0 && parseInt(d, 16) < 0x110000 ? String.fromCodePoint(parseInt(d, 16)) : x))
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&')
    .replace(/\s+/g, ' ')
    .trim();
  return text ? text.slice(0, 200) : null;
}

/**
 * A Strict-Transport-Security header as `{ raw, maxAge, includeSubDomains, preload }`, or null.
 * @param {string|null} value
 * @returns {{ raw: string, maxAge: number|null, includeSubDomains: boolean, preload: boolean }|null}
 */
export function parseHsts(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const parts = value.split(';').map((p) => p.trim().toLowerCase()).filter(Boolean);
  const age = parts.map((p) => /^max-age\s*=\s*"?(\d+)"?$/.exec(p)).find(Boolean);
  return { raw: value.trim(), maxAge: age ? Number(age[1]) : null, includeSubDomains: parts.includes('includesubdomains'), preload: parts.includes('preload') };
}

const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/**
 * @typedef {object} CompareSide
 * @property {string} ip
 * @property {boolean} ok the probe got an HTTP answer
 * @property {{ kind: string, text: string }|null} failure verify.parseFailure of a failed test
 * @property {number|null} status
 * @property {string|null} location
 * @property {string|null} contentType
 * @property {string|null} server
 * @property {object|null} hsts {@link parseHsts}
 * @property {{ sha256: string, length: number, truncated: boolean, title: string|null }|null} body
 * @property {{ sha256: string, subjectCN: string|null, hostnames: string[], covers: boolean, issuer: string|null,
 *   notAfter: Date|null, daysLeft: number|null, authorized: boolean, error: string|null }|null} cert
 * @property {object|null} probe globalping.probeSummary
 * @property {string|null} measurementId
 */

/**
 * One side of the comparison from its finished measurement.
 * @param {object} measurement a Globalping HTTP measurement (one probe)
 * @param {{ ip: string, host: string, now?: number }} ctx
 * @returns {CompareSide}
 */
export function readSide(measurement, { ip, host, now = Date.now() }) {
  const first = measurement && Array.isArray(measurement.results) ? measurement.results[0] : null;
  const r = first && first.result && typeof first.result === 'object' ? first.result : null;
  const side = {
    ip, ok: false, failure: null, status: null, location: null, contentType: null, server: null, hsts: null, body: null, cert: null,
    probe: first ? probeSummary(first.probe) : null, measurementId: (measurement && measurement.id) || null
  };
  if (!r) return { ...side, failure: { kind: 'unknown', text: 'no result' } };
  const served = servedCert(r.tls);
  if (served) {
    const notAfter = served.notAfter instanceof Date && Number.isFinite(served.notAfter.getTime()) ? served.notAfter : null;
    side.cert = {
      sha256: served.sha256,
      subjectCN: served.subjectCN,
      hostnames: served.hostnames,
      covers: certCovers(served.hostnames, host).covered,
      issuer: [served.issuerCN, served.issuerO].filter(Boolean).join(' · ') || null,
      notAfter,
      daysLeft: notAfter ? Math.floor((notAfter.getTime() - now) / DAY_MS) : null,
      authorized: served.authorized,
      error: served.error
    };
  }
  if (r.status !== 'finished' || !Number.isInteger(r.statusCode)) {
    const f = parseFailure(r);
    return { ...side, failure: { kind: f.kind, text: f.text } };
  }
  const body = typeof r.rawBody === 'string' ? r.rawBody : '';
  Object.assign(side, {
    ok: true,
    status: r.statusCode,
    location: headerValue(r.headers, 'location'),
    contentType: headerValue(r.headers, 'content-type'),
    server: headerValue(r.headers, 'server'),
    hsts: parseHsts(headerValue(r.headers, 'strict-transport-security')),
    body: {
      sha256: hex(sha256(new TextEncoder().encode(body))),
      length: body.length,
      truncated: r.truncated === true || body.length >= COMPARE_BODY_LIMIT,
      title: pageTitle(body)
    }
  });
  return side;
}

/* ------------------------------------------------------------------------ */
/* The comparison                                                           */
/* ------------------------------------------------------------------------ */

const SEVERITY_RANK = { ok: 0, info: 1, warn: 2, error: 3 };
/** Notes about the new server itself: they keep their severity even when both servers agree. */
const ABSOLUTE_NOTES = new Set(['cert-name', 'cert-untrusted', 'cert-expiring']);

/** One compared field; a field both servers agree on is 'ok' unless its note is about the new server itself. */
function field(key, oldValue, newValue, same, severity, note = null) {
  return { key, old: oldValue, new: newValue, same, severity: same && !ABSOLUTE_NOTES.has(note) ? 'ok' : severity, note };
}

const dateKey = (d) => (d instanceof Date ? d.toISOString().slice(0, 10) : null);
const hstsText = (h) => (h ? h.raw : null);

/**
 * Compare two sides. Every field in {@link COMPARE_FIELDS} order with `old` / `new` display
 * values (strings, numbers, booleans or null), `same`, a `severity` (ok, info, warn, error) and a
 * `note` ({@link COMPARE_NOTES}). What matters:
 *
 * - the new server not answering, answering 5xx or 4xx where the old one did not, or serving a
 *   certificate that does not cover the name or that the probe did not trust (while the old one
 *   was trusted) is an error; a new server that does not answer is compared no further, and
 *   the certificate fields come only with a certificate from the new server;
 * - another status, redirect, content type or title, a lost HSTS header, or a certificate that
 *   expires within {@link COMPARE_EXPIRY_WARN_DAYS} days is a warning;
 * - another body, Server header, issuer, expiry or certificate is information: a page with a
 *   token or a time in it differs on every request, and a new server usually has its own
 *   certificate.
 *
 * `verdict`: 'broken' (an error), 'differs' (a warning), 'same' (information only), or
 * 'incomplete' (the old server did not answer, so there is nothing to compare with).
 * @param {CompareSide} a the old server
 * @param {CompareSide} b the new server
 * @param {{ now?: number }} [opts]
 * @returns {{ verdict: string, fields: object[], differences: number, worst: string }}
 */
export function compareSides(a, b, { now = Date.now() } = {}) {
  const fields = [];
  const reachText = (s) => (s.ok ? 'ok' : (s.failure && s.failure.kind) || 'unknown');
  let reachNote = null;
  let reachSev = 'ok';
  if (!b.ok && a.ok) [reachNote, reachSev] = ['new-unreachable', 'error'];
  else if (!b.ok && !a.ok) [reachNote, reachSev] = ['both-unreachable', 'error'];
  else if (b.ok && !a.ok) [reachNote, reachSev] = ['old-unreachable', 'info'];
  fields.push({ key: 'reach', old: reachText(a), new: reachText(b), same: a.ok === b.ok, severity: reachSev, note: reachNote });

  // The HTTP fields only when the new server answered (a failure says it all); without an answer
  // from the old one there is nothing to compare with, so a difference is information only.
  if (b.ok) {
    const warn = a.ok ? 'warn' : 'info';
    const bad = (s) => Number.isInteger(s) && s >= 400;
    const statusSev = bad(b.status) && !(a.ok && bad(a.status)) ? 'error' : warn;
    fields.push(field('status', a.status, b.status, a.status === b.status, statusSev, statusSev === 'error' && a.status !== b.status ? 'new-error-status' : null));
    fields.push(field('location', a.location, b.location, a.location === b.location, warn));
    fields.push(field('contentType', a.contentType, b.contentType, a.contentType === b.contentType, warn));
    const ta = a.body ? a.body.title : null;
    const tb = b.body ? b.body.title : null;
    fields.push(field('title', ta, tb, ta === tb, warn));
    const ha = a.body ? a.body.sha256 : null;
    const hb = b.body ? b.body.sha256 : null;
    const cut = !!((a.body && a.body.truncated) || (b.body && b.body.truncated));
    fields.push(field('body', ha, hb, ha === hb, 'info', ha === hb ? (cut ? 'body-cut' : null) : 'dynamic-body'));
    let hstsNote = null;
    let hstsSev = 'info';
    if (a.hsts && !b.hsts) [hstsNote, hstsSev] = ['hsts-lost', warn];
    else if (!a.hsts && b.hsts) hstsNote = 'hsts-new';
    fields.push(field('hsts', hstsText(a.hsts), hstsText(b.hsts), hstsText(a.hsts) === hstsText(b.hsts), hstsSev, hstsNote));
    fields.push(field('server', a.server, b.server, a.server === b.server, 'info'));
  }

  // The certificate fields when the new server served one.
  const ca = a.cert;
  const cb = b.cert;
  if (cb) {
    const covers = (c) => (c ? c.covers : null);
    fields.push(field('certCovers', covers(ca), covers(cb), covers(ca) === covers(cb), cb && !cb.covers ? 'error' : 'info', cb && !cb.covers ? 'cert-name' : null));
    const trusted = (c) => (c ? c.authorized : null);
    const untrusted = cb && !cb.authorized;
    fields.push(field('certTrusted', trusted(ca), trusted(cb), trusted(ca) === trusted(cb), untrusted ? (ca && ca.authorized ? 'error' : 'warn') : 'info', untrusted ? 'cert-untrusted' : null));
    fields.push(field('certIssuer', ca ? ca.issuer : null, cb ? cb.issuer : null, (ca && ca.issuer) === (cb && cb.issuer), 'info'));
    const soon = cb && cb.notAfter && cb.notAfter.getTime() - now < COMPARE_EXPIRY_WARN_DAYS * DAY_MS;
    fields.push(field('certExpires', ca ? dateKey(ca.notAfter) : null, cb ? dateKey(cb.notAfter) : null,
      (ca && dateKey(ca.notAfter)) === (cb && dateKey(cb.notAfter)), soon ? 'warn' : 'info', soon ? 'cert-expiring' : null));
    const same = !!(ca && cb && ca.sha256 === cb.sha256);
    fields.push(field('certFingerprint', ca ? ca.sha256 : null, cb ? cb.sha256 : null, same, 'info', same ? 'same-cert' : (ca && cb ? 'new-cert' : null)));
  }

  const worst = fields.reduce((w, f) => (SEVERITY_RANK[f.severity] > SEVERITY_RANK[w] ? f.severity : w), 'ok');
  let verdict;
  if (worst === 'error') verdict = 'broken';
  else if (!a.ok) verdict = 'incomplete';
  else if (worst === 'warn') verdict = 'differs';
  else verdict = 'same';
  return { verdict, fields, differences: fields.filter((f) => !f.same).length, worst };
}

/**
 * Run one comparison: the old address first, then the new one from the same probe. Globalping
 * errors propagate (a quota 429 before the first measurement costs nothing; one after it
 * carries `err.spent` = 1 and `err.first`, the old side already measured).
 * @param {{ client: object, host: string, oldIp: string, newIp: string, path?: string, port?: number, signal?: AbortSignal,
 *   onSide?: (which: 'old'|'new', side: CompareSide) => void, now?: () => number }} opts
 * @returns {Promise<{ old: CompareSide, new: CompareSide, comparison: object, spent: number, ids: string[], at: Date }>}
 * @throws {TypeError} for a form {@link checkCompare} refuses or addresses a probe cannot reach
 */
export async function runCompare({ client, host, oldIp, newIp, path = '/', port = 443, signal, onSide, now = () => Date.now() }) {
  const c = checkCompare({ host, oldIp, newIp, path, port });
  if (!c.ok || !c.probeable) throw new TypeError(`runCompare: ${c.ok ? 'an address a probe cannot reach' : c.issues[0].code}`);
  if (!client || typeof client.measure !== 'function') throw new TypeError('runCompare: a Globalping client is required');
  const first = await client.measure(compareRequest({ ip: c.oldIp, host: c.host, path: c.path, port: c.port }), { signal });
  const old = readSide(first.measurement, { ip: c.oldIp, host: c.host, now: now() });
  if (typeof onSide === 'function') onSide('old', old);
  let second;
  try {
    second = await client.measure(compareRequest({ ip: c.newIp, host: c.host, path: c.path, port: c.port, locations: first.id }), { signal });
  } catch (err) {
    if (err && typeof err === 'object') {
      try {
        err.spent = (Number(first.cost) || 1) + (err.measurementId ? Number(err.cost) || 1 : 0);
        err.first = old;
      } catch { /* frozen error object */ }
    }
    throw err;
  }
  const side = readSide(second.measurement, { ip: c.newIp, host: c.host, now: now() });
  if (typeof onSide === 'function') onSide('new', side);
  return {
    old,
    new: side,
    comparison: compareSides(old, side, { now: now() }),
    spent: (Number(first.cost) || 1) + (Number(second.cost) || 1),
    ids: [first.id, second.id],
    at: new Date(now())
  };
}

/* ------------------------------------------------------------------------ */
/* The CLI                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * `python3 ssl_origin_scan.py --compare OLD NEW -n NAME [-p PORT] [--path PATH]` for the chosen
 * shell (private addresses; the CLI connects from inside your network). Built from checked
 * values only ({@link checkCompare}); null when the form is not valid or the path holds
 * characters no shell quoting should carry.
 * @param {{ host: string, oldIp: string, newIp: string, path?: string, port?: number, shell?: 'posix'|'powershell' }} opts
 * @returns {string|null}
 */
export function buildCompareCommand({ host, oldIp, newIp, path = '/', port = 443, shell = 'posix' }) {
  const c = checkCompare({ host, oldIp, newIp, path, port });
  if (!c.ok || !FILE_SAFE_PATH.test(c.path)) return null;
  const sh = shell === 'powershell' ? 'powershell' : 'posix';
  const parts = [PYTHON[sh], 'ssl_origin_scan.py', '--compare', quoteArg(c.oldIp, sh), quoteArg(c.newIp, sh), '-n', quoteArg(c.host, sh)];
  if (c.port !== 443) parts.push('-p', String(c.port));
  if (c.path !== '/') parts.push('--path', quoteArg(c.path, sh));
  return parts.join(' ');
}
