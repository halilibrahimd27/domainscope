/**
 * verify.js — "is the new certificate live on every server?" checked from the
 * internet through Globalping (ROADMAP P0.1, Phase A) plus the zero-probe
 * origin-exposure hook (P0.2). DOM-free; runs in browsers and Node 22.
 *
 * lib/globalping.js is the transport and knows nothing about certificates. This
 * module holds the semantics, mirroring cli/ssl_origin_scan.py:
 *
 *  - result interpretation: {@link trimTest}, {@link parseFailure},
 *    {@link servedCert} and {@link classifyTest}, which yields the CLI's six
 *    verdicts (UPDATED, NEEDS_UPDATE, NOT_HOSTED, TLS_ERROR, TIMEOUT, CLOSED);
 *  - identity is the leaf's SHA-256 fingerprint. Name coverage is computed from
 *    `subject.alt` (the CN only when there is no DNS SAN), never from
 *    `tls.error`: that field holds one code and chain errors mask name errors.
 *    Serials are compared without leading zeros and displayed byte-aligned, as
 *    x509.serialHex and the CLI print them (no "00" sign byte is re-added);
 *  - rules over rows: the CLI `works` rule ({@link applyWorksRule}), the CLI
 *    `server_status()` roll-up ({@link serverStatus}), the exposure of proxied
 *    origins ({@link exposureOf}) and the "Check again" set ({@link recheckRows});
 *  - pairs from a ScanResult ({@link buildVerifyPairs}), the queue runner
 *    ({@link runVerify}), the summary and headline ({@link summarizeVerify},
 *    {@link verifyHeadline}), CLI-compatible exports and the CLI plan for what
 *    the internet cannot check ({@link cliPlan}).
 *
 * Nothing here sends anything by itself: {@link runVerify} only drives the
 * client it is given, and only for rows in state 'pending'. A re-check keeps a
 * row's last verdict (marked `stale`) until a new measurement replaces it, so a
 * stopped or quota-limited re-check never makes a server look "live".
 */

import {
  httpsCheckRequest, isProbeableIP, isProbeableHost, isProbeablePort, probeSummary, GlobalpingError
} from './globalping.js';
import { certCovers, sortHostnames } from './domain.js';
import { isPrivateIP, matchProviderByIP, normalizeIP, parseIP } from './netinfo.js';
import { computeFingerprints } from './x509.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies (frozen; the i18n coverage test derives keys from them)      */
/* ------------------------------------------------------------------------ */

/** The CLI's STATUSES, in the CLI's order. */
export const VERIFY_STATUSES = Object.freeze(['UPDATED', 'NEEDS_UPDATE', 'NOT_HOSTED', 'TLS_ERROR', 'TIMEOUT', 'CLOSED']);
/** Why a verdict was given (`vfy.reason.<reason>`). */
export const VERIFY_REASONS = Object.freeze(['new-cert', 'old-cert', 'no-new-cert', 'not-covered', 'unrecognized-name',
  'refused-name', 'sni-refused', 'tls-alert', 'reset', 'not-tls', 'tls-failed', 'connect-timeout', 'tls-timeout',
  'refused', 'unreachable']);
/** `row.error.code` of a row in state 'error' — never a server verdict. */
export const VERIFY_ERRORS = Object.freeze(['dns', 'private', 'probe', 'offline', 'no-probes', 'validation', 'deadline',
  'server', 'network', 'bad-response', 'poll-rate', 'unknown']);
/** Per-row warnings (`vfy.warn.<code>`). */
export const VERIFY_WARNINGS = Object.freeze(['chain-incomplete', 'expired', 'not-yet-valid', 'self-signed',
  'untrusted-root', 'untrusted', 'name-mismatch', 'same-key', 'http-421', 'mixed', 'origin-ca']);
/** Row life cycle. */
export const VERIFY_STATES = Object.freeze(['skipped', 'pending', 'running', 'done', 'error', 'not-run']);
/** Why a pair is listed but never sent. */
export const SKIP_REASONS = Object.freeze(['private', 'reserved', 'cdn-edge', 'bad-name', 'bad-port', 'over-cap']);
/** Why a pending row did not run. 'optional': an origin pair (hint or zone) while the origin opt-in is off. */
export const NOT_RUN_REASONS = Object.freeze(['quota', 'budget', 'cancelled', 'unreachable', 'optional']);
/**
 * P0.2 exposure of a proxied origin pair. 'filtered' needs ≥ 2 probes from
 * different ASNs that all got no TCP answer; one probe's silence is 'no-answer'.
 */
export const EXPOSURES = Object.freeze(['exposed', 'filtered', 'no-answer', 'closed', 'not-this-host', 'unknown']);
/** {@link parseFailure} kinds. */
export const FAILURE_KINDS = Object.freeze(['refused', 'unreachable', 'connect-timeout', 'tls-timeout', 'tls-alert',
  'reset', 'not-tls', 'dns', 'private', 'internal', 'offline', 'unknown']);
/** `vfy.head.<key>` entries {@link verifyHeadline} can return. */
export const HEADLINE_KEYS = Object.freeze(['all', 'some', 'partial', 'none', 'noAnswer', 'incomplete', 'chain',
  'tlsError', 'unreachable', 'other', 'exposed', 'filtered', 'notHere']);
/** `vfy.notHere.<key>` parts of the not-checkable line ({@link notHereParts}). */
export const NOT_HERE_KEYS = Object.freeze([...SKIP_REASONS, 'proxied', 'managed']);

export const VERIFY_PORT = 443;
export const VERIFY_TIMEOUT_S = 10;
export const VERIFY_CONCURRENCY = 4;
export const VERIFY_MAX_ROWS = 500;
export const VERIFY_MAX_RETRIES = 5;
export const VERIFY_SOFT_CONFIRM_PROBES = 50;
/** A paid but unfinished measurement is polled again (free) only within this window… */
export const VERIFY_REUSE_WINDOW_MS = 120000;
/** …and at most this many times; afterwards a new measurement is created. */
export const VERIFY_MAX_REUSE = 1;

const CERT_RANK = { NEEDS_UPDATE: 3, NOT_HOSTED: 2, UPDATED: 1 };
const FAIL_RANK = { NOT_HOSTED: 4, TLS_ERROR: 3, TIMEOUT: 2, CLOSED: 1 };
const CHAIN_ERRORS = new Set(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT']);
const KNOWN_TLS_ERRORS = new Set([...CHAIN_ERRORS, 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID', 'DEPTH_ZERO_SELF_SIGNED_CERT',
  'SELF_SIGNED_CERT_IN_CHAIN', 'ERR_TLS_CERT_ALTNAME_INVALID']);
const ORIGIN_CA_REPLACES = new Set(['chain-incomplete', 'untrusted', 'untrusted-root']);
const RECHECK_WARNINGS = new Set(['chain-incomplete', 'http-421', 'mixed']);
const EXPECTED_ORIGIN = new Set(['filtered', 'no-answer', 'closed']);
const PROBE_FAULTS = new Set(['probe', 'offline']);
/** TLS alert 120 (no_application_protocol) is an ALPN mismatch, not a name refusal: kept out of the works rule. */
const ALPN_ALERT = 120;
const DAY_MS = 86400000;

/**
 * @typedef {{ sha256: string[], spkiHex: string[], hostnames: string[], subjectCN: string|null, notAfter: Date|null }} Expectation
 * @typedef {{ sha256: string, serialHex: string, subjectCN: string|null, dnsNames: string[], ipAddresses: string[],
 *   hostnames: string[], issuerCN: string|null, issuerO: string|null, notBefore: Date|null, notAfter: Date|null,
 *   keyType: string|null, keyBits: number|null, protocol: string|null, cipher: string|null, authorized: boolean,
 *   error: string|null, publicKeyHex: string|null }} ServedCert  publicKeyHex stays in memory, never exported
 * @typedef {{ probe: object, status: string, failureSource: string|null, resolvedAddress: string|null,
 *   statusCode: number|null, timings: { total: number|null, tcp: number|null, tls: number|null }|null,
 *   tls: object|null, publicKeyHex: string|null, rawOutput: string|null }} TrimmedTest
 * @typedef {{ status: string|null, reason: string|null, error: string|null, served: ServedCert|null,
 *   coveredBy: string|null, sameKey: boolean|null, warnings: string[], httpStatus: number|null,
 *   tlsError: string|null, alert: number|null, detail: string|null, probe: object, resolvedAddress: string|null }} ProbeVerdict
 * @typedef {ProbeVerdict & { agreement: 'all'|'mixed', probes: ProbeVerdict[] }} Verdict
 * @typedef {{ key: string, ip: string, port: number, name: string, server: { id: string, name: string }|null,
 *   alsoServers: Array<{ id: string, name: string }>, via: 'dns'|'zone'|'hint', proxied: boolean,
 *   provider: string|null, needsCert: boolean, newCertCovers: boolean|null, skip: string|null }} VerifyPair
 * @typedef {VerifyPair & { state: string, notRun: string|null, verdict: Verdict|null, status: string|null,
 *   reason: string|null, warnings: string[], exposure: string|null, served: ServedCert|null, httpStatus: number|null,
 *   tests: TrimmedTest[], measurementId: string|null, measurementDone: boolean, measurementAt: number|null,
 *   reuseAttempts: number, cost: number, retries: number, checkedAt: Date|null, stale: boolean,
 *   error: { code: string, message: string, raw: string|null }|null }} VerifyRow
 */

/* ------------------------------------------------------------------------ */
/* Small helpers                                                             */
/* ------------------------------------------------------------------------ */

/**
 * Hex digits only, lowercase: `'A5:9E:BD'` → `'a59ebd'`. Used for fingerprints,
 * public keys and serials.
 * @param {unknown} s
 * @returns {string}
 */
export const hexKey = (s) => String(s ?? '').replace(/[^0-9a-f]/gi, '').toLowerCase();

/**
 * Serial COMPARISON key: hex without any leading zeros (`'00:07'` → `'7'`,
 * `'00'` → `'0'`). Apply to both sides; never re-add a `00` sign byte.
 * @param {unknown} s
 * @returns {string}
 */
export const serialKey = (s) => hexKey(s).replace(/^0+(?=.)/, '');

/**
 * Serial DISPLAY form, byte-aligned like x509.serialHex and the CLI's
 * serial_hex: leading `00` bytes stripped, the last byte always kept
 * (`'06:5B:E1'` → `'065be1'`, `'07'` → `'07'`, `'00:A5'` → `'a5'`).
 * @param {unknown} s
 * @returns {string}
 */
export const serialDisplay = (s) => hexKey(s).replace(/^(?:00)+(?=[0-9a-f]{2})/, '');

const first = (v) => (Array.isArray(v) ? v[0] : v);
const strOrNull = (v) => {
  const x = first(v);
  return x === null || x === undefined || x === '' ? null : String(x);
};
const toDate = (v) => {
  if (v === null || v === undefined || v === '') return null;
  const d = v instanceof Date ? new Date(v.getTime()) : new Date(v);
  return Number.isNaN(d.getTime()) ? null : d;
};
const isoOrNull = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString() : null);
const toHex = (bytes) => Array.from(bytes || [], (b) => b.toString(16).padStart(2, '0')).join('');
const nowMs = (now) => (now instanceof Date ? now.getTime() : Number(now));
const isDnsLike = (via) => via !== 'hint';
const serverKeyOf = (row) => (row.server ? `s:${row.server.id}` : `ip:${row.ip}`);

/** Lowercase, strip trailing dots, IDN → punycode (x509's private normalizeCertHostname). */
function normalizeCertHostname(name) {
  let h = String(name).trim().toLowerCase().replace(/\.+$/, '');
  if (/[^\x00-\x7f]/.test(h)) {
    const wildcard = h.startsWith('*.');
    try {
      const host = new URL(`http://${wildcard ? h.slice(2) : h}/`).hostname;
      h = (wildcard ? '*.' : '') + host;
    } catch {
      /* keep the lowercase form */
    }
  }
  return h;
}

const CERT_LABEL_RE = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;

/** x509's private isHostnameLike: "legacy.example.org" / "*.example.org" yes; "Test Root CA", IPs, single labels no. */
function isHostnameLike(h) {
  if (!h || h.length > 253) return false;
  const labels = h.split('.');
  if (labels.length < 2) return false;
  if (labels[0] === '*') labels.shift();
  if (labels.length < 2 || !labels.every((l) => CERT_LABEL_RE.test(l))) return false;
  return /[a-z]/.test(labels[labels.length - 1]);
}

/** Numeric IP ordering: IPv4 before IPv6, then by value; unparsable last (as text). */
function compareIp(a, b) {
  const x = parseIP(a);
  const y = parseIP(b);
  if (x && y) {
    if (x.version !== y.version) return x.version - y.version;
    return x.value < y.value ? -1 : x.value > y.value ? 1 : 0;
  }
  if (x) return -1;
  if (y) return 1;
  return String(a).localeCompare(String(b));
}

function isGpError(err) {
  return !!err && typeof err === 'object'
    && ((typeof GlobalpingError === 'function' && err instanceof GlobalpingError) || err.name === 'GlobalpingError')
    && typeof err.code === 'string';
}

/* ------------------------------------------------------------------------ */
/* Result interpretation                                                     */
/* ------------------------------------------------------------------------ */

const ALT_RE = /(?:^|,\s*)(DNS|IP Address|email|URI|DirName|Registered ID|othername):("(?:[^"\\]|\\.)*"|[^,]*)/g;

/**
 * Split Node's `subjectaltname` string (Globalping `tls.subject.alt`). Values
 * Node JSON-quoted (they contain `,` or `"`) are JSON-parsed. IP entries are
 * normalised (Node prints IPv6 uncompressed; this returns RFC 5952).
 * @param {unknown} alt e.g. `'DNS:a.example, IP Address:1.1.1.1'`
 * @returns {{ dns: string[], ip: string[], other: string[] }} `other` entries keep their `type:` prefix
 */
export function parseAltNames(alt) {
  const out = { dns: [], ip: [], other: [] };
  if (typeof alt !== 'string' || !alt) return out;
  for (const m of alt.matchAll(ALT_RE)) {
    const type = m[1];
    let value = m[2].trim();
    if (value.startsWith('"')) {
      try {
        value = JSON.parse(value);
      } catch {
        value = value.slice(1, -1);
      }
    }
    if (type === 'DNS') out.dns.push(value);
    else if (type === 'IP Address') out.ip.push(normalizeIP(value) ?? value);
    else out.other.push(`${type}:${value}`);
  }
  return out;
}

/**
 * The served leaf as the app models it, from a Globalping `result.tls`.
 * `hostnames` follows x509.js: the DNS SANs normalised (SAN entries are not
 * filtered by hostname-likeness), or `[CN]` only when there is no DNS SAN and
 * the CN looks like a host name.
 * @param {object|null|undefined} tls
 * @returns {ServedCert|null} null without a fingerprint256
 */
export function servedCert(tls) {
  if (!tls || typeof tls !== 'object' || !tls.fingerprint256) return null;
  const subject = tls.subject && typeof tls.subject === 'object' ? tls.subject : {};
  const issuer = tls.issuer && typeof tls.issuer === 'object' ? tls.issuer : {};
  const alt = parseAltNames(first(subject.alt));
  const subjectCN = strOrNull(subject.CN);
  const hostnames = new Set();
  for (const n of alt.dns) {
    const h = normalizeCertHostname(n);
    if (h) hostnames.add(h);
  }
  if (!hostnames.size && subjectCN) {
    const cn = normalizeCertHostname(subjectCN);
    if (isHostnameLike(cn)) hostnames.add(cn);
  }
  const keyBits = Number.isFinite(tls.keyBits) ? tls.keyBits : null;
  return {
    sha256: hexKey(tls.fingerprint256),
    serialHex: serialDisplay(tls.serialNumber),
    subjectCN,
    dnsNames: alt.dns,
    ipAddresses: alt.ip,
    hostnames: [...hostnames],
    issuerCN: strOrNull(issuer.CN),
    issuerO: strOrNull(issuer.O),
    notBefore: toDate(tls.createdAt),
    notAfter: toDate(tls.expiresAt),
    keyType: strOrNull(tls.keyType),
    keyBits,
    protocol: strOrNull(tls.protocol),
    cipher: strOrNull(tls.cipherName),
    authorized: !!tls.authorized,
    error: strOrNull(tls.error),
    publicKeyHex: tls.publicKey ? hexKey(tls.publicKey) || null : null
  };
}

const FAILURE_PATTERNS = [
  [/Private IP ranges/i, 'private'],
  [/ENOTFOUND|ENODATA|queryA|EAI_AGAIN/, 'dns'],
  [/ECONNREFUSED/, 'refused'],
  [/EHOSTUNREACH|ENETUNREACH/, 'unreachable'],
  [/timed out while establishing the TCP connection/i, 'connect-timeout'],
  [/timed out/i, 'tls-timeout'],
  [/alert number (\d+)/, 'tls-alert'],
  // A reset, or the server closing mid-handshake (HAProxy strict-sni, Envoy without a matching
  // filter chain): Node reports the graceful close as "Client network socket disconnected before
  // secure TLS connection was established", OpenSSL 3 as "unexpected eof while reading". The CLI
  // treats both (ConnectionResetError, ssl.SSLEOFError) as a refusal.
  [/ECONNRESET|socket hang up|EPIPE|socket disconnected before secure TLS|unexpected eof/i, 'reset'],
  [/wrong version number|packet length too long|unknown protocol/i, 'not-tls']
];

/**
 * Classify a failed test from its (unstructured) `rawOutput`. Globalping says
 * rawOutput is "not meant to be parsed", so the patterns are tolerant; the
 * first match wins and anything else is 'unknown'.
 * @param {object} result a Globalping test `result` (or a TrimmedTest)
 * @returns {{ kind: string, alert: number|null, text: string }} text = first line, ≤ 200 chars
 */
export function parseFailure(result) {
  const r = result && typeof result === 'object' ? result : {};
  const raw = typeof r.rawOutput === 'string' ? r.rawOutput : '';
  const text = (raw.split(/\r?\n/).find((l) => l.trim()) ?? '').trim().slice(0, 200);
  if (r.status === 'offline') return { kind: 'offline', alert: null, text };
  if (r.failureSource === 'internal') return { kind: 'internal', alert: null, text };
  for (const [re, kind] of FAILURE_PATTERNS) {
    const m = raw.match(re);
    if (m) return { kind, alert: kind === 'tls-alert' ? Number(m[1]) : null, text };
  }
  return { kind: 'unknown', alert: null, text };
}

const isTrimmed = (test) => !!test && typeof test === 'object' && !('result' in test) && 'publicKeyHex' in test;

/**
 * Keep only what the app needs from one Globalping test (`{ probe, result }`):
 * no response headers, raw headers or body; `tls.publicKey` moves to the
 * in-memory-only `publicKeyHex`; `rawOutput` is kept for failed tests only
 * (≤ 300 chars). An already trimmed test is returned as is.
 * @param {{ probe?: object, result?: object }} test
 * @returns {TrimmedTest}
 */
export function trimTest(test) {
  if (isTrimmed(test)) return test;
  const t = test && typeof test === 'object' ? test : {};
  const r = t.result && typeof t.result === 'object' ? t.result : {};
  let tls = null;
  let publicKeyHex = null;
  if (r.tls && typeof r.tls === 'object') {
    const { publicKey, ...rest } = r.tls;
    tls = JSON.parse(JSON.stringify(rest));
    publicKeyHex = publicKey ? hexKey(publicKey) || null : null;
  }
  const tm = r.timings && typeof r.timings === 'object' ? r.timings : null;
  const num = (v) => (Number.isFinite(v) ? v : null);
  return {
    probe: probeSummary(t.probe && typeof t.probe === 'object' ? t.probe : {}),
    status: typeof r.status === 'string' ? r.status : 'failed',
    failureSource: typeof r.failureSource === 'string' ? r.failureSource : null,
    resolvedAddress: typeof r.resolvedAddress === 'string' ? r.resolvedAddress : null,
    statusCode: num(r.statusCode),
    timings: tm ? { total: num(tm.total), tcp: num(tm.tcp), tls: num(tm.tls) } : null,
    tls,
    publicKeyHex,
    rawOutput: r.status === 'failed' && typeof r.rawOutput === 'string' ? r.rawOutput.slice(0, 300) : null
  };
}

/**
 * What the loaded (new) certificate(s) look like to a probe: SHA-256
 * fingerprints (identity), SPKI DER hex (same-key hint) and the union of their
 * host names.
 * @param {object|object[]} certs x509 Certificate(s)
 * @param {{ subtle?: SubtleCrypto|null }} [opts] forwarded to computeFingerprints
 * @returns {Promise<Expectation>}
 */
export async function expectationFor(certs, { subtle } = {}) {
  const list = (Array.isArray(certs) ? certs : [certs]).filter((c) => c && c.der);
  const sha256 = [];
  const spkiHex = [];
  const hostnames = new Set();
  for (const c of list) {
    const fp = await computeFingerprints(c.der, subtle === undefined ? {} : { subtle });
    if (!sha256.includes(fp.sha256)) sha256.push(fp.sha256);
    const spki = c.spkiDer ? toHex(c.spkiDer) : '';
    if (spki && !spkiHex.includes(spki)) spkiHex.push(spki);
    for (const h of Array.isArray(c.hostnames) ? c.hostnames : []) hostnames.add(h);
  }
  return {
    sha256,
    spkiHex,
    hostnames: [...hostnames],
    subjectCN: list[0]?.subjectCN ?? null,
    notAfter: list[0]?.notAfter instanceof Date ? new Date(list[0].notAfter.getTime()) : null
  };
}

const ORIGIN_CA_ISSUER_O = /cloudflare/i;
const ORIGIN_CA_ISSUER_CN = /origin (ssl|ecc )?.*certificate authority/i;

function certWarnings(served, { covered, statusCode, nowTime }) {
  const w = new Set();
  const err = served.error;
  if (err) {
    if (CHAIN_ERRORS.has(err)) w.add('chain-incomplete');
    else if (err === 'CERT_HAS_EXPIRED') w.add('expired');
    else if (err === 'CERT_NOT_YET_VALID') w.add('not-yet-valid');
    else if (err === 'DEPTH_ZERO_SELF_SIGNED_CERT') w.add('self-signed');
    else if (err === 'SELF_SIGNED_CERT_IN_CHAIN') w.add('untrusted-root');
    else if (err === 'ERR_TLS_CERT_ALTNAME_INVALID') { if (covered) w.add('name-mismatch'); }
    else if (!KNOWN_TLS_ERRORS.has(err)) w.add('untrusted');
  }
  if (served.notAfter && served.notAfter.getTime() < nowTime) w.add('expired');
  if (served.notBefore && served.notBefore.getTime() > nowTime) w.add('not-yet-valid');
  // Unverified heuristic: a Cloudflare Origin CA leaf is trusted by Cloudflare only.
  if (ORIGIN_CA_ISSUER_O.test(served.issuerO ?? '') && ORIGIN_CA_ISSUER_CN.test(served.issuerCN ?? '')) {
    for (const x of ORIGIN_CA_REPLACES) w.delete(x);
    w.add('origin-ca');
  }
  if (statusCode === 421 && covered) w.add('http-421');
  return w;
}

const orderWarnings = (set) => VERIFY_WARNINGS.filter((w) => set.has(w));

/**
 * One probe's test → verdict, mirroring the CLI's `_verdict()` and
 * `classify_exception()`.
 * @param {object} test a raw `{ probe, result }` test or a {@link TrimmedTest}
 * @param {{ name: string, expect: Expectation|null, now?: number|Date }} opts
 *   `expect` null = no certificate loaded (NEEDS_UPDATE / no-new-cert, as the CLI without --cert)
 * @returns {ProbeVerdict}
 */
export function classifyTest(test, { name, expect = null, now = Date.now() } = {}) {
  const t = trimTest(test);
  const v = {
    status: null, reason: null, error: null, served: null, coveredBy: null, sameKey: null, warnings: [],
    httpStatus: t.statusCode, tlsError: null, alert: null, detail: null, probe: t.probe,
    resolvedAddress: t.resolvedAddress
  };
  const served = servedCert(t.tls ? { ...t.tls, publicKey: t.publicKeyHex } : null);
  if (served) {
    const cov = certCovers(served.hostnames, name);
    v.served = served;
    v.coveredBy = cov.by;
    v.tlsError = served.error;
    const sha = expect ? (Array.isArray(expect.sha256) ? expect.sha256 : []).map(hexKey) : [];
    if (expect) {
      const pk = served.publicKeyHex;
      v.sameKey = !!pk && pk.length >= 64
        && (Array.isArray(expect.spkiHex) ? expect.spkiHex : []).some((s) => hexKey(s).endsWith(pk));
    }
    if (!cov.covered) [v.status, v.reason] = ['NOT_HOSTED', 'not-covered'];
    else if (expect && sha.includes(served.sha256)) [v.status, v.reason] = ['UPDATED', 'new-cert'];
    else if (expect) [v.status, v.reason] = ['NEEDS_UPDATE', 'old-cert'];
    else [v.status, v.reason] = ['NEEDS_UPDATE', 'no-new-cert'];
    const w = certWarnings(served, { covered: cov.covered, statusCode: t.statusCode, nowTime: nowMs(now) });
    if (v.status === 'NEEDS_UPDATE' && v.sameKey) w.add('same-key');
    v.warnings = orderWarnings(w);
    return v;
  }
  if (t.status !== 'failed' && t.status !== 'offline') {
    // Finished without a usable certificate (tls without fingerprint256, or an
    // HTTP status but no tls): an old or odd probe — retry elsewhere.
    v.error = 'probe';
    v.detail = t.tls ? 'tls without fingerprint256' : `test ${t.status} without tls`;
    return v;
  }
  const f = parseFailure(t);
  v.detail = f.text || null;
  v.alert = f.alert;
  switch (f.kind) {
    case 'refused': [v.status, v.reason] = ['CLOSED', 'refused']; break;
    case 'unreachable': [v.status, v.reason] = ['CLOSED', 'unreachable']; break;
    case 'connect-timeout': [v.status, v.reason] = ['TIMEOUT', 'connect-timeout']; break;
    case 'tls-timeout': [v.status, v.reason] = ['TIMEOUT', 'tls-timeout']; break;
    case 'tls-alert':
      if (f.alert === 112) [v.status, v.reason] = ['NOT_HOSTED', 'unrecognized-name'];
      else if (f.alert === 40) [v.status, v.reason] = ['TLS_ERROR', 'sni-refused'];
      else [v.status, v.reason] = ['TLS_ERROR', 'tls-alert'];
      break;
    case 'reset': [v.status, v.reason] = ['TLS_ERROR', 'reset']; break;
    case 'not-tls': [v.status, v.reason] = ['TLS_ERROR', 'not-tls']; break;
    case 'dns': v.error = 'dns'; break;
    case 'private': v.error = 'private'; break;
    case 'internal': v.error = 'probe'; break;
    case 'offline': v.error = 'offline'; break;
    default: [v.status, v.reason] = ['TLS_ERROR', 'tls-failed'];
  }
  return v;
}

/**
 * Several probes on one pair → one verdict. The worst verdict that carries a
 * certificate wins (NEEDS_UPDATE > NOT_HOSTED > UPDATED), so a timeout on one
 * probe never hides a certificate another probe saw. Only when no probe got a
 * certificate does a failure win (NOT_HOSTED by alert > TLS_ERROR > TIMEOUT >
 * CLOSED). Warnings are the union; 'mixed' is added when statuses differ.
 * @param {ProbeVerdict[]} verdicts
 * @returns {Verdict|null} null for an empty list
 */
export function aggregateVerdicts(verdicts) {
  const list = Array.isArray(verdicts) ? verdicts.filter(Boolean) : [];
  if (!list.length) return null;
  const pick = (cands, rank) => cands.reduce((best, v) => ((rank[v.status] ?? 0) > (rank[best.status] ?? 0) ? v : best));
  const withCert = list.filter((v) => v.served && v.status);
  const withStatus = list.filter((v) => v.status);
  const chosen = withCert.length ? pick(withCert, CERT_RANK) : withStatus.length ? pick(withStatus, FAIL_RANK) : list[0];
  const warnings = new Set(list.flatMap((v) => v.warnings || []));
  const mixed = new Set(withStatus.map((v) => v.status)).size > 1;
  if (mixed) warnings.add('mixed');
  return { ...chosen, warnings: orderWarnings(warnings), agreement: mixed ? 'mixed' : 'all', probes: list };
}

/* ------------------------------------------------------------------------ */
/* Rules over rows                                                           */
/* ------------------------------------------------------------------------ */

const isRefusal = (v) => v && v.status === 'TLS_ERROR'
  && (v.reason === 'sni-refused' || v.reason === 'reset' || (v.reason === 'tls-alert' && v.alert !== ALPN_ALERT));

/**
 * The CLI `works` rule (cli `_verdict`): per ip|port, when some row's verdict
 * carries a certificate, every row whose verdict is a TLS refusal (alert 40,
 * another alert except ALPN's 120, or a reset / close during the handshake) becomes NOT_HOSTED /
 * refused-name. Recomputed from `row.verdict` every time, so it is idempotent
 * and reverts when a re-check changes the picture. Rows without a verdict get
 * status/reason null.
 * @param {VerifyRow[]} rows
 * @returns {VerifyRow[]} rows whose effective status or reason changed
 */
export function applyWorksRule(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const works = new Set();
  for (const r of list) if (r.verdict && r.verdict.served) works.add(`${r.ip}|${r.port}`);
  const changed = [];
  for (const r of list) {
    const v = r.verdict;
    let status = v ? v.status ?? null : null;
    let reason = v ? v.reason ?? null : null;
    if (v && isRefusal(v) && works.has(`${r.ip}|${r.port}`)) [status, reason] = ['NOT_HOSTED', 'refused-name'];
    if (r.status !== status || r.reason !== reason) {
      r.status = status;
      r.reason = reason;
      changed.push(r);
    }
  }
  return changed;
}

/** A row that answers for its server: it has a verdict (current, or kept while stale). */
const hasVerdict = (r) => !!(r && r.verdict && r.status);

/**
 * The roll-up status the CLI's `server_status()` gives, over one server's rows
 * that have a verdict (done, or stale with their last verdict):
 * NEEDS_UPDATE > UPDATED > TLS_ERROR > TIMEOUT (handshake) > NOT_HOSTED >
 * TIMEOUT (connect) > CLOSED. A NEEDS_UPDATE row the new certificate does not
 * cover (`newCertCovers === false`) counts as NOT_HOSTED, and so does one
 * serving a Cloudflare Origin CA certificate (`origin-ca`: hosted with its own
 * certificate on purpose, not "still old"; the row itself stays NEEDS_UPDATE).
 * Globalping's TCP-connect timeout is the CLI's connect-level TIMEOUT.
 * @param {VerifyRow[]} rows
 * @returns {string|null} null when no row has a verdict
 */
export function serverStatus(rows) {
  const named = new Set();
  let handshakeTimeout = false;
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!hasVerdict(r)) continue;
    let s = r.status;
    if (s === 'NEEDS_UPDATE' && (r.newCertCovers === false || (r.warnings || []).includes('origin-ca'))) s = 'NOT_HOSTED';
    if (s === 'TIMEOUT' && r.reason === 'tls-timeout') handshakeTimeout = true;
    named.add(s);
  }
  if (!named.size) return null;
  if (named.has('NEEDS_UPDATE')) return 'NEEDS_UPDATE';
  if (named.has('UPDATED')) return 'UPDATED';
  if (named.has('TLS_ERROR')) return 'TLS_ERROR';
  if (handshakeTimeout) return 'TIMEOUT';
  if (named.has('NOT_HOSTED')) return 'NOT_HOSTED';
  if (named.has('TIMEOUT')) return 'TIMEOUT';
  return 'CLOSED';
}

/**
 * P0.2 hook for a proxied pair (the origin IP with the proxied name), from its
 * last verdict's probes:
 * - any probe served a certificate covering the name → 'exposed' (whatever the
 *   HTTP status: a 403 over a valid certificate is still exposed);
 * - any probe says "not this name" (NOT_HOSTED, alert 40 / 112, or the row
 *   became refused-name through the works rule) → 'not-this-host';
 * - every probe got no TCP answer → 'filtered' with ≥ 2 probes from different
 *   ASNs, else 'no-answer' (one probe cannot tell a firewall from a geo-block);
 * - every probe was refused → 'closed';
 * - otherwise 'unknown'.
 * @param {VerifyRow} row
 * @returns {string|null} null when the row is not proxied or has no verdict
 */
export function exposureOf(row) {
  if (!row || !row.proxied || !row.verdict) return null;
  const probes = Array.isArray(row.verdict.probes) && row.verdict.probes.length ? row.verdict.probes : [row.verdict];
  if (probes.some((p) => p.served && certCovers(p.served.hostnames, row.name).covered)) return 'exposed';
  if (row.reason === 'refused-name' || probes.some((p) => p.status === 'NOT_HOSTED'
    || p.reason === 'sni-refused' || p.reason === 'unrecognized-name')) return 'not-this-host';
  if (!probes.every((p) => p.status)) return 'unknown';
  if (probes.every((p) => p.status === 'TIMEOUT' && p.reason === 'connect-timeout')) {
    const asns = new Set(probes.map((p) => p.probe?.asn).filter((a) => a !== null && a !== undefined));
    return probes.length >= 2 && asns.size >= 2 ? 'filtered' : 'no-answer';
  }
  if (probes.every((p) => p.status === 'CLOSED' && p.reason === 'refused')) return 'closed';
  return 'unknown';
}

/**
 * A proxied origin pair that behaves as it should behind a CDN, judged from
 * its current verdict (never the stored `exposure`, which a later works-rule
 * change could leave behind): filtered, no answer or closed; or, for an
 * origin-hint candidate (`via: 'hint'`), answering but not for the proxied
 * name — most general hints (SPF, MX, sibling) are simply not the origin.
 * Such rows are not problems, not re-checked and not counted against the base.
 * @param {VerifyRow} row
 * @returns {boolean}
 */
function isExpectedOrigin(row) {
  if (!row || !row.proxied) return false;
  const x = exposureOf(row);
  return EXPECTED_ORIGIN.has(x) || (row.via === 'hint' && x === 'not-this-host');
}

/**
 * Rows "Check again" re-runs: not skipped, not an origin pair left out by the
 * opt-in, and (not done, or not UPDATED, or UPDATED with chain-incomplete /
 * http-421 / mixed) — except proxied rows that behave as expected behind a
 * CDN: filtered, no-answer or closed, and origin-hint rows answering "not
 * this name" (re-probing them only burns quota).
 * @param {VerifyRow[]} rows
 * @returns {VerifyRow[]}
 */
export function recheckRows(rows) {
  return (Array.isArray(rows) ? rows : []).filter((r) => {
    if (r.state === 'skipped') return false;
    if (r.state === 'not-run' && r.notRun === 'optional' && !r.verdict) return false;
    if (isExpectedOrigin(r)) return false;
    if (r.state !== 'done' || r.status !== 'UPDATED') return true;
    return (r.warnings || []).some((w) => RECHECK_WARNINGS.has(w));
  });
}

/**
 * Put rows back in the queue for a re-check: state 'pending', keeping their
 * last verdict (marked `stale`) until a new measurement replaces it.
 * @param {VerifyRow[]} rows
 * @returns {VerifyRow[]} the same rows
 */
export function requeueRows(rows) {
  const list = Array.isArray(rows) ? rows : [];
  for (const r of list) {
    if (r.state === 'skipped') continue;
    r.state = 'pending';
    r.notRun = null;
    r.error = null;
    r.stale = !!r.verdict;
  }
  return list;
}

/**
 * An origin pair: an inventory origin IP with a proxied name it serves behind
 * the CDN, from an origin hint (`via: 'hint'`, a candidate) or the zone file
 * (`via: 'zone'`, that name's exact origin, which public DNS does not show).
 * Globalping keeps the result public by measurement id, so these pairs wait
 * for the origin opt-in. Verdict rules still treat a zone pair like a DNS one.
 * @param {VerifyPair|VerifyRow|null|undefined} p
 * @returns {boolean}
 */
export const isOriginPair = (p) => !!p && (p.via === 'hint' || p.via === 'zone');

/**
 * The origin opt-in: origin pairs ({@link isOriginPair}) run only when the
 * user asks. Switches never-checked origin rows between 'pending' (on) and
 * 'not-run: optional' (off).
 * @param {VerifyRow[]} rows
 * @param {boolean} enabled
 * @returns {VerifyRow[]} the rows that changed
 */
export function applyOriginOptIn(rows, enabled) {
  const changed = [];
  for (const r of Array.isArray(rows) ? rows : []) {
    if (!isOriginPair(r) || r.skip || r.verdict) continue;
    if (enabled && r.state === 'not-run' && r.notRun === 'optional') {
      r.state = 'pending';
      r.notRun = null;
      changed.push(r);
    } else if (!enabled && r.state === 'pending') {
      r.state = 'not-run';
      r.notRun = 'optional';
      changed.push(r);
    }
  }
  return changed;
}

/** A paid, unfinished measurement that may still be polled for free. */
function reusable(row, time) {
  return !!row.measurementId && !row.measurementDone && (row.reuseAttempts ?? 0) < VERIFY_MAX_REUSE
    && Number.isFinite(row.measurementAt) && time - row.measurementAt < VERIFY_REUSE_WINDOW_MS;
}

/**
 * Plan and cost preview for the plan line and the confirm dialog, over the
 * rows in state 'pending': `checks` must post a new measurement (× probes per
 * check = `probes`), `reuse` poll an already-paid one for free, `servers` is
 * how many servers they cover, `origins` how many of them are origin pairs
 * ({@link isOriginPair}). `optional` counts the origin pairs still waiting
 * for the opt-in.
 * @param {VerifyRow[]} rows
 * @param {{ probesPerCheck?: number, now?: number|Date }} [opts]
 * @returns {{ checks: number, reuse: number, probes: number, servers: number, origins: number, optional: number }}
 */
export function verifyCost(rows, { probesPerCheck = 1, now = Date.now() } = {}) {
  const time = nowMs(now);
  let checks = 0;
  let reuse = 0;
  let origins = 0;
  let optional = 0;
  const servers = new Set();
  for (const r of Array.isArray(rows) ? rows : []) {
    if (r.state === 'not-run' && r.notRun === 'optional') optional += 1;
    if (r.state !== 'pending') continue;
    if (reusable(r, time)) reuse += 1;
    else checks += 1;
    if (isOriginPair(r)) origins += 1;
    servers.add(serverKeyOf(r));
  }
  return { checks, reuse, probes: checks * probesPerCheck, servers: servers.size, origins, optional };
}

/* ------------------------------------------------------------------------ */
/* Pairs from a ScanResult                                                   */
/* ------------------------------------------------------------------------ */

function skipReason(ip, name, port) {
  if (isPrivateIP(ip)) return 'private';
  if (!isProbeableIP(ip)) return 'reserved';
  if (matchProviderByIP(ip)?.hidesOrigin) return 'cdn-edge';
  if (!isProbeableHost(name)) return 'bad-name';
  if (!isProbeablePort(port)) return 'bad-port';
  return null;
}

/**
 * Every (public IP, host name) pair the scan ties to the certificate, in
 * execution order: server groups in scanner order (needs-cert, maybe, name),
 * inside a group DNS (and zone) matches before origin hints, then host name,
 * then IP; then unmatched direct IPs by IP. Names the new certificate does not
 * cover and wildcard suspects are left out. Duplicate `ip|port|name` keys keep
 * the first (server-attributed) pair; another inventory server listing the
 * same IP (a shared VIP) is kept in `alsoServers`. Pairs that cannot be sent
 * are listed with `skip`. Every pair is returned: the cap on checks depends on
 * the scope, so {@link createVerifyRows} applies it after {@link scopePairs}.
 * @param {object} result ScanResult
 * @param {{ port?: number }} [opts]
 * @returns {{ pairs: VerifyPair[], stats: object }}
 */
export function buildVerifyPairs(result, { port = VERIFY_PORT } = {}) {
  const r = result && typeof result === 'object' ? result : {};
  const hostList = Array.isArray(r.hosts) ? r.hosts : [];
  const byName = new Map(hostList.map((x) => [x.name, x]));
  const all = [];
  const byKey = new Map();
  const add = (pair) => {
    const prev = byKey.get(pair.key);
    if (prev) {
      if (pair.server && (!prev.server || prev.server.id !== pair.server.id)
        && !prev.alsoServers.some((s) => s.id === pair.server.id)) prev.alsoServers.push(pair.server);
      return;
    }
    byKey.set(pair.key, pair);
    all.push(pair);
  };
  const pairFor = ({ ip: rawIp, name, server, via, needsCert, covered, host }) => {
    const ip = normalizeIP(rawIp) ?? String(rawIp);
    const cls = host?.classification ?? {};
    return {
      key: `${ip}|${port}|${name}`, ip, port, name, server, alsoServers: [], via,
      proxied: !!cls.hidesOrigin, provider: cls.provider?.name ?? null,
      needsCert: !!needsCert, newCertCovers: covered === true ? true : covered === false ? false : null,
      skip: skipReason(ip, name, port)
    };
  };

  for (const g of Array.isArray(r.servers) ? r.servers : []) {
    const server = g?.server ? { id: String(g.server.id ?? g.server.name ?? ''), name: String(g.server.name ?? g.server.id ?? '') } : null;
    const entries = (Array.isArray(g?.hosts) ? g.hosts : []).filter((e) => {
      if (!e || e.covered === false) return false;
      return !byName.get(e.name)?.wildcardSuspect;
    });
    const order = new Map(sortHostnames([...new Set(entries.map((e) => e.name))]).map((n, i) => [n, i]));
    entries.sort((a, b) => Number(!isDnsLike(a.via)) - Number(!isDnsLike(b.via))
      || order.get(a.name) - order.get(b.name) || compareIp(a.ip, b.ip));
    for (const e of entries) {
      add(pairFor({ ip: e.ip, name: e.name, server, via: e.via === 'hint' || e.via === 'zone' ? e.via : 'dns',
        needsCert: g.needsCert, covered: e.covered ?? null, host: byName.get(e.name) }));
    }
  }
  const unmatched = (Array.isArray(r.unmatchedIps) ? r.unmatchedIps : []).slice().sort((a, b) => compareIp(a.ip, b.ip));
  for (const u of unmatched) {
    for (const name of sortHostnames(Array.isArray(u.hosts) ? u.hosts : [])) {
      const host = byName.get(name);
      if (host?.wildcardSuspect) continue;
      const covered = host?.cert ? host.cert.covered : null;
      if (covered === false) continue;
      add(pairFor({ ip: u.ip, name, server: null, via: 'dns', needsCert: true, covered, host }));
    }
  }

  const pairs = all;
  // 'over-cap' is not a property of a pair: createVerifyRows() decides it for the scope's rows.
  const skipped = Object.fromEntries(SKIP_REASONS.filter((k) => k !== 'over-cap').map((k) => [k, 0]));
  for (const p of pairs) if (p.skip) skipped[p.skip] += 1;
  const checkable = pairs.filter((p) => !p.skip);
  const pairNames = new Set(pairs.map((p) => p.name));
  const noPair = (h) => h && !h.wildcardSuspect && h.cert && h.cert.covered === true && !pairNames.has(h.name);
  const stats = {
    names: new Set(pairs.map((p) => p.name)).size,
    ips: new Set(pairs.map((p) => p.ip)).size,
    servers: new Set(checkable.map((p) => (p.server ? `s:${p.server.id}` : `ip:${p.ip}`))).size,
    checkable: checkable.length,
    originPairs: checkable.filter(isOriginPair).length,
    skipped,
    proxiedNoOrigin: hostList.filter((h) => noPair(h) && h.classification?.hidesOrigin).length,
    managed: hostList.filter((h) => noPair(h) && !h.classification?.hidesOrigin && h.classification?.certManagedByProvider).length
  };
  return { pairs, stats };
}

/**
 * Narrow the pairs: 'all' keeps every pair; 'perIp' keeps, per IP, the first
 * DNS pair and the first origin pair — zone before hint — (so the exposure
 * check on that IP survives, and an origin pair waiting for the opt-in never
 * displaces the DNS pair). Skipped pairs are always kept.
 * @param {VerifyPair[]} pairs
 * @param {'all'|'perIp'} scope
 * @returns {VerifyPair[]}
 */
export function scopePairs(pairs, scope) {
  const list = Array.isArray(pairs) ? pairs : [];
  if (scope !== 'perIp') return list.slice();
  const seen = new Set();
  return list.filter((p) => {
    if (p.skip) return true;
    const k = `${p.ip}|${p.port}|${isOriginPair(p) ? 'origin' : 'dns'}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * The pairs past a cap of `maxRows` checks. Skipped pairs cost nothing; the
 * others take the places in this order, each tier in execution order: the
 * first DNS pair of every server address, the other DNS pairs, the first
 * origin pair of every server address, the other origin pairs. So a server
 * with many names never pushes another server out, and an origin pair (it may
 * wait for the opt-in) never pushes out a DNS pair.
 * @param {VerifyPair[]} pairs
 * @param {number} maxRows
 * @returns {Set<VerifyPair>}
 */
function pairsOverCap(pairs, maxRows) {
  const cap = Number.isFinite(maxRows) && maxRows >= 0 ? Math.floor(maxRows) : Infinity;
  const checkable = pairs.filter((p) => !p.skip);
  if (checkable.length <= cap) return new Set();
  const seen = new Set();
  const ranked = checkable.map((p, i) => {
    const origin = isOriginPair(p);
    const k = `${origin ? 'origin' : 'dns'}|${p.server ? `s:${p.server.id}` : ''}|${p.ip}|${p.port}`;
    const tier = (origin ? 2 : 0) + (seen.has(k) ? 1 : 0);
    seen.add(k);
    return { p, i, tier };
  });
  ranked.sort((a, b) => a.tier - b.tier || a.i - b.i);
  return new Set(ranked.slice(cap).map((x) => x.p));
}

/**
 * Fresh rows for the pairs (apply {@link scopePairs} first): skipped pairs →
 * 'skipped'; pairs past the cap of `maxRows` checks (see pairsOverCap) →
 * 'skipped' as 'over-cap', listed for the CLI; origin pairs (hint or zone,
 * {@link isOriginPair}) → 'not-run: optional' unless `origins` is on; the
 * rest → 'pending'.
 * @param {VerifyPair[]} pairs
 * @param {{ origins?: boolean, maxRows?: number }} [opts]
 * @returns {VerifyRow[]}
 */
export function createVerifyRows(pairs, { origins = false, maxRows = VERIFY_MAX_ROWS } = {}) {
  const list = Array.isArray(pairs) ? pairs : [];
  const over = pairsOverCap(list, maxRows);
  return list.map((p) => {
    const skip = p.skip || (over.has(p) ? 'over-cap' : null);
    const optional = !skip && isOriginPair(p) && !origins;
    return {
      ...p,
      skip,
      alsoServers: Array.isArray(p.alsoServers) ? p.alsoServers.map((s) => ({ ...s })) : [],
      state: skip ? 'skipped' : optional ? 'not-run' : 'pending',
      notRun: optional ? 'optional' : null,
      verdict: null, status: null, reason: null, warnings: [], exposure: null, served: null, httpStatus: null,
      tests: [], measurementId: null, measurementDone: false, measurementAt: null, reuseAttempts: 0,
      cost: 0, retries: 0, checkedAt: null, stale: false, error: null
    };
  });
}

/* ------------------------------------------------------------------------ */
/* Runner                                                                    */
/* ------------------------------------------------------------------------ */

const mapErrorCode = (code) => (VERIFY_ERRORS.includes(code) ? code : 'unknown');

/**
 * Run every row in state 'pending' (callers set rows back to 'pending' — see
 * {@link requeueRows} — to re-check). Rows are mutated IN PLACE (a DataTable
 * updates them by identity) and every transition is reported through `onRow`.
 *
 * - A paid but unfinished measurement (Stop, deadline) is polled again for free
 *   first — at most once and within 2 minutes of its creation — before any new
 *   measurement is posted.
 * - The probe budget is reserved synchronously before each POST, so
 *   concurrent workers never overspend `maxProbes`.
 * - Only probe-side faults (internal, offline, empty or odd results) are
 *   retried, with a fresh probe, at most `maxRetries` times per run. TIMEOUT is
 *   never retried automatically.
 * - A 429 quota answer stops the queue ('quota'); three network failures in a
 *   row stop it ('unreachable'); the rest of the queue becomes 'not-run'.
 * - A re-check keeps the row's last verdict (stale) when it ends without a new
 *   one (error, not-run), so the roll-up never forgets an old certificate.
 *
 * @param {VerifyRow[]} rows
 * @param {object} opts
 * @param {object} opts.client createGlobalping() instance (create, poll, quota)
 * @param {Expectation|null} opts.expect
 * @param {AbortSignal} [opts.signal]
 * @param {number} [opts.concurrency=4]
 * @param {number} [opts.timeoutS=10]
 * @param {number} [opts.probesPerCheck=1]
 * @param {((row: VerifyRow) => null|object[]|string)|null} [opts.locationsFor]
 * @param {number} [opts.maxProbes=Infinity] budget from the confirm dialog
 * @param {number} [opts.maxRetries=5]
 * @param {(row: VerifyRow) => void} [opts.onRow]
 * @param {(quota: object|null) => void} [opts.onQuota]
 * @param {() => number} [opts.now]
 * @returns {Promise<{ spent: number, retries: number, stoppedBy: null|'quota'|'budget'|'abort'|'unreachable' }>}
 */
export async function runVerify(rows, {
  client, expect = null, signal = null, concurrency = VERIFY_CONCURRENCY, timeoutS = VERIFY_TIMEOUT_S,
  probesPerCheck = 1, locationsFor = null, maxProbes = Infinity, maxRetries = VERIFY_MAX_RETRIES,
  onRow = () => {}, onQuota = () => {}, now = () => Date.now()
} = {}) {
  const list = Array.isArray(rows) ? rows : [];
  const emit = (row) => { try { onRow(row); } catch { /* a UI listener must not break the run */ } };
  const emitQuota = (q) => { try { onQuota(q ?? null); } catch { /* idem */ } };
  const startTime = now();
  const pending = list.filter((r) => r.state === 'pending');
  // Already-paid measurements first: they are polled for free.
  const queue = [...pending.filter((r) => reusable(r, startTime)), ...pending.filter((r) => !reusable(r, startTime))];
  let spent = 0;
  let reserved = 0;
  let retries = 0;
  let netErrors = 0;
  let stoppedBy = null;

  const setNotRun = (row, reason) => {
    row.state = 'not-run';
    row.notRun = reason;
    row.stale = !!row.verdict;
  };
  const fail = (row, code, message, raw = null) => {
    row.state = 'error';
    row.error = { code: mapErrorCode(code), message: String(message ?? '').slice(0, 300), raw };
    row.stale = !!row.verdict;
  };
  const skipAs = (row, reason) => {
    row.state = 'skipped';
    row.skip = reason;
    row.stale = false;
  };

  const handle = async (row) => {
    const time = now();
    let reuse = reusable(row, time);
    if (row.measurementId && !row.measurementDone && !reuse) {
      row.measurementId = null; // too old or already re-polled: post a new measurement
      row.reuseAttempts = 0;
    }
    let held = 0;
    if (!reuse) {
      if (spent + reserved + probesPerCheck > maxProbes) {
        stoppedBy = stoppedBy ?? 'budget';
        setNotRun(row, 'budget');
        return;
      }
      reserved += probesPerCheck;
      held = probesPerCheck;
    }
    row.state = 'running';
    row.notRun = null;
    row.error = null;
    row.stale = !!row.verdict;
    emit(row);
    try {
      let measurement = null;
      if (reuse) {
        row.reuseAttempts = (row.reuseAttempts ?? 0) + 1;
        try {
          const deadlineMs = (timeoutS + 10) * 1000;
          measurement = await client.poll(row.measurementId, { signal, deadlineMs, deadlineAt: now() + deadlineMs });
        } catch (err) {
          if (!(isGpError(err) && err.code === 'not-found')) throw err;
          reuse = false;
          row.measurementId = null;
          row.reuseAttempts = 0;
        }
        if (!reuse) {
          // The paid id is gone: fall back to a new measurement (budget permitting).
          if (spent + reserved + probesPerCheck > maxProbes) {
            stoppedBy = stoppedBy ?? 'budget';
            setNotRun(row, 'budget');
            return;
          }
          reserved += probesPerCheck;
          held = probesPerCheck;
        }
      }
      if (!reuse) {
        let body;
        try {
          body = httpsCheckRequest({ ip: row.ip, name: row.name, port: row.port, timeoutS, probes: probesPerCheck,
            locations: (typeof locationsFor === 'function' ? locationsFor(row) : null) ?? null });
        } catch (err) {
          if (!(err instanceof TypeError)) throw err;
          // Nothing was sent: give the reserved budget back before leaving.
          reserved -= held;
          held = 0;
          // Defensive: the prefilter already skips unprobeable targets, never send them. Any other
          // refusal (a location, probe count or timeout the body cannot carry) is not the pair's
          // fault: an error on this row, not a skip reason with a CLI route.
          const skip = !isProbeableIP(row.ip) ? 'reserved' : !isProbeableHost(row.name) ? 'bad-name'
            : !isProbeablePort(row.port) ? 'bad-port' : null;
          if (skip) skipAs(row, skip);
          else fail(row, 'validation', err.message);
          return;
        }
        const c = await client.create(body, { signal });
        const cost = Number.isFinite(c?.cost) ? c.cost : probesPerCheck;
        reserved -= held;
        held = 0;
        spent += cost;
        row.cost += cost;
        row.measurementId = c.id;
        row.measurementDone = false;
        row.measurementAt = now();
        row.reuseAttempts = 0;
        emit(row);
        const deadlineMs = ((body.timeout ?? timeoutS) + 10) * 1000;
        measurement = await client.poll(c.id, { signal, deadlineMs, deadlineAt: row.measurementAt + deadlineMs });
      }
      row.measurementDone = true;
      const results = Array.isArray(measurement?.results) ? measurement.results : [];
      const verdicts = results.map((t) => classifyTest(t, { name: row.name, expect, now: now() }));
      if (!verdicts.length || verdicts.every((v) => !v.status && PROBE_FAULTS.has(v.error))) {
        if (retries < maxRetries) {
          retries += 1;
          row.retries += 1;
          row.measurementId = null;
          row.state = 'pending';
          row.stale = !!row.verdict;
          emit(row);
          queue.unshift(row);
          return;
        }
      }
      const v = aggregateVerdicts(verdicts);
      const tests = results.map(trimTest);
      const checkedAt = toDate(measurement?.createdAt) ?? new Date(now());
      if (!v || v.status === null) {
        fail(row, v ? v.error ?? 'unknown' : 'probe', v ? v.detail ?? '' : 'no test results', v ? v.error ?? null : null);
        if (!row.verdict) {
          row.tests = tests;
          row.checkedAt = checkedAt;
          row.httpStatus = v ? v.httpStatus : null;
        }
      } else {
        row.verdict = v;
        row.tests = tests;
        row.checkedAt = checkedAt;
        row.served = v.served;
        row.httpStatus = v.httpStatus;
        row.warnings = v.warnings;
        row.state = 'done';
        row.stale = false;
        row.error = null;
      }
      // The works rule can change a sibling's status / reason, and its exposure depends on them:
      // refresh it before reporting the sibling, so the view and the exports never show a stale one.
      for (const r of applyWorksRule(list.filter((x) => x.ip === row.ip && x.port === row.port))) {
        r.exposure = exposureOf(r);
        if (r !== row) emit(r);
      }
      row.exposure = exposureOf(row);
      netErrors = 0;
    } catch (err) {
      reserved -= held;
      held = 0;
      const name = err && typeof err === 'object' ? err.name : '';
      if (name === 'AbortError' || signal?.aborted) {
        row.state = 'not-run';
        row.notRun = 'cancelled';
        row.stale = !!row.verdict;
      } else if (isGpError(err)) {
        if (err.code === 'rate-limit' || err.code === 'insufficient-credits') {
          stoppedBy = 'quota';
          row.state = 'not-run';
          row.notRun = 'quota';
          row.stale = !!row.verdict;
          emitQuota(err.quota ?? client?.quota ?? null);
        } else if (err.code === 'private-target') {
          skipAs(row, 'reserved');
        } else if (err.code === 'bad-host') {
          skipAs(row, 'bad-name');
        } else {
          fail(row, err.code, err.message, err.code);
        }
      } else if (name === 'TimeoutError' || err instanceof TypeError) {
        // A POST that timed out may already have been charged; no automatic retry.
        fail(row, 'network', err.message, name || 'TypeError');
        netErrors += 1;
        if (netErrors >= 3) stoppedBy = stoppedBy ?? 'unreachable';
      } else {
        fail(row, 'unknown', err && err.message, name || null);
      }
    }
  };

  const worker = async () => {
    while (queue.length) {
      const row = queue.shift();
      if (signal?.aborted) {
        setNotRun(row, 'cancelled');
        emit(row);
        continue;
      }
      if (stoppedBy && !(stoppedBy === 'budget' && reusable(row, now()))) {
        setNotRun(row, stoppedBy);
        emit(row);
        continue;
      }
      await handle(row);
      if (row.state === 'pending') continue; // queued again for a probe-fault retry (already reported)
      emit(row);
      emitQuota(client?.quota ?? null);
    }
  };
  const n = Math.max(1, Math.min(Number.isFinite(concurrency) ? Math.floor(concurrency) : VERIFY_CONCURRENCY, queue.length || 1));
  await Promise.all(Array.from({ length: n }, worker));
  return { spent, retries, stoppedBy: signal?.aborted ? 'abort' : stoppedBy };
}

/* ------------------------------------------------------------------------ */
/* Summary and headline                                                      */
/* ------------------------------------------------------------------------ */

const countBy = (items, keyFn) => {
  const out = {};
  for (const x of items) {
    const k = keyFn(x);
    if (k !== null && k !== undefined) out[k] = (out[k] ?? 0) + 1;
  }
  return out;
};

/**
 * Rows that speak for their server: not skipped, and not an origin pair the user left out. A
 * DNS pair past the cap speaks (never checked, it keeps its server from being called live); an
 * origin pair past it is left out like an optional one.
 */
const considered = (r) => (r.state !== 'skipped' || (r.skip === 'over-cap' && !isOriginPair(r)))
  && !(r.state === 'not-run' && r.notRun === 'optional' && !r.verdict);

/**
 * Counts for the headline, the tab badge and the exports. Servers are
 * `server.id` for inventory rows and the bare IP otherwise; a row whose IP
 * several inventory servers list (`alsoServers`) counts for each of them.
 *
 * servers: `total` (≥ 1 considered row), `checked` (a roll-up status),
 * `live` (UPDATED and complete), `updated` (UPDATED, complete or not),
 * `old` (NEEDS_UPDATE), `other` (NOT_HOSTED),
 * `tlsError`, `unreachable` (TIMEOUT / CLOSED),
 * `filteredOrigins` (complete, and every answering row is a proxied origin
 * that is filtered, no-answer or closed — the desired state),
 * `notHostingOrigins` (complete, every answering row behaves as expected
 * behind a CDN and at least one origin-hint candidate answers "not this
 * name"), `unchecked` (no verdict at all), `incomplete` (≥ 1 considered row
 * that never produced a verdict: pending, running, not-run, error; a DNS pair
 * past the cap also keeps its server from being live, but is not counted
 * here: "Check again" cannot finish it, the not-checkable line names it), `chain`
 * (≥ 1 UPDATED row with chain-incomplete), `wrongCert` (rolled up NOT_HOSTED
 * because a DNS-matched name gets another certificate or a refusal there:
 * visitors of that name get an error), `served` (a server in the base with
 * ≥ 1 row that returned a certificate), `base`
 * (= total − filteredOrigins − notHostingOrigins, the headline/badge
 * denominator), `list`.
 *
 * Origin rows that behave as expected (see isExpectedOrigin) never make a
 * server a problem: the roll-up of a server with other answering rows ignores
 * them, and a server with only such rows is counted in old / other /
 * tlsError / unreachable never. It leaves the base only once complete: a
 * server with a name still unchecked stays in the base, so the headline can
 * never call it live.
 *
 * @param {VerifyRow[]} rows
 * @returns {object}
 */
export function summarizeVerify(rows) {
  const list = Array.isArray(rows) ? rows : [];
  const skippedRows = list.filter((r) => r.state === 'skipped');
  const uniq = (items, fn) => new Set(items.map(fn)).size;
  const skippedUnits = {};
  for (const reason of SKIP_REASONS) {
    const of = skippedRows.filter((r) => r.skip === reason);
    if (!of.length) continue;
    skippedUnits[reason] = reason === 'bad-name' ? uniq(of, (r) => r.name)
      : reason === 'bad-port' || reason === 'over-cap' ? of.length : uniq(of, (r) => r.ip);
  }
  const rowStats = {
    total: list.length,
    byState: countBy(list, (r) => r.state),
    byStatus: countBy(list, (r) => (hasVerdict(r) ? r.status : null)),
    skippedBy: countBy(skippedRows, (r) => r.skip),
    skippedUnits,
    notRunBy: countBy(list.filter((r) => r.state === 'not-run'), (r) => r.notRun),
    errorsBy: countBy(list.filter((r) => r.state === 'error'), (r) => r.error?.code ?? 'unknown'),
    stale: list.filter((r) => r.stale).length
  };

  const groups = new Map();
  const groupFor = (key, label) => {
    let g = groups.get(key);
    if (!g) {
      g = { key, label, ips: [], rows: [] };
      groups.set(key, g);
    }
    return g;
  };
  for (const r of list.filter(considered)) {
    const owners = r.server ? [r.server, ...(r.alsoServers || [])] : [null];
    for (const s of owners) {
      const g = s ? groupFor(`s:${s.id}`, s.name) : groupFor(`ip:${r.ip}`, r.ip);
      g.rows.push(r);
      if (!g.ips.includes(r.ip)) g.ips.push(r.ip);
    }
  }
  const servers = { total: 0, checked: 0, live: 0, updated: 0, old: 0, other: 0, tlsError: 0, unreachable: 0,
    filteredOrigins: 0, notHostingOrigins: 0, unchecked: 0, incomplete: 0, chain: 0, wrongCert: 0, served: 0, base: 0,
    list: [] };
  let filteredDefinite = true;
  for (const g of groups.values()) {
    const answered = g.rows.filter(hasVerdict);
    const incomplete = g.rows.some((r) => !hasVerdict(r));
    const expectedOnly = answered.length > 0 && answered.every(isExpectedOrigin);
    const counted = expectedOnly ? answered : answered.filter((r) => !isExpectedOrigin(r));
    const status = serverStatus(counted);
    const filtered = expectedOnly && !incomplete && answered.every((r) => EXPECTED_ORIGIN.has(exposureOf(r)));
    const notHosting = expectedOnly && !incomplete && !filtered;
    servers.total += 1;
    if (status) servers.checked += 1;
    else servers.unchecked += 1;
    if (g.rows.some((r) => !hasVerdict(r) && r.skip !== 'over-cap')) servers.incomplete += 1;
    if (status === 'UPDATED') servers.updated += 1;
    if (status === 'UPDATED' && !incomplete) servers.live += 1;
    if (filtered) {
      servers.filteredOrigins += 1;
      if (answered.some((r) => exposureOf(r) === 'no-answer')) filteredDefinite = false;
    } else if (notHosting) {
      servers.notHostingOrigins += 1;
    } else if (!expectedOnly) {
      if (status === 'NEEDS_UPDATE') servers.old += 1;
      if (status === 'NOT_HOSTED') servers.other += 1;
      if (status === 'NOT_HOSTED' && counted.some((r) => isDnsLike(r.via) && r.status === 'NOT_HOSTED')) servers.wrongCert += 1;
      if (status === 'TLS_ERROR') servers.tlsError += 1;
      if (status === 'TIMEOUT' || status === 'CLOSED') servers.unreachable += 1;
    }
    if (!filtered && !notHosting && answered.some((r) => r.served)) servers.served += 1;
    if (g.rows.some((r) => r.status === 'UPDATED' && hasVerdict(r) && (r.warnings || []).includes('chain-incomplete'))) servers.chain += 1;
    servers.list.push({
      key: g.key.replace(/^(?:s|ip):/, ''), label: g.label, ips: g.ips, status, incomplete, filteredOrigin: filtered,
      notHostingOrigin: notHosting, rows: g.rows
    });
  }
  servers.base = servers.total - servers.filteredOrigins - servers.notHostingOrigins;
  const exposedRows = list.filter((r) => r.exposure === 'exposed');
  const warnings = {};
  for (const r of list) for (const w of r.warnings || []) warnings[w] = (warnings[w] ?? 0) + 1;
  return {
    rows: rowStats,
    servers,
    exposed: exposedRows.length,
    exposedServers: uniq(exposedRows, serverKeyOf),
    filteredDefinite,
    warnings,
    spent: list.reduce((s, r) => s + (Number.isFinite(r.cost) ? r.cost : 0), 0)
  };
}

/**
 * The parts of the not-checkable line (`vfy.notHere` / `vfy.head.notHere`):
 * i18n keys `vfy.notHere.<reason>` with `{ count }` — unique addresses for
 * private / reserved / CDN-edge, unique names for bad-name, checks otherwise
 * (bad-port, and over-cap for the rows of the current scope) — plus proxied
 * names without a known origin and provider-managed names.
 * The view joins them into the `{list}` placeholder.
 * @param {object} summary {@link summarizeVerify} result
 * @param {object} [stats] {@link buildVerifyPairs} stats
 * @returns {Array<{ key: string, params: { count: number } }>}
 */
export function notHereParts(summary, stats = null) {
  const units = summary?.rows?.skippedUnits ?? {};
  const parts = [];
  for (const reason of SKIP_REASONS) {
    const count = units[reason] ?? 0;
    if (count > 0) parts.push({ key: `vfy.notHere.${reason}`, params: { count } });
  }
  if (stats?.proxiedNoOrigin > 0) parts.push({ key: 'vfy.notHere.proxied', params: { count: stats.proxiedNoOrigin } });
  if (stats?.managed > 0) parts.push({ key: 'vfy.notHere.managed', params: { count: stats.managed } });
  return parts;
}

/**
 * The headline as i18n keys + params (views never build sentences from codes).
 * When at least one server was checked and base > 0 (base = servers.base =
 * total − filtered and not-hosting origins, so servers not checked yet count
 * as not live), the first entry is exactly one of — `updated` counts UPDATED
 * servers, complete or not, `live` only complete ones:
 * - all (ok): live === base && incomplete === 0 (every server checked,
 *   complete and live);
 * - some (warn): old > 0 && updated > 0, params { live, total, old };
 * - none (warn): updated === 0 && (old > 0 || wrongCert > 0), params { count }
 *   — a DNS-matched name served another certificate (or refused) is not
 *   serving the new one either;
 * - partial (info): updated > 0, or some server returned a certificate
 *   (e.g. its own Origin CA one), params { live, total };
 * - noAnswer (info): otherwise — no counted server returned a certificate.
 * Then, only when non-zero and in this order: incomplete (info), chain (warn),
 * tlsError (warn), unreachable (info), other (warn when a DNS-matched name is
 * not served — wrongCert — else info), exposed (warn), filtered (ok when
 * every filtered origin is definite, info for single-probe no-answer),
 * notHere (info; `parts` for the view's `{list}`). Every entry whose string
 * counts one thing carries `params.count`.
 * @param {object} summary {@link summarizeVerify} result
 * @param {object} [stats] {@link buildVerifyPairs} stats
 * @returns {Array<{ key: string, variant: 'ok'|'warn'|'info', params: object, parts?: object[] }>}
 */
export function verifyHeadline(summary, stats = null) {
  const s = summary?.servers ?? {};
  const out = [];
  const push = (k, variant, params = {}) => out.push({ key: `vfy.head.${k}`, variant, params });
  const base = s.base ?? 0;
  const updated = s.updated ?? s.live ?? 0;
  const wrongCert = s.wrongCert ?? 0;
  if (s.checked > 0 && base > 0) {
    if (s.live > 0 && s.live === base && !((s.incomplete ?? 0) > 0)) push('all', 'ok', { count: base });
    else if (s.old > 0 && updated > 0) push('some', 'warn', { live: s.live, total: base, old: s.old });
    else if (updated === 0 && (s.old > 0 || wrongCert > 0)) push('none', 'warn', { count: base });
    else if (updated > 0 || (s.served ?? 0) > 0) push('partial', 'info', { live: s.live, total: base });
    else push('noAnswer', 'info');
  }
  if (s.incomplete > 0 && s.checked > 0) push('incomplete', 'info', { count: s.incomplete });
  if (s.chain > 0) push('chain', 'warn', { count: s.chain });
  if (s.tlsError > 0) push('tlsError', 'warn', { count: s.tlsError });
  if (s.unreachable > 0) push('unreachable', 'info', { count: s.unreachable });
  if (s.other > 0) push('other', wrongCert > 0 ? 'warn' : 'info', { count: s.other });
  if (summary?.exposedServers > 0) push('exposed', 'warn', { count: summary.exposedServers });
  if (s.filteredOrigins > 0) push('filtered', summary.filteredDefinite ? 'ok' : 'info', { count: s.filteredOrigins });
  const parts = notHereParts(summary, stats);
  if (parts.length) out.push({ key: 'vfy.head.notHere', variant: 'info', params: {}, parts });
  return out;
}

/* ------------------------------------------------------------------------ */
/* Exports and the CLI plan                                                  */
/* ------------------------------------------------------------------------ */

/** CLI `issuer_label()`: "CN (O)" when O adds information. */
function issuerLabel(served) {
  if (!served) return null;
  const cn = served.issuerCN;
  const org = served.issuerO;
  if (cn && org && !cn.includes(org)) return `${cn} (${org})`;
  return cn || org || null;
}

function vantageText(p) {
  if (!p) return '';
  return [p.country, p.city, Number.isFinite(p.asn) ? `AS${p.asn}` : null].filter(Boolean).join(' ');
}

function errorText(row) {
  const v = row.verdict;
  const text = (v && (v.tlsError || v.detail)) || (row.error ? row.error.code : '') || row.skip
    || (row.notRun ? `not-run:${row.notRun}` : '') || '';
  return String(text).slice(0, 300) || null;
}

const statusOut = (row) => (hasVerdict(row) ? row.status : null);
/** Probe summaries behind the row: its tests, else its verdict's probes. */
const probesOf = (row) => {
  const fromTests = (row.tests || []).map((t) => t && t.probe).filter(Boolean);
  if (fromTests.length) return fromTests;
  return (row.verdict?.probes || []).map((p) => p && p.probe).filter(Boolean);
};
const daysLeft = (served, time) => (served?.notAfter ? Math.floor((served.notAfter.getTime() - time) / DAY_MS) : null);

/**
 * The CLI's 17 CSV_COLUMNS in CLI order (a unit test parses them out of
 * cli/ssl_origin_scan.py), then the web extras. For export.toCsv over
 * {@link verifyExportRows}.
 * @type {ReadonlyArray<{ key: string, header: string }>}
 */
export const VERIFY_CSV_COLUMNS = Object.freeze([
  'server', 'ip', 'port', 'probe', 'name', 'sni', 'status', 'covered_by', 'new_cert_covers', 'cert_subject_cn',
  'cert_issuer', 'cert_serial', 'cert_not_after', 'cert_days_left', 'cert_sha256', 'tls_version', 'error',
  // web extras
  'source', 'state', 'stale', 'skip', 'reason', 'warnings', 'exposure', 'via', 'http_status', 'vantage',
  'measurement_id', 'checked_at'
].map((key) => Object.freeze({ key, header: key })));

/**
 * Flat CSV rows (keys = {@link VERIFY_CSV_COLUMNS}). `status` is CLI
 * vocabulary only: empty for rows without a verdict (skipped, never checked,
 * error, not-run); `state` explains those. A stale row (re-check pending,
 * failed or not run) keeps its last verdict and says `stale: yes`.
 * @param {VerifyRow[]} rows
 * @param {{ now?: number|Date }} [opts]
 * @returns {object[]}
 */
export function verifyExportRows(rows, { now = Date.now() } = {}) {
  const time = nowMs(now);
  return (Array.isArray(rows) ? rows : []).map((r) => {
    const served = hasVerdict(r) ? r.served : null;
    const cov = r.newCertCovers;
    return {
      server: r.server?.name ?? r.ip,
      ip: r.ip,
      port: r.port,
      probe: 'sni',
      name: r.name,
      sni: r.name,
      status: statusOut(r) ?? '',
      covered_by: (hasVerdict(r) && r.verdict.coveredBy) || '',
      new_cert_covers: cov === true ? 'yes' : cov === false ? 'no' : '',
      cert_subject_cn: served?.subjectCN ?? '',
      cert_issuer: issuerLabel(served) ?? '',
      cert_serial: served?.serialHex ?? '',
      cert_not_after: isoOrNull(served?.notAfter) ?? '',
      cert_days_left: daysLeft(served, time) ?? '',
      cert_sha256: served?.sha256 ?? '',
      tls_version: served?.protocol ?? '',
      error: errorText(r) ?? '',
      source: 'globalping',
      state: r.state,
      stale: r.stale ? 'yes' : '',
      skip: r.skip ?? '',
      reason: (hasVerdict(r) && r.reason) || '',
      warnings: (r.warnings || []).join(';'),
      exposure: r.exposure ?? '',
      via: r.via,
      http_status: Number.isFinite(r.httpStatus) ? r.httpStatus : '',
      vantage: probesOf(r).map(vantageText).filter(Boolean).join('; '),
      measurement_id: r.measurementId ?? '',
      checked_at: isoOrNull(r.checkedAt) ?? ''
    };
  });
}

function vantageOf(p) {
  if (!p) return null;
  const adopted = typeof p.adopted === 'boolean' ? p.adopted : typeof p.community === 'boolean' ? p.community : null;
  return {
    country: p.country ?? null, city: p.city ?? null, asn: Number.isFinite(p.asn) ? p.asn : null,
    network: p.network ?? null, kind: p.kind ?? null, adopted
  };
}

/**
 * The JSON export (`domainscope.verify/1`). Each row starts with the CLI's
 * `_row_dict` keys in CLI order (`newCertCovers` a boolean or null, as the
 * CLI), then the web extras. Never contains a public key, headers, raw output
 * beyond the 300-char `error`, or DER.
 * @param {VerifyRow[]} rows
 * @param {{ expect?: Expectation|null, summary?: object|null, app?: string, version?: string|null, now?: Date|number }} [opts]
 * @returns {object}
 */
export function verifyExportJson(rows, { expect = null, summary = null, app = 'DomainScope', version = null, now = new Date() } = {}) {
  const list = Array.isArray(rows) ? rows : [];
  const time = nowMs(now);
  const sum = summary ?? summarizeVerify(list);
  const s = sum.servers ?? {};
  return {
    schema: 'domainscope.verify/1',
    generator: app,
    version: version ?? null,
    exportedAt: new Date(time).toISOString(),
    newCertificate: expect ? {
      sha256: [...(expect.sha256 || [])], subjectCN: expect.subjectCN ?? null,
      notAfter: isoOrNull(expect.notAfter), hostnames: [...(expect.hostnames || [])]
    } : null,
    summary: {
      servers: {
        total: s.total ?? 0, checked: s.checked ?? 0, live: s.live ?? 0, old: s.old ?? 0, other: s.other ?? 0,
        tlsError: s.tlsError ?? 0, unreachable: s.unreachable ?? 0, filteredOrigins: s.filteredOrigins ?? 0,
        notHostingOrigins: s.notHostingOrigins ?? 0, unchecked: s.unchecked ?? 0, incomplete: s.incomplete ?? 0
      },
      rows: JSON.parse(JSON.stringify(sum.rows ?? {})),
      spent: sum.spent ?? 0
    },
    rows: list.map((r) => {
      const served = hasVerdict(r) ? r.served : null;
      const chosenTest = (r.tests || [])[0] ?? null;
      return {
        server: r.server?.name ?? r.ip,
        ip: r.ip,
        port: r.port,
        probe: 'sni',
        name: r.name,
        sni: r.name,
        status: statusOut(r),
        coveredBy: (hasVerdict(r) && r.verdict.coveredBy) || null,
        newCertCovers: r.newCertCovers === true ? true : r.newCertCovers === false ? false : null,
        certSha256: served?.sha256 ?? null,
        certSubjectCN: served?.subjectCN ?? null,
        certIssuer: issuerLabel(served),
        certSerial: served?.serialHex ?? null,
        certNotAfter: isoOrNull(served?.notAfter),
        certDaysLeft: daysLeft(served, time),
        tlsVersion: served?.protocol ?? null,
        error: errorText(r),
        elapsedMs: Number.isFinite(chosenTest?.timings?.total) ? chosenTest.timings.total : null,
        // web extras
        source: 'globalping',
        state: r.state,
        stale: !!r.stale,
        skip: r.skip ?? null,
        reason: (hasVerdict(r) && r.reason) || null,
        warnings: [...(r.warnings || [])],
        exposure: r.exposure ?? null,
        via: r.via,
        httpStatus: Number.isFinite(r.httpStatus) ? r.httpStatus : null,
        alsoServers: (r.alsoServers || []).map((x) => x.name),
        vantage: probesOf(r).map(vantageOf).filter(Boolean),
        measurementId: r.measurementId ?? null,
        checkedAt: isoOrNull(r.checkedAt)
      };
    })
  };
}

const CLI_SKIPS = new Set(['private', 'reserved', 'bad-name', 'bad-port', 'over-cap']);

/**
 * Everything the internet could not answer, for the CLI card: rows skipped as
 * private / reserved / bad-name / bad-port / over-cap, plus rows whose (last) verdict is
 * TIMEOUT or CLOSED — filtered origins included, since only a machine inside
 * the network can read their certificate. CDN-edge rows are not included (the
 * CDN serves its own certificate). Targets and names are unique, in row order.
 * @param {VerifyRow[]} rows
 * @returns {{ targets: string[], names: string[], rows: number }}
 */
export function cliPlan(rows) {
  const targets = [];
  const names = [];
  let count = 0;
  for (const r of Array.isArray(rows) ? rows : []) {
    const inPlan = (r.state === 'skipped' && CLI_SKIPS.has(r.skip))
      || (hasVerdict(r) && (r.status === 'TIMEOUT' || r.status === 'CLOSED'));
    if (!inPlan) continue;
    count += 1;
    if (!targets.includes(r.ip)) targets.push(r.ip);
    if (!names.includes(r.name)) names.push(r.name);
  }
  return { targets, names, rows: count };
}
