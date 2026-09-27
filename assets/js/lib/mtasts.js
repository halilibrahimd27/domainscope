/**
 * mtasts.js — the MTA-STS policy (RFC 8461) behind a domain's `_mta-sts` TXT record: the
 * Globalping request that fetches it, the policy parser, and the validation Domain Health shows
 * after an explicit "Check the policy" click.
 *
 * - A browser cannot read https://mta-sts.<domain>/.well-known/mta-sts.txt itself (no CORS), so
 *   one Globalping probe fetches it ({@link mtaStsPolicyRequest}); the measurement carries the
 *   status code, the response headers, the decoded body and the TLS certificate
 *   ({@link interpretPolicyFetch}, verified live 2026-09-27: tests/fixtures/globalping/m26, m27).
 * - {@link parseMtaStsPolicy} follows the RFC 8461 §3.2 grammar strictly (field names are
 *   case-sensitive, a line that is not `key: value` breaks the grammar, the first of a duplicated
 *   non-mx field wins) and {@link validateMtaSts} turns fetch + policy + the domain's MX hosts
 *   into findings `{ id, severity, params }` with EN / TR texts in {@link MTA_STS_I18N}
 *   (`mtasts.<id>.title` / `.detail`, params pre-joined, language-neutral).
 *
 * The probe cannot open SMTP, so the STARTTLS certificates of the MX hosts (RFC 8461 §4.2) are
 * not checked here. DOM-free; runs in browsers and Node 22.
 */

import { httpsGetRequest, isProbeableHost, probeSummary } from './globalping.js';
import { normalizeHostname, wildcardMatches, certCovers } from './domain.js';
import { parseFailure, servedCert } from './verify.js';

/** The fixed policy path (RFC 8461 §3.2). */
export const MTA_STS_PATH = '/.well-known/mta-sts.txt';
/** `max_age` ceiling (RFC 8461 §3.2, about one year). */
export const MTA_STS_MAX_AGE_LIMIT = 31557600;
/** Policy modes (RFC 8461 §5). */
export const MTA_STS_MODES = Object.freeze(['enforce', 'testing', 'none']);
/** Probe-side timeout of the policy fetch (seconds; RFC 8461 suggests senders wait up to a minute). */
export const MTA_STS_TIMEOUT_S = 10;
/** A policy certificate expiring within this many days is flagged. */
export const MTA_STS_CERT_WARN_DAYS = 14;
/** `max_age` below one day is flagged as a warning, below a week as a note (RFC 8461: "weeks or greater"). */
export const MTA_STS_SHORT_MAX_AGE = 86400;
export const MTA_STS_WEEK = 604800;

/** Every finding id {@link validateMtaSts} can emit (`mtasts.<id>.title` / `.detail`). */
export const MTA_STS_FINDINGS = Object.freeze([
  'fetch.dns', 'fetch.private', 'fetch.unreachable', 'fetch.tls-failed', 'fetch.probe',
  'tls.ok', 'tls.expiring', 'tls.expired', 'tls.name', 'tls.chain', 'tls.untrusted', 'tls.rejected',
  'http.redirect', 'http.status', 'http.content-type', 'http.truncated',
  'policy.syntax', 'policy.blank-line', 'policy.field-case', 'policy.duplicate', 'policy.version', 'policy.mode',
  'policy.max-age', 'policy.max-age-too-large', 'policy.mx-missing', 'policy.mx-invalid',
  'mode.enforce', 'mode.testing', 'mode.testing-no-report', 'mode.none',
  'max-age.short', 'max-age.days', 'max-age.ok',
  'mx.ok', 'mx.unmatched', 'mx.unused', 'mx.none',
  'txt.missing'
]);
/** The one-line verdicts (`mtasts.head.<key>`), worst first. */
export const MTA_STS_HEADLINES = Object.freeze(['unreachable', 'invalid', 'inconclusive', 'problems', 'warnings', 'ok']);

const FIELDS = ['version', 'mode', 'max_age', 'mx'];
const FIELD_RE = /^([A-Za-z0-9][A-Za-z0-9_.-]{0,31}):[ \t]*(.*?)[ \t]*$/;
const CHAIN_ERRORS = new Set(['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT']);
const UNTRUSTED_ERRORS = new Set(['DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'CERT_UNTRUSTED']);
const DAY_MS = 86400000;
const SEVERITY_RANK = { error: 0, warn: 1, info: 2, ok: 3 };

const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');
const arr = (v) => (Array.isArray(v) ? v : []);
const join = (list) => [...new Set(list)].join(', ');
const isoDay = (d) => (d instanceof Date && !Number.isNaN(d.getTime()) ? d.toISOString().slice(0, 10) : '');

/**
 * The Policy Host `mta-sts.<domain>` (RFC 8461 §3.2), or null when Globalping would refuse it
 * (an invalid domain, an underscore, a single label, an IP address).
 * @param {string} domain
 * @returns {string|null}
 */
export function mtaStsPolicyHost(domain) {
  const d = normalizeHostname(typeof domain === 'string' ? domain : '');
  if (!d) return null;
  const host = `mta-sts.${d}`;
  return isProbeableHost(host) ? host : null;
}

/**
 * The policy URL a sending MTA fetches.
 * @param {string} domain
 * @returns {string|null}
 */
export function mtaStsPolicyUrl(domain) {
  const host = mtaStsPolicyHost(domain);
  return host ? `https://${host}${MTA_STS_PATH}` : null;
}

/**
 * The Globalping body for one probe fetching the policy: HTTPS GET of {@link MTA_STS_PATH} on
 * `mta-sts.<domain>` (lib/globalping.httpsGetRequest).
 * @param {string} domain
 * @param {{ timeoutS?: number }} [opts]
 * @returns {object}
 * @throws {TypeError} when the domain has no probeable policy host
 */
export function mtaStsPolicyRequest(domain, { timeoutS = MTA_STS_TIMEOUT_S } = {}) {
  const host = mtaStsPolicyHost(domain);
  if (!host) throw new TypeError(`No MTA-STS policy host for: ${String(domain)}`);
  return httpsGetRequest({ host, path: MTA_STS_PATH, timeoutS, probes: 1 });
}

/**
 * Does an `mx` pattern match an MX host name (RFC 8461 §4.1)? A literal name matches itself; a
 * `*.` pattern matches exactly one more left-most label (`*.example.com` matches
 * `mail.example.com`, not `example.com` or `a.b.example.com`). Case and a trailing dot do not matter.
 * @param {string} pattern
 * @param {string} host
 * @returns {boolean}
 */
export function mxPatternMatches(pattern, host) {
  const p = canon(pattern);
  const h = canon(host);
  if (!p || !h) return false;
  if (p.startsWith('*.')) return wildcardMatches(p, h);
  return !p.includes('*') && p === h;
}

/** `["*."] Domain` (RFC 8461 §3.2, RFC 5321 §4.1.2): an A-label host name, optionally `*.`-prefixed. */
function validMxPattern(value) {
  const bare = value.startsWith('*.') ? value.slice(2) : value;
  if (!bare || bare.includes('*') || !/^[A-Za-z0-9.-]+$/.test(bare)) return false;
  const n = normalizeHostname(bare);
  return !!n && n === bare.toLowerCase() && n.includes('.') && !/(^|\.)-|-(\.|$)/.test(n);
}

/**
 * Parse a policy body (RFC 8461 §3.2). Never throws.
 *
 * - Lines end in LF or CRLF; a final line break is optional. A line that is not `key: value`
 *   (no space before the colon, a key of letters, digits, `_`, `-`, `.`) breaks the grammar
 *   ('syntax'); a blank line between fields is outside it too ('blank-line').
 * - Field names are case-sensitive: `Version:` is an unknown extension ('field-case').
 * - version, mode and max_age are required once (a duplicate keeps the first, 'duplicate'); `mx`
 *   is required at least once unless the mode is "none". Unknown fields are ignored.
 *
 * @param {string} text
 * @returns {{ version: string|null, mode: string|null, maxAge: number|null, mx: string[],
 *   extensions: Array<{ name: string, value: string }>, issues: Array<{ code: string, params: object }>,
 *   valid: boolean }}
 *   `issues[].code` is the part after `policy.` of a {@link MTA_STS_FINDINGS} id; `valid` = a policy
 *   a sender accepts: the grammar holds, version STSv1, a known mode, a max_age within range and
 *   (except for mode none) at least one mx pattern.
 */
export function parseMtaStsPolicy(text) {
  const out = { version: null, mode: null, maxAge: null, mx: [], extensions: [], issues: [], valid: false };
  const issue = (code, params = {}) => out.issues.push({ code, params });
  const lines = String(text ?? '').split(/\r?\n/);
  while (lines.length && lines[lines.length - 1] === '') lines.pop(); // the optional final line break
  const seen = new Set();
  const raw = {};
  let fatal = false;
  lines.forEach((line, i) => {
    const n = i + 1;
    if (!line.trim()) {
      issue('blank-line', { line: n });
      return;
    }
    const m = FIELD_RE.exec(line);
    if (!m) {
      issue('syntax', { line: n, text: line.slice(0, 80) });
      fatal = true;
      return;
    }
    const [, name, value] = m;
    if (name === 'mx') {
      out.mx.push(value);
      return;
    }
    if (FIELDS.includes(name)) {
      if (seen.has(name)) {
        issue('duplicate', { field: name });
        return;
      }
      seen.add(name);
      raw[name] = value;
      return;
    }
    if (FIELDS.includes(name.toLowerCase())) issue('field-case', { field: name, expected: name.toLowerCase() });
    out.extensions.push({ name, value });
  });

  if (raw.version === undefined || raw.version !== 'STSv1') issue('version', { value: raw.version ?? '—' });
  else out.version = raw.version;
  if (raw.mode === undefined || !MTA_STS_MODES.includes(raw.mode)) issue('mode', { value: raw.mode ?? '—' });
  else out.mode = raw.mode;
  if (raw.max_age === undefined || !/^\d{1,10}$/.test(raw.max_age)) issue('max-age', { value: raw.max_age ?? '—' });
  else if (Number(raw.max_age) > MTA_STS_MAX_AGE_LIMIT) issue('max-age-too-large', { value: raw.max_age, max: MTA_STS_MAX_AGE_LIMIT });
  else out.maxAge = Number(raw.max_age);
  const badMx = out.mx.filter((p) => !validMxPattern(p));
  if (badMx.length) issue('mx-invalid', { values: join(badMx.map((v) => v || '""')) });
  if (out.mode !== 'none' && !out.mx.some(validMxPattern)) issue('mx-missing', {});

  out.valid = !fatal && out.version === 'STSv1' && out.mode !== null && out.maxAge !== null
    && (out.mode === 'none' || out.mx.some(validMxPattern));
  return out;
}

/**
 * What one Globalping policy measurement says (the first probe's result). Never throws.
 * @param {object} measurement a finished Globalping measurement (`{ id, results: [{ probe, result }] }`)
 * @param {{ host?: string|null }} [opts] the policy host, to check the certificate's names
 * @returns {{ measurementId: string|null, probe: object|null, finished: boolean,
 *   failure: { kind: string, text: string }|null, httpStatus: number|null, contentType: string|null,
 *   location: string|null, body: string|null, truncated: boolean,
 *   tls: { authorized: boolean, error: string|null, hostnames: string[], covers: boolean|null,
 *     notAfter: Date|null, issuer: string|null }|null }}
 *   `finished`: the probe completed an HTTPS exchange (any status code); otherwise `failure` holds
 *   lib/verify.parseFailure's kind and first line.
 */
export function interpretPolicyFetch(measurement, { host = null } = {}) {
  const m = measurement && typeof measurement === 'object' ? measurement : {};
  const test = arr(m.results)[0] || {};
  const r = test.result && typeof test.result === 'object' ? test.result : {};
  const out = {
    measurementId: typeof m.id === 'string' ? m.id : null,
    probe: test.probe ? probeSummary(test.probe) : null,
    finished: false, failure: null, httpStatus: null, contentType: null, location: null, body: null, truncated: false, tls: null
  };
  const served = servedCert(r.tls);
  if (served) {
    out.tls = {
      authorized: served.authorized, error: served.error, hostnames: served.hostnames,
      covers: host ? certCovers(served.hostnames, host).covered : null,
      notAfter: served.notAfter, issuer: served.issuerO || served.issuerCN
    };
  }
  if (r.status !== 'finished' || !Number.isInteger(r.statusCode)) {
    const f = parseFailure(r);
    out.failure = { kind: r.status === 'finished' ? 'unknown' : f.kind, text: f.text };
    return out;
  }
  const headers = r.headers && typeof r.headers === 'object' ? r.headers : {};
  const header = (name) => {
    const key = Object.keys(headers).find((k) => k.toLowerCase() === name);
    const v = key === undefined ? null : headers[key];
    return Array.isArray(v) ? String(v[0] ?? '') : v === null || v === undefined ? null : String(v);
  };
  out.finished = true;
  out.httpStatus = r.statusCode;
  out.contentType = header('content-type');
  out.location = header('location');
  out.body = typeof r.rawBody === 'string' ? r.rawBody : null;
  out.truncated = r.truncated === true;
  return out;
}

/**
 * Validate a fetched policy against RFC 8461 and the domain's MX hosts.
 *
 * Order of the findings: transport (fetch, TLS, HTTP), the policy grammar, mode, max_age, the MX
 * cross-check (every MX host must match an mx pattern: an unmatched one is an error in enforce
 * mode, where senders refuse to deliver to it, and a warning in testing mode), then the TXT record.
 * A policy senders cannot fetch (no answer, an invalid certificate, a status other than 200, a
 * redirect) or cannot parse stops after the transport / grammar findings: senders then deliver as
 * if the domain had no MTA-STS (RFC 8461 §3.3; a policy cached earlier still applies until it expires).
 *
 * @param {{ domain: string, fetch: ReturnType<typeof interpretPolicyFetch>, mxHosts?: string[],
 *   txt?: string|null, tlsRpt?: string|null, now?: Date|number }} input
 *   `mxHosts`: the domain's MX exchanges (a null MX "." is ignored); `txt` / `tlsRpt`: the
 *   `_mta-sts` / `_smtp._tls` TXT records (undefined = not known, no finding)
 * @returns {{ headline: string, severity: 'ok'|'info'|'warn'|'error', mode: string|null, policy: object|null,
 *   usable: boolean, host: string|null, findings: Array<{ id: string, severity: string, params: object }>,
 *   mx: Array<{ host: string, matchedBy: string|null }>, unusedPatterns: string[] }}
 */
export function validateMtaSts({ domain, fetch, mxHosts = [], txt = undefined, tlsRpt = undefined, now = Date.now() } = {}) {
  const host = mtaStsPolicyHost(domain) || `mta-sts.${canon(domain)}`;
  const nowMs = now instanceof Date ? now.getTime() : Number(now);
  const f = fetch && typeof fetch === 'object' ? fetch : { finished: false, failure: { kind: 'unknown', text: '' } };
  const findings = [];
  const add = (id, severity, params = {}) => findings.push({ id, severity, params: { host, ...params } });
  const out = { headline: 'ok', severity: 'ok', mode: null, policy: null, usable: false, host, findings, mx: [], unusedPatterns: [] };
  const finish = (headline) => {
    out.severity = findings.reduce((w, x) => (SEVERITY_RANK[x.severity] < SEVERITY_RANK[w] ? x.severity : w), 'ok');
    out.headline = headline || (out.severity === 'error' ? 'problems' : out.severity === 'warn' ? 'warnings' : 'ok');
    return out;
  };

  // --- transport ------------------------------------------------------------------------------
  if (!f.finished) {
    const kind = f.failure ? f.failure.kind : 'unknown';
    const text = f.failure ? f.failure.text : '';
    if (kind === 'dns') add('fetch.dns', 'error', { text });
    else if (kind === 'private') add('fetch.private', 'error', { text });
    else if (['refused', 'unreachable', 'connect-timeout'].includes(kind)) add('fetch.unreachable', 'error', { text });
    else if (['tls-timeout', 'tls-alert', 'reset', 'not-tls'].includes(kind)) add('fetch.tls-failed', 'error', { text });
    else add('fetch.probe', 'warn', { text });
    if (txt === null) add('txt.missing', 'warn', { domain: canon(domain) });
    return finish(findings.some((x) => x.id === 'fetch.probe') ? 'inconclusive' : 'unreachable');
  }
  let blocked = false;
  const tls = f.tls;
  if (tls) {
    const expires = isoDay(tls.notAfter);
    const days = tls.notAfter ? Math.floor((tls.notAfter.getTime() - nowMs) / DAY_MS) : null;
    const nameOk = tls.covers !== false && tls.error !== 'ERR_TLS_CERT_ALTNAME_INVALID';
    if (!tls.authorized || !nameOk) {
      blocked = true;
      const error = tls.error || '—';
      if (tls.error === 'CERT_HAS_EXPIRED' || (days !== null && days < 0)) add('tls.expired', 'error', { error, date: expires });
      if (!nameOk) add('tls.name', 'error', { error, names: join(tls.hostnames) || '—' });
      if (CHAIN_ERRORS.has(tls.error)) add('tls.chain', 'error', { error });
      else if (tls.error && tls.error !== 'CERT_HAS_EXPIRED' && tls.error !== 'ERR_TLS_CERT_ALTNAME_INVALID') {
        add(UNTRUSTED_ERRORS.has(tls.error) ? 'tls.untrusted' : 'tls.rejected', 'error', { error });
      }
    } else if (days !== null && days < MTA_STS_CERT_WARN_DAYS) {
      add('tls.expiring', 'warn', { days, date: expires });
    } else {
      add('tls.ok', 'ok', { issuer: tls.issuer || '—', date: expires || '—' });
    }
  }
  if (f.httpStatus >= 300 && f.httpStatus < 400) {
    blocked = true;
    add('http.redirect', 'error', { status: f.httpStatus, location: f.location || '—' });
  } else if (f.httpStatus !== 200) {
    blocked = true;
    add('http.status', 'error', { status: f.httpStatus });
  }
  if (blocked) {
    if (txt === null) add('txt.missing', 'warn', { domain: canon(domain) });
    return finish('unreachable');
  }
  const type = (f.contentType || '').split(';')[0].trim().toLowerCase();
  if (type !== 'text/plain') add('http.content-type', 'warn', { type: type || '—' });
  if (f.truncated) add('http.truncated', 'warn', {});

  // --- the policy -----------------------------------------------------------------------------
  const policy = parseMtaStsPolicy(f.body ?? '');
  out.policy = policy;
  out.mode = policy.mode;
  for (const x of policy.issues) {
    const severity = x.code === 'duplicate' || x.code === 'blank-line' || x.code === 'mx-invalid' ? 'warn' : 'error';
    add(`policy.${x.code}`, severity, x.params);
  }
  if (!policy.valid) {
    if (txt === null) add('txt.missing', 'warn', { domain: canon(domain) });
    return finish('invalid');
  }
  out.usable = true;

  if (policy.mode === 'enforce') add('mode.enforce', 'ok', {});
  else if (policy.mode === 'testing') {
    add('mode.testing', 'info', {});
    if (tlsRpt === null) add('mode.testing-no-report', 'warn', { domain: canon(domain) });
  } else add('mode.none', 'info', {});

  const days = Math.floor(policy.maxAge / 86400);
  if (policy.maxAge < MTA_STS_SHORT_MAX_AGE) add('max-age.short', 'warn', { value: policy.maxAge });
  else if (policy.maxAge < MTA_STS_WEEK && policy.mode !== 'none') add('max-age.days', 'info', { value: policy.maxAge, days });
  else add('max-age.ok', 'ok', { value: policy.maxAge, days });

  const patterns = policy.mx.filter(validMxPattern).map((p) => p.toLowerCase());
  const hosts = [...new Set(arr(mxHosts).map(canon).filter((x) => x && x !== '.'))];
  out.mx = hosts.map((h) => ({ host: h, matchedBy: patterns.find((p) => mxPatternMatches(p, h)) || null }));
  out.unusedPatterns = patterns.filter((p) => !hosts.some((h) => mxPatternMatches(p, h)));
  if (policy.mode !== 'none') {
    if (!hosts.length) add('mx.none', 'info', {});
    else {
      const unmatched = out.mx.filter((x) => !x.matchedBy).map((x) => x.host);
      if (unmatched.length) {
        add('mx.unmatched', policy.mode === 'enforce' ? 'error' : 'warn', { hosts: join(unmatched), patterns: join(patterns) });
      } else add('mx.ok', 'ok', { count: hosts.length });
      if (out.unusedPatterns.length) add('mx.unused', 'info', { patterns: join(out.unusedPatterns) });
    }
  }
  if (txt === null) add('txt.missing', 'warn', { domain: canon(domain) });
  return finish(null);
}

/**
 * One policy check as plain, language-neutral JSON (Domain Health's "Report (JSON)"): the URL,
 * the probe, what came back, the verdict and the findings. Dates are ISO strings; the probe
 * summary never carries coordinates (lib/globalping.probeSummary).
 * @param {{ domain: string, fetch: ReturnType<typeof interpretPolicyFetch>,
 *   validation: ReturnType<typeof validateMtaSts>, checkedAt?: Date|number|null }} check
 * @returns {{ url: string|null, checkedAt: string|null, measurementId: string|null, probe: object|null,
 *   headline: string, severity: string, usable: boolean, mode: string|null, maxAge: number|null,
 *   mx: Array<{ host: string, matchedBy: string|null }>, unusedPatterns: string[],
 *   http: { status: number, contentType: string|null, location: string|null, truncated: boolean }|null,
 *   failure: { kind: string, text: string }|null,
 *   tls: { authorized: boolean, error: string|null, issuer: string|null, notAfter: string|null, names: string[], covers: boolean|null }|null,
 *   policy: string|null, findings: Array<{ id: string, severity: string, params: object }> }}
 */
export function mtaStsExport({ domain, fetch, validation, checkedAt = null } = {}) {
  const f = fetch && typeof fetch === 'object' ? fetch : {};
  const v = validation && typeof validation === 'object' ? validation : {};
  const iso = (d) => {
    const x = d instanceof Date ? d : (d === null || d === undefined ? null : new Date(d));
    return x && !Number.isNaN(x.getTime()) ? x.toISOString() : null;
  };
  const tls = f.tls || null;
  return {
    url: mtaStsPolicyUrl(domain),
    checkedAt: iso(checkedAt),
    measurementId: f.measurementId ?? null,
    probe: f.probe ?? null,
    headline: v.headline ?? 'inconclusive',
    severity: v.severity ?? 'warn',
    usable: v.usable === true,
    mode: v.mode ?? null,
    maxAge: v.policy && Number.isInteger(v.policy.maxAge) ? v.policy.maxAge : null,
    mx: arr(v.mx).map((x) => ({ host: x.host, matchedBy: x.matchedBy })),
    unusedPatterns: arr(v.unusedPatterns).slice(),
    http: f.finished ? { status: f.httpStatus, contentType: f.contentType, location: f.location, truncated: f.truncated === true } : null,
    failure: f.failure ?? null,
    tls: tls ? {
      authorized: tls.authorized === true, error: tls.error ?? null, issuer: tls.issuer ?? null,
      notAfter: iso(tls.notAfter), names: arr(tls.hostnames).slice(), covers: tls.covers ?? null
    } : null,
    policy: typeof f.body === 'string' ? f.body : null,
    findings: arr(v.findings).map((x) => ({ id: x.id, severity: x.severity, params: { ...x.params } }))
  };
}

/* ------------------------------------------------------------------------ */
/* i18n                                                                     */
/* ------------------------------------------------------------------------ */

// [id, [en, tr] title, [en, tr] detail]; headlines are plain labels (`mtasts.head.<key>`).
const STRINGS = [
  ['head.unreachable', ['Senders cannot use this policy: they deliver as if the domain had no MTA-STS (a policy they cached earlier still applies until it expires).',
    'Gönderenler bu politikayı kullanamıyor: alan adında MTA-STS yokmuş gibi teslim ederler (daha önce önbelleğe aldıkları bir politika süresi dolana kadar geçerli kalır).']],
  ['head.invalid', ['The policy is invalid: senders treat the domain as if it had no MTA-STS.',
    'Politika geçersiz: gönderenler alan adını MTA-STS yokmuş gibi değerlendirir.']],
  ['head.inconclusive', ['The check was inconclusive: the probe could not complete it.', 'Kontrol sonuçsuz kaldı: ölçüm noktası kontrolü tamamlayamadı.']],
  ['head.problems', ['The policy is valid, but mail delivery is at risk (see below).', 'Politika geçerli, ancak e-posta teslimi risk altında (aşağıya bakın).']],
  ['head.warnings', ['The policy works; some settings need attention.', 'Politika çalışıyor; bazı ayarlar ilgi istiyor.']],
  ['head.ok', ['The policy is valid and every MX host matches it.', 'Politika geçerli ve her MX sunucusu onunla eşleşiyor.']],

  ['fetch.dns', ['The policy host does not resolve', 'Politika sunucusu çözümlenmiyor'],
    ['The probe could not resolve {host} ({text}). Publish an A / AAAA (or CNAME) record for it and serve the policy there.',
      'Ölçüm noktası {host} adını çözümleyemedi ({text}). Bu ad için bir A / AAAA (veya CNAME) kaydı yayınlayın ve politikayı orada sunun.']],
  ['fetch.private', ['The policy host has a private address', 'Politika sunucusunun adresi özel'],
    ['{host} resolves to a private or reserved address ({text}); sending servers on the internet cannot reach it.',
      '{host} özel ya da ayrılmış bir adrese çözümleniyor ({text}); internetteki gönderen sunucular ona ulaşamaz.']],
  ['fetch.unreachable', ['The policy host does not answer', 'Politika sunucusu yanıt vermiyor'],
    ['No HTTPS answer from {host} on port 443 ({text}).', '{host}, 443 numaralı portta HTTPS yanıtı vermiyor ({text}).']],
  ['fetch.tls-failed', ['The TLS handshake with the policy host failed', 'Politika sunucusuyla TLS el sıkışması başarısız'],
    ['{host} broke off the HTTPS connection ({text}).', '{host} HTTPS bağlantısını kesti ({text}).']],
  ['fetch.probe', ['The probe could not complete the check', 'Ölçüm noktası kontrolü tamamlayamadı'],
    ['This says nothing about {host} ({text}). Check again: another probe will be used.',
      'Bu, {host} hakkında bir şey söylemiyor ({text}). Yeniden kontrol edin: başka bir ölçüm noktası kullanılır.']],

  ['tls.ok', ['Valid certificate for the policy host', 'Politika sunucusu için geçerli sertifika'],
    ['{host} serves a trusted certificate for its name (issuer: {issuer}, valid until {date}).',
      '{host} kendi adı için güvenilir bir sertifika sunuyor (veren: {issuer}, {date} tarihine kadar geçerli).']],
  ['tls.expiring', ['The policy host certificate expires soon', 'Politika sunucusunun sertifikası yakında doluyor'],
    ['It expires in {days} days ({date}). Once it has expired, senders can no longer fetch the policy.',
      '{days} gün içinde ({date}) sona eriyor. Süresi dolduğunda gönderenler politikayı artık alamaz.']],
  ['tls.expired', ['The policy host certificate has expired', 'Politika sunucusunun sertifikasının süresi dolmuş'],
    ['{host} serves an expired certificate ({error}, {date}); senders refuse to fetch the policy over it (RFC 8461 §3.3). Renew it.',
      '{host} süresi dolmuş bir sertifika sunuyor ({error}, {date}); gönderenler politikayı bu bağlantı üzerinden almayı reddeder (RFC 8461 §3.3). Sertifikayı yenileyin.']],
  ['tls.name', ['The certificate does not cover the policy host', 'Sertifika politika sunucusunun adını kapsamıyor'],
    ['{host} must be among the certificate\'s names (RFC 8461 §3.3), which are: {names} ({error}). Add {host} to the certificate.',
      '{host} sertifikadaki adlar arasında olmalıdır (RFC 8461 §3.3); adlar şunlar: {names} ({error}). {host} adını sertifikaya ekleyin.']],
  ['tls.chain', ['Incomplete certificate chain on the policy host', 'Politika sunucusunda eksik sertifika zinciri'],
    ['The server does not send its intermediate certificate ({error}), so senders cannot verify it. Serve the full chain.',
      'Sunucu ara sertifikasını göndermiyor ({error}); bu yüzden gönderenler sertifikayı doğrulayamaz. Tam zinciri sunun.']],
  ['tls.untrusted', ['Self-signed certificate on the policy host', 'Politika sunucusunda kendinden imzalı sertifika'],
    ['The certificate does not chain to a trusted root ({error}). Senders need a publicly trusted certificate for {host} (RFC 8461 §3.3).',
      'Sertifika güvenilir bir köke bağlanmıyor ({error}). Gönderenler {host} için herkesçe güvenilen bir sertifika bekler (RFC 8461 §3.3).']],
  ['tls.rejected', ['Certificate rejected on the policy host', 'Politika sunucusunda sertifika reddedildi'],
    ['The probe did not accept the certificate ({error}). Senders need a valid, publicly trusted certificate for {host} (RFC 8461 §3.3).',
      'Ölçüm noktası sertifikayı kabul etmedi ({error}). Gönderenler {host} için geçerli ve herkesçe güvenilen bir sertifika bekler (RFC 8461 §3.3).']],

  ['http.redirect', ['The policy URL redirects', 'Politika adresi yönlendiriyor'],
    ['HTTP {status} to {location}. Senders do not follow redirects (RFC 8461 §3.3): serve the policy at the URL itself with status 200.',
      '{location} adresine HTTP {status}. Gönderenler yönlendirmeleri izlemez (RFC 8461 §3.3): politikayı bu adresin kendisinde, 200 durum koduyla sunun.']],
  ['http.status', ['The policy URL does not answer 200', 'Politika adresi 200 döndürmüyor'],
    ['HTTP {status}. Senders accept a policy only with status 200 (RFC 8461 §3.3).', 'HTTP {status}. Gönderenler politikayı yalnızca 200 durum koduyla kabul eder (RFC 8461 §3.3).']],
  ['http.content-type', ['Not served as text/plain', 'text/plain olarak sunulmuyor'],
    ['The policy is served as "{type}". Senders should accept it only as text/plain (RFC 8461 §3.2): set Content-Type: text/plain.',
      'Politika "{type}" olarak sunuluyor. Gönderenlerin yalnızca text/plain kabul etmesi beklenir (RFC 8461 §3.2): Content-Type: text/plain ayarlayın.']],
  ['http.truncated', ['Only the start of the policy was checked', 'Politikanın yalnızca başı kontrol edildi'],
    ['Globalping returns at most 10 KB of a response. A policy is normally a few lines long; check what the file holds.',
      'Globalping bir yanıtın en fazla 10 KB’ını döndürür. Bir politika normalde birkaç satırdır; dosyanın içeriğine bakın.']],

  ['policy.syntax', ['Line outside the policy grammar', 'Politika sözdizimine uymayan satır'],
    ['Line {line} ("{text}") is not a "key: value" field (RFC 8461 §3.2); a strict sender rejects the whole policy.',
      '{line}. satır ("{text}") "anahtar: değer" biçiminde değil (RFC 8461 §3.2); katı bir gönderen tüm politikayı reddeder.']],
  ['policy.blank-line', ['Blank line inside the policy', 'Politikanın içinde boş satır'],
    ['Line {line} is blank, which the RFC 8461 grammar does not allow between fields. Remove it.',
      '{line}. satır boş; RFC 8461 sözdizimi alanlar arasında boş satıra izin vermez. Kaldırın.']],
  ['policy.field-case', ['Field name in the wrong case', 'Alan adı yanlış harf büyüklüğünde'],
    ['"{field}" is not "{expected}": field names are case-sensitive (RFC 8461 §3.2), so senders ignore it.',
      '"{field}", "{expected}" değil: alan adları büyük/küçük harfe duyarlıdır (RFC 8461 §3.2); bu yüzden gönderenler onu yok sayar.']],
  ['policy.duplicate', ['Field given more than once', 'Alan birden fazla kez verilmiş'],
    ['"{field}" appears more than once; senders use the first one and ignore the rest (RFC 8461 §3.2).',
      '"{field}" birden fazla kez geçiyor; gönderenler ilkini kullanır, diğerlerini yok sayar (RFC 8461 §3.2).']],
  ['policy.version', ['Missing or wrong version', 'Sürüm eksik ya da hatalı'],
    ['The policy needs "version: STSv1" (found: {value}).', 'Politikada "version: STSv1" olmalıdır (bulunan: {value}).']],
  ['policy.mode', ['Missing or unknown mode', 'Mod eksik ya da bilinmiyor'],
    ['"mode" must be enforce, testing or none (found: {value}).', '"mode" enforce, testing ya da none olmalıdır (bulunan: {value}).']],
  ['policy.max-age', ['Missing or invalid max_age', 'max_age eksik ya da geçersiz'],
    ['"max_age" must be a number of seconds (found: {value}).', '"max_age" saniye cinsinden bir sayı olmalıdır (bulunan: {value}).']],
  ['policy.max-age-too-large', ['max_age is too large', 'max_age çok büyük'],
    ['{value} seconds is above the maximum of {max} (about one year, RFC 8461 §3.2).', '{value} saniye, {max} üst sınırının üzerinde (yaklaşık bir yıl, RFC 8461 §3.2).']],
  ['policy.mx-missing', ['No mx pattern', 'mx kalıbı yok'],
    ['A policy in enforce or testing mode must list at least one valid "mx:" line.', 'enforce ya da testing modundaki bir politika en az bir geçerli "mx:" satırı içermelidir.']],
  ['policy.mx-invalid', ['Invalid mx patterns', 'Geçersiz mx kalıpları'],
    ['These are not host names (optionally "*."-prefixed, in A-label form, without a trailing dot) and match no MX: {values}.',
      'Bunlar ana makine adı değil (isteğe bağlı "*." önekiyle, A-label biçiminde, sonda nokta olmadan) ve hiçbir MX ile eşleşmez: {values}.']],

  ['mode.enforce', ['Mode: enforce', 'Mod: enforce'],
    ['Senders that support MTA-STS deliver only over authenticated TLS to the MX hosts the policy lists.',
      'MTA-STS destekleyen gönderenler yalnızca politikada listelenen MX sunucularına, doğrulanmış TLS üzerinden teslim eder.']],
  ['mode.testing', ['Mode: testing', 'Mod: testing'],
    ['Failures are only reported (TLS-RPT); mail is still delivered. Switch to enforce once the reports are clean.',
      'Hatalar yalnızca bildirilir (TLS-RPT); e-posta yine de teslim edilir. Raporlar temiz olunca enforce moduna geçin.']],
  ['mode.testing-no-report', ['Testing mode without TLS reports', 'TLS raporu olmadan test modu'],
    ['{domain} has no _smtp._tls TXT record (RFC 8460), so nobody receives the failures that testing mode is meant to reveal.',
      '{domain} için _smtp._tls TXT kaydı (RFC 8460) yok; bu yüzden test modunun ortaya çıkarması gereken hataları kimse almıyor.']],
  ['mode.none', ['Mode: none', 'Mod: none'],
    ['MTA-STS is switched off: senders drop the policy they cached. Use this mode only to retire MTA-STS.',
      'MTA-STS kapalı: gönderenler önbelleğe aldıkları politikayı bırakır. Bu modu yalnızca MTA-STS’yi kaldırırken kullanın.']],

  ['max-age.short', ['max_age is very short', 'max_age çok kısa'],
    ['{value} seconds (under a day). A short lifetime leaves senders without a cached policy at refresh time; RFC 8461 expects weeks or more.',
      '{value} saniye (bir günden az). Kısa bir süre, yenileme anında gönderenleri önbellekte politika olmadan bırakır; RFC 8461 haftalar ya da daha uzun bir süre bekler.']],
  ['max-age.days', ['max_age is under a week', 'max_age bir haftadan kısa'],
    ['{value} seconds is less than a week; RFC 8461 expects weeks or more (for example 604800, one week, or longer).',
      '{value} saniye bir haftadan kısa; RFC 8461 haftalar ya da daha uzun bir süre bekler (örneğin 604800, bir hafta, ya da daha uzun).']],
  ['max-age.ok', ['max_age is fine', 'max_age uygun'],
    ['Senders keep the policy for up to {value} seconds before they fetch it again.', 'Gönderenler politikayı yeniden almadan önce en fazla {value} saniye önbellekte tutar.']],

  ['mx.ok', ['Every MX host matches the policy', 'Her MX sunucusu politikayla eşleşiyor'],
    ['All {count} MX hosts of the domain match an mx pattern.', 'Alan adının {count} MX sunucusunun tamamı bir mx kalıbıyla eşleşiyor.']],
  ['mx.unmatched', ['MX hosts missing from the policy', 'Politikada olmayan MX sunucuları'],
    ['No mx pattern ({patterns}) matches {hosts}. Senders that support MTA-STS do not deliver to an MX host the policy does not list (in testing mode they deliver and report a failure). Add an "mx:" line for each.',
      '{hosts} hiçbir mx kalıbıyla eşleşmiyor ({patterns}). MTA-STS destekleyen gönderenler politikada listelenmeyen bir MX sunucusuna teslim etmez (test modunda teslim eder ve bir hata bildirir). Her biri için bir "mx:" satırı ekleyin.']],
  ['mx.unused', ['mx patterns without an MX host', 'MX sunucusu olmayan mx kalıpları'],
    ['No current MX host matches {patterns}. That is fine for a planned or backup MX; otherwise remove the line.',
      'Hiçbir güncel MX sunucusu {patterns} ile eşleşmiyor. Planlanan ya da yedek bir MX için sorun değil; aksi hâlde satırı kaldırın.']],
  ['mx.none', ['No MX hosts to compare', 'Karşılaştırılacak MX sunucusu yok'],
    ['The domain publishes no MX record, so the mx patterns could not be checked against it.',
      'Alan adı MX kaydı yayınlamıyor; bu yüzden mx kalıpları karşılaştırılamadı.']],

  ['txt.missing', ['No _mta-sts TXT record', '_mta-sts TXT kaydı yok'],
    ['Senders look for the policy only when _mta-sts.{domain} has a "v=STSv1; id=…" TXT record. Publish one (and change its id whenever the policy changes).',
      'Gönderenler politikayı yalnızca _mta-sts.{domain} için "v=STSv1; id=…" TXT kaydı varsa arar. Bir tane yayınlayın (ve politika her değiştiğinde id değerini değiştirin).']]
];

function buildStrings(lang) {
  const out = {};
  for (const [id, title, detail] of STRINGS) {
    if (detail) {
      out[`mtasts.${id}.title`] = title[lang];
      out[`mtasts.${id}.detail`] = detail[lang];
    } else {
      out[`mtasts.${id}`] = title[lang];
    }
  }
  return out;
}

/**
 * English and Turkish texts: `mtasts.<finding>.title` / `.detail` for every {@link MTA_STS_FINDINGS}
 * id and `mtasts.head.<key>` for every {@link MTA_STS_HEADLINES} key. Placeholders: `{param}`.
 * @type {{ en: Object<string, string>, tr: Object<string, string> }}
 */
export const MTA_STS_I18N = Object.freeze({ en: Object.freeze(buildStrings(0)), tr: Object.freeze(buildStrings(1)) });
