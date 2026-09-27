/**
 * sourceinfo.js — what the views need to know about the passive subdomain sources without
 * loading them: the catalogue (names, notes, quotas), each source's quota semantics and
 * sourceHealthSummary(), which turns the results of a scan into a compact status list. The
 * fetchers (lib/sources.js) belong to the discovery engine, which loads when a scan starts.
 *
 * lib/sources.js imports the catalogue and the quota builder from here and re-exports SOURCES,
 * sourceQuota, SOURCE_HEALTH_STATES and sourceHealthSummary unchanged.
 *
 * DOM-free, no I/O.
 */

/** @typedef {import('./sources.js').SourceResult} SourceResult */

/**
 * @typedef {object} SourceQuota
 * @property {boolean} limited the service refused the request because of its quota
 * @property {'day'|'hour'|'minutes'|null} period how long such a limit typically lasts
 * @property {number|null} retryAfterMs from a readable Retry-After header
 * @property {Date|null} resetAt now + retryAfterMs
 * @property {number|null} limit from readable X-RateLimit-Limit (Node; browsers cannot read it)
 * @property {number|null} remaining from readable X-RateLimit-Remaining
 * @property {string|null} resetHint short English explanation
 * @property {string|null} hintKey i18n key of the localized explanation ('source.quota.*')
 */

/* ------------------------------------------------------------------------ */
/* Source catalogue                                                         */
/* ------------------------------------------------------------------------ */

/**
 * Passive sources. `noteKey` is an i18n key ('source.<id>.note') explaining
 * quotas / speed. Extensions: `timeoutMs` (default per-request timeout),
 * `quota` (short English description).
 * @type {ReadonlyArray<{ id: string, name: string, homepage: string, providesIps: boolean,
 *   providesCerts: boolean, defaultEnabled: boolean, noteKey: string, timeoutMs: number, quota: string }>}
 */
export const SOURCES = Object.freeze([
  {
    id: 'crtsh', name: 'crt.sh', homepage: 'https://crt.sh/', providesIps: false, providesCerts: true,
    defaultEnabled: true, noteKey: 'source.crtsh.note', timeoutMs: 90000,
    quota: 'No key; slow for large domains (up to 60 s+), occasional 502/503.'
  },
  {
    id: 'certspotter', name: 'Cert Spotter', homepage: 'https://sslmate.com/certspotter/', providesIps: false,
    providesCerts: true, defaultEnabled: true, noteKey: 'source.certspotter.note', timeoutMs: 25000,
    quota: 'Unauthenticated: about 10 requests per hour per IP; unexpired certificates only.'
  },
  {
    id: 'hackertarget', name: 'HackerTarget', homepage: 'https://hackertarget.com/find-dns-host-records/',
    providesIps: true, providesCerts: false, defaultEnabled: true, noteKey: 'source.hackertarget.note',
    timeoutMs: 25000, quota: 'Free: about 50 requests per day per IP (shared with reverse IP lookup).'
  },
  {
    id: 'anubis', name: 'Anubis DB', homepage: 'https://anubisdb.com/', providesIps: false, providesCerts: false,
    defaultEnabled: true, noteKey: 'source.anubis.note', timeoutMs: 25000, quota: 'No key.'
  },
  {
    id: 'otx', name: 'AlienVault OTX', homepage: 'https://otx.alienvault.com/', providesIps: true,
    providesCerts: false, defaultEnabled: true, noteKey: 'source.otx.note', timeoutMs: 25000,
    quota: 'Anonymous access is often rate-limited (HTTP 429).'
  },
  {
    id: 'thc', name: 'ip.thc.org', homepage: 'https://ip.thc.org', providesIps: false, providesCerts: false,
    defaultEnabled: true, noteKey: 'source.thc.note', timeoutMs: 25000,
    quota: 'No key; about 250 requests per IP refilling 1 every 2 s. Up to 10 pages (1,000 names) per domain, 2 s apart.'
  }
].map((s) => Object.freeze(s)));

/**
 * Per-source quota semantics (what a 'rate-limit' means and how long it lasts).
 * `hintKey` values are i18n keys registered in i18n.js.
 */
const QUOTA_POLICY = Object.freeze({
  hackertarget: {
    period: 'day', hintKey: 'source.quota.day',
    resetHint: 'Daily free quota for your IP is used up (about 50 requests); it resets within 24 hours.'
  },
  certspotter: {
    period: 'hour', hintKey: 'source.quota.hour',
    resetHint: 'Hourly free quota for your IP is used up (about 10 requests); try again in about an hour.'
  },
  otx: {
    period: null, hintKey: 'source.quota.later',
    resetHint: 'OTX limits anonymous access per IP; try again later.'
  },
  thc: {
    period: 'minutes', hintKey: 'source.quota.minutes',
    resetHint: 'Rate limit reached (about 250 requests, refilling 1 every 2 s); try again in a few minutes.'
  },
  crtsh: {
    period: 'minutes', hintKey: 'source.quota.minutes',
    resetHint: 'crt.sh rate limit reached; try again in a few minutes.'
  }
});
const DEFAULT_QUOTA_POLICY = Object.freeze({
  period: null, hintKey: 'source.quota.later', resetHint: 'Rate limited by the service; try again later.'
});

/**
 * Quota info for a result: `limited` when the service refused the request (used by lib/sources.js).
 * @returns {SourceQuota|null}
 */
export function buildQuota(id, { limited = false, err = null, rate = null } = {}) {
  if (!limited && !rate) return null;
  const policy = QUOTA_POLICY[id] || DEFAULT_QUOTA_POLICY;
  const retryAfterMs = err && Number.isFinite(err.retryAfterMs) && err.retryAfterMs >= 0 ? err.retryAfterMs : null;
  return {
    limited: !!limited,
    period: policy.period,
    retryAfterMs,
    resetAt: retryAfterMs !== null ? new Date(Date.now() + retryAfterMs) : null,
    limit: rate ? rate.limit : null,
    remaining: rate ? rate.remaining : null,
    resetHint: limited ? policy.resetHint : null,
    hintKey: limited ? policy.hintKey : null
  };
}

/**
 * The {@link SourceQuota} of a source's rate limit, for callers that query a source themselves
 * (lib/ctcert.js reads one host name's certificate from Cert Spotter / crt.sh): the same period
 * and i18n hint as a scan's source status.
 * @param {string} id source id ('certspotter', 'crtsh', …; unknown ids get the generic policy)
 * @param {{ limited?: boolean, retryAfterMs?: number|null }} [opts]
 * @returns {SourceQuota|null} null when not limited
 */
export function sourceQuota(id, { limited = false, retryAfterMs = null } = {}) {
  return buildQuota(id, { limited, err: { retryAfterMs } });
}

/* ------------------------------------------------------------------------ */
/* Health summary                                                           */
/* ------------------------------------------------------------------------ */

/** States reported by sourceHealthSummary(), best first. */
export const SOURCE_HEALTH_STATES = Object.freeze(['ok', 'empty', 'partial', 'rate-limited', 'unavailable', 'timeout', 'error']);

const OK_STATES = new Set(['ok', 'empty', 'partial']);
/** Most informative failure first when a source failed differently for several domains. */
const FAIL_PRIORITY = ['rate-limited', 'unavailable', 'timeout', 'error'];
/** CT twins: when one fails, the other still provides certificate data. */
const CT_TWIN = Object.freeze({ crtsh: 'certspotter', certspotter: 'crtsh' });

/** @returns {'ok'|'empty'|'partial'|'rate-limited'|'unavailable'|'timeout'|'error'} */
function resultState(r) {
  if (r.ok) {
    if (r.partial) return 'partial';
    return (r.names?.length || r.certs?.length || r.ipHints?.length) ? 'ok' : 'empty';
  }
  if (r.errorKind === 'rate-limit') return 'rate-limited';
  if (r.errorKind === 'unavailable') return 'unavailable';
  if (r.errorKind === 'timeout') return 'timeout';
  return 'error';
}

function plural(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

/**
 * @typedef {object} SourceHealth
 * @property {string} source id
 * @property {string} name display name
 * @property {string|null} homepage
 * @property {'ok'|'empty'|'partial'|'rate-limited'|'unavailable'|'timeout'|'error'} state
 *   aggregated over domains ('partial' when it worked for some domains only)
 * @property {boolean} ok at least one domain returned data or a clean empty answer
 * @property {number} names unique names over all domains
 * @property {number} ipHints
 * @property {number} certs
 * @property {number} elapsedMs slowest domain
 * @property {number} attempts HTTP requests over all domains
 * @property {string|null} errorKind first failure's kind
 * @property {string|null} error first failure's message
 * @property {SourceQuota|null} quota a limited quota first, else any readable one
 * @property {boolean} truncated
 * @property {number|null} available total records the source reported (summed)
 * @property {string|null} fallback CT twin id whose data replaced this failed source (crtsh ↔ certspotter)
 * @property {string} message short English status line (UIs localize from `state` + fields)
 * @property {Array<{ domain: string|null, state: string, names: number, errorKind: string|null, error: string|null }>} domains
 */

/**
 * Compact per-source status list for UIs and CLIs (in SOURCES order, unknown
 * ids after). Accepts SourceResult[] (any number of domains) or a
 * fetchAllSources() output.
 * @param {SourceResult[]|{ results: SourceResult[] }} results
 * @returns {SourceHealth[]}
 */
export function sourceHealthSummary(results) {
  const list = Array.isArray(results) ? results : Array.isArray(results?.results) ? results.results : [];
  const groups = new Map();
  for (const r of list) {
    if (!r || typeof r !== 'object' || typeof r.source !== 'string') continue;
    if (!groups.has(r.source)) groups.set(r.source, []);
    groups.get(r.source).push(r);
  }
  const order = [...SOURCES.map((s) => s.id).filter((id) => groups.has(id)),
    ...[...groups.keys()].filter((id) => !SOURCES.some((s) => s.id === id))];
  const okDomains = (id) => new Set((groups.get(id) || []).filter((r) => r.ok).map((r) => r.domain));
  return order.map((id) => {
    const rs = groups.get(id);
    const def = SOURCES.find((s) => s.id === id);
    const name = def ? def.name : id;
    const states = rs.map(resultState);
    const okCount = states.filter((s) => OK_STATES.has(s)).length;
    let state;
    if (okCount === states.length) {
      state = states.includes('partial') ? 'partial' : states.includes('ok') ? 'ok' : 'empty';
    } else if (okCount) {
      state = 'partial';
    } else {
      state = FAIL_PRIORITY.find((s) => states.includes(s)) || 'error';
    }
    const failed = rs.filter((r) => !r.ok || r.partial);
    const firstFail = failed.find((r) => !r.ok) || failed[0] || null;
    const quotas = rs.map((r) => r.quota).filter(Boolean);
    const quota = quotas.find((q) => q.limited) || quotas[0] || null;
    const uniqueNames = new Set(rs.flatMap((r) => r.names || []));
    const twin = CT_TWIN[id];
    let fallback = null;
    if (twin && groups.has(twin)) {
      const twinOk = okDomains(twin);
      if (rs.some((r) => !r.ok && twinOk.has(r.domain))) fallback = twin;
    }
    const twinName = fallback ? (SOURCES.find((s) => s.id === fallback) || { name: fallback }).name : '';
    const also = fallback ? `; ${twinName} was used for certificate data` : '';
    const errText = firstFail && firstFail.error ? firstFail.error : 'failed';
    const found = [plural(uniqueNames.size, 'name')];
    const ipCount = rs.reduce((a, r) => a + (r.ipHints?.length || 0), 0);
    if (ipCount) found.push(plural(ipCount, 'IP hint'));
    let message;
    switch (state) {
      case 'ok': message = found.join(', ') + (rs.some((r) => r.truncated) ? ' (page limit reached)' : ''); break;
      case 'empty': message = 'No names found'; break;
      case 'partial': message = `${found.join(', ')} (incomplete: ${errText})`; break;
      case 'rate-limited': message = `${name}: ${(quota && quota.resetHint) || errText}`; break;
      case 'unavailable': message = `${name} is temporarily down${also}`; break;
      case 'timeout': message = `${name} timed out${also}`; break;
      default: message = `${errText}${also}`;
    }
    const available = rs.map((r) => r.available).filter((v) => Number.isFinite(v));
    return {
      source: id,
      name,
      homepage: def ? def.homepage : null,
      state,
      ok: okCount > 0,
      names: uniqueNames.size,
      ipHints: ipCount,
      certs: rs.reduce((a, r) => a + (r.certs?.length || 0), 0),
      elapsedMs: Math.max(0, ...rs.map((r) => (Number.isFinite(r.elapsedMs) ? r.elapsedMs : 0))),
      attempts: rs.reduce((a, r) => a + (Number.isFinite(r.attempts) ? r.attempts : 0), 0),
      errorKind: firstFail ? firstFail.errorKind || null : null,
      error: firstFail ? firstFail.error || null : null,
      quota,
      truncated: rs.some((r) => r.truncated),
      available: available.length ? available.reduce((a, b) => a + b, 0) : null,
      fallback,
      message,
      domains: rs.map((r, i) => ({
        domain: r.domain ?? null, state: states[i], names: r.names?.length || 0, errorKind: r.errorKind ?? null, error: r.error ?? null
      }))
    };
  });
}
