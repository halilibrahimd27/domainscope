/**
 * tools/ds/commands.mjs — the checks of the headless runner, each over the app's own
 * DOM-free libraries (assets/js/lib) with an injected DohClient, fetch and AbortSignal.
 *
 * Every command returns `{ options, targets, docs, warnings }`:
 * - `options`: what the run was asked to do (goes into the report, compared by the baseline);
 * - `targets`: one plain, JSON-ready object per domain / name / zone / certificate — the part
 *   of the `--json` report tools/ds/diff.mjs compares, each with the lib's own export where
 *   there is one (`report` / `detail`);
 * - `docs`: lib/summary.js SummaryDocs (the app's "Copy summary" builders where the app has
 *   one: health, subdomains, renew; the same model for drift, ct and dane);
 * - `warnings`: sentences for stderr and the report.
 * The libraries and the views' pure helpers are imported on first use, so `ct` never loads
 * the discovery engine. Nothing here goes to Globalping.
 */

import { createHash } from 'node:crypto';
import { NODE_UNREADABLE, CT_SOURCES, DS_DEFAULT_RADAR, DS_VERSION, UsageError } from './args.mjs';
import { code, strong, isoDay, isoTime, summaryDoc, valueParts, localYesNo, sourceName, certCount } from './render.mjs';
import { targetOf, carryHealth, carryHosts, carryCt, ctIssuers, ctCertOrder, lookupFailed } from './carry.mjs';
import { isSubdomainOf, sortHostnames } from '../../assets/js/lib/domain.js';
import { chunk, throwIfAborted } from '../../assets/js/lib/util.js';
import { textParts, renderParts, cleanText } from '../../assets/js/lib/summary.js';
import { scoreHealth, countSeverities } from '../../assets/js/lib/healthscore.js';
import { createCtCooldown, CT_COOLDOWN_MS } from '../../assets/js/lib/ctcert.js';
import { healthWaivers, isWaivableCheck } from '../../assets/js/lib/waivers.js';
import { watchTarget, renewalOverdue } from './ctwatch.mjs';
import { waiversDoc } from './waivers.mjs';

const APP = 'DomainScope';
const DAY_MS = 86400000;
/** Lines of problems / rows / issuances a summary lists before "+N more" (lib/summary.js SUMMARY_MAX_PROBLEMS). */
const MAX_LINES = 5;

/* ------------------------------------------------------------------------ */
/* Sources a run stops asking                                               */
/* ------------------------------------------------------------------------ */

/** crt.sh failures of the service itself (every retry answered 5xx / 429 / nothing): not asked again. */
const CRTSH_DOWN = new Set(['unavailable', 'rate-limit', 'network']);
/** crt.sh timeouts on this many domains in a row: not asked again (one very large domain can be too slow alone). */
const CRTSH_TIMEOUTS = 2;

/**
 * The passive sources a run stops asking, so a list of domains neither prolongs a rate limit nor
 * waits for a service that is down on every domain (lib/doh.js does the same for resolvers):
 * - Cert Spotter after a rate limit (HTTP 429, or a readable X-RateLimit-Remaining of 0): its
 *   anonymous quota is about 10 full-domain queries an hour per IP address, and GitHub's hosted
 *   runners share addresses. Not asked until its Retry-After (at most an hour, lib/ctcert.js
 *   CT_COOLDOWN_MS) is over.
 * - crt.sh after it failed as a service (every retry unavailable or rate limited: up to three
 *   minutes per domain), or timed out on {@link CRTSH_TIMEOUTS} domains in a row. Not asked again
 *   this run.
 * The domains after that get the source as "not asked" (`skipped`): nothing read, nothing known.
 * @param {{ now: () => Date, spotterHint?: string }} opts `spotterHint`: how to leave Cert
 *   Spotter out, for the sentence ('--sources crtsh leaves it out')
 * @returns {{ ask: (ids: string[]) => string[], skipped: (ids: string[]) => object[],
 *   note: (domain: string, results: object[]) => string[] }} `ask`: the ids to ask now;
 *   `skipped`: SourceHealth-like entries of the ids not asked; `note`: one domain's
 *   lib/sources.js SourceResults, returning a sentence for each source it stops asking
 */
export function createSourceBreaker({ now, spotterHint = '' }) {
  const at = () => now().getTime();
  const spotter = createCtCooldown();
  let crtsh = null;
  let crtshTimeouts = 0;
  const benched = (id) => (id === 'certspotter' ? spotter.get(at()) : id === 'crtsh' ? crtsh : null);
  return {
    ask: (ids) => ids.filter((id) => !benched(id)),
    skipped: (ids) => ids.filter((id) => benched(id)).map((id) => {
      const b = benched(id);
      return { source: id, state: b.state, ok: false, truncated: false, errorKind: b.errorKind, error: b.error, skipped: true };
    }),
    note(domain, results) {
      const out = [];
      for (const r of results || []) {
        if (!r || typeof r !== 'object') continue;
        if (r.source === 'certspotter' && !spotter.get(at())) {
          const quota = r.quota || {};
          const limited = r.errorKind === 'rate-limit';
          if (!limited && quota.remaining !== 0) continue;
          const waitMs = Number.isFinite(quota.retryAfterMs) && quota.retryAfterMs > 0 ? Math.min(quota.retryAfterMs, CT_COOLDOWN_MS) : CT_COOLDOWN_MS;
          const until = new Date(at() + waitMs);
          spotter.set({ state: 'rate-limited', errorKind: 'rate-limit', error: `not asked: rate limited since ${domain}` }, until.getTime());
          out.push(`Cert Spotter ${limited ? 'answered "rate limited"' : 'had no request left this hour'} for ${domain}: not asked again until ${isoTime(until).slice(11, 16)} UTC `
            + `(its anonymous quota is about 10 full-domain queries an hour per IP address, and GitHub's runners share addresses${spotterHint ? `; ${spotterHint}` : ''})`);
        }
        if (r.source === 'crtsh' && !crtsh) {
          if (r.ok) {
            crtshTimeouts = 0;
            continue;
          }
          crtshTimeouts = r.errorKind === 'timeout' ? crtshTimeouts + 1 : 0;
          if (!CRTSH_DOWN.has(r.errorKind) && crtshTimeouts < CRTSH_TIMEOUTS) continue;
          const state = r.errorKind === 'rate-limit' ? 'rate-limited' : r.errorKind === 'timeout' ? 'timeout' : 'unavailable';
          crtsh = { state, errorKind: r.errorKind, error: `not asked: ${state.replace('-', ' ')} since ${domain}` };
          out.push(r.errorKind === 'timeout'
            ? `crt.sh timed out on ${CRTSH_TIMEOUTS} domains in a row (the last: ${domain}): not asked again this run`
            : `crt.sh was ${state.replace('-', ' ')} for ${domain}: not asked again this run`);
        }
      }
      return out;
    }
  };
}

/** The source ids a run asks by default (lib/sourceinfo.js `defaultEnabled`). */
async function defaultSourceIds() {
  const { SOURCES } = await import('../../assets/js/lib/sourceinfo.js');
  return SOURCES.filter((s) => s.defaultEnabled).map((s) => s.id);
}

/* ------------------------------------------------------------------------ */
/* health                                                                   */
/* ------------------------------------------------------------------------ */

/** A waiver as a report keeps it beside its item (the file's own fields, never its kind or ref twice). */
export const waiverOut = (w) => ({ id: w.id, reason: w.reason, owner: w.owner || '', expires: w.expires });

/**
 * The compared part of one Domain Health report: the score, the counts, every check (its
 * title key and language-neutral params, so a change quotes their values as code spans, and
 * the English title to read the file by), the lookups that failed and, for each area whose
 * lookup failed, the checks the last run that read it found (`carried`, carry.mjs carryHealth);
 * `report` is the report itself (the view's "Report (JSON)"). With `--waivers`: an error or a
 * warning an active waiver accepts carries it (`waiver`) and is left out of the score, the grade
 * and the light (`waived`: how many, the first day one ends, the score with them), one whose
 * waiver is over carries that (`waiverExpired`: it counts again).
 * @param {object} report lib/health.js domainHealth() result
 * @param {{ t: Function, trafficLight: Function }} kit (the score and its grade: lib/healthscore.js, SPEC §5.78)
 * @param {{ prev?: object|null, prevAt?: string|null }} [baseline] the baseline's target of the
 *   domain and the baseline run's start
 * @param {{ waivers?: object[]|null, now?: Date }} [accepted] lib/waivers.js waivers, read at `now`
 * @returns {object}
 */
export function healthTarget(report, { t, trafficLight }, { prev = null, prevAt = null } = {}, { waivers = null, now = new Date() } = {}) {
  const hw = waivers ? healthWaivers(report, waivers, { now }) : null;
  const ids = hw ? hw.ids : null;
  const graded = scoreHealth(report.checks, { waived: ids });
  const expiredById = new Map(hw ? hw.expired.map((e) => [e.check.id, e.waiver]) : []);
  const x = {
    target: report.domain,
    checkedAt: isoTime(report.checkedAt),
    score: graded.score,
    grade: graded.grade,
    light: trafficLight(ids && ids.size ? countSeverities(report.checks, { waived: ids }) : report.summary),
    summary: { ...report.summary },
    ...(hw ? { waived: { count: graded.waived, until: hw.until, scoreWith: graded.full ? graded.full.score : graded.score, gradeWith: graded.full ? graded.full.grade : graded.grade } } : {}),
    failedLookups: [...(report.failedLookups || [])],
    checks: (report.checks || []).map((c) => {
      const w = hw && isWaivableCheck(c) ? hw.byId.get(c.id) : null;
      const gone = hw && !w && isWaivableCheck(c) ? expiredById.get(c.id) : null;
      return {
        id: c.id, severity: c.severity, titleKey: c.titleKey, params: { ...c.params }, title: t(c.titleKey, localYesNo(t, c.params)),
        ...(w ? { waiver: waiverOut(w) } : {}), ...(gone ? { waiverExpired: waiverOut(gone) } : {})
      };
    })
  };
  const carried = carryHealth(x, prev, { prevAt });
  return { ...x, ...(carried.length ? { carried } : {}), report };
}

async function runHealth(targets, options, env) {
  const { domainHealth } = await import('../../assets/js/lib/health.js');
  const { healthSummary, trafficLight } = await import('../../assets/js/lib/summary.js');
  const waivers = env.inputs && env.inputs.waivers ? env.inputs.waivers : null;
  const out = [];
  const docs = [];
  const use = { applied: [], expired: [], checked: [] };
  const prevAt = env.baseline ? env.baseline.startedAt ?? null : null;
  for (const [i, domain] of targets.entries()) {
    env.progress(`health ${domain} (${i + 1}/${targets.length})`);
    const report = await domainHealth(domain, { dns: env.dns, fetchImpl: env.fetchImpl, signal: env.signal });
    const now = env.now();
    const target = healthTarget(report, { t: env.t, trafficLight }, { prev: targetOf(env.baseline, domain), prevAt }, { waivers: waivers ? waivers.list : null, now });
    out.push(target);
    const accepted = target.checks.filter((c) => c.waiver);
    docs.push(healthSummary({ report, waived: waivers ? { ids: accepted.map((c) => c.id), until: target.waived ? target.waived.until : null } : null }, { t: env.t, now }));
    const what = (c) => [code(c.id), ' — ', ...textParts(env.t, c.titleKey || `health.${c.id}.title`, localYesNo(env.t, c.params))];
    use.checked.push(target.target);
    use.applied.push(...accepted.map((c) => ({ target: target.target, what: what(c), waiver: c.waiver })));
    use.expired.push(...target.checks.filter((c) => c.waiverExpired).map((c) => ({ target: target.target, what: what(c), waiver: c.waiverExpired })));
  }
  if (waivers) docs.push(waiversDoc('health', waivers, use, { t: env.t, now: env.now() }));
  return { options: { resolvers: [...options.chain], ...(waivers ? { waivers: waivers.file } : {}) }, targets: out, docs, warnings: [] };
}

/* ------------------------------------------------------------------------ */
/* subdomains                                                               */
/* ------------------------------------------------------------------------ */

const sortedIps = (list) => [...new Set(list || [])].sort();

/**
 * One host of a ScanResult as the report keeps it (lib/export.js scanHostRows without what
 * changes on every run — TTL, the resolver that answered — or needs a certificate or an
 * inventory; addresses sorted, so a rotating answer order is no change).
 * @param {object} row a scanHostRows row
 * @param {Set<string>} seeded names the previous run's report seeded
 */
export function hostRow(row, seeded = new Set()) {
  const origins = row.origins.map((o) => (o === 'input' && seeded.has(row.name) ? 'baseline' : o));
  return {
    name: row.name, status: row.status, kind: row.kind, provider: row.provider, providerId: row.providerId,
    hidesOrigin: row.hidesOrigin, dangling: row.dangling,
    ipv4: sortedIps(row.ipv4), ipv6: sortedIps(row.ipv6), cnames: [...row.cnames],
    origins: [...new Set(origins)], wildcardSuspect: row.wildcardSuspect, error: row.error
  };
}

/** Does a report host answer with an address (IPv4 or IPv6)? */
export function hostResolves(host) {
  return !!host && ((host.ipv4 && host.ipv4.length > 0) || (host.ipv6 && host.ipv6.length > 0));
}

/**
 * The hosts a report lists. An exact run lists every name of its file. A discovery run lists the
 * hosts that resolve, dangling aliases, failed lookups and the names the previous run seeded
 * (so one that stopped resolving is compared); the rest — names the passive sources know that
 * resolve to nothing, wildcard look-alikes — are only counted (`counts`), or a busy domain's
 * nightly report would carry tens of thousands of dead names.
 * @param {object[]} rows {@link hostRow} rows
 * @param {{ exact: boolean, seeded: Set<string> }} opts
 * @returns {object[]}
 */
export function reportHosts(rows, { exact, seeded }) {
  if (exact) return rows;
  return rows.filter((h) => !h.wildcardSuspect && (hostResolves(h) || h.dangling || lookupFailed(h) || seeded.has(h.name)));
}

/**
 * The names of the previous run of a domain to resolve again this run (discovery only): its
 * resolving hosts, dangling aliases and hosts whose lookup failed, so a host is never "gone"
 * (nor dropped from the watch) only because a passive source was down, a guess was not tried
 * this time or one lookup failed.
 * @param {object|null} baseline a validated `subdomains` report
 * @param {string} domain
 * @returns {string[]}
 */
export function baselineSeeds(baseline, domain) {
  const prev = targetOf(baseline, domain);
  if (!prev || prev.mode !== 'discover' || !Array.isArray(prev.hosts)) return [];
  return prev.hosts.filter((h) => h && !h.wildcardSuspect && (hostResolves(h) || h.dangling || lookupFailed(h)) && h.name !== domain
    && isSubdomainOf(h.name, domain)).map((h) => h.name);
}

/** A discovery stage this long gets progress lines (a nightly log that says nothing for minutes looks hung). */
const PROGRESS_MIN_TOTAL = 1000;
/** Progress lines per long stage (one per tenth). */
const PROGRESS_STEPS = 10;

/**
 * A lib/scanner.js `onProgress` hook that says how far a long stage is, in steps of a tenth:
 * `subdomains example.com: resolve 2,000/20,000 (10%)`. Stages under {@link PROGRESS_MIN_TOTAL}
 * names say nothing more than their start.
 * @param {string} domain
 * @param {(text: string) => void} progress
 * @returns {(p: { stage: string, done: number, total: number }) => void}
 */
export function stageProgress(domain, progress) {
  const last = new Map();
  const n = (v) => Number(v).toLocaleString('en-US');
  return ({ stage, done, total } = {}) => {
    if (!Number.isFinite(total) || total < PROGRESS_MIN_TOTAL || !Number.isFinite(done)) return;
    const step = Math.min(PROGRESS_STEPS, Math.floor((done * PROGRESS_STEPS) / total));
    if (step <= (last.get(stage) ?? 0)) return;
    last.set(stage, step);
    progress(`subdomains ${domain}: ${stage} ${n(Math.min(done, total))}/${n(total)} (${Math.round((step * 100) / PROGRESS_STEPS)}%)`);
  };
}

/**
 * A ScanResult warning as the Subdomains view words it (`sub.warn.<code>`, registered when
 * views/subdomains.js is imported), as summary parts: its detail is a code part (it can be a
 * name from a source). Unknown codes read `CODE: detail`.
 * @param {Function} t
 * @param {{ code: string, detail?: unknown }} w
 * @param {string[]} known views/subdomains.js WARNING_CODES
 * @returns {Array}
 */
export function scanWarningParts(t, w, known) {
  const detail = w.detail === undefined || w.detail === null ? '' : String(w.detail);
  if (known.includes(w.code)) return textParts(t, `sub.warn.${w.code}`, { detail });
  return [String(w.code), ...(detail ? [': ', code(detail)] : [])];
}

async function runSubdomains(targets, options, env) {
  const { runScan } = await import('../../assets/js/lib/scanner.js');
  const { scanHostRows } = await import('../../assets/js/lib/export.js');
  const { subdomainsSummary } = await import('../../assets/js/lib/summary.js');
  // The view's own pure helpers (DOM-free at import, tests/js/i18n-coverage.test.js): the stat
  // cards, its Copy summary facts (with the run's results, ui/subdomains-run.js), its scan
  // concurrency and its warning sentences, so the report says what the app says.
  const { countHosts, scanConcurrency, WARNING_CODES } = await import('../../assets/js/views/subdomains.js');
  const { subdomainsSummaryFacts } = await import('../../assets/js/ui/subdomains-run.js');
  const exact = Array.isArray(env.inputs.exactNames);
  const out = [];
  const docs = [];
  const warnings = [];
  const pool = scanConcurrency(options.concurrency);
  const sources = exact ? [] : options.sources || await defaultSourceIds();
  const breaker = createSourceBreaker({ now: env.now });
  if (exact) {
    const outside = env.inputs.exactNames.filter((n) => !targets.some((d) => n === d || isSubdomainOf(n, d)));
    if (outside.length) warnings.push(`${outside.length} name${outside.length === 1 ? '' : 's'} of ${env.inputs.exactFile} under none of the domains left out (never sent)`);
  }
  for (const [i, domain] of targets.entries()) {
    const own = exact ? env.inputs.exactNames.filter((n) => n === domain || isSubdomainOf(n, domain)) : [];
    if (exact && !own.length) warnings.push(`${domain}: no name of ${env.inputs.exactFile} is under it; only the domain itself is resolved`);
    const seeds = exact ? [] : baselineSeeds(env.baseline, domain);
    const ask = breaker.ask(sources);
    const notAsked = sources.filter((s) => !ask.includes(s));
    env.progress(`subdomains ${domain} (${i + 1}/${targets.length})${exact ? `, ${own.length} names` : `, level ${options.level}`}`
      + `${notAsked.length ? `, not asking ${notAsked.map(sourceName).join(' or ')}` : ''}`);
    const result = await runScan({
      domains: [domain],
      extraNames: exact ? own : seeds,
      exact,
      ...(exact ? { sources: [], bruteforce: 'off', permutationBudget: 0, recursive: false, mine: false } : {
        ...(options.sources || notAsked.length ? { sources: ask } : {}),
        bruteforce: options.level
      }),
      originHints: true,
      resolverLeak: true,
      dns: env.dns,
      fetchImpl: env.fetchImpl,
      signal: env.signal,
      concurrency: pool,
      maxConcurrency: pool
    }, {
      onStage: (stage, info = {}) => {
        if (!info.skipped && stage !== 'done') env.progress(`subdomains ${domain}: ${stage}`);
      },
      onProgress: stageProgress(domain, env.progress)
    });
    if (!exact) warnings.push(...breaker.note(domain, result.sources));
    // The scanner's own warnings (a cut list of names, a DNS pool that stopped answering …): what
    // the view shows above its results, for stderr, the report and the summary.
    const scanWarnings = [];
    for (const w of result.warnings || []) {
      if (!w || typeof w.code !== 'string' || scanWarnings.some((x) => x.code === w.code && x.detail === w.detail)) continue;
      scanWarnings.push(w);
    }
    const warnParts = scanWarnings.map((w) => scanWarningParts(env.t, w, WARNING_CODES));
    for (const parts of warnParts) warnings.push(`${domain}: ${renderParts(parts, 'text')}`);
    const seeded = new Set(seeds);
    out.push({
      target: domain,
      mode: exact ? 'exact' : 'discover',
      level: exact ? null : result.options.bruteforce,
      sources: [
        ...(result.sourceHealth || []).map((s) => ({ source: s.source, state: s.state, names: s.names, error: s.error || null })),
        ...breaker.skipped(notAsked).map((s) => ({ source: s.source, state: s.state, names: 0, error: s.error, skipped: true }))
      ],
      finishedAt: isoTime(result.finishedAt),
      counts: countHosts(result.hosts),
      warnings: [...new Set(scanWarnings.map((w) => w.code))],
      seeded: seeds.length,
      // A host whose lookup failed keeps its last answer (carry.mjs): the next run compares with it.
      hosts: carryHosts(reportHosts(scanHostRows(result).map((row) => hostRow(row, seeded)), { exact, seeded }),
        targetOf(env.baseline, domain), { prevAt: env.baseline ? env.baseline.startedAt ?? null : null })
    });
    const run = { status: 'done', config: { domains: [domain] }, result, hosts: result.hosts, found: new Map(), sourceResults: result.sources, finishedAt: result.finishedAt };
    const doc = subdomainsSummary(subdomainsSummaryFacts(run), { t: env.t, now: env.now() });
    const unasked = breaker.skipped(notAsked).map((s) => `${sourceName(s.source)} (${s.state.replace('-', ' ')} earlier in this run)`);
    docs.push({
      ...doc,
      lines: [
        ...doc.lines,
        ...(unasked.length ? [[`Not asked: ${unasked.join(', ')}: the list may be incomplete`]] : []),
        ...warnParts.map((parts) => [strong('Warning:'), ' ', ...parts])
      ]
    });
  }
  return {
    options: exact
      ? { mode: 'exact', names: env.inputs.exactNames.length, resolvers: [...options.chain] }
      : { mode: 'discover', level: options.level, sources: options.sources, resolvers: [...options.chain] },
    targets: out, docs, warnings
  };
}

/* ------------------------------------------------------------------------ */
/* ct                                                                       */
/* ------------------------------------------------------------------------ */

/**
 * A certificate's identity across sources and runs: crt.sh and Cert Spotter key the same
 * certificate differently (lib/sources.js mergeCerts folds twins by validity and names), so the
 * id is a digest of the validity, the names and the issuing intermediate's CN.
 * @param {{ notBefore: Date|string|null, notAfter: Date|string|null, names: string[], intermediate: string|null }} cert
 * @returns {string} 16 hex characters
 */
export function ctCertId(cert) {
  const sig = [isoTime(cert.notBefore), isoTime(cert.notAfter), [...(cert.names || [])].sort().join(','), (cert.intermediate || '').toLowerCase()].join('|');
  return createHash('sha256').update(sig).digest('hex').slice(0, 16);
}

/**
 * What a certificate's DER (Cert Spotter's `cert_der`, base64) says: its serial number, whether
 * it is a precertificate (the CT poison extension) and its public key's SHA-256 (the
 * SubjectPublicKeyInfo's: a known certificate's ref, lib/waivers.js). Null when there is none or it
 * cannot be read.
 * @param {string|undefined} b64
 * @param {(der: Uint8Array) => { serialHex: string, isPrecertificate: boolean, spkiDer?: Uint8Array }} parseCertificate lib/x509.js
 * @returns {{ serialHex: string|null, precert: boolean, spkiSha256: string|null }|null}
 */
export function readCertDer(b64, parseCertificate) {
  if (typeof b64 !== 'string' || !b64 || typeof parseCertificate !== 'function') return null;
  try {
    const cert = parseCertificate(new Uint8Array(Buffer.from(b64, 'base64')));
    const spki = cert.spkiDer instanceof Uint8Array && cert.spkiDer.length ? createHash('sha256').update(cert.spkiDer).digest('hex') : null;
    return { serialHex: cert.serialHex ? String(cert.serialHex).toLowerCase() : null, precert: !!cert.isPrecertificate, spkiSha256: spki };
  } catch {
    return null;
  }
}

/**
 * The compared part of one domain's certificates in CT: when it was read, every current
 * certificate (id, CA, intermediate, validity, names, the serial number when a source says it, the
 * sources that list it, revoked and precertificate only — null where no source says), the issuers
 * with their counts, the names, and how each source answered (`complete`: every source answered in
 * full; `skipped`: not asked, {@link createSourceBreaker}). The CA is named from the issuer DN
 * alone (the known CA, else its O, else its CN), never from Cert Spotter's friendly name, so a
 * certificate reads the same whichever source answered: a night without crt.sh is no "new
 * issuer". What a source not read in full listed before is added by carry.mjs carryCt, the CT
 * watch's fields by tools/ds/ctwatch.mjs watchTarget.
 * @param {string} domain
 * @param {{ certs: object[], health: object[] }} fetched lib/sources.js fetchAllSources() result
 *   (`health` may add the sources not asked)
 * @param {{ issuerName: Function, dnPart: Function, days: number, now: Date, sources: string[], readAt?: Date,
 *   parseCertificate?: Function }} opts `readAt`: when the read began (default `now`);
 *   `parseCertificate`: lib/x509.js's, for the DER Cert Spotter sent ({@link readCertDer})
 * @returns {object}
 */
export function ctTarget(domain, fetched, { issuerName, dnPart, days, now, sources, readAt = now, parseCertificate = null }) {
  const certificates = [];
  const byId = new Map();
  // The names under the domain only: crt.sh rows carry the searched names, Cert Spotter every
  // SAN of a certificate that also names other domains, and the id must be the same for both.
  const own = (n) => {
    const bare = String(n).replace(/^\*\./, '');
    return bare === domain || isSubdomainOf(bare, domain);
  };
  for (const c of fetched.certs || []) {
    const intermediate = dnPart(c.issuer, 'CN');
    const der = readCertDer(c.der, parseCertificate);
    const fields = {
      ca: issuerName(c.issuer),
      intermediate,
      issuer: c.issuer || '',
      notBefore: isoTime(c.notBefore),
      notAfter: isoTime(c.notAfter),
      names: sortHostnames([...new Set((c.names || []).filter(own))]),
      sha256: c.sha256 || null,
      // the public key's SHA-256: Cert Spotter's pubkey_sha256, else from its DER (a known certificate's ref)
      spkiSha256: (typeof c.pubkeySha256 === 'string' && /^[0-9a-f]{64}$/.test(c.pubkeySha256) && c.pubkeySha256) || (der && der.spkiSha256) || null,
      serialHex: (typeof c.serialHex === 'string' && c.serialHex) || (der && der.serialHex) || null,
      sources: [...(c.sources || [c.source])].sort(),
      revoked: typeof c.revoked === 'boolean' ? c.revoked : null,
      precert: der ? der.precert : null
    };
    const cert = { id: ctCertId(fields), ...fields };
    const twin = byId.get(cert.id);
    if (twin) {
      twin.sources = [...new Set([...twin.sources, ...cert.sources])].sort();
      twin.sha256 = twin.sha256 || cert.sha256;
      twin.spkiSha256 = twin.spkiSha256 || cert.spkiSha256;
      twin.serialHex = twin.serialHex || cert.serialHex;
      if (twin.revoked === null) twin.revoked = cert.revoked;
      if (twin.precert === null) twin.precert = cert.precert;
      continue;
    }
    byId.set(cert.id, cert);
    certificates.push(cert);
  }
  certificates.sort(ctCertOrder);
  const health = (fetched.health || []).filter((h) => sources.includes(h.source));
  const since = now.getTime() - days * DAY_MS;
  return {
    target: domain,
    days,
    readAt: isoTime(readAt),
    sources: health.map((h) => ({
      source: h.source, state: h.state, ok: h.ok, truncated: !!h.truncated, errorKind: h.errorKind || null, error: h.error || null,
      ...(h.skipped ? { skipped: true } : {})
    })),
    complete: sources.every((id) => health.some((h) => h.source === id && h.ok && h.state !== 'partial' && !h.truncated)),
    answered: health.some((h) => h.ok),
    recent: certificates.filter((c) => Date.parse(c.notBefore) >= since).length,
    issuers: ctIssuers(certificates),
    names: sortHostnames([...new Set(certificates.flatMap((c) => c.names))]),
    certificates
  };
}

/**
 * "on 2026-09-27", "between 2026-09-25 and 2026-09-27", or "by an earlier run": when a
 * domain's carried certificates were last read.
 * @param {Array<string|null>} times ISO times (null: unknown)
 */
function readWhen(times) {
  const days = [...new Set(times.map((at) => (at ? isoDay(at) : '')))].sort();
  if (!days.length || days.includes('')) return 'by an earlier run';
  return days.length === 1 ? `on ${days[0]}` : `between ${days[0]} and ${days.at(-1)}`;
}

/** "12 days left", "1 day left", "less than a day left". */
const daysLeftText = (n) => (n < 1 ? 'less than a day left' : `${n} day${n === 1 ? '' : 's'} left`);

/** A certificate's CA and intermediate as parts: `Let's Encrypt` (`R11`). */
const caParts = (c) => [code(c.ca), ...(c.intermediate ? [' (', code(c.intermediate), ')'] : [])];

/** What a listed certificate also is, after its names. */
function flagParts(c, { unexpected = true } = {}) {
  const out = [];
  if (unexpected && c.unexpected === true) out.push(' — not one of the expected CAs');
  if (c.precert === true) out.push(' — precertificate only');
  if (c.revoked === true) out.push(' — revoked');
  return out;
}

/**
 * The CT watch's lines of a domain's summary (tools/ds/ctwatch.mjs watchTarget), as the app's tab
 * shows them: the expiry radar and the current certificates within it, soonest first (with a
 * renewal that is overdue said); with --baseline what was logged since the last run that read the
 * domain, or that this is the first; with --expected-ca the certificates from another CA; how many
 * are wildcard, precertificate only or revoked.
 * @param {object} target
 * @param {{ t: Function, baselined: boolean }} opts
 * @returns {Array[]} lines of parts
 */
export function ctWatchLines(target, { t, baselined }) {
  const w = target.watch;
  if (!w || !Array.isArray(w.radar) || !w.radar.length) return [];
  const lines = [];
  const certs = target.certificates || [];
  const reach = w.radar[0];
  const more = (n, what) => lines.push([`${n} more ${what} (see the JSON report)`]);
  const within = certs.filter((c) => c.current && Number.isFinite(c.daysLeft) && c.daysLeft <= reach)
    .sort((a, b) => a.daysLeft - b.daysLeft || a.id.localeCompare(b.id));
  lines.push([`Expiry radar (${w.radar.join(', ')} days): `, within.length
    ? `${within.length} current certificate${within.length === 1 ? '' : 's'} within ${reach} days`
    : `no current certificate within ${reach} days`]);
  for (const c of within.slice(0, MAX_LINES)) {
    lines.push([`${daysLeftText(c.daysLeft)} (${isoDay(c.notAfter)}), `, ...caParts(c), ': ', ...valueParts(t, c.names),
      ...(renewalOverdue(c) ? [' — its renewal is overdue'] : []), ...flagParts(c)]);
  }
  if (within.length > MAX_LINES) more(within.length - MAX_LINES, `within ${reach} days`);
  if (baselined) {
    if (!w.comparedWith) {
      lines.push(['First run for this domain: nothing is marked new; the next run marks what is logged after this one']);
    } else {
      const fresh = certs.filter((c) => c.isNew === true);
      lines.push([`New since the last run (${isoDay(w.comparedWith)}): ${fresh.length || 'none'}`]);
      for (const c of fresh.slice(0, MAX_LINES)) lines.push([`${isoDay(c.notBefore)} `, ...caParts(c), ': ', ...valueParts(t, c.names), ...flagParts(c)]);
      if (fresh.length > MAX_LINES) more(fresh.length - MAX_LINES, 'new since the last run');
    }
  }
  if (Array.isArray(w.expected) && w.expected.length) {
    const odd = certs.filter((c) => c.unexpected === true);
    lines.push(['Unexpected CA (expected: ', ...valueParts(t, w.expected, 5), `): ${odd.length || 'none'}`]);
    for (const c of odd.slice(0, MAX_LINES)) {
      lines.push([`${isoDay(c.notBefore)} `, ...caParts(c), ': ', ...valueParts(t, c.names), ...flagParts(c, { unexpected: false })]);
    }
    if (odd.length > MAX_LINES) more(odd.length - MAX_LINES, 'from an unexpected CA');
  }
  const counts = w.counts || {};
  const extra = [['wildcard', counts.wildcard], ['precertificate only', counts.precert], ['revoked', counts.revoked]].filter(([, n]) => n > 0);
  if (extra.length) {
    const text = extra.map(([label, n]) => `${label} ${n}`).join(' · ');
    lines.push([text[0].toUpperCase() + text.slice(1)]);
  }
  return lines;
}

/**
 * The summary of one domain's CT result: this run's read (the certificates carried from an
 * earlier read are counted apart, as kept for the next comparison), then the CT watch's lines
 * ({@link ctWatchLines}).
 * @param {object} target {@link ctTarget}, carried (carry.mjs carryCt), watched (ctwatch.mjs watchTarget)
 * @param {{ t: Function, now: Date, baselined?: boolean }} opts `baselined`: the run was given --baseline
 */
export function ctDoc(target, { t, now, baselined = false }) {
  const lines = [];
  const failed = target.sources.filter((s) => !s.ok);
  const why = (s) => `${sourceName(s.source)} (${String(s.state || 'error').replace('-', ' ')}${s.skipped ? ' earlier in this run: not asked' : ''})`;
  const read = target.certificates.filter((c) => !c.carried);
  const kept = target.certificates.filter((c) => c.carried);
  const keptText = `${kept.length === 1 ? 'The certificate' : `The ${kept.length} certificates`} last read ${readWhen(kept.map((c) => c.carried.from))} `
    + `${kept.length === 1 ? 'is' : 'are'} kept for the next comparison`;
  if (!target.answered) {
    const lastFull = target.sources.map((s) => s.lastFullAt).filter(Boolean);
    lines.push([`Certificate Transparency could not be read: ${failed.map(why).join(', ')}. `
      + `${kept.length ? `${keptText}.` : lastFull.length ? `The next run compares with the last full read ${readWhen(lastFull)} (no current certificate then).` : 'Nothing is known about this domain\'s certificates.'}`]);
  } else {
    const n = read.length;
    lines.push([n ? `${certCount(n)} · ${target.recent} issued in the last ${target.days} days` : 'No current certificate is logged for it']);
    const issuers = ctIssuers(read);
    if (issuers.length) {
      const parts = ['Issuers: '];
      issuers.slice(0, MAX_LINES).forEach((g, i) => {
        if (i) parts.push(', ');
        parts.push(code(g.name), ` ${g.count}`);
      });
      if (issuers.length > MAX_LINES) parts.push(` ${t('common.moreCount', { count: issuers.length - MAX_LINES })}`);
      lines.push(parts);
    }
    const since = now.getTime() - target.days * DAY_MS;
    const recent = read.filter((c) => Date.parse(c.notBefore) >= since);
    for (const c of recent.slice(0, MAX_LINES)) {
      lines.push([`${isoDay(c.notBefore)} `, code(c.ca), ...(c.intermediate ? [' (', code(c.intermediate), ')'] : []), ': ', ...valueParts(t, c.names)]);
    }
    if (recent.length > MAX_LINES) lines.push([`${recent.length - MAX_LINES} more issued in the last ${target.days} days (see the JSON report)`]);
    lines.push(...ctWatchLines(target, { t, baselined }));
    if (failed.length) lines.push([`Not read: ${failed.map(why).join(', ')}: the list may be incomplete`]);
    else if (!target.complete) lines.push(['A source returned only part of its list: the list may be incomplete']);
    if (kept.length) lines.push([`${keptText} (listed by a source not read in full this run)`]);
  }
  return summaryDoc('ct', ['Certificate Transparency · ', code(target.target)], lines, { t, now });
}

async function runCt(targets, options, env) {
  const { fetchAllSources } = await import('../../assets/js/lib/sources.js');
  const { issuerName, dnPart } = await import('../../assets/js/lib/passport.js');
  const { parseCertificate } = await import('../../assets/js/lib/x509.js');
  const { resolveExpectedCa, expectedCaStatus } = await import('../../assets/js/lib/expectedca.js');
  const sources = options.sources || [...CT_SOURCES];
  const radar = Array.isArray(options.radar) && options.radar.length ? [...options.radar] : [...DS_DEFAULT_RADAR];
  const expected = [...(options.expectedCas || [])];
  // the known certificates (--waivers, kind 'cert'): never new nor unexpected while their waiver lasts
  const waivers = env.inputs && env.inputs.waivers ? env.inputs.waivers : null;
  const use = { applied: [], expired: [], checked: [] };
  const breaker = createSourceBreaker({ now: env.now, spotterHint: sources.includes('crtsh') ? '--sources crtsh leaves it out' : '' });
  const prevAt = env.baseline ? env.baseline.startedAt ?? null : null;
  const out = [];
  const docs = [];
  const warnings = [];
  // A typo would make every issuer unexpected: an entry that names no CA the app knows (it is
  // looked for as text in the issuer, as for a private CA) and matches no issuer read is said.
  const textual = expected.filter((entry) => !resolveExpectedCa(entry).ca);
  const matched = new Set();
  for (const [i, domain] of targets.entries()) {
    const ask = breaker.ask(sources);
    env.progress(`ct ${domain} (${i + 1}/${targets.length})${ask.length < sources.length ? `, not asking ${sources.filter((s) => !ask.includes(s)).map(sourceName).join(' or ')}` : ''}`);
    const readAt = env.now();
    // Cert Spotter's DER of each issuance says which are precertificates only, and their serials.
    const fetched = ask.length
      ? await fetchAllSources(domain, { sources: ask, fetchImpl: env.fetchImpl, signal: env.signal, certDer: true })
      : { results: [], certs: [], health: [] };
    warnings.push(...breaker.note(domain, fetched.results));
    const now = env.now();
    const health = [...(fetched.health || []), ...breaker.skipped(sources.filter((s) => !ask.includes(s)))];
    // What a source not read in full listed before is carried from the baseline (carry.mjs): the
    // next run compares with the last read of each source, not with tonight's gap. Then the app's
    // CT watch over what is known (ctwatch.mjs), with the store of the ids seen for the next run.
    const prev = targetOf(env.baseline, domain);
    const read = ctTarget(domain, { certs: fetched.certs, health }, { issuerName, dnPart, days: options.days, now, sources, readAt, parseCertificate });
    const target = watchTarget(carryCt(read, prev, { now, prevAt }), { prev, prevAt, now, radar, expected, known: waivers ? waivers.list : [] });
    for (const entry of textual) {
      if (target.certificates.some((c) => (expectedCaStatus(c.issuer, [entry]) || {}).expected)) matched.add(entry);
    }
    out.push(target);
    docs.push(ctDoc(target, { t: env.t, now, baselined: !!options.baseline }));
    if (waivers && target.answered) {
      const what = (c) => [...valueParts(env.t, c.names), ' (', code(c.ca), ')'];
      use.checked.push(domain);
      use.applied.push(...target.certificates.filter((c) => c.known).map((c) => ({ target: domain, what: what(c), waiver: c.known })));
      use.expired.push(...target.certificates.filter((c) => c.knownExpired).map((c) => ({ target: domain, what: what(c), waiver: c.knownExpired })));
    }
  }
  for (const entry of textual.filter((e) => !matched.has(e))) {
    warnings.push(`--expected-ca "${cleanText(entry).slice(0, 80)}" names no CA DomainScope knows and no issuer read contains it: `
      + 'a typo there makes every issuer unexpected');
  }
  if (waivers) docs.push(waiversDoc('ct', waivers, use, { t: env.t, now: env.now() }));
  return { options: { sources, days: options.days, radar, expectedCas: expected, ...(waivers ? { waivers: waivers.file } : {}) }, targets: out, docs, warnings };
}

/* ------------------------------------------------------------------------ */
/* drift                                                                    */
/* ------------------------------------------------------------------------ */

/** DRIFT_SEVERITY ranks for "the worst rows first". */
const DRIFT_RANK = { error: 0, warn: 1, unknown: 2, info: 3, ok: 4 };

/**
 * One drift row as the report keeps it: every row by key and status; the values of a row that
 * needs a look (warn, error, could not check), with the origin addresses behind proxied names
 * hidden unless `includeOrigins` (the Zone File view's export rule). Rows that match keep no
 * values: the report is committed nightly and should not become a copy of the zone.
 * @param {object} row lib/zonedrift.js DriftRow
 * @param {{ severity: object, redact: (values: string[]) => string[] }} opts
 */
export function driftRow(row, { severity, redact }) {
  const out = { key: row.key, name: row.name, type: row.type, status: row.status, reasons: [...row.reasons] };
  const sev = severity[row.status];
  if (sev === 'warn' || sev === 'error' || sev === 'unknown') {
    Object.assign(out, {
      file: redact(row.file), live: redact(row.live), added: redact(row.added), removed: redact(row.removed),
      resolver: row.resolver, rcode: row.rcode
    });
  }
  return out;
}

/**
 * The summary of a drift result.
 * @param {object} target the report's drift target
 * @param {{ t: Function, now: Date, severity: object, statuses: string[] }} opts
 */
export function driftDoc(target, { t, now, severity, statuses }) {
  const counts = statuses.filter((s) => target.counts[s] > 0).map((s) => `${t(`zone.drift.${s}`)} ${target.counts[s]}`).join(' · ');
  const lines = [[`Live check: ${target.rows.length} record sets, ${target.queries} DNS queries`], counts ? [counts] : null];
  if (target.aborted) lines.push(['Stopped before the end: the rows not reached are not checked']);
  const pf = target.preflight || {};
  if (pf.serial === 'newer') lines.push([t('zone.live.soaNewer', { live: pf.liveSerial, file: pf.fileSerial })]);
  if (pf.nsMatch === 'disjoint') lines.push([t('zone.live.nsDisjoint')]);
  const worst = target.rows.filter((r) => ['error', 'warn', 'unknown'].includes(severity[r.status]))
    .map((r, i) => ({ r, i })).sort((a, b) => DRIFT_RANK[severity[a.r.status]] - DRIFT_RANK[severity[b.r.status]] || a.i - b.i).map((x) => x.r);
  for (const r of worst.slice(0, MAX_LINES)) lines.push([strong(`${t(`zone.drift.${r.status}`)}:`), ' ', code(`${r.name} ${r.type}`)]);
  if (worst.length > MAX_LINES) lines.push([t('sum.moreProblems', { count: worst.length - MAX_LINES })]);
  if (!worst.length && !target.aborted) lines.push(['Every checked record set matches live DNS']);
  const budget = target.rows.filter((r) => r.reasons.includes('budget')).length;
  if (budget) lines.push([`${budget} record sets were over the query budget and not checked (--max-queries)`]);
  return summaryDoc('drift', [`${t('nav.zone')} · `, code(target.target)], lines, { t, now });
}

async function runDrift(targets, options, env) {
  const { parseZone } = await import('../../assets/js/lib/zoneparse.js');
  const { driftZone, DRIFT_SEVERITY, DRIFT_STATUSES } = await import('../../assets/js/lib/zonedrift.js');
  const { proxiedOriginMap } = await import('../../assets/js/lib/zoneorigins.js');
  // The Zone File view's own redaction (and its drift labels, registered at import).
  const { redactValues, originSecrets } = await import('../../assets/js/views/zone.js');
  const { name, bytes } = env.inputs.file;
  const zone = parseZone(bytes, { filename: name, ...(options.origin ? { origin: options.origin } : {}) });
  if (zone.fatal) throw new UsageError(`${name}: not a zone the runner can read (${zone.fatal.code}${zone.fatal.detail ? `: ${zone.fatal.detail}` : ''})`);
  if (!zone.origin) throw new UsageError(`${name}: the zone name is not known: give it with --origin`);
  if (zone.originConfidence === 'low' && !options.origin) {
    throw new UsageError(`${name}: the zone name ${zone.origin} is a guess (from the ${zone.originSource}): confirm it with --origin ${zone.origin}`);
  }
  const secrets = originSecrets(proxiedOriginMap(zone));
  const redact = (values) => redactValues(values || [], secrets, options.includeOrigins);
  env.progress(`drift ${zone.origin}: ${zone.records.length} records`);
  const result = await driftZone(zone, {
    dns: env.dns, signal: env.signal, maxQueries: options.maxQueries,
    onProgress: ({ done, total }) => {
      if (done === total || done % 100 === 0) env.progress(`drift ${zone.origin}: ${done}/${total}`);
    }
  });
  // driftZone resolves with `aborted` on a cancel; the runner treats it as every lib's AbortError.
  throwIfAborted(env.signal);
  const warnings = [];
  if (zone.partial) warnings.push(`${name}: the file was read only in part (${zone.warnings.length} issues): the rows cover what was read`);
  const target = {
    target: zone.origin,
    file: name,
    format: zone.format,
    records: zone.stats.records,
    queries: result.queries,
    planned: result.planned,
    aborted: result.aborted,
    finishedAt: isoTime(result.finishedAt),
    preflight: { ...result.preflight },
    counts: { ...result.counts },
    rows: result.rows.map((r) => driftRow(r, { severity: DRIFT_SEVERITY, redact }))
  };
  return {
    options: { origin: zone.origin, file: name, maxQueries: options.maxQueries, includeOrigins: options.includeOrigins, resolvers: [...options.chain] },
    targets: [target],
    docs: [driftDoc(target, { t: env.t, now: env.now(), severity: DRIFT_SEVERITY, statuses: DRIFT_STATUSES })],
    warnings
  };
}

/* ------------------------------------------------------------------------ */
/* renew                                                                    */
/* ------------------------------------------------------------------------ */

/** The resolvers renew compares CAA on: the app's four, without the ones Node cannot read. */
async function consistencyResolvers() {
  const { CONSISTENCY_RESOLVERS } = await import('../../assets/js/lib/renewal.js');
  return CONSISTENCY_RESOLVERS.filter((id) => !NODE_UNREADABLE[id]);
}

async function runRenew(targets, options, env) {
  const { checkRenewal, renewalExport, parseRenewalNames, RENEWAL_LIMITS } = await import('../../assets/js/lib/renewal.js');
  const { renewSummary } = await import('../../assets/js/lib/summary.js');
  // The view's param wording (challenge names, HTTP-01 outcomes) for the finding titles.
  const { localParams } = await import('../../assets/js/views/renew.js');
  const resolvers = await consistencyResolvers();
  const { names } = parseRenewalNames(targets, { max: Number.MAX_SAFE_INTEGER });
  const t = env.t;
  const out = [];
  const facts = [];
  let finishedAt = null;
  let caName = null;
  // The app checks at most RENEWAL_LIMITS.names names at a time: a longer list goes in batches.
  for (const batch of chunk(names, RENEWAL_LIMITS.names)) {
    env.progress(`renew ${batch.length} name${batch.length === 1 ? '' : 's'}${names.length > batch.length ? ` (${out.length + batch.length}/${names.length})` : ''}`);
    const report = await checkRenewal({ names: batch, ca: options.ca, challenge: options.challenge }, {
      dns: env.dns, signal: env.signal, noCache: true, resolvers
    });
    finishedAt = report.finishedAt;
    caName = report.ca ? report.ca.name : null;
    const exported = renewalExport(report, { app: APP, version: DS_VERSION });
    report.names.forEach((r, i) => {
      out.push({
        target: r.name,
        wildcard: r.wildcard,
        verdict: r.verdict,
        findings: r.findings.filter((f) => f.severity !== 'ok').map((f) => ({
          id: f.id, severity: f.severity, ...(f.unchecked ? { unchecked: true } : {}), params: { ...f.params },
          title: t(`renew.f.${f.id}.title`, localParams(f, t))
        })),
        detail: exported.names[i]
      });
      facts.push({
        name: r.name,
        verdict: r.verdict,
        problems: r.findings.filter((f) => f.severity === 'error' || f.severity === 'warn')
          .map((f) => ({ severity: f.severity, key: `renew.f.${f.id}.title`, params: localParams(f, t) }))
      });
    });
  }
  // The HTTP-01 reachability test needs Globalping and a click: never run here (tested: 0).
  const doc = renewSummary({ names: facts, ca: caName, challenge: options.challenge, tested: 0, at: finishedAt }, { t, now: env.now() });
  return {
    options: { ca: options.ca, challenge: options.challenge, resolvers, chain: [...options.chain] },
    targets: out, docs: [doc], warnings: []
  };
}

/* ------------------------------------------------------------------------ */
/* dane                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * The summary of a DANE report.
 * @param {object} report lib/dane.js checkDane() result
 * @param {{ t: Function, now: Date, daneSummary: Function, statuses: string[], severity: object, subject: string }} opts
 */
export function daneDoc(report, { t, now, daneSummary, statuses, severity, subject }) {
  const s = daneSummary(report);
  const lines = [];
  if (s.headline) lines.push([t(`dane.head.${s.headline}`, { count: s.count })]);
  else lines.push([t('dane.noNames')]);
  const counts = statuses.filter((st) => s.counts[st] > 0).map((st) => `${t(`dane.st.${st}`)} ${s.counts[st]}`).join(' · ');
  if (counts) lines.push([counts]);
  const rank = { error: 0, warn: 1, unknown: 2, info: 3, ok: 4 };
  const worst = report.endpoints.filter((ep) => ['error', 'warn'].includes(severity[ep.status]))
    .map((ep, i) => ({ ep, i })).sort((a, b) => rank[severity[a.ep.status]] - rank[severity[b.ep.status]] || a.i - b.i).map((x) => x.ep);
  for (const ep of worst.slice(0, MAX_LINES)) lines.push([strong(`${t(`dane.st.${ep.status}`)}:`), ' ', code(ep.qname)]);
  if (worst.length > MAX_LINES) lines.push([t('sum.moreProblems', { count: worst.length - MAX_LINES })]);
  if (s.mxFailed.length) lines.push([t('dane.mxFailed', { list: s.mxFailed.join(', ') })]);
  return summaryDoc('dane', ['DANE / TLSA · ', code(subject)], lines, { t, at: report.finishedAt, now });
}

async function runDane(targets, options, env) {
  const { parseCertificates } = await import('../../assets/js/lib/x509.js');
  const { checkDane, daneExportJson, daneSummary, DANE_STATUSES, DANE_SEVERITY } = await import('../../assets/js/lib/dane.js');
  // The DANE panel's own words (headlines, statuses), registered at import.
  await import('../../assets/js/ui/dane-panel.js');
  const { name, bytes } = env.inputs.file;
  const parsed = parseCertificates(bytes);
  const codes = new Set(parsed.warnings.map((w) => w.code));
  if (!parsed.leaf) {
    if (codes.has('PKCS12_UNSUPPORTED')) {
      throw new UsageError(`${name}: a PKCS#12 bundle: give the certificates as PEM (openssl pkcs12 -in ${name} -nokeys -out fullchain.pem)`);
    }
    throw new UsageError(`${name}: no certificate in it (${[...codes].join(', ') || 'nothing readable'})`);
  }
  const warnings = [];
  if (codes.has('PRIVATE_KEY_PRESENT')) warnings.push(`${name} also holds a private key: it was ignored, never read or sent. Keep keys out of the repository.`);
  if (codes.has('EXPIRED')) warnings.push(`${name}: the certificate has expired`);
  const leaf = parsed.leaf;
  const subject = leaf.subjectCN || leaf.hostnames[0] || leaf.serialHex;
  env.progress(`dane ${subject}: ${leaf.hostnames.length} names`);
  const report = await checkDane({ leaf, chain: parsed.certificates }, {
    dns: env.dns, subtle: globalThis.crypto.subtle, signal: env.signal, noCache: true
  });
  const s = daneSummary(report);
  const target = {
    target: subject,
    serialHex: leaf.serialHex,
    notAfter: isoTime(leaf.notAfter),
    headline: s.headline,
    endpoints: report.endpoints.map((ep) => ({ key: `${ep.service}|${ep.host}`, qname: ep.qname, service: ep.service, port: ep.port, host: ep.host, status: ep.status, severity: ep.severity })),
    domains: report.domains.map((d) => ({ domain: d.domain, error: d.error || null, nullMx: !!d.nullMx })),
    detail: daneExportJson(report, { app: APP, version: DS_VERSION })
  };
  return {
    options: { certificate: name, serialHex: leaf.serialHex, resolvers: [...options.chain] },
    targets: [target],
    docs: [daneDoc(report, { t: env.t, now: env.now(), daneSummary, statuses: DANE_STATUSES, severity: DANE_SEVERITY, subject })],
    warnings
  };
}

/* ------------------------------------------------------------------------ */
/* dispatch                                                                 */
/* ------------------------------------------------------------------------ */

/* ------------------------------------------------------------------------ */
/* audit                                                                    */
/* ------------------------------------------------------------------------ */

/** Domains a summary of the audit names before "+N more". */
const AUDIT_MAX_DOMAINS = 20;

/**
 * The compared part of one domain's audit: its export row (lib/portfolio.js exportRow: the facts
 * as codes and values) and every rule with its status, the requirement, the actual value and the
 * evidence (in English, and as its key and params). A rule that could not be checked this run
 * carries `last`: the status the last run that checked it found (`from`: that run's check), so
 * the next run compares with that check and not with the gap — as long as the requirement is the
 * same (tools/ds/carry.mjs does the same for health, CT and hosts). A rule an active waiver
 * accepts is 'waived' with the waiver and the status it had (`was`); a rule that names an active
 * waiver without needing it carries it too; a failed one whose waiver is over says so
 * (`waiverExpired`: it counts again).
 * @param {object} row an auditPortfolio row
 * @param {object} facts portfolioFacts of the domain
 * @param {{ t: Function, exportRow: Function, evidenceText: Function, checkedAt: Date }} kit
 * @param {{ prev?: object|null }} [baseline] the baseline's target of the domain
 * @returns {object}
 */
export function auditTarget(row, facts, { t, exportRow, evidenceText, checkedAt }, { prev = null } = {}) {
  const before = new Map(((prev && prev.rules) || []).map((r) => [r.id, r]));
  return {
    target: row.domain,
    checkedAt: isoTime(checkedAt),
    pass: row.pass,
    fail: row.fail,
    unknown: row.unknown,
    ...(row.waived ? { waived: row.waived } : {}),
    rules: row.cells.map((c) => {
      const out = {
        id: c.id, status: c.status, required: c.required, actual: c.actual, evidence: evidenceText(c, t), key: c.evidence.key, params: { ...c.evidence.params },
        ...(c.was ? { was: c.was } : {}), ...(c.waiver ? { waiver: waiverOut(c.waiver) } : {}),
        ...(c.waiverExpired ? { waiverExpired: { id: c.waiverExpired.id, expires: c.waiverExpired.expires } } : {})
      };
      const p = c.status === 'unknown' ? before.get(c.id) : null;
      if (p && p.required === c.required) {
        // an accepted rule was a failed one: its status as checked
        const status = p.status === 'waived' ? p.was || 'fail' : p.status;
        const last = status === 'pass' || status === 'fail'
          ? { status, evidence: p.evidence || '', from: prev.checkedAt || null }
          : p.last || null;
        if (last) out.last = last;
      }
      return out;
    }),
    row: exportRow(facts)
  };
}

/**
 * The summaries of an audit: one for the run (the policy, the counts, the rules not checked this
 * run that failed when last checked — they still fail the run —, the domains that meet every rule),
 * then one per domain with a failed or unchecked rule, its rules worst first.
 * @param {object} audit lib/policy.js auditPortfolio
 * @param {{ t: Function, now: Date, at: Date, policy: object,
 *   carried?: Array<{ domain: string, id: string, required: string, from: string|null }> }} opts
 *   `carried`: the rules carried as failed (not checked this run, failed when last checked)
 * @returns {object[]} SummaryDocs
 */
export function auditDocs(audit, { t, now, at, policy, carried = [] }) {
  const c = audit.counts;
  const name = policy.name ? [' · ', code(policy.name)] : [];
  const plural = (n, one, other) => `${n} ${n === 1 ? one : other}`;
  const lines = [
    [`${plural(c.domains, 'domain', 'domains')}, ${plural(audit.rules.length, 'rule', 'rules')}: `,
      `${c.failing} fail${c.failing === 1 ? 's' : ''} the policy, ${c.unknown} could not be checked in full, ${c.passing} meet${c.passing === 1 ? 's' : ''} every rule`,
      c.waived ? ` (${plural(c.waived, 'failed rule', 'failed rules')} accepted by a waiver, not counted)` : ''],
    ['Rules: ', ...audit.rules.flatMap((r, i) => [i ? ', ' : '', code(`${r.id} ${r.required}`)])]
  ];
  if (carried.length) {
    // why the run fails (exit 4) on a night no rule failed: an outage never closes the issue
    const shown = carried.slice(0, AUDIT_MAX_DOMAINS);
    lines.splice(1, 0, [strong('Still counted as failed'), ' (not checked this run, failed when last checked): ',
      ...shown.flatMap((x, i) => [i ? ', ' : '', code(`${x.id} ${x.required}`), ' of ', code(x.domain), ` (${isoDay(x.from) || 'an earlier run'})`]),
      carried.length > shown.length ? ` and ${carried.length - shown.length} more` : '']);
  }
  const lastFail = new Map(carried.map((x) => [`${x.domain}|${x.id}`, x]));
  const passing = audit.rows.filter((r) => !r.fail && !r.unknown).map((r) => r.domain);
  if (passing.length) lines.push(['Every rule met: ', ...valueParts(t, passing, AUDIT_MAX_DOMAINS)]);
  const docs = [summaryDoc('audit', ['Policy audit', ...name], lines, { t, at, now })];
  const rank = { fail: 0, unknown: 1, waived: 2, pass: 3 };
  const label = { fail: 'FAIL', unknown: 'NOT KNOWN', waived: 'ACCEPTED' };
  for (const r of audit.rows.filter((x) => x.fail || x.unknown)) {
    const cells = [...r.cells].sort((a, b) => rank[a.status] - rank[b.status]).filter((x) => x.status !== 'pass');
    docs.push(summaryDoc('audit', ['Policy audit · ', code(r.domain)], [
      [`${plural(r.fail, 'rule', 'rules')} failed, ${r.unknown} could not be checked, ${r.pass} passed${r.waived ? `, ${r.waived} accepted (waiver)` : ''}`],
      // the evidence quotes values from DNS and the registry: code parts (lib/summary.js textParts)
      ...cells.map((x) => {
        const last = x.status === 'unknown' ? lastFail.get(`${r.domain}|${x.id}`) : null;
        return [strong(label[x.status] || x.status), ' ', code(`${x.id} ${x.required}`), ': ', ...textParts(t, x.evidence.key, x.evidence.params),
          last ? ` — failed when last checked (${isoDay(last.from) || 'an earlier run'}): still counts as failed` : '',
          x.status === 'waived' && x.waiver ? ` — accepted until ${x.waiver.expires}` : '',
          x.status === 'fail' && x.waiverExpired ? ` — its waiver expired on ${x.waiverExpired.expires}: it counts again` : ''];
      })
    ], { t, at, now }));
  }
  return docs;
}

/** Domains the security score table lists before "… and N more" (a GitHub issue holds 65,536 characters). */
export const SECURITY_MAX_ROWS = 100;
/** How the score table marks a measure: met, not met, not known. */
const SECURITY_MARKS = Object.freeze({ pass: '✓', fail: '✗', unknown: '?' });

/**
 * The domain security score of an audit's domains (lib/secscore.js, CSC's eight measures) as a
 * table doc: one row per domain, the lowest score first (then the most not known, then the
 * run's order), its score and each measure as ✓ met, ✗ not met or ? not known; under it what
 * the marks mean, the domains left out past {@link SECURITY_MAX_ROWS}, and each measure's
 * adoption. render.mjs writes it as a Markdown table (`--md`) and as aligned columns (stdout).
 * @param {object[]} rows lib/secscore.js securityScores, in the run's order
 * @param {{ t: Function }} opts
 * @param {{ SECURITY_MEASURES: object[], SECURITY_MAX: number, securityAdoption: Function }} kit lib/secscore.js
 * @returns {{ kind: 'audit', title: Array, table: { columns: string[], align: string[], rows: Array<Array<Array>> }, lines: Array<Array> }}
 */
export function securityDoc(rows, { t }, { SECURITY_MEASURES, SECURITY_MAX, securityAdoption }) {
  const order = rows.map((r, i) => ({ r, i }))
    .sort((a, b) => a.r.score - b.r.score || b.r.unknown - a.r.unknown || a.i - b.i).map((x) => x.r);
  const shown = order.slice(0, SECURITY_MAX_ROWS);
  const names = SECURITY_MEASURES.map((m) => t(`sec.m.${m.id}`));
  const adoption = securityAdoption(rows);
  return {
    kind: 'audit',
    title: ['Domain security score'],
    table: {
      columns: ['Domain', 'Score', ...names],
      align: ['left', 'right', ...names.map(() => 'center')],
      rows: shown.map((r) => [[code(r.domain)], [`${r.score}/${SECURITY_MAX}`], ...r.measures.map((m) => [SECURITY_MARKS[m.status]])])
    },
    lines: [
      [`CSC's ${SECURITY_MAX} domain security measures: ${SECURITY_MARKS.pass} met, ${SECURITY_MARKS.fail} not met, ${SECURITY_MARKS.unknown} not known (never counted as met)`],
      rows.length > shown.length ? [`… and ${rows.length - shown.length} more domains: the JSON report has every domain's score`] : null,
      ['Adoption: ', adoption.map((a, i) => `${names[i]} ${a.pass} of ${a.total}`).join(', ')]
    ].filter(Boolean)
  };
}

/**
 * The warnings of an audit run: what could not be read, so the rules that need it could not be
 * checked (a TLD without RDAP, an RDAP or DNS lookup that failed, a name server domain's RDAP).
 * @param {object[]} facts portfolioFacts per domain
 * @param {{ cellFailures: Function, cells: string[] }} kit lib/portfolio.js
 * @returns {string[]}
 */
export function auditWarnings(facts, { cellFailures, cells }) {
  const out = [];
  const list = (names) => names.slice(0, AUDIT_MAX_DOMAINS).join(', ') + (names.length > AUDIT_MAX_DOMAINS ? ` and ${names.length - AUDIT_MAX_DOMAINS} more` : '');
  const noRdap = facts.filter((f) => f.registration.state === 'unsupported').map((f) => f.domain);
  if (noRdap.length) out.push(`no RDAP for ${list(noRdap)} (the registry publishes none): the registration rules could not be checked; the registry's WHOIS has the dates`);
  const rdapFailed = facts.filter((f) => f.registration.state === 'failed').map((f) => f.domain);
  if (rdapFailed.length) out.push(`RDAP could not be read for ${list(rdapFailed)}: the registration rules could not be checked`);
  // A name server domain nobody has registered: whoever registers it answers DNS for the zone.
  const gone = new Map();
  for (const f of facts) {
    for (const d of (f.ns && f.ns.domains) || []) {
      if (d.own || d.state !== 'not-found') continue;
      if (!gone.has(d.domain)) gone.set(d.domain, []);
      gone.get(d.domain).push(f.domain);
    }
  }
  for (const [ns, of] of gone) out.push(`the name server domain ${ns} (of ${list(of)}) is not registered: anyone can register it and take over DNS`);
  const nsFailed = new Map();
  for (const f of facts) {
    for (const x of cellFailures(f, 'ns')) {
      if (!x.nsDomain) continue;
      if (!nsFailed.has(x.nsDomain)) nsFailed.set(x.nsDomain, []);
      nsFailed.get(x.nsDomain).push(f.domain);
    }
  }
  for (const [ns, of] of nsFailed) out.push(`RDAP could not be read for the name server domain ${ns} (of ${list(of)}): nsExpiryDays could not be checked`);
  const dnsFailed = facts.filter((f) => cells.some((c) => cellFailures(f, c).some((x) => x.lookup !== 'rdap'))).map((f) => f.domain);
  if (dnsFailed.length) out.push(`a DNS lookup failed for ${list(dnsFailed)}: the rules that read it could not be checked`);
  return out;
}

async function runAudit(targets, options, env) {
  const { createPortfolio, exportRow, cellFailures, PORTFOLIO_CELLS, PORTFOLIO_DKIM_SELECTORS } = await import('../../assets/js/lib/portfolio.js');
  const { auditPortfolio, evidenceText, policyObject } = await import('../../assets/js/lib/policy.js');
  const secscore = await import('../../assets/js/lib/secscore.js');
  const policy = env.inputs.policy;
  const startedAt = env.now();
  const prevBy = new Map(((env.baseline && env.baseline.targets) || []).map((x) => [x.target, x]));
  let done = 0;
  const run = createPortfolio({
    domains: targets,
    dns: env.dns,
    fetchImpl: env.fetchImpl,
    dkim: options.dkim,
    onEvent: (e) => {
      if (e.type === 'row' && e.state === 'done') {
        done += 1;
        env.progress(`audit ${e.domain} (${done}/${targets.length})`);
      }
    }
  });
  env.progress(`audit: ${targets.length} domain${targets.length === 1 ? '' : 's'}, ${policy.rules.length} rule${policy.rules.length === 1 ? '' : 's'}`
    + `${options.dkim ? `, DKIM at ${PORTFOLIO_DKIM_SELECTORS.length} selectors` : ''}`);
  await run.start({ signal: env.signal });
  throwIfAborted(env.signal);
  const now = env.now();
  const facts = run.allFacts({ now });
  // the accepted risks (--waivers, kind 'rule'): a failed rule they accept is 'waived', never a failure
  const waivers = env.inputs && env.inputs.waivers ? env.inputs.waivers : null;
  const audit = auditPortfolio(policy, facts, { waivers: waivers ? waivers.list : [], now });
  const audited = audit.rows.map((row, i) => auditTarget(row, facts[i], { t: env.t, exportRow, evidenceText, checkedAt: now }, { prev: prevBy.get(row.domain) || null }));
  // CSC's eight measures, whatever the policy asks: each target's score, and the table after the run's summary.
  const scores = secscore.securityScores(facts);
  audited.forEach((x, i) => { x.security = secscore.securityExport(scores[i]); });
  // A rule that failed when last checked and could not be checked tonight still fails the run: a
  // registry outage never closes the nightly issue (the carried status is the requirement's own) —
  // unless a waiver accepts it now.
  const carried = audited.flatMap((x) => x.rules.filter((r) => r.status === 'unknown' && r.last && r.last.status === 'fail' && !r.waiver)
    .map((r) => ({ domain: x.target, id: r.id, required: r.required, from: r.last.from })));
  const carriedFails = carried.map((x) => `${x.id} of ${x.domain} could not be checked this run and failed when last checked (${isoDay(x.from) || 'an earlier run'}): it still counts as failed`);
  const [runDoc, ...domainDocs] = auditDocs(audit, { t: env.t, now, at: startedAt, policy, carried });
  const docs = [runDoc, securityDoc(scores, { t: env.t }, secscore), ...domainDocs];
  if (waivers) {
    const what = (r) => [code(`${r.id} ${r.required}`)];
    const use = {
      checked: audited.map((x) => x.target),
      applied: audited.flatMap((x) => x.rules.filter((r) => r.status === 'waived' && r.waiver).map((r) => ({ target: x.target, what: what(r), waiver: r.waiver }))),
      expired: audited.flatMap((x) => x.rules.filter((r) => r.status === 'fail' && r.waiverExpired).map((r) => {
        const w = waivers.list.find((y) => y.id === r.waiverExpired.id) || r.waiverExpired;
        return { target: x.target, what: what(r), waiver: waiverOut({ reason: '', ...w }) };
      }))
    };
    docs.push(waiversDoc('audit', waivers, use, { t: env.t, now }));
  }
  return {
    options: {
      policy: policyObject(policy), policyFile: policy.file || null, preset: options.preset, dkim: options.dkim, resolvers: [...options.chain],
      ...(waivers ? { waivers: waivers.file } : {})
    },
    targets: audited,
    docs,
    warnings: [...auditWarnings(facts, { cellFailures, cells: PORTFOLIO_CELLS }), ...carriedFails],
    failed: audit.counts.failing > 0 || carriedFails.length > 0
  };
}

/** tls: tools/ds/tls.mjs (node:tls), loaded with its command only. */
async function runTlsCommand(targets, options, env) {
  const { runTls } = await import('./tls.mjs');
  return runTls(targets, options, env);
}

const RUNNERS = Object.freeze({
  health: runHealth, subdomains: runSubdomains, drift: runDrift, ct: runCt, renew: runRenew, dane: runDane, audit: runAudit,
  tls: runTlsCommand,
  // the takeover and dependency-expiry watch: tools/ds/takeover.mjs
  takeover: (targets, options, env) => import('./takeover.mjs').then((m) => m.runTakeover(targets, options, env))
});

/**
 * Run one subcommand.
 * @param {string} command
 * @param {string[]} targets normalized targets (domains, names, or one file path)
 * @param {import('./args.mjs').DsOptions} options
 * @param {{ dns: object, fetchImpl: typeof fetch, signal?: AbortSignal, now: () => Date, t: Function,
 *   progress: (text: string) => void, baseline: object|null,
 *   inputs: { file?: { name: string, bytes: Uint8Array }, exactNames?: string[], exactFile?: string } }} env
 * @returns {Promise<{ options: object, targets: object[], docs: object[], warnings: string[], failed?: boolean }>}
 *   `failed` (audit): a rule of the policy failed, exit 4; rejects with a UsageError for an input it cannot check (a zone without a name, no
 *   certificate), with an AbortError when `signal` aborts
 */
export async function runCommand(command, targets, options, env) {
  const run = RUNNERS[command];
  if (!run) throw new UsageError(`unknown command "${command}"`);
  return run(targets, options, env);
}
