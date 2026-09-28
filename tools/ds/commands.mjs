/**
 * tools/ds/commands.mjs — the six checks of the headless runner, each over the app's own
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
import { NODE_UNREADABLE, CT_SOURCES, DS_VERSION, UsageError } from './args.mjs';
import { code, strong, isoDay, isoTime, summaryDoc, valueParts, localYesNo } from './render.mjs';
import { isSubdomainOf, sortHostnames } from '../../assets/js/lib/domain.js';
import { chunk, throwIfAborted } from '../../assets/js/lib/util.js';

const APP = 'DomainScope';
const DAY_MS = 86400000;
/** Lines of problems / rows / issuances a summary lists before "+N more" (lib/summary.js SUMMARY_MAX_PROBLEMS). */
const MAX_LINES = 5;

/* ------------------------------------------------------------------------ */
/* health                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * The compared part of one Domain Health report: the score, the counts, every check (its
 * title key and language-neutral params, so a change quotes their values as code spans, and
 * the English title to read the file by), the lookups that failed; `report` is the report
 * itself (the view's "Report (JSON)").
 * @param {object} report lib/health.js domainHealth() result
 * @param {{ t: Function, healthScore: Function, trafficLight: Function }} kit
 * @returns {object}
 */
export function healthTarget(report, { t, healthScore, trafficLight }) {
  return {
    target: report.domain,
    checkedAt: isoTime(report.checkedAt),
    score: healthScore(report.summary),
    light: trafficLight(report.summary),
    summary: { ...report.summary },
    failedLookups: [...(report.failedLookups || [])],
    checks: (report.checks || []).map((c) => ({
      id: c.id, severity: c.severity, titleKey: c.titleKey, params: { ...c.params }, title: t(c.titleKey, localYesNo(t, c.params))
    })),
    report
  };
}

async function runHealth(targets, options, env) {
  const { domainHealth } = await import('../../assets/js/lib/health.js');
  const { healthSummary, healthScore, trafficLight } = await import('../../assets/js/lib/summary.js');
  const out = [];
  const docs = [];
  for (const [i, domain] of targets.entries()) {
    env.progress(`health ${domain} (${i + 1}/${targets.length})`);
    const report = await domainHealth(domain, { dns: env.dns, fetchImpl: env.fetchImpl, signal: env.signal });
    out.push(healthTarget(report, { t: env.t, healthScore, trafficLight }));
    docs.push(healthSummary({ report }, { t: env.t, now: env.now() }));
  }
  return { options: { resolvers: [...options.chain] }, targets: out, docs, warnings: [] };
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

/** A lookup that got no usable answer (the host may exist). */
const LOOKUP_FAILED = new Set(['SERVFAIL', 'REFUSED', 'ERROR']);

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
  return rows.filter((h) => !h.wildcardSuspect && (hostResolves(h) || h.dangling || LOOKUP_FAILED.has(h.status) || seeded.has(h.name)));
}

/**
 * The names of the previous run of a domain to resolve again this run (discovery only): its
 * resolving hosts and dangling aliases, so a host is never "gone" only because a passive
 * source was down or a guess was not tried this time.
 * @param {object|null} baseline a validated `subdomains` report
 * @param {string} domain
 * @returns {string[]}
 */
export function baselineSeeds(baseline, domain) {
  const prev = baseline && Array.isArray(baseline.targets) ? baseline.targets.find((x) => x && x.target === domain) : null;
  if (!prev || prev.mode !== 'discover' || !Array.isArray(prev.hosts)) return [];
  return prev.hosts.filter((h) => h && !h.wildcardSuspect && (hostResolves(h) || h.dangling) && h.name !== domain
    && isSubdomainOf(h.name, domain)).map((h) => h.name);
}

async function runSubdomains(targets, options, env) {
  const { runScan } = await import('../../assets/js/lib/scanner.js');
  const { scanHostRows } = await import('../../assets/js/lib/export.js');
  const { subdomainsSummary } = await import('../../assets/js/lib/summary.js');
  // The view's own pure helpers (DOM-free at import, tests/js/i18n-coverage.test.js): the stat
  // cards, its Copy summary facts and its scan concurrency, so the report says what the app says.
  const { countHosts, subdomainsSummaryFacts, scanConcurrency } = await import('../../assets/js/views/subdomains.js');
  const exact = Array.isArray(env.inputs.exactNames);
  const out = [];
  const docs = [];
  const warnings = [];
  const pool = scanConcurrency(options.concurrency);
  if (exact) {
    const outside = env.inputs.exactNames.filter((n) => !targets.some((d) => n === d || isSubdomainOf(n, d)));
    if (outside.length) warnings.push(`${outside.length} name${outside.length === 1 ? '' : 's'} of ${env.inputs.exactFile} under none of the domains left out (never sent)`);
  }
  for (const [i, domain] of targets.entries()) {
    const own = exact ? env.inputs.exactNames.filter((n) => n === domain || isSubdomainOf(n, domain)) : [];
    if (exact && !own.length) warnings.push(`${domain}: no name of ${env.inputs.exactFile} is under it; only the domain itself is resolved`);
    const seeds = exact ? [] : baselineSeeds(env.baseline, domain);
    env.progress(`subdomains ${domain} (${i + 1}/${targets.length})${exact ? `, ${own.length} names` : `, level ${options.level}`}`);
    const result = await runScan({
      domains: [domain],
      extraNames: exact ? own : seeds,
      exact,
      ...(exact ? { sources: [], bruteforce: 'off', permutationBudget: 0, recursive: false, mine: false } : {
        ...(options.sources ? { sources: options.sources } : {}),
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
      }
    });
    const seeded = new Set(seeds);
    out.push({
      target: domain,
      mode: exact ? 'exact' : 'discover',
      level: exact ? null : result.options.bruteforce,
      sources: (result.sourceHealth || []).map((s) => ({ source: s.source, state: s.state, names: s.names, error: s.error || null })),
      finishedAt: isoTime(result.finishedAt),
      counts: countHosts(result.hosts),
      warnings: [...new Set((result.warnings || []).map((w) => w.code))],
      seeded: seeds.length,
      hosts: reportHosts(scanHostRows(result).map((row) => hostRow(row, seeded)), { exact, seeded })
    });
    const run = { status: 'done', config: { domains: [domain] }, result, hosts: result.hosts, found: new Map(), sourceResults: result.sources, finishedAt: result.finishedAt };
    docs.push(subdomainsSummary(subdomainsSummaryFacts(run), { t: env.t, now: env.now() }));
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
 * The compared part of one domain's certificates in CT: every current certificate (id, CA,
 * intermediate, validity, names), the issuers with their counts, the names, and how each source
 * answered (`complete`: every source answered in full).
 * @param {string} domain
 * @param {object} fetched lib/sources.js fetchAllSources() result
 * @param {{ issuerName: Function, dnPart: Function, days: number, now: Date, sources: string[] }} opts
 * @returns {object}
 */
export function ctTarget(domain, fetched, { issuerName, dnPart, days, now, sources }) {
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
    const fields = {
      ca: issuerName(c.issuer, c.issuerFriendlyName || null),
      intermediate,
      issuer: c.issuer || '',
      notBefore: isoTime(c.notBefore),
      notAfter: isoTime(c.notAfter),
      names: sortHostnames([...new Set((c.names || []).filter(own))]),
      sha256: c.sha256 || null,
      sources: [...(c.sources || [c.source])].sort()
    };
    const cert = { id: ctCertId(fields), ...fields };
    const twin = byId.get(cert.id);
    if (twin) {
      twin.sources = [...new Set([...twin.sources, ...cert.sources])].sort();
      twin.sha256 = twin.sha256 || cert.sha256;
      continue;
    }
    byId.set(cert.id, cert);
    certificates.push(cert);
  }
  certificates.sort((a, b) => String(b.notBefore).localeCompare(String(a.notBefore)) || a.id.localeCompare(b.id));
  const issuers = new Map();
  for (const c of certificates) {
    const g = issuers.get(c.ca) || { name: c.ca, count: 0, intermediates: [], newest: null };
    g.count += 1;
    if (c.intermediate && !g.intermediates.includes(c.intermediate)) g.intermediates.push(c.intermediate);
    if (!g.newest || String(c.notBefore) > g.newest) g.newest = c.notBefore;
    issuers.set(c.ca, g);
  }
  const health = (fetched.health || []).filter((h) => sources.includes(h.source));
  const since = now.getTime() - days * DAY_MS;
  return {
    target: domain,
    days,
    sources: health.map((h) => ({ source: h.source, state: h.state, ok: h.ok, truncated: !!h.truncated, errorKind: h.errorKind || null, error: h.error || null })),
    complete: sources.every((id) => health.some((h) => h.source === id && h.ok && h.state !== 'partial' && !h.truncated)),
    answered: health.some((h) => h.ok),
    recent: certificates.filter((c) => Date.parse(c.notBefore) >= since).length,
    issuers: [...issuers.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'en')).map((g) => ({ ...g, intermediates: g.intermediates.sort() })),
    names: sortHostnames([...new Set(certificates.flatMap((c) => c.names))]),
    certificates
  };
}

/** Source names for a sentence ('crt.sh', 'Cert Spotter'). */
const SOURCE_NAMES = Object.freeze({ crtsh: 'crt.sh', certspotter: 'Cert Spotter' });

/**
 * The summary of one domain's CT result.
 * @param {object} target {@link ctTarget}
 * @param {{ t: Function, now: Date }} opts
 */
export function ctDoc(target, { t, now }) {
  const lines = [];
  const failed = target.sources.filter((s) => !s.ok);
  const why = (s) => `${SOURCE_NAMES[s.source] || s.source} (${String(s.state || 'error').replace('-', ' ')})`;
  if (!target.answered) {
    lines.push([`Certificate Transparency could not be read: ${failed.map(why).join(', ')}. Nothing is known about this domain's certificates.`]);
  } else {
    const n = target.certificates.length;
    lines.push([n ? `${n} current certificate${n === 1 ? '' : 's'} · ${target.recent} issued in the last ${target.days} days`
      : 'No current certificate is logged for it']);
    if (target.issuers.length) {
      const parts = ['Issuers: '];
      target.issuers.slice(0, MAX_LINES).forEach((g, i) => {
        if (i) parts.push(', ');
        parts.push(code(g.name), ` ${g.count}`);
      });
      if (target.issuers.length > MAX_LINES) parts.push(` ${t('common.moreCount', { count: target.issuers.length - MAX_LINES })}`);
      lines.push(parts);
    }
    const since = now.getTime() - target.days * DAY_MS;
    const recent = target.certificates.filter((c) => Date.parse(c.notBefore) >= since);
    for (const c of recent.slice(0, MAX_LINES)) {
      lines.push([`${isoDay(c.notBefore)} `, code(c.ca), ...(c.intermediate ? [' (', code(c.intermediate), ')'] : []), ': ', ...valueParts(t, c.names)]);
    }
    if (recent.length > MAX_LINES) lines.push([`${recent.length - MAX_LINES} more issued in the last ${target.days} days (see the JSON report)`]);
    if (failed.length) lines.push([`Not read: ${failed.map(why).join(', ')}: the list may be incomplete`]);
    else if (!target.complete) lines.push(['A source returned only part of its list: the list may be incomplete']);
  }
  return summaryDoc('ct', ['Certificate Transparency · ', code(target.target)], lines, { t, now });
}

async function runCt(targets, options, env) {
  const { fetchAllSources } = await import('../../assets/js/lib/sources.js');
  const { issuerName, dnPart } = await import('../../assets/js/lib/passport.js');
  const sources = options.sources || [...CT_SOURCES];
  const out = [];
  const docs = [];
  for (const [i, domain] of targets.entries()) {
    env.progress(`ct ${domain} (${i + 1}/${targets.length})`);
    const fetched = await fetchAllSources(domain, { sources, fetchImpl: env.fetchImpl, signal: env.signal });
    const now = env.now();
    const target = ctTarget(domain, fetched, { issuerName, dnPart, days: options.days, now, sources });
    out.push(target);
    docs.push(ctDoc(target, { t: env.t, now }));
  }
  return { options: { sources, days: options.days }, targets: out, docs, warnings: [] };
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

const RUNNERS = Object.freeze({ health: runHealth, subdomains: runSubdomains, drift: runDrift, ct: runCt, renew: runRenew, dane: runDane });

/**
 * Run one subcommand.
 * @param {string} command
 * @param {string[]} targets normalized targets (domains, names, or one file path)
 * @param {import('./args.mjs').DsOptions} options
 * @param {{ dns: object, fetchImpl: typeof fetch, signal?: AbortSignal, now: () => Date, t: Function,
 *   progress: (text: string) => void, baseline: object|null,
 *   inputs: { file?: { name: string, bytes: Uint8Array }, exactNames?: string[], exactFile?: string } }} env
 * @returns {Promise<{ options: object, targets: object[], docs: object[], warnings: string[] }>}
 *   rejects with a UsageError for an input it cannot check (a zone without a name, no
 *   certificate), with an AbortError when `signal` aborts
 */
export async function runCommand(command, targets, options, env) {
  const run = RUNNERS[command];
  if (!run) throw new UsageError(`unknown command "${command}"`);
  return run(targets, options, env);
}
