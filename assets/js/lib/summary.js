/**
 * summary.js — "Copy summary": a view's finished result as a few lines of Markdown (or plain
 * text) for a Jira ticket or a Slack thread, in the UI language.
 *
 * - Each builder takes the facts a view already shows ({@link healthSummary}, {@link globalSummary},
 *   {@link subdomainsSummary}, {@link scanSummary}, {@link zoneSummary}, {@link certSummary},
 *   {@link renewSummary}, {@link lookupSummary}, {@link ipSummary}, {@link retireSummary},
 *   {@link domainSummary}; {@link buildSummary} dispatches by view id) and returns a
 *   {@link SummaryDoc}: a title, 3–10 content lines (one line for DNS Lookup and IP Intel) and a
 *   footer with the view's permalink and a UTC timestamp. DMARC & TLS reports keeps its builder
 *   and texts in lib/reportsummary.js, which loads with its view ({@link registerSummaryBuilder}).
 * - The core — the document model, rendering, {@link permalinkParams}, the registry and the
 *   Subdomains builder — is lib/summarycore.js, on the start route; this module re-exports it and
 *   registers every other view's builder with {@link registerSummaryBuilder} when it loads, so the
 *   builders and their texts come with the first view that has a Copy summary (ui/view-summaries.js
 *   registers the texts), never on the start route.
 * - {@link renderMarkdown} / {@link renderPlainText} turn a doc into text. Untrusted values
 *   (host names, record data, certificate subjects and issuers, inventory server names, a network's
 *   AS name and place, the names and lines of a zone file a problem quotes) are code spans in
 *   Markdown (no link, mention or formatting survives inside one) and every other text is
 *   Markdown-escaped; control and bidi characters never reach the output.
 * - {@link permalinkParams} keeps only a view's own shareable route params (never inventory data
 *   or zone contents; IP Intel and Retire an IP drop private and inventory addresses), for `ctx.shareUrl()`.
 * - A summary holds only what the result on screen shows. Inventory data in it: SSL Targets names
 *   the servers that need the certificate, as its Servers tab lists them; IP Intel says whether
 *   (or how many of) its addresses are in the server list, never a server's name.
 * - The footer's time is when the result was made where the view knows it ("checked" /
 *   "scanned"); Zone File and Certificate say "as of" the copy time.
 *
 * Texts come from an injected `t(key, params)` (i18n.js): the `sum.*` keys of {@link SUMMARY_I18N}
 * plus a few the shell always has (`nav.<view>`, `severity.*`, `kind.*`, `common.moreCount`) and
 * the keys a fact carries itself (a health check's `titleKey`, a Verify headline key).
 * DOM-free; runs in browsers and Node 22.
 */

import { isPrivateIP } from './netinfo.js';
import { scoreHealth } from './healthscore.js';
import {
  BUILDER_KIT, SUMMARY_CORE_I18N, SUMMARY_MAX_PROBLEMS, cleanText, registerSummaryBuilder, textParts, trafficLight
} from './summarycore.js';

export * from './summarycore.js';

const { kit, doc, code, strong, isoDay, whenText, problemLines } = BUILDER_KIT;

/* ------------------------------------------------------------------------ */
/* Builders                                                                 */
/* ------------------------------------------------------------------------ */

/** The score and letter of a report (lib/healthscore.js, SPEC §5.78), as the view's hero shows them. */
function gradeOf(report) {
  const g = scoreHealth(report.checks);
  return { score: g.score, grade: g.grade };
}

/**
 * Domain Health: the verdict and score, the counts, the worst problems (errors, then warnings).
 * @param {{ report: { domain: string, checkedAt?: Date, summary: object, checks: Array<{ severity: string,
 *   titleKey: string, params?: object, id?: string }> } }} facts a lib/health.domainHealth report
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function healthSummary({ report }, opts) {
  const k = kit(opts);
  const { t } = k;
  const s = report.summary || {};
  const light = trafficLight(s);
  // lib/health passes booleans as the English words 'yes' / 'no' (the view shows them translated too).
  const local = (params) => Object.fromEntries(Object.entries(params || {}).map(([key, v]) => [key, v === 'yes' ? t('common.yes') : v === 'no' ? t('common.no') : v]));
  const problems = (report.checks || []).map((c) => ({ severity: c.severity, key: c.titleKey, params: local(c.params) }));
  const tally = k.counts([['sum.count.error', s.error], ['sum.count.warn', s.warn], ['sum.count.info', s.info], ['sum.count.ok', s.ok]]);
  const listed = problemLines(k, problems);
  return doc('health', k.title('health', [code(report.domain)]), [
    [t('sum.health.verdictGrade', { verdict: t(`sum.health.light.${light}`), ...gradeOf(report) })],
    tally ? [tally] : null,
    ...(listed.length ? listed : [[t('sum.health.noProblems')]])
  ], { when: whenText(t, 'sum.at.checked', report.checkedAt, opts.now || new Date()), url: opts.url });
}

/**
 * Global DNS: why the answers agree or differ (lib/propagation.propagationVerdict), how many
 * answers from how many sources (with none, only how many failed), who operates them, the
 * findings and the addresses seen. A verdict that rests on a branch only mainland China takes
 * which the control could not confirm (a `geoSplits` entry without `line`) is worded as likely.
 * With an expected value (Global DNS › Expected value), a line says how many of the sources that
 * answered serve it.
 * @param {{ name: string, type: string, verdict: object|null, total: number, answered: number,
 *   failed?: number, cancelled?: boolean, addresses?: number, at?: Date,
 *   expected?: { pattern: string, mode: 'exact'|'contains'|'regex', match: number, judged: number }|null }} facts `at`: when the check ended
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function globalSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const v = facts.verdict || { state: 'none', groups: [], operators: [], findings: [] };
  const answered = Number(facts.answered) || 0;
  const operators = (v.operators || []).map((op) => op.name).filter(Boolean);
  const opList = operators.slice(0, 3).join(', ') + (operators.length > 3 ? ` ${t('common.moreCount', { count: operators.length - 3 })}` : '');
  // A branch only mainland China takes that the control could not confirm: a likely answer, not a certain one.
  const unsure = (v.geoSplits || []).some((split) => !split.line);
  let state;
  if (!answered) state = facts.cancelled ? t('sum.global.stopped') : t('sum.global.failed');
  else if (v.state === 'by-design' && v.noRecords) state = t(unsure ? 'sum.global.nodataUnsure' : 'sum.global.nodata', { type: facts.type, operators: opList });
  else if (v.state === 'by-design') state = t(unsure ? 'sum.global.designUnsure' : 'sum.global.design', { operators: opList });
  else if (v.state === 'geo' && unsure) state = t('sum.global.geoUnsure');
  else if (v.state === 'stale') state = t('sum.global.stale', { count: k.num(((v.isp && v.isp.stale) || []).reduce((n, g) => n + g.members.length, 0)) });
  else if (['agree', 'geo', 'unresolved', 'differ'].includes(v.state)) state = t(`sum.global.${v.state}`);
  else state = t('sum.global.differ');
  if (facts.cancelled && answered) state = `${state} ${t('sum.global.partial')}`;
  const groups = (v.groups || []).filter((g) => !g.rewritten).length;
  // No answer: the state says so; only how many sources failed is left to tell.
  const sources = answered ? [t('sum.global.answers', { count: groups, answered: k.num(answered), total: k.num(facts.total) })] : [];
  if (facts.failed > 0) sources.push(`${sources.length ? ' · ' : ''}${t('sum.global.errors', { count: facts.failed })}`);
  const findings = (v.state === 'differ' || v.state === 'unresolved') ? (v.findings || []) : [];
  const findingLines = findings.slice(0, 3).map((f) => [t(`sum.global.find.${f.code}`, {
    count: (f.members || []).length, rcode: f.rcode || '', type: facts.type
  })]);
  if (findings.length > 3) findingLines.push([t('sum.moreFindings', { count: findings.length - 3 })]);
  // Global DNS › Expected value (lib/expected.js): how many of the sources that answered serve it.
  const ex = facts.expected && facts.expected.pattern ? facts.expected : null;
  const modeKey = { exact: 'sum.global.mode.exact', contains: 'sum.global.mode.contains', regex: 'sum.global.mode.regex' };
  const expectedLine = ex ? [
    t('sum.global.expected', { mode: t(modeKey[ex.mode] || modeKey.exact) }), ' ', code(ex.pattern), ' ',
    Number(ex.judged) > 0 ? t('sum.global.expectedCount', { count: Number(ex.match) || 0, match: k.num(Number(ex.match) || 0), judged: k.num(Number(ex.judged)) })
      : t('sum.global.expectedNone')
  ] : null;
  return doc('global', k.title('global', [code(facts.name), ` ${cleanText(facts.type)}`]), [
    [state],
    sources,
    expectedLine,
    operators.length && v.state !== 'by-design' ? [t('sum.global.operators', { list: opList })] : null,
    ...findingLines,
    [t('sum.global.addresses', { count: Number(facts.addresses) || 0 })]
  ], { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

/**
 * SSL Targets: the scanned domains (the title), the certificate, hosts found and covered, passive
 * sources that failed (the host list may be incomplete, so the lines after it may miss a host),
 * the inventory servers that need the certificate (by name, as the Servers tab lists them), hosts
 * behind a CDN and the Verify state.
 * @param {{ domains: string[], cert: { name: string, issuer: string, notBefore?: Date,
 *   notAfter: Date }|null, hosts: number, covered?: number, failedSources?: number, inventory: number,
 *   needsCert?: string[], matched?: number, hiddenOrigin?: number, networks?: number,
 *   verify?: { key: string, params?: object }|null, dangling?: string[], at?: Date,
 *   sets?: Array<{ id: string, name: string, names: number, keyTypes: string[], servers?: number|null }>|null }} facts of a
 *   finished scan (SSL Targets keeps no result of a cancelled one)
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function scanSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const now = opts.now || new Date();
  const cert = facts.cert;
  // Several certificates (a renewal of certificate sets): each set by its first name and key
  // types, and how many of your servers need it, in place of the one certificate.
  const sets = Array.isArray(facts.sets) && facts.sets.length ? facts.sets : null;
  const lines = [];
  if (sets) {
    const parts = [t('sum.scan.sets', { count: sets.length }), ' '];
    sets.forEach((s, i) => {
      if (i) parts.push(' · ');
      parts.push(`${s.id}: `, code(s.name), s.names > 1 ? ` +${k.num(s.names - 1)}` : '', ` (${(s.keyTypes || []).join(', ')})`,
        Number.isFinite(s.servers) && facts.inventory > 0 ? ` ${t('sum.scan.setServers', { count: s.servers })}` : '');
    });
    lines.push(parts.filter((p) => p !== ''));
  } else {
    lines.push(cert
      ? [t('sum.scan.cert'), ' ', code(cert.name), ' · ', ...issuedBy(t, cert.issuer), ' · ', validityText(k, cert, now)]
      : [t('sum.scan.noCert')]);
  }
  const hosts = [t('sum.scan.hosts', { count: Number(facts.hosts) || 0 })];
  if (cert) hosts.push(' · ', t('sum.scan.covered', { count: Number(facts.covered) || 0 }));
  lines.push(hosts);
  // Right under the host count: every line after it is built from that (maybe incomplete) list.
  if (facts.failedSources > 0) lines.push([t('sum.sub.sourcesFailed', { count: facts.failedSources })]);
  if (!(facts.inventory > 0)) lines.push([t('sum.scan.noInventory')]);
  else if (cert) {
    const needs = facts.needsCert || [];
    lines.push(needs.length ? [t('sum.scan.needs', { count: needs.length }), ': ', ...k.values(needs, SUMMARY_MAX_PROBLEMS)] : [t('sum.scan.needsNone')]);
  } else {
    lines.push([t('sum.scan.matched', { count: Number(facts.matched) || 0 })]);
  }
  if (facts.hiddenOrigin > 0) {
    lines.push([[t('sum.scan.hidden', { count: facts.hiddenOrigin }), facts.networks > 0 ? t('sum.sub.networks', { count: facts.networks }) : null].filter(Boolean).join(' · ')]);
  }
  if (cert) lines.push(facts.verify && facts.verify.key ? [`${t('sum.scan.verify')} `, t(facts.verify.key, facts.verify.params || {})] : [t('sum.scan.verifyNone')]);
  const dangling = facts.dangling || [];
  if (dangling.length) lines.push([t('sum.sub.dangling', { count: dangling.length }), ': ', ...k.values(dangling)]);
  // The title names what was scanned, as the results title does (the certificate is line 1: its
  // name may be another domain's).
  const scanned = k.domains(facts.domains);
  const subject = scanned.length ? scanned : cert ? [code(cert.name)] : [];
  return doc('scan', k.title('scan', subject), lines, { when: whenText(t, 'sum.at.scanned', facts.at, now), url: opts.url });
}

/**
 * Zone File: records / names / proxied, the problems by severity and the worst of them. The zone
 * itself never goes into the permalink, and the summary says so.
 * @param {{ origin: string|null, format?: string, counts: { records: number, names: number, proxied: number,
 *   errors: number, warnings: number, info: number }, problems?: Array<{ severity: string, key: string, params?: object }> }} facts
 *   `problems`: views/zone.js problemList, each with its text key and params (the names and lines it quotes become code spans)
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function zoneSummary(facts, opts) {
  if (facts.compare) return zoneCompareSummary(facts.compare, opts);
  const k = kit(opts);
  const { t } = k;
  const c = facts.counts || {};
  const counts = [t('sum.zone.records', { count: Number(c.records) || 0 }), t('sum.zone.names', { count: Number(c.names) || 0 }), t('sum.zone.proxied', { count: Number(c.proxied) || 0 })].join(' · ');
  const tally = k.counts([['sum.count.error', c.errors], ['sum.count.warn', c.warnings], ['sum.count.info', c.info]]);
  return doc('zone', k.title('zone', facts.origin ? [code(facts.origin)] : t('sum.zone.noOrigin')), [
    [facts.format ? `${cleanText(facts.format)}: ` : '', counts],
    [tally ? t('sum.zone.problems', { list: tally }) : t('sum.zone.noProblems')],
    ...problemLines(k, facts.problems, 3),
    [t('sum.zone.private')]
  ], { when: whenText(t, 'sum.at.asOf', null, opts.now || new Date()), url: opts.url });
}

/** The options a comparison names when they are on, in their order (`sum.zcmp.opt.<option>`). */
export const ZONE_COMPARE_OPTIONS = Object.freeze(['ignoreTtl', 'joinTxt', 'ignoreSoa', 'ignoreApexNs']);
/** The differences a comparison's summary words (`sum.zcmp.st.<status>`, `sum.zcmp.why.<reason>`). */
export const ZONE_COMPARE_STATUSES = Object.freeze(['added', 'removed', 'changed']);
export const ZONE_COMPARE_REASONS = Object.freeze(['values', 'ttl', 'proxied', 'routing', 'soa-names', 'soa-serial', 'soa-timers']);

/**
 * Zone File › Compare: both zones by name and format, what makes either less than a whole zone (a
 * Route 53 change batch, an incomplete export) and how the other file was read (a guessed name,
 * problems), the counts, the options that hid something, and the first differences by name and
 * type with what changed — never a value of either file.
 * @param {{ a: CompareSide, b: CompareSide, relative?: boolean,
 *   counts: { added: number, removed: number, changed: number, same: number, ignored: number }, options?: string[],
 *   differences?: Array<{ status: string, name: string, type: string, reasons?: string[] }>, more?: number }} cmp
 *   lib/zonediff.js diffSummaryFacts (the format labels the view shows); CompareSide = { origin: string|null,
 *   format?: string, partial?: boolean, changeBatch?: { upserts: number, deletes: number }|null, guessed?: boolean,
 *   problems?: { errors: number, warnings: number } }
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function zoneCompareSummary(cmp, opts) {
  const k = kit(opts);
  const { t } = k;
  const c = cmp.counts || {};
  const diffs = (Number(c.added) || 0) + (Number(c.removed) || 0) + (Number(c.changed) || 0);
  const name = (z) => (z && z.origin ? code(z.origin) : t('sum.zone.noOrigin'));
  const lines = [];
  if (cmp.a && cmp.b && (cmp.a.format || cmp.b.format)) {
    lines.push([t('sum.zcmp.formats', { a: cleanText(cmp.a.format || '?'), b: cleanText(cmp.b.format || '?') })]);
  }
  const batch = (cb) => ({ upserts: Number(cb.upserts) || 0, deletes: Number(cb.deletes) || 0 });
  if (cmp.a && cmp.a.changeBatch) lines.push([t('sum.zcmp.batch.a', batch(cmp.a.changeBatch))]);
  if (cmp.a && cmp.a.partial) lines.push([t('sum.zcmp.partial.a')]);
  if (cmp.b && cmp.b.changeBatch) lines.push([t('sum.zcmp.batch.b', batch(cmp.b.changeBatch))]);
  if (cmp.b && cmp.b.partial) lines.push([t('sum.zcmp.partial.b')]);
  if (cmp.b && cmp.b.guessed) lines.push([t('sum.zcmp.guessed')]);
  const problems = cmp.b && cmp.b.problems ? k.counts([['sum.count.error', cmp.b.problems.errors], ['sum.count.warn', cmp.b.problems.warnings]]) : '';
  if (problems) lines.push([t('sum.zcmp.problems', { list: problems })]);
  if (cmp.relative) lines.push([t('sum.zcmp.relative')]);
  if (!diffs) lines.push([t('sum.zcmp.none', { count: Number(c.same) || 0 })]);
  else {
    lines.push([k.counts([['sum.zcmp.added', c.added], ['sum.zcmp.removed', c.removed], ['sum.zcmp.changed', c.changed],
      ['sum.zcmp.same', c.same], ['sum.zcmp.ignored', c.ignored]])]);
  }
  const on = (cmp.options || []).filter((o) => ZONE_COMPARE_OPTIONS.includes(o));
  if (on.length) lines.push([t('sum.zcmp.options', { list: on.map((o) => t(`sum.zcmp.opt.${o}`)).join(', ') })]);
  for (const d of (cmp.differences || []).filter((x) => ZONE_COMPARE_STATUSES.includes(x.status))) {
    const why = (d.reasons || []).filter((r) => ZONE_COMPARE_REASONS.includes(r)).map((r) => t(`sum.zcmp.why.${r}`));
    lines.push([strong(`${t(`sum.zcmp.st.${d.status}`)}:`), ' ', code(d.name), ` ${cleanText(d.type)}`, why.length ? ` (${why.join(', ')})` : '']);
  }
  if (cmp.more > 0) lines.push([t('sum.zcmp.more', { count: cmp.more })]);
  lines.push([t('sum.zcmp.private')]);
  return doc('zone', k.title('zone', [name(cmp.a), ' ↔ ', name(cmp.b)]), lines,
    { when: whenText(t, 'sum.at.asOf', null, opts.now || new Date()), url: opts.url });
}

/**
 * "issued by `Example CA`": the issuer is whatever the certificate says (a self-signed one says
 * anything), so it is a code span like the subject. Lower-case mid-line (SSL Targets); a line of
 * its own capitalises it ({@link certSummary}).
 */
function issuedBy(t, issuer) {
  return textParts(t, 'sum.cert.issuedBy', { issuer: String(issuer ?? '') });
}

/** "valid until 2026-12-01 (65 days left)" / "expired on …" / "not valid before …". */
function validityText(k, cert, now) {
  const at = now instanceof Date ? now.getTime() : Number(now);
  const na = cert.notAfter instanceof Date ? cert.notAfter.getTime() : new Date(cert.notAfter).getTime();
  const nb = cert.notBefore ? new Date(cert.notBefore).getTime() : null;
  if (Number.isFinite(nb) && at < nb) return k.t('sum.cert.notYet', { date: isoDay(nb) });
  if (at > na) return k.t('sum.cert.expired', { date: isoDay(na), count: Math.floor((at - na) / 86400000) });
  return k.t('sum.cert.until', { date: isoDay(na), count: Math.floor((na - at) / 86400000) });
}

/** Certificate warnings {@link certSummary} words (`sum.cert.warn.<code>`). */
export const CERT_SUMMARY_WARNINGS = Object.freeze(['SELF_SIGNED', 'CA', 'NO_SAN', 'PRECERT', 'WEAK']);

/**
 * Certificate: who issued it, its names, its validity and what is wrong with it; loaded from CT
 * or the sample, it says so. The file never goes into the permalink, and the summary says so.
 * @param {{ name: string, issuer: string, dnsNames: string[], notBefore: Date, notAfter: Date,
 *   warnings?: string[], source?: 'file'|'ct'|'sample' }} facts `warnings`: {@link CERT_SUMMARY_WARNINGS} codes
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function certSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const now = opts.now || new Date();
  const names = facts.dnsNames || [];
  const warnings = (facts.warnings || []).filter((w) => CERT_SUMMARY_WARNINGS.includes(w));
  return doc('cert', k.title('cert', [code(facts.name)]), [
    k.cap(issuedBy(t, facts.issuer)),
    names.length ? [t('sum.cert.names', { count: names.length }), ': ', ...k.values(names, 4)] : [t('sum.cert.noNames')],
    k.cap([validityText(k, facts, now)]),
    ...warnings.map((w) => [strong(`${t('severity.warn')}:`), ' ', t(`sum.cert.warn.${w}`)]),
    facts.source === 'ct' ? [t('sum.cert.fromCt')] : facts.source === 'sample' ? [t('sum.cert.sample')] : null,
    [t('sum.cert.private')]
  ], { when: whenText(t, 'sum.at.asOf', null, now), url: opts.url });
}

/**
 * Renewal readiness: how many names will fail, could not be checked, have warnings or are ready,
 * the CA and challenge checked against, then the worst problems as "Error: `name` — title"
 * (lib/renewal.js finding titles, `renew.f.<id>.title`, which the view registers), and whether
 * HTTP-01 reachability was tested from Globalping.
 * @param {{ names: Array<{ name: string, verdict: 'ready'|'warnings'|'unknown'|'fail',
 *   problems?: Array<{ severity: string, key: string, params?: object }> }>, ca?: string|null, challenge?: string,
 *   tested?: number, at?: Date }} facts `ca`: the CA's name (null: not chosen); `at`: when the check ended
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function renewSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const list = (facts.names || []).filter((n) => n && n.name);
  const count = (verdict) => list.filter((n) => n.verdict === verdict).length;
  const tally = k.counts([['sum.renew.fail', count('fail')], ['sum.renew.unknown', count('unknown')],
    ['sum.renew.warnings', count('warnings')], ['sum.renew.ready', count('ready')]]);
  const rank = { error: 0, warn: 1 };
  const problems = list.flatMap((n) => (n.problems || []).filter((p) => p && rank[p.severity] !== undefined).map((p) => ({ n, p })))
    .map((x, i) => ({ ...x, i })).sort((a, b) => rank[a.p.severity] - rank[b.p.severity] || a.i - b.i);
  const lines = problems.slice(0, SUMMARY_MAX_PROBLEMS)
    .map(({ n, p }) => [strong(`${t(`severity.${p.severity}`)}:`), ' ', code(n.name), ' — ', ...textParts(t, p.key, p.params)]);
  if (problems.length > SUMMARY_MAX_PROBLEMS) lines.push([t('sum.moreProblems', { count: problems.length - SUMMARY_MAX_PROBLEMS })]);
  const challenge = t(`renew.ch.${facts.challenge || 'unknown'}`);
  return doc('renew', k.title('renew', k.domains(list.map((n) => n.name))), [
    tally ? [tally] : [t('sum.renew.none')],
    facts.ca ? [t('sum.renew.setup', { ca: cleanText(facts.ca), challenge })] : [t('sum.renew.setupNoCa', { challenge })],
    ...(lines.length ? lines : list.length ? [[t('sum.renew.noProblems')]] : []),
    facts.tested ? [t('sum.renew.tested', { count: Number(facts.tested) })] : null
  ], { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

/** Presentation text of a record's data, or null when it has no short form. */
function recordValue(rr) {
  const d = rr && rr.data;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) return d.join('');
  if (d && typeof d === 'object' && d.exchange !== undefined) return `${d.preference} ${d.exchange}`;
  return null;
}

/**
 * DNS Lookup (one line): per type the number of records (or the rcode), the values when there
 * are three or fewer, and the DNSSEC AD bit when it was asked for and every answer has it.
 * @param {{ name: string, ptrFor?: string|null, types: string[], responses: Array<object|null>, dnssec?: boolean, at?: Date }} facts
 *   `responses`: DohClient responses in `types` order; `at`: when the last one arrived
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function lookupSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const rows = (facts.types || []).map((type, i) => ({ type, r: (facts.responses || [])[i] || null }));
  const answered = rows.filter((x) => x.r && x.r.ok);
  const parts = [];
  if (answered.length && answered.every((x) => x.r.rcode === 'NXDOMAIN')) {
    parts.push(t('sum.lookup.nxdomain'));
  } else {
    const records = rows.map((x) => ({ ...x, rrs: x.r && x.r.ok ? (x.r.answers || []).filter((rr) => rr.type === x.type) : [] }));
    const total = records.reduce((n, x) => n + x.rrs.length, 0);
    const vals = records.flatMap((x) => x.rrs.map(recordValue));
    const showValues = total > 0 && total <= 3 && vals.every((v) => v !== null && cleanText(v).length <= 64);
    records.forEach((x, i) => {
      if (i) parts.push(' · ');
      parts.push(`${x.type}: `);
      if (!x.r) parts.push(t('sum.lookup.pending'));
      else if (!x.r.ok) parts.push(t('sum.lookup.failed'));
      else if (x.r.rcode !== 'NOERROR') parts.push(cleanText(x.r.rcode));
      else if (!x.rrs.length) parts.push(t('sum.lookup.noRecords'));
      else if (showValues) parts.push(...k.values(x.rrs.map(recordValue), 3));
      else parts.push(t('sum.lookup.records', { count: x.rrs.length }));
    });
  }
  if (facts.dnssec && answered.length && answered.every((x) => x.r.flags && x.r.flags.ad)) parts.push(` · ${t('sum.lookup.ad')}`);
  return doc('lookup', k.title('lookup', [code(facts.ptrFor || facts.name)]), [parts],
    { inline: true, when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

/**
 * IP Intel (one line): for one address its network, country, reverse name and operator; for
 * several, how many sit behind a CDN, are private, are in the server list, and how many networks
 * and countries. No inventory server name is included: only whether (or how many) are in the list.
 * A lookup that failed (lib/ipintel `info.error`: every source failed or was rate-limited) is
 * counted as failed, and a stopped lookup says how many addresses it never looked up (the rows
 * without data); "no network data" is said only of an address that was looked up and answered.
 * @param {{ rows: Array<{ ip: string, info?: object|null, classification?: object, servers?: object[] }>, at?: Date,
 *   stopped?: boolean }} facts `at`: when the lookup ended; `stopped`: the user stopped it
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function ipSummary({ rows = [], at = null, stopped = false }, opts) {
  const k = kit(opts);
  const { t } = k;
  const list = rows.filter((r) => r && r.ip);
  const parts = [];
  const operator = (r) => {
    const c = r.classification || {};
    if (c.provider && c.provider.name) return c.provider.name;
    return c.kind ? t(`kind.${c.kind}`) : null;
  };
  // views/ip leaves `info` null on a row it never reached: a stopped lookup's, else one whose
  // lookup ended without a result (counted as failed, like a row whose every source failed).
  const failedRow = (r) => (r.info ? !!r.info.error : !stopped);
  const failed = list.filter(failedRow).length;
  const notLooked = stopped ? list.filter((r) => !r.info).length : 0;
  // Only an address that was looked up and answered can have "no network data".
  const answered = list.length - failed - notLooked;
  let subject;
  if (list.length === 1) {
    const r = list[0];
    const info = r.info || {};
    subject = [code(r.ip)];
    const bits = [];
    // The AS name and the place come from registry / geolocation data anyone can word: code spans.
    if (info.asn) bits.push([`AS${cleanText(info.asn)}`, ...(info.asName || info.holder ? [' ', code(info.asName || info.holder)] : [])]);
    if (info.country) bits.push([code(info.city ? `${info.city}, ${info.country}` : info.country)]);
    if (info.ptr && info.ptr.length) bits.push(k.values(info.ptr, 1));
    const op = operator(r);
    if (op) bits.push([op]);
    if (r.servers && r.servers.length) bits.push([t('sum.ip.mineOne')]);
    if (!bits.length && answered) bits.push([t('sum.ip.noData')]);
    if (failed) bits.push([t('sum.ip.failedOne')]);
    if (notLooked) bits.push([t('sum.ip.stoppedOne')]);
    bits.forEach((b, i) => parts.push(...(i ? [' · '] : []), ...b));
  } else {
    subject = t('sum.ip.addresses', { count: list.length });
    const cdn = list.filter((r) => r.classification && r.classification.hidesOrigin);
    const names = [...new Set(cdn.map((r) => r.classification.provider && r.classification.provider.name).filter(Boolean))];
    const bits = [];
    if (cdn.length) bits.push(`${t('sum.ip.cdn', { count: cdn.length })}${names.length ? ` (${names.slice(0, 3).join(', ')})` : ''}`);
    const priv = list.filter((r) => isPrivateIP(r.ip)).length;
    if (priv) bits.push(t('sum.ip.private', { count: priv }));
    const mine = list.filter((r) => r.servers && r.servers.length).length;
    if (mine) bits.push(t('sum.ip.mine', { count: mine }));
    const asns = new Set(list.map((r) => r.info && r.info.asn).filter(Boolean)).size;
    if (asns) bits.push(t('sum.ip.networks', { count: asns }));
    const countries = new Set(list.map((r) => r.info && r.info.country).filter(Boolean)).size;
    if (countries) bits.push(t('sum.ip.countries', { count: countries }));
    if (!bits.length && (answered || !list.length)) bits.push(t('sum.ip.noData'));
    if (failed) bits.push(t('sum.ip.failed', { count: failed }));
    if (notLooked) bits.push(t('sum.ip.stopped', { count: notLooked }));
    parts.push(bits.join(' · '));
  }
  return doc('ip', k.title('ip', subject), [parts], { inline: true, when: whenText(t, 'sum.at.checked', at, opts.now || new Date()), url: opts.url });
}

/** Severities of lib/retire.js whose records break something, worst first (`sum.retire.sev.<id>` labels them). */
export const RETIRE_BREAKING_SEVERITIES = Object.freeze(['mail', 'ns', 'live', 'origin', 'chain']);
/** Records a Retire an IP summary lists by name (the 12-line budget holds four next to its other lines). */
const RETIRE_MAX_RECORDS = 4;

/**
 * Retire an IP: how many records still point at the addresses and how many of them break
 * something, what was checked, the worst records (≤ 4, then "+N more"), what the check could not
 * settle — SPF terms it cannot tell, passive hits nobody checked, failed lookups, domains that do not
 * exist, a stop — and what it never covers (internal DNS, domains not in the list). The server list
 * only as a count, never a name.
 * @param {{ label: string, domains?: string[], notChecked?: string[], zone?: string|null, passive?: boolean,
 *   counts: { total: number, breaking: number, bySeverity: Record<string, number>, byVerified?: Record<string, number> },
 *   top?: Array<{ severity: string, name: string, type: string, value: string }>, owners?: number|null,
 *   unverified?: number, failed?: number, missing?: number, unresolved?: number, stopped?: boolean, at?: Date }} facts lib/retire.js buildChanges counts and
 *   changes (worst first); `domains`: the domains whose check finished, `notChecked`: the ones it did not reach
 *   (a stop) or could not check; `zone`: the imported zone's origin when its records were compared; `passive`: a
 *   passive reverse-IP lookup was made; `owners`: servers of the list that own an address (null: no list loaded);
 *   `unverified`: rows of the passive group (nobody checked them, or their lookup failed); `failed`: lookups that got
 *   no answer; `missing`: checked domains that do not exist (a typo in the list?); `unresolved`: known host names past the
 *   check's cap on names, never resolved
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function retireSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const c = facts.counts || { total: 0, breaking: 0, bySeverity: {} };
  const sev = c.bySeverity || {};
  // What cannot be told and what nobody checked is said on lines of its own, never counted as pointing here.
  const total = Math.max(0, (Number(c.total) || 0) - (Number(sev.unknown) || 0) - (Number(facts.unverified) || 0));
  const breaking = Number(c.breaking) || 0;
  // A failed lookup, a "cannot tell", a domain that does not exist or a host name never resolved leaves the list open:
  // never "nothing points at it" then.
  const open = (Number(facts.failed) || 0) > 0 || (Number(sev.unknown) || 0) > 0 || (Number(facts.missing) || 0) > 0
    || (Number(facts.unresolved) || 0) > 0;
  let verdict;
  if (!total) verdict = facts.stopped ? t('sum.retire.noneStopped') : open ? t('sum.retire.noneOpen') : t('sum.retire.none');
  else verdict = `${t('sum.retire.records', { count: total })} · ${breaking ? t('sum.retire.breaking', { count: breaking }) : t('sum.retire.breakingNone')}`;
  if (facts.stopped && total) verdict = `${verdict} ${t('sum.retire.partial')}`;
  const domains = facts.domains || [];
  const checked = domains.length ? [`${t('sum.retire.domains', { count: domains.length })} `, ...k.domains(domains)] : [t('sum.retire.noDomains')];
  if (facts.notChecked && facts.notChecked.length) checked.push(` · ${t('sum.retire.notChecked')} `, ...k.domains(facts.notChecked));
  if (facts.zone) checked.push(' · ', ...textParts(t, 'sum.retire.lookedZone', { zone: facts.zone }));
  if (facts.passive) checked.push(' · ', t('sum.retire.lookedPassive'));
  const top = (facts.top || []).filter((r) => r && RETIRE_BREAKING_SEVERITIES.includes(r.severity));
  const topLines = top.slice(0, RETIRE_MAX_RECORDS).map((r) => [
    strong(`${t(`sum.retire.sev.${r.severity}`)}:`), ' ', code(r.name), ` ${cleanText(r.type)} `, code(r.value)
  ]);
  if (top.length > RETIRE_MAX_RECORDS) topLines.push([t('sum.retire.more', { count: top.length - RETIRE_MAX_RECORDS })]);
  const owners = facts.owners;
  // What the check could not settle, on one line: the budget is 12 lines with the worst records.
  const unsettled = k.counts([['sum.retire.unknown', sev.unknown], ['sum.retire.unverified', facts.unverified], ['sum.retire.failed', facts.failed],
    ['sum.retire.missing', facts.missing], ['sum.retire.unresolved', facts.unresolved]]);
  return doc('retire', k.title('retire', [code(facts.label)]), [
    [verdict],
    checked,
    owners === null || owners === undefined ? null : [owners > 0 ? t('sum.retire.owners', { count: owners }) : t('sum.retire.ownersNone')],
    ...topLines,
    unsettled ? [strong(`${t('sum.retire.open')}:`), ' ', unsettled] : null,
    [t('sum.retire.scope')]
  ], { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

/**
 * Domain overview: one line per card — registration, DNS hosting, mail, web, certificates, SaaS
 * verifications, health — from lib/passport.js passportSummaryFacts: names only (providers,
 * platforms, vendors and CAs from the app's own tables as text; the registrar, host names and the
 * issuers read from CT as code spans), never a verification token, a record value or an address.
 * A part whose lookup failed says so, one that was not looked up (a stopped build) too: a line
 * never reads as complete without the lookup that failed (SPF, DMARC, a host's HTTPS record, CAA).
 * @param {object} facts passportSummaryFacts() output (`at`: when the overview was built)
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function domainSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const f = facts || {};
  const label = (key) => [strong(`${t(key)}:`), ' '];
  /** Trusted names (the app's own tables) as text: three, then "+N more". */
  const names = (list, max = 3) => {
    const items = [...new Set((list || []).map(cleanText).filter(Boolean))];
    return items.slice(0, max).join(', ') + (items.length > max ? ` ${t('common.moreCount', { count: items.length - max })}` : '');
  };
  /** What a part says when it has nothing to show: not looked up (pending), or its lookup failed. */
  const state = (part, empty) => {
    if (!part || part.pending) return [t('sum.domain.notLooked')];
    if (part.failed && empty) return [t('sum.domain.failed')];
    return null;
  };
  const join = (bits) => bits.filter((b) => b && b.length).flatMap((b, i) => (i ? [' · ', ...b] : b));
  const lines = [];

  // Registration
  const reg = f.registration || { pending: true };
  let regLine = state(reg, reg.outcome === 'failed' || !reg.outcome);
  if (!regLine) {
    if (reg.outcome === 'unsupported') {
      regLine = [reg.whois ? t('sum.domain.noRdapAt', { tld: reg.tld || '', registry: reg.whois }) : t('sum.domain.noRdap', { tld: reg.tld || '' })];
    } else if (reg.outcome === 'not-found') regLine = [t('sum.domain.notRegistered')];
    else if (reg.outcome === 'invalid') regLine = [t('sum.domain.notRegistrable')];
    else if (reg.outcome === 'ok') {
      const bits = [];
      if (reg.registrar) bits.push([code(reg.registrar)]);
      if (reg.expires) {
        const days = Number(reg.daysLeft);
        bits.push([days < 0 ? t('sum.domain.expired', { date: isoDay(reg.expires), count: -days }) : t('sum.domain.expires', { date: isoDay(reg.expires), count: days })]);
      }
      if (reg.transferLock === false) bits.push([t('sum.domain.noLock')]);
      regLine = bits.length ? join(bits) : [t('sum.domain.noData')];
    } else regLine = [t('sum.domain.failed')];
  }
  lines.push([...label('sum.domain.registration'), ...regLine]);

  // DNS hosting
  const dns = f.dns || { pending: true };
  let dnsLine = state(dns, !(dns.providers || []).length && !dns.self && !(dns.other || []).length && !dns.dnssec);
  if (!dnsLine) {
    if (dns.exists === false) dnsLine = [t('sum.domain.nxdomain')];
    else {
      const who = [];
      if ((dns.providers || []).length) who.push([names(dns.providers)]);
      if (dns.self) who.push([t('sum.domain.ownNs')]);
      if ((dns.other || []).length) who.push(k.values(dns.other, 2));
      const bits = [who.length ? join(who) : [t(dns.nsFailed ? 'sum.domain.nsFailed' : 'sum.domain.noNs')]];
      if (dns.dnssec) bits.push([t(`sum.domain.dnssec.${dns.dnssec}`)]);
      if (dns.delegationDiffers) bits.push([t('sum.domain.delegation')]);
      // Another lookup of the card failed (SOA, DS / DNSKEY): the line does not claim it all.
      if (dns.failed && !(dns.nsFailed && !who.length)) bits.push([t('sum.domain.partFailed')]);
      dnsLine = join(bits);
    }
  }
  lines.push([...label('sum.domain.dns'), ...dnsLine]);

  // Mail
  const mail = f.mail || { pending: true };
  let mailLine = state(mail, !mail.mx && !mail.spf && !mail.dmarc);
  if (!mailLine && mail.exists === false) mailLine = [t('sum.domain.nxdomain')];
  if (!mailLine) {
    const bits = [];
    if (mail.mx === 'none') bits.push([t('sum.domain.noMx')]);
    else if (mail.mx === 'null') bits.push([t('sum.domain.nullMx')]);
    else if (mail.mx === 'some') {
      const who = [];
      if ((mail.platforms || []).length) who.push([names(mail.platforms)]);
      if ((mail.other || []).length) who.push(k.values(mail.other, 2));
      bits.push(join(who));
    } else bits.push([t('sum.domain.mxFailed')]);
    // The qualifier and the policy as code spans: `~all` pasted into Slack keeps its tilde.
    const spf = mail.spf;
    if (spf) {
      if (spf.state === 'ok') {
        bits.push(spf.all ? textParts(t, 'sum.domain.spfAll', { all: `${spf.all}all` }) : [t(spf.redirect ? 'sum.domain.spfRedirect' : 'sum.domain.spfNoAll')]);
      } else bits.push([t(`sum.domain.spf.${spf.state}`, { count: spf.count })]);
    } else if (mail.spfFailed) bits.push([t('sum.domain.spfFailed')]);
    const dmarc = mail.dmarc;
    if (dmarc) {
      bits.push(dmarc.state === 'ok' ? textParts(t, 'sum.domain.dmarcPolicy', { policy: `p=${dmarc.policy}` }) : [t(`sum.domain.dmarc.${dmarc.state}`, { count: dmarc.count })]);
    } else if (mail.dmarcFailed) bits.push([t('sum.domain.dmarcFailed')]);
    mailLine = join(bits);
  }
  lines.push([...label('sum.domain.mail'), ...mailLine]);

  // Web
  const web = f.web || { pending: true };
  let webLine = state(web, !(web.hosts || []).some((h) => h.state !== 'failed' && h.state !== 'pending'));
  if (!webLine) {
    const hostText = (h) => {
      if (h.state === 'failed') return t('sum.domain.failed');
      if (h.state === 'pending') return t('sum.domain.notLooked');
      if (h.state === 'nxdomain') return t('sum.domain.hostNx');
      if (h.state === 'nodata') return t('sum.domain.hostNoData');
      if (h.state === 'dangling') return t('kind.dangling');
      if (h.kind === 'cloudflare') return 'Cloudflare';
      if ((h.kind === 'cdn' || h.kind === 'platform') && h.provider) return cleanText(h.provider);
      return t(`kind.${h.kind || 'unresolved'}`);
    };
    const bits = (web.hosts || []).map((h) => [code(h.name), ' ', hostText(h)]);
    if (web.https === true) bits.push([t('sum.domain.https')]);
    // "HTTPS record" is not all there is to say while a host's HTTPS lookup failed.
    if ((web.httpsFailed || []).length) bits.push([t('sum.domain.httpsFailed'), ' ', ...k.values(web.httpsFailed, 2)]);
    webLine = join(bits);
  }
  lines.push([...label('sum.domain.web'), ...webLine]);

  // Certificates: CAA, then the CT issuers when they were looked up (kept after a CAA failure)
  const certs = f.certs || { pending: true };
  let certLine = state(certs, !certs.caa && !certs.ct && !certs.ctFailed);
  if (!certLine) {
    const bits = [];
    if (certs.exists === false) bits.push([t('sum.domain.nxdomain')]);
    else if (certs.caa === 'none') bits.push([t('sum.domain.caaNone')]);
    else if (certs.caa === 'critical') {
      // Three tags as code spans, then "+N more" inside the parentheses, as every other list here.
      const tags = certs.criticalTags || [];
      const parts = textParts(t, 'sum.domain.caaCritical', { tags: tags.slice(0, 3), count: tags.length });
      if (tags.length > 3) parts.splice(parts.map((p) => typeof p !== 'string').lastIndexOf(true) + 1, 0, ` ${t('common.moreCount', { count: tags.length - 3 })}`);
      bits.push(parts);
    }
    else if (certs.caa === 'present' || certs.caa === 'unrestricted') {
      const cas = certs.cas || [];
      const wild = certs.wildCas || [];
      if (certs.caa === 'unrestricted') bits.push([t('sum.domain.caaAny')]);
      else if (cas.length) bits.push([t('sum.domain.caaAllows', { list: names(cas) })]);
      else if (wild.length) bits.push([t('sum.domain.caaWildOnly', { list: names(wild) })]);
      else bits.push([t('sum.domain.caaDeny')]);
      // issuewild rules wildcard certificates on its own (a set without it: they follow issue).
      if (certs.wildcard && (certs.caa === 'unrestricted' || cas.length)) {
        bits.push([wild.length ? t('sum.domain.caaWild', { list: names(wild) }) : t('sum.domain.caaNoWild')]);
      }
    } else if (certs.caa === 'deny-all') bits.push([t('sum.domain.caaDeny')]);
    else if (certs.caaFailed || certs.failed) bits.push([t('sum.domain.caaFailed')]);
    if (certs.ct && certs.ct.issuers.length) {
      const issuers = certs.ct.issuers.slice(0, 3).flatMap((i, n) => [...(n ? [', '] : []), code(i.name), ` (${k.num(i.count)})`]);
      bits.push([t('sum.domain.ctIssuers'), ' ', ...issuers]);
      if ((certs.ct.notAllowed || []).length) bits.push([t('sum.domain.ctNotAllowed'), ' ', ...k.values(certs.ct.notAllowed, 3)]);
    } else if (certs.ct) bits.push([t('sum.domain.ctNone')]);
    else if (certs.ctFailed) bits.push([t('sum.domain.ctFailed')]);
    certLine = join(bits);
  }
  lines.push([...label('sum.domain.certs'), ...certLine]);

  // SaaS verifications
  const saas = f.saas || { pending: true };
  const saasLine = state(saas, saas.failed) || [saas.exists === false ? t('sum.domain.nxdomain') : (saas.vendors || []).length
    ? t('sum.domain.saas', { count: saas.vendors.length, list: names(saas.vendors) })
    : t('sum.domain.saasNone')];
  lines.push([...label('sum.domain.saasLabel'), ...saasLine]);

  // Health
  const health = f.health || { pending: true };
  const healthLine = state(health, health.score === null || health.score === undefined)
    || [t('sum.health.verdict', { verdict: t(`sum.health.light.${health.light || 'ok'}`), score: health.score })];
  lines.push([...label('sum.domain.health'), ...healthLine]);

  return doc('domain', k.title('domain', [code(f.domain)]), lines, { when: whenText(t, 'sum.at.checked', f.at, opts.now || new Date()), url: opts.url });
}

/** Certificates an estate summary names as expiring first (the rest as "+N more"). */
const ESTATE_MAX_FIRST = 3;
/** Names an estate summary lists as served with different certificates. */
const ESTATE_MAX_CONFLICTS = 3;

/**
 * Certificate estate: how many certificates the reports hold and on how many endpoints, when they
 * expire (the buckets up to 90 days that hold one), the ones that expire first and the names served
 * with different certificates — by name only: a summary never lists an address or a server of the
 * reports — and what needs a look (keys shared by many hosts or several certificates, weak keys or
 * signatures, certificates covering none of the names asked; unknown when no name was asked). The
 * reports never go into its link.
 * @param {{ reports: number, certificates: number, endpoints: number, expiry: Record<string, number>,
 *   first?: Array<{ name: string, daysLeft: number }>, conflicts?: string[], stale?: number, sharedKeys?: number,
 *   weak?: number, coversNone?: number|null, at?: Date|null }} facts views/estate.js estateSummaryFacts
 *   (lib/estate.js estateOf of the reports on screen); `first`: expired or expiring within 30 days, soonest first
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function estateSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const ex = facts.expiry || {};
  const lines = [[t('sum.estate.certs', { count: Number(facts.certificates) || 0 }), ' · ', t('sum.estate.endpoints', { count: Number(facts.endpoints) || 0 })]];
  const soon = k.counts([['sum.estate.expired', ex.expired], ['sum.estate.week', ex['7d']], ['sum.estate.month', ex['30d']], ['sum.estate.quarter', ex['90d']]]);
  lines.push(soon ? k.cap([soon]) : [t('sum.estate.noneSoon')]);
  const first = (facts.first || []).filter((c) => c && Number.isFinite(c.daysLeft));
  if (first.length) {
    const parts = [strong(`${t('sum.estate.first')}:`), ' '];
    first.slice(0, ESTATE_MAX_FIRST).forEach((c, i) => {
      const left = c.daysLeft < 0 ? t('sum.estate.expiredAgo', { count: -c.daysLeft })
        : c.daysLeft === 0 ? t('sum.estate.today') : t('sum.estate.daysLeft', { count: c.daysLeft });
      parts.push(i ? ', ' : '', code(c.name), ` (${left})`);
    });
    if (first.length > ESTATE_MAX_FIRST) parts.push(` ${t('common.moreCount', { count: first.length - ESTATE_MAX_FIRST })}`);
    lines.push(parts);
  }
  const conflicts = facts.conflicts || [];
  if (conflicts.length) lines.push([strong(`${t('sum.estate.conflicts', { count: conflicts.length })}:`), ' ', ...k.values(conflicts, ESTATE_MAX_CONFLICTS)]);
  if (Number(facts.stale) > 0) lines.push(k.cap([t('sum.estate.stale', { count: Number(facts.stale) })]));
  const look = k.counts([['sum.estate.shared', facts.sharedKeys], ['sum.estate.weak', facts.weak], ['sum.estate.coversNone', facts.coversNone]]);
  if (look) lines.push(k.cap([look]));
  else if (!conflicts.length) lines.push([t('sum.estate.clean')]);
  if (facts.coversNone === null || facts.coversNone === undefined) lines.push([t('sum.estate.noNames')]);
  lines.push([t('sum.estate.filesStay')]);
  return doc('estate', k.title('estate', t('sum.estate.reports', { count: Number(facts.reports) || 0 })), lines,
    { when: whenText(t, 'sum.at.scanned', facts.at, opts.now || new Date()), url: opts.url });
}

/** Record sets a DNS change check summary lists one by one (the rest as "+N more"). */
const CHANGE_MAX_SETS = 5;
/** The states of a record set on the check page (lib/changecheck.js checkState). */
export const CHANGE_SET_STATES = Object.freeze(['done', 'pending', 'wrong', 'unknown']);

/**
 * DNS change request › the check page ("is it live?"): the headline the page shows (its own key),
 * each record set by name and type with what the resolvers answered (live, not yet, another
 * value, no answer yet; seen on n of m), and why the check stopped where it stopped. Names and
 * types only: the values are in the link, which is the check page itself.
 * @param {{ zone: string, headline: { key: string, params?: object }, sets: Array<{ name: string, type: string,
 *   state: string, done: number, resolvers: number }>, stop?: { key: string, params?: object }|null, at?: Date|number|null }} facts
 *   views/change.js checkSummaryFacts (lib/changecheck.js checkState of the check on screen)
 * @param {{ t: Function, lang?: string, url?: string|null, now?: Date }} opts
 * @returns {SummaryDoc}
 */
export function changeSummary(facts, opts) {
  const k = kit(opts);
  const { t } = k;
  const head = facts.headline || { key: 'sum.change.state.unknown' };
  const lines = [[t(head.key, head.params || {})]];
  const sets = facts.sets || [];
  for (const s of sets.slice(0, CHANGE_MAX_SETS)) {
    const state = CHANGE_SET_STATES.includes(s.state) ? s.state : 'unknown';
    lines.push([code(s.name), ` ${cleanText(s.type)}: `, t(`sum.change.state.${state}`), ' · ',
      t('sum.change.resolvers', { count: Number(s.resolvers) || 0, done: Number(s.done) || 0 })]);
  }
  if (sets.length > CHANGE_MAX_SETS) lines.push([t('sum.change.more', { count: sets.length - CHANGE_MAX_SETS })]);
  if (facts.stop && facts.stop.key) lines.push([t(facts.stop.key, facts.stop.params || {})]);
  return doc('change', k.title('change', [code(facts.zone)]), lines,
    { when: whenText(t, 'sum.at.checked', facts.at, opts.now || new Date()), url: opts.url });
}

const BUILDERS = {
  domain: domainSummary,
  zone: zoneSummary,
  scan: scanSummary,
  cert: certSummary,
  renew: renewSummary,
  global: globalSummary,
  lookup: lookupSummary,
  ip: ipSummary,
  retire: retireSummary,
  health: healthSummary,
  estate: estateSummary,
  change: changeSummary
};
for (const [kind, build] of Object.entries(BUILDERS)) registerSummaryBuilder(kind, build);

/* ------------------------------------------------------------------------ */
/* i18n                                                                     */
/* ------------------------------------------------------------------------ */

const STRINGS = [
  ['sum.health.verdict', ['{verdict} · score {score}/100', '{verdict} · puan {score}/100']],
  ['sum.health.verdictGrade', ['{verdict} · grade {grade} · score {score}/100', '{verdict} · not {grade} · puan {score}/100']],
  ['sum.health.light.ok', ['Healthy', 'Sağlıklı']],
  ['sum.health.light.warn', ['Needs attention', 'İlgilenilmesi gerekiyor']],
  ['sum.health.light.error', ['Problems found', 'Sorun bulundu']],
  ['sum.health.noProblems', ['No errors or warnings', 'Hata ya da uyarı yok']],

  ['sum.domain.registration', ['Registration', 'Kayıt']],
  ['sum.domain.dns', ['DNS', 'DNS']],
  ['sum.domain.mail', ['Mail', 'E-posta']],
  ['sum.domain.web', ['Web', 'Web']],
  ['sum.domain.certs', ['Certificates', 'Sertifikalar']],
  ['sum.domain.saasLabel', ['Services', 'Hizmetler']],
  ['sum.domain.health', ['Health', 'Sağlık']],
  ['sum.domain.notLooked', ['not looked up', 'sorgulanmadı']],
  ['sum.domain.failed', ['lookup failed', 'sorgu başarısız']],
  ['sum.domain.partFailed', ['some lookups failed', 'bazı sorgular başarısız']],
  ['sum.domain.noData', ['no registration data', 'kayıt bilgisi yok']],
  ['sum.domain.noRdap', ['.{tld} publishes no RDAP: see the registry’s WHOIS', '.{tld} RDAP yayımlamıyor: kayıt kuruluşunun WHOIS hizmetine bakın']],
  ['sum.domain.noRdapAt', ['.{tld} publishes no RDAP: see {registry}', '.{tld} RDAP yayımlamıyor: {registry} hizmetine bakın']],
  ['sum.domain.notRegistered', ['not registered (RDAP)', 'kayıtlı değil (RDAP)']],
  ['sum.domain.notRegistrable', ['not a domain a registry holds', 'bir kayıt kuruluşunun tuttuğu bir alan adı değil']],
  ['sum.domain.expires', [{ zero: 'expires {date} (today)', one: 'expires {date} ({count} day left)', other: 'expires {date} ({count} days left)' },
    { zero: '{date} tarihinde sona eriyor (bugün)', other: '{date} tarihinde sona eriyor ({count} gün kaldı)' }]],
  ['sum.domain.expired', [{ one: 'expired {date} ({count} day ago)', other: 'expired {date} ({count} days ago)' }, '{date} tarihinde sona erdi ({count} gün önce)']],
  ['sum.domain.noLock', ['no transfer lock', 'transfer kilidi yok']],
  ['sum.domain.nxdomain', ['the domain does not exist (NXDOMAIN)', 'alan adı mevcut değil (NXDOMAIN)']],
  ['sum.domain.ownNs', ['its own name servers', 'kendi ad sunucuları']],
  ['sum.domain.noNs', ['no NS records', 'NS kaydı yok']],
  ['sum.domain.nsFailed', ['NS lookup failed', 'NS sorgusu başarısız']],
  ['sum.domain.dnssec.validated', ['DNSSEC validated', 'DNSSEC doğrulanıyor']],
  ['sum.domain.dnssec.signed', ['DNSSEC signed', 'DNSSEC imzalı']],
  ['sum.domain.dnssec.unsigned', ['no DNSSEC', 'DNSSEC yok']],
  ['sum.domain.dnssec.failing', ['DNSSEC may be broken', 'DNSSEC bozuk olabilir']],
  ['sum.domain.delegation', ['the registry delegates to other name servers', 'kayıt kuruluşu başka ad sunucularına yönlendiriyor']],
  ['sum.domain.noMx', ['no MX record', 'MX kaydı yok']],
  ['sum.domain.nullMx', ['accepts no mail (null MX)', 'e-posta kabul etmiyor (null MX)']],
  ['sum.domain.mxFailed', ['MX lookup failed', 'MX sorgusu başarısız']],
  ['sum.domain.spfFailed', ['SPF lookup failed', 'SPF sorgusu başarısız']],
  ['sum.domain.dmarcFailed', ['DMARC lookup failed', 'DMARC sorgusu başarısız']],
  ['sum.domain.spfAll', ['SPF {all}', 'SPF {all}']],
  ['sum.domain.spfRedirect', ['SPF redirect', 'SPF redirect']],
  ['sum.domain.spfNoAll', ['SPF without “all”', '“all” içermeyen SPF']],
  ['sum.domain.spf.none', ['no SPF', 'SPF yok']],
  ['sum.domain.spf.many', ['{count} SPF records (invalid)', '{count} SPF kaydı (geçersiz)']],
  ['sum.domain.spf.invalid', ['SPF invalid', 'SPF geçersiz']],
  ['sum.domain.dmarcPolicy', ['DMARC {policy}', 'DMARC {policy}']],
  ['sum.domain.dmarc.none', ['no DMARC', 'DMARC yok']],
  ['sum.domain.dmarc.many', ['{count} DMARC records (invalid)', '{count} DMARC kaydı (geçersiz)']],
  ['sum.domain.dmarc.invalid', ['DMARC invalid', 'DMARC geçersiz']],
  ['sum.domain.hostNx', ['does not exist', 'mevcut değil']],
  ['sum.domain.hostNoData', ['no address', 'adres yok']],
  ['sum.domain.https', ['HTTPS record', 'HTTPS kaydı']],
  ['sum.domain.httpsFailed', ['HTTPS record lookup failed for', 'HTTPS kaydı sorgusu başarısız:']],
  ['sum.domain.caaNone', ['no CAA: any CA may issue', 'CAA yok: her CA sertifika verebilir']],
  ['sum.domain.caaDeny', ['CAA allows no CA', 'CAA hiçbir CA’ya izin vermiyor']],
  ['sum.domain.caaAllows', ['CAA allows {list}', 'CAA izinli: {list}']],
  ['sum.domain.caaAny', ['CAA allows any CA (no issue property)', 'CAA her CA’ya izin veriyor (issue özelliği yok)']],
  ['sum.domain.caaWildOnly', ['CAA allows wildcard certificates only, from {list}', 'CAA yalnızca joker (wildcard) sertifikalara izin veriyor: {list}']],
  ['sum.domain.caaWild', ['wildcard certificates: {list}', 'joker sertifikalar: {list}']],
  ['sum.domain.caaNoWild', ['no CA for wildcard certificates', 'joker sertifikalara hiçbir CA izinli değil']],
  ['sum.domain.caaCritical', [{ one: 'CAA has an unknown tag marked critical ({tags}): no CA may issue', other: 'CAA has unknown tags marked critical ({tags}): no CA may issue' },
    'CAA’da kritik işaretli bilinmeyen etiket var ({tags}): hiçbir CA sertifika veremez']],
  ['sum.domain.caaFailed', ['CAA lookup failed', 'CAA sorgusu başarısız']],
  ['sum.domain.ctIssuers', ['issuers in CT:', 'CT’deki sertifika sağlayıcıları:']],
  ['sum.domain.ctNone', ['no current certificate in CT', 'CT’de geçerli sertifika yok']],
  ['sum.domain.ctNotAllowed', ['not allowed by CAA:', 'CAA izin vermiyor:']],
  ['sum.domain.ctFailed', ['CT lookup failed', 'CT sorgusu başarısız']],
  ['sum.domain.saas', [{ one: '{count} service verified the domain by TXT: {list}', other: '{count} services verified the domain by TXT: {list}' },
    '{count} hizmet alan adını TXT ile doğrulamış: {list}']],
  ['sum.domain.saasNone', ['no service verification records', 'hizmet doğrulama kaydı yok']],
  // The verdicts word what the Global DNS summary shows (glb.sum.*Title).,

  ['sum.global.agree', ['All answers agree', 'Tüm yanıtlar aynı']],
  ['sum.global.design', ['Differs by design: CDN / GeoDNS edges ({operators})', 'Tasarım gereği farklı: CDN / GeoDNS uç sunucuları ({operators})']],
  ['sum.global.designUnsure', ['Most likely by design: CDN / GeoDNS edges ({operators}); AliDNS may still hold an older answer for mainland China',
    'Büyük olasılıkla tasarım gereği farklı: CDN / GeoDNS uç sunucuları ({operators}); AliDNS anakara Çin için hâlâ eski bir yanıtı tutuyor olabilir']],
  ['sum.global.nodata', ['No {type} records anywhere — the CNAME chains differ by design ({operators})', 'Hiçbir kaynakta {type} kaydı yok — CNAME zincirleri tasarım gereği farklı ({operators})']],
  ['sum.global.nodataUnsure', ['No {type} records anywhere — the CNAME chains most likely differ by design ({operators}); AliDNS may still hold an older answer for mainland China',
    'Hiçbir kaynakta {type} kaydı yok — CNAME zincirleri büyük olasılıkla tasarım gereği farklı ({operators}); AliDNS anakara Çin için hâlâ eski bir yanıtı tutuyor olabilir']],
  ['sum.global.geo', ['Resolvers agree — locations differ (GeoDNS)', 'Çözümleyiciler aynı — konumlar farklı (GeoDNS)']],
  ['sum.global.geoUnsure', ['Resolvers agree — locations differ, most likely by GeoDNS; AliDNS may still hold an older answer for mainland China',
    'Çözümleyiciler aynı — konumlar büyük olasılıkla GeoDNS yüzünden farklı; AliDNS anakara Çin için hâlâ eski bir yanıtı tutuyor olabilir']],
  ['sum.global.unresolved', ['No source could resolve the name', 'Hiçbir kaynak adı çözümleyemedi']],
  ['sum.global.stale', ['Stale at ISP resolvers ({count}): an older answer no public resolver or location gives is still cached there',
    'İSS çözümleyicilerinde eskimiş yanıt ({count}): hiçbir genel çözümleyicinin ya da konumun vermediği eski bir yanıt orada hâlâ önbellekte']],
  ['sum.global.differ', ['Answers differ', 'Yanıtlar farklı']],
  ['sum.global.failed', ['No answers', 'Yanıt alınamadı']],
  ['sum.global.stopped', ['Stopped before any source answered', 'Hiçbir kaynak yanıt vermeden durduruldu']],
  ['sum.global.partial', ['(stopped early: not every source answered)', '(erken durduruldu: her kaynak yanıt vermedi)']],
  ['sum.global.answers', [{ one: '{count} answer from {answered} of {total} sources', other: '{count} different answers from {answered} of {total} sources' },
    { one: '{total} kaynağın {answered} tanesi aynı yanıtı verdi', other: '{total} kaynağın {answered} tanesinden {count} farklı yanıt' }]],
  ['sum.global.errors', [{ one: '{count} source failed', other: '{count} sources failed' }, '{count} kaynak başarısız']],
  ['sum.global.operators', ['Operated by {list}', 'İşleten: {list}']],
  ['sum.global.expected', ['Expected value ({mode}):', 'Beklenen değer ({mode}):']],
  ['sum.global.mode.exact', ['exact', 'tam eşleşme']],
  ['sum.global.mode.contains', ['contains', 'içerir']],
  ['sum.global.mode.regex', ['regex', 'regex']],
  ['sum.global.expectedCount', [{ one: '— served by {match} of {judged} sources', other: '— served by {match} of {judged} sources' },
    '— {judged} kaynaktan {match} tanesi döndürüyor']],
  ['sum.global.expectedNone', ['— no source has answered yet', '— henüz yanıt veren kaynak yok']],
  ['sum.global.addresses', [{ zero: 'No addresses', one: '{count} address seen worldwide', other: '{count} addresses seen worldwide' },
    { zero: 'Adres yok', other: 'Dünya genelinde {count} adres görüldü' }]],
  ['sum.global.find.rcode', [{ one: '{rcode} from {count} source', other: '{rcode} from {count} sources' }, '{count} kaynaktan {rcode}']],
  ['sum.global.find.nxdomain', [{ one: 'NXDOMAIN from {count} source', other: 'NXDOMAIN from {count} sources' }, '{count} kaynaktan NXDOMAIN']],
  ['sum.global.find.nodata', [{ one: 'No {type} records at {count} source', other: 'No {type} records at {count} sources' }, '{count} kaynakta {type} kaydı yok']],
  ['sum.global.find.private', [{ one: 'A private address from {count} source', other: 'Private addresses from {count} sources' }, '{count} kaynaktan özel (private) adres']],
  ['sum.global.find.mixed', [{ one: 'Direct addresses next to CDN edges ({count} source)', other: 'Direct addresses next to CDN edges ({count} sources)' },
    'CDN uç noktalarının yanında doğrudan adresler ({count} kaynak)']],
  ['sum.global.find.cname', [{ one: 'The CNAME differs ({count} source)', other: 'The CNAME differs ({count} sources)' }, 'CNAME farklı ({count} kaynak)']],
  ['sum.global.find.operators', [{ one: 'The name points to different providers ({count} source)', other: 'The name points to different providers ({count} sources)' },
    'Ad farklı sağlayıcılara işaret ediyor ({count} kaynak)']],
  ['sum.global.find.direct', [{ one: 'Different direct addresses ({count} source)', other: 'Different direct addresses ({count} sources)' }, 'Farklı doğrudan adresler ({count} kaynak)']],
  ['sum.global.find.records', [{ one: 'Different records ({count} source)', other: 'Different records ({count} sources)' }, 'Farklı kayıtlar ({count} kaynak)']],

  ['sum.scan.cert', ['Certificate', 'Sertifika']],
  ['sum.scan.sets', [{ one: '{count} certificate set:', other: '{count} certificate sets:' }, '{count} sertifika seti:']],
  ['sum.scan.setServers', [{ one: '— {count} server', other: '— {count} servers' }, '— {count} sunucu']],
  ['sum.scan.noCert', ['No certificate loaded: names and servers only', 'Sertifika yüklenmedi: yalnızca adlar ve sunucular']],
  ['sum.scan.hosts', [{ one: '{count} host found', other: '{count} hosts found' }, '{count} host bulundu']],
  ['sum.scan.covered', [{ one: '{count} covered by the certificate', other: '{count} covered by the certificate' }, '{count} tanesi sertifikanın kapsamında']],
  ['sum.scan.needs', [{ one: '{count} server in your list needs the certificate', other: '{count} servers in your list need the certificate' },
    'Listenizdeki {count} sunucunun sertifikaya ihtiyacı var']],
  ['sum.scan.needsNone', ['No server in your list needs the certificate', 'Listenizdeki hiçbir sunucunun sertifikaya ihtiyacı yok']],
  ['sum.scan.matched', [{ one: '{count} server in your list serves these names', other: '{count} servers in your list serve these names' },
    'Listenizdeki {count} sunucu bu adlara hizmet veriyor']],
  ['sum.scan.noInventory', ['No server list loaded: which servers need the certificate is not known', 'Sunucu listesi yüklenmedi: sertifikanın hangi sunuculara gerektiği bilinmiyor']],
  ['sum.scan.hidden', [{ one: '{count} host behind a CDN (origin hidden)', other: '{count} hosts behind a CDN (origin hidden)' }, '{count} host CDN arkasında (asıl sunucu gizli)']],
  ['sum.scan.verify', ['Verify:', 'Doğrulama:']],
  ['sum.scan.verifyNone', ['Verify: not checked from the internet yet', 'Doğrulama: henüz internetten kontrol edilmedi']],

  ['sum.zone.noOrigin', ['zone name not known', 'zone adı bilinmiyor']],
  ['sum.zone.records', [{ one: '{count} record', other: '{count} records' }, '{count} kayıt']],
  ['sum.zone.names', [{ one: '{count} name', other: '{count} names' }, '{count} ad']],
  ['sum.zone.proxied', ['{count} proxied', '{count} proxy’li']],
  ['sum.zone.problems', ['Problems: {list}', 'Sorunlar: {list}']],
  ['sum.zone.noProblems', ['No problems found in the zone', 'Zone’da sorun bulunmadı']],
  ['sum.zone.private', ['The zone file stays in this browser: the link opens Zone File without it', 'Zone dosyası bu tarayıcıda kalır: bağlantı Zone Dosyası aracını dosya olmadan açar']],
  ['sum.zcmp.formats', ['This zone: {a} · the other: {b}', 'Bu zone: {a} · diğeri: {b}']],
  ['sum.zcmp.batch.a', ['This zone’s file is a Route 53 change batch, not a whole zone (created or updated: {upserts}, deleted: {deletes}): only the record sets it changes were compared',
    'Bu zone’un dosyası bütün bir zone değil, bir Route 53 değişiklik paketi (oluşturulan ya da güncellenen: {upserts}, silinen: {deletes}): yalnızca değiştirdiği kayıt kümeleri karşılaştırıldı']],
  ['sum.zcmp.batch.b', ['The other file is a Route 53 change batch, not a whole zone (created or updated: {upserts}, deleted: {deletes}): only the record sets it changes were compared',
    'Diğer dosya bütün bir zone değil, bir Route 53 değişiklik paketi (oluşturulan ya da güncellenen: {upserts}, silinen: {deletes}): yalnızca değiştirdiği kayıt kümeleri karşılaştırıldı']],
  ['sum.zcmp.partial.a', ['This zone’s file is incomplete: a record set it lacks may only be in the part that is missing', 'Bu zone’un dosyası eksik: onda olmayan bir kayıt kümesi yalnızca eksik kısımda olabilir']],
  ['sum.zcmp.partial.b', ['The other file is incomplete: a record set it lacks may only be in the part that is missing', 'Diğer dosya eksik: onda olmayan bir kayıt kümesi yalnızca eksik kısımda olabilir']],
  ['sum.zcmp.guessed', ['The other file names no zone: its name was guessed from its records', 'Diğer dosya bir zone adı belirtmiyor: adı kayıtlarından tahmin edildi']],
  ['sum.zcmp.problems', ['Reading the other file: {list}', 'Diğer dosya okunurken: {list}']],
  ['sum.zcmp.relative', ['Different zone names: the names were compared relative to each zone', 'Farklı zone adları: adlar her zone’a göre göreli karşılaştırıldı']],
  ['sum.zcmp.none', [{ one: 'No differences: the {count} record set is the same', other: 'No differences: all {count} record sets are the same' },
    'Fark yok: {count} kayıt kümesinin hepsi aynı']],
  ['sum.zcmp.added', ['{count} added', '{count} eklendi']],
  ['sum.zcmp.removed', ['{count} removed', '{count} kaldırıldı']],
  ['sum.zcmp.changed', ['{count} changed', '{count} değişti']],
  ['sum.zcmp.same', [{ one: '{count} record set the same', other: '{count} record sets the same' }, '{count} kayıt kümesi aynı']],
  ['sum.zcmp.ignored', ['{count} ignored', '{count} yok sayıldı']],
  ['sum.zcmp.options', ['Ignored: {list}', 'Yok sayılanlar: {list}']],
  ['sum.zcmp.opt.ignoreTtl', ['TTL differences', 'TTL farkları']],
  ['sum.zcmp.opt.joinTxt', ['how TXT strings are split', 'TXT dizilerinin nasıl bölündüğü']],
  ['sum.zcmp.opt.ignoreSoa', ['the SOA serial and timers', 'SOA seri numarası ve zamanlayıcıları']],
  ['sum.zcmp.opt.ignoreApexNs', ['NS at the apex', 'zone kökündeki NS kayıtları']],
  ['sum.zcmp.st.added', ['Added', 'Eklendi']],
  ['sum.zcmp.st.removed', ['Removed', 'Kaldırıldı']],
  ['sum.zcmp.st.changed', ['Changed', 'Değişti']],
  ['sum.zcmp.why.values', ['values', 'değerler']],
  ['sum.zcmp.why.ttl', ['TTL', 'TTL']],
  ['sum.zcmp.why.proxied', ['Cloudflare proxy', 'Cloudflare proxy’si']],
  ['sum.zcmp.why.routing', ['routing', 'yönlendirme']],
  ['sum.zcmp.why.soa-names', ['SOA name server or mailbox', 'SOA ad sunucusu ya da e-posta adresi']],
  ['sum.zcmp.why.soa-serial', ['SOA serial', 'SOA seri numarası']],
  ['sum.zcmp.why.soa-timers', ['SOA timers', 'SOA zamanlayıcıları']],
  ['sum.zcmp.more', [{ one: '+{count} more difference', other: '+{count} more differences' }, '+{count} fark daha']],
  ['sum.zcmp.private', ['Both zone files stay in this browser: the link opens Zone File without them', 'İki zone dosyası da bu tarayıcıda kalır: bağlantı Zone Dosyası aracını onlar olmadan açar']],

  ['sum.cert.issuedBy', ['issued by {issuer}', 'veren: {issuer}']],
  ['sum.cert.names', [{ one: '{count} DNS name', other: '{count} DNS names' }, '{count} DNS adı']],
  ['sum.cert.noNames', ['No DNS names', 'DNS adı yok']],
  ['sum.cert.until', [{ zero: 'valid until {date} (expires today)', one: 'valid until {date} ({count} day left)', other: 'valid until {date} ({count} days left)' },
    { zero: '{date} tarihine kadar geçerli (bugün sona eriyor)', other: '{date} tarihine kadar geçerli ({count} gün kaldı)' }]],
  ['sum.cert.expired', [{ zero: 'expired on {date} (today)', one: 'expired on {date} ({count} day ago)', other: 'expired on {date} ({count} days ago)' },
    { zero: '{date} tarihinde sona erdi (bugün)', other: '{date} tarihinde sona erdi ({count} gün önce)' }]],
  ['sum.cert.notYet', ['not valid before {date}', '{date} tarihinden önce geçerli değil']],
  ['sum.cert.warn.SELF_SIGNED', ['self-signed: browsers do not trust it', 'kendinden imzalı: tarayıcılar güvenmez']],
  ['sum.cert.warn.CA', ['a CA certificate, not a server certificate', 'bir CA sertifikası, sunucu sertifikası değil']],
  ['sum.cert.warn.NO_SAN', ['no DNS names: browsers reject it for a host name', 'DNS adı yok: tarayıcılar bir host adı için kabul etmez']],
  ['sum.cert.warn.PRECERT', ['a precertificate: no server serves this exact certificate', 'bir ön sertifika (precertificate): hiçbir sunucu tam olarak bunu sunmaz']],
  ['sum.cert.warn.WEAK', ['weak key or signature algorithm', 'zayıf anahtar ya da imza algoritması']],
  ['sum.cert.fromCt', ['Loaded from Certificate Transparency: a server may serve a different one', 'Certificate Transparency kayıtlarından yüklendi: bir sunucu farklı bir sertifika sunuyor olabilir']],
  ['sum.cert.sample', ['This is the built-in sample certificate', 'Bu, uygulamadaki örnek sertifika']],
  ['sum.cert.private', ['The certificate file stays in this browser: the link opens the Certificate tool without it', 'Sertifika dosyası bu tarayıcıda kalır: bağlantı Sertifika aracını dosya olmadan açar']],

  ['sum.renew.fail', ['{count} will fail', '{count} tanesi başarısız olacak']],
  ['sum.renew.unknown', ['{count} could not be checked', '{count} tanesi kontrol edilemedi']],
  ['sum.renew.warnings', ['{count} with warnings', '{count} tanesi uyarılı']],
  ['sum.renew.ready', ['{count} ready', '{count} tanesi hazır']],
  ['sum.renew.none', ['No names checked', 'Hiçbir ad kontrol edilmedi']],
  ['sum.renew.setup', ['CA: {ca} · challenge: {challenge}', 'Otorite: {ca} · doğrulama: {challenge}']],
  ['sum.renew.setupNoCa', ['CA not chosen · challenge: {challenge}', 'Otorite seçilmedi · doğrulama: {challenge}']],
  ['sum.renew.noProblems', ['No errors or warnings', 'Hata ya da uyarı yok']],
  ['sum.renew.tested', [{ one: 'HTTP-01 reachability tested for {count} name from three continents (Globalping)', other: 'HTTP-01 reachability tested for {count} names from three continents (Globalping)' },
    'HTTP-01 erişilebilirliği {count} ad için üç kıtadan test edildi (Globalping)']],

  ['sum.lookup.records', [{ one: '{count} record', other: '{count} records' }, '{count} kayıt']],
  ['sum.lookup.noRecords', ['none', 'yok']],
  ['sum.lookup.failed', ['lookup failed', 'sorgu başarısız']],
  ['sum.lookup.pending', ['no answer yet', 'henüz yanıt yok']],
  ['sum.lookup.nxdomain', ['the name does not exist (NXDOMAIN)', 'ad mevcut değil (NXDOMAIN)']],
  ['sum.lookup.ad', ['DNSSEC validated (AD)', 'DNSSEC doğrulandı (AD)']],

  ['sum.ip.addresses', [{ one: '{count} address', other: '{count} addresses' }, '{count} adres']],
  ['sum.ip.cdn', [{ one: '{count} behind a CDN', other: '{count} behind a CDN' }, '{count} tanesi CDN arkasında']],
  ['sum.ip.private', [{ one: '{count} private', other: '{count} private' }, '{count} tanesi özel (private)']],
  ['sum.ip.mine', ['{count} in your server list', '{count} tanesi sunucu listenizde']],
  ['sum.ip.mineOne', ['in your server list', 'sunucu listenizde']],
  ['sum.ip.networks', [{ one: '{count} network', other: '{count} networks' }, '{count} ağ']],
  ['sum.ip.countries', [{ one: '{count} country', other: '{count} countries' }, '{count} ülke']],
  ['sum.ip.noData', ['no network data', 'ağ bilgisi yok']],
  ['sum.ip.failed', [{ one: '{count} lookup failed', other: '{count} lookups failed' }, '{count} adreste sorgu başarısız']],
  ['sum.ip.failedOne', ['lookup failed', 'sorgu başarısız']],
  ['sum.ip.stopped', [{ one: 'stopped: {count} address not looked up', other: 'stopped: {count} addresses not looked up' }, 'durduruldu: {count} adres sorgulanmadı']],
  ['sum.ip.stoppedOne', ['stopped before it was looked up', 'sorgulanmadan durduruldu']],

  ['sum.retire.records', [{ one: '{count} record still points at it', other: '{count} records still point at it' }, '{count} kayıt hâlâ bu adresi gösteriyor']],
  ['sum.retire.breaking', [{ one: '{count} breaks something once it is gone', other: '{count} break something once it is gone' }, 'adres kalkınca {count} tanesi bir şeyi bozar']],
  ['sum.retire.breakingNone', ['none of them breaks anything once it is gone', 'adres kalkınca hiçbiri bir şeyi bozmaz']],
  ['sum.retire.none', ['Nothing in the checked domains points at it', 'Kontrol edilen alan adlarında bu adresi gösteren bir şey yok']],
  ['sum.retire.noneStopped', ['Stopped before anything pointing at it was found', 'Bu adresi gösteren bir şey bulunmadan durduruldu']],
  ['sum.retire.noneOpen', ['Nothing found pointing at it, but not everything could be checked (below)', 'Bu adresi gösteren bir şey bulunmadı, ama her şey kontrol edilemedi (aşağıda)']],
  ['sum.retire.notChecked', ['not checked:', 'kontrol edilmedi:']],
  ['sum.retire.partial', ['(stopped early: not every domain was checked)', '(erken durduruldu: her alan adı kontrol edilmedi)']],
  ['sum.retire.domains', [{ one: 'Checked {count} domain over public DNS:', other: 'Checked {count} domains over public DNS:' }, 'Genel DNS üzerinden {count} alan adı kontrol edildi:']],
  ['sum.retire.noDomains', ['No domain checked', 'Hiçbir alan adı kontrol edilmedi']],
  ['sum.retire.lookedZone', ['the zone file of {zone}', '{zone} zone dosyası']],
  ['sum.retire.lookedPassive', ['passive reverse IP', 'pasif ters IP']],
  ['sum.retire.owners', [{ one: 'Owned by {count} server in your list', other: 'Owned by {count} servers in your list' }, 'Listenizdeki {count} sunucuya ait']],
  ['sum.retire.ownersNone', ['Not in your server list', 'Sunucu listenizde yok']],
  ['sum.retire.sev.mail', ['Mail', 'E-posta']],
  ['sum.retire.sev.ns', ['Name server', 'Ad sunucusu']],
  ['sum.retire.sev.live', ['Address record', 'Adres kaydı']],
  ['sum.retire.sev.origin', ['Proxy origin', 'Proxy asıl sunucusu']],
  ['sum.retire.sev.chain', ['CNAME chain', 'CNAME zinciri']],
  ['sum.retire.more', [{ one: '+{count} more record to change', other: '+{count} more records to change' }, 'değiştirilecek +{count} kayıt daha']],
  ['sum.retire.open', ['Not settled', 'Belirsiz kalanlar']],
  ['sum.retire.scope', ['Not covered: internal (split-horizon) DNS and domains that are not in the list', 'Kapsam dışı: iç (split-horizon) DNS ve listede olmayan alan adları']],
  ['sum.retire.unknown', [{ one: '{count} SPF term that cannot be told from here', other: '{count} SPF terms that cannot be told from here' },
    'buradan anlaşılamayan {count} SPF terimi']],
  ['sum.retire.unverified', [{ one: '{count} passive hit not checked yet', other: '{count} passive hits not checked yet' }, 'henüz kontrol edilmemiş {count} pasif sonuç']],
  ['sum.retire.failed', [{ one: '{count} failed lookup (the list may be incomplete)', other: '{count} failed lookups (the list may be incomplete)' },
    '{count} başarısız sorgu (liste eksik olabilir)']],
  ['sum.retire.missing', [{ one: '{count} domain that does not exist (a typo?)', other: '{count} domains that do not exist (a typo?)' },
    'mevcut olmayan {count} alan adı (yazım hatası mı?)']],
  ['sum.retire.unresolved', [{ one: '{count} host name not resolved (name limit reached)', other: '{count} host names not resolved (name limit reached)' },
    'çözümlenmeyen {count} host adı (ad sınırı aşıldı)']],

  ['sum.estate.reports', [{ one: '{count} report', other: '{count} reports' }, '{count} rapor']],
  ['sum.estate.certs', [{ one: '{count} certificate', other: '{count} certificates' }, '{count} sertifika']],
  ['sum.estate.endpoints', [{ one: 'served on {count} endpoint', other: 'served on {count} endpoints' }, '{count} uç noktada sunuluyor']],
  ['sum.estate.expired', [{ one: '{count} expired', other: '{count} expired' }, 'süresi dolmuş: {count}']],
  ['sum.estate.week', [{ one: '{count} within 7 days', other: '{count} within 7 days' }, '7 gün içinde: {count}']],
  ['sum.estate.month', [{ one: '{count} within 30 days', other: '{count} within 30 days' }, '30 gün içinde: {count}']],
  ['sum.estate.quarter', [{ one: '{count} within 90 days', other: '{count} within 90 days' }, '90 gün içinde: {count}']],
  ['sum.estate.noneSoon', ['None expires within 90 days', '90 gün içinde süresi dolan yok']],
  ['sum.estate.first', ['Expiring first', 'İlk dolacaklar']],
  ['sum.estate.daysLeft', [{ one: '{count} day left', other: '{count} days left' }, '{count} gün kaldı']],
  ['sum.estate.today', ['less than a day left', '1 günden az kaldı']],
  ['sum.estate.expiredAgo', [{ one: 'expired {count} day ago', other: 'expired {count} days ago' }, '{count} gün önce doldu']],
  ['sum.estate.conflicts', [{ one: '{count} name served with different certificates', other: '{count} names served with different certificates' },
    'Farklı sertifikalarla sunulan {count} ad']],
  ['sum.estate.stale', [{ one: '{count} older certificate left behind on its servers', other: '{count} older certificates left behind on their servers' },
    'Sunucularında geride kalmış {count} eski sertifika']],
  ['sum.estate.shared', [{ one: '{count} key on many hosts or in several certificates', other: '{count} keys on many hosts or in several certificates' },
    'birçok sunucuda ya da birden çok sertifikada {count} anahtar']],
  ['sum.estate.weak', [{ one: '{count} certificate with a weak key or signature', other: '{count} certificates with a weak key or signature' },
    'zayıf anahtarlı ya da imzalı {count} sertifika']],
  ['sum.estate.coversNone', [{ one: '{count} certificate covering none of the names asked', other: '{count} certificates covering none of the names asked' },
    'sorulan adların hiçbirini kapsamayan {count} sertifika']],
  ['sum.estate.clean', ['No name served with different certificates, no shared or weak key', 'Farklı sertifikalarla sunulan ad, ortak ya da zayıf anahtar yok']],
  ['sum.estate.noNames', ['The reports asked for no name: which certificates cover none cannot be told',
    'Raporlar hiçbir ad sormadı: hiçbir adı kapsamayan sertifikalar söylenemez']],
  ['sum.estate.filesStay', ['The reports stay in this browser: the link opens the Certificate estate without them',
    'Raporlar bu tarayıcıda kalır: bağlantı Sertifika envanterini onlar olmadan açar']],

  ['sum.change.state.done', ['live', 'yayında']],
  ['sum.change.state.pending', ['not live yet', 'henüz yayında değil']],
  ['sum.change.state.wrong', ['another value', 'başka bir değer']],
  ['sum.change.state.unknown', ['no answer yet', 'henüz yanıt yok']],
  ['sum.change.resolvers', [{ one: 'seen on {done} of {count} resolver', other: 'seen on {done} of {count} resolvers' },
    '{count} çözümleyiciden {done} tanesinde görülüyor']],
  ['sum.change.more', [{ one: '+{count} more record set', other: '+{count} more record sets' }, '+{count} kayıt kümesi daha']]
];

function buildStrings(lang) {
  return Object.fromEntries(STRINGS.map(([key, pair]) => [key, pair[lang]]));
}

/**
 * English and Turkish texts of every `sum.*` key the builders use, the core's included
 * (lib/summarycore.js SUMMARY_CORE_I18N). Placeholders: `{param}`; a text that shows a number is a
 * plural object `{ zero?, one?, other }`. Register with `registerStrings('en', SUMMARY_I18N.en)` /
 * `registerStrings('tr', SUMMARY_I18N.tr)` (ui/view-summaries.js does).
 * @type {{ en: Object<string, string|object>, tr: Object<string, string|object> }}
 */
export const SUMMARY_I18N = Object.freeze({
  en: Object.freeze({ ...SUMMARY_CORE_I18N.en, ...buildStrings(0) }),
  tr: Object.freeze({ ...SUMMARY_CORE_I18N.tr, ...buildStrings(1) })
});
