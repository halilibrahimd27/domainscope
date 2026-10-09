/**
 * tools/ds/takeover.mjs — the headless runner's `takeover`: the takeover and dependency-expiry
 * watch. Per domain, lib/takeover.js auditTakeover over the runner's DohClient and lib/rdap.js
 * rdapDomain (each registry paced there): the CNAME chains of the hosts given (`--names`, or the
 * ones with a CNAME in a `subdomains` report, `--from-subdomains`), and the registrable domains
 * the domain's NS, MX, SPF, DMARC, DKIM, CAA, MTA-STS, SRV, HTTPS and `_acme-challenge` records
 * name — unregistered (RDAP 404 and NXDOMAIN), pending deletion, expired or expiring within 30
 * days. The other domains of the run are the caller's own (never looked up), and a registrable
 * domain is looked up once a run.
 *
 * - The report's target: `{ target, checkedAt, references, checked, hosts, spfMacros, domains,
 *   risks, failures }`; a risk `{ key, kind, host, target, chain, term, severity, reason, reasons,
 *   domain, expires, service, evidence, fix, carried? }` (the key is `kind|host|target`; evidence
 *   and fix in the app's English words). A risk whose lookup failed this run is carried from the
 *   last run that read it (carry.mjs carryRisks), never "gone".
 * - {@link diffTakeover}: RISK (a new risk; counts at medium severity or above), GONE (good),
 *   WORSE and BETTER; a domain new or no longer watched. Services only their page can confirm
 *   (the app's page check) stay "to check" here: info, listed, never counted — the Globalping page
 *   check stays a consented click in the app.
 * Nothing here goes to Globalping.
 */

import { code, strong, isoDay, isoTime, summaryDoc, valueParts } from './render.mjs';
import { targetOf, carryRisks, riskRank } from './carry.mjs';
import { DS_TOOL, DS_VERSION, UsageError } from './args.mjs';
import { isSubdomainOf, normalizeHostname, parseHostList } from '../../assets/js/lib/domain.js';
import { cleanText, textParts } from '../../assets/js/lib/summary.js';
import { takeoverTargetProblem } from '../../assets/js/lib/runreport.js';

/** Risk lines a target's summary lists before "N more". */
const MAX_RISK_LINES = 10;
/** Names a summary line quotes before "+N more". */
const MAX_NAMES = 5;
/** The least severity a change must reach to count (RISK, WORSE) or have had (GONE, BETTER). */
export const COUNTED_SEVERITY = 'medium';

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
/** Does a severity count (the nightly issue, --fail-on-change)? Medium or worse. */
export const countsAt = (severity) => riskRank(severity) <= riskRank(COUNTED_SEVERITY);

/* ------------------------------------------------------------------------ */
/* Inputs                                                                   */
/* ------------------------------------------------------------------------ */

/** The host names of a list read from a file: each valid one in canonical form, the rest left out. */
const hostNames = (list) => (Array.isArray(list) ? list.map((c) => (isStr(c) ? normalizeHostname(c) : null)).filter(Boolean) : []);

/**
 * The hosts of a `subdomains` report of this runner whose CNAME chain is worth asking again: every
 * host with a CNAME (a dangling one too), or with one in the answer it carried while its lookup
 * failed (`lastGood`); wildcard look-alikes left out. A name that is no host name is never sent:
 * it is listed in `invalid` (the caller warns, quoted without its control characters), and a CNAME
 * target that is none is dropped.
 * @param {any} doc the parsed report
 * @returns {{ hosts: Array<{ name: string, wildcardSuspect: boolean, resolution: { cnames: string[] } }>, invalid: string[], problem: string|null }}
 */
export function subdomainHosts(doc) {
  const refused = (problem) => ({ hosts: [], invalid: [], problem });
  if (!isObj(doc) || doc.tool !== DS_TOOL) return refused(`it is not a --json report of ${DS_TOOL}`);
  if (!isStr(doc.version) || doc.version.split('.')[0] !== DS_VERSION.split('.')[0]) return refused(`it was written by version ${JSON.stringify(doc.version ?? null)}`);
  if (doc.command !== 'subdomains') return refused(`it is a report of "${doc.command}", not of "subdomains"`);
  if (!Array.isArray(doc.targets)) return refused('it has no "targets" list');
  const out = new Map();
  const invalid = new Set();
  for (const x of doc.targets) {
    for (const h of (isObj(x) && Array.isArray(x.hosts) ? x.hosts : [])) {
      if (!isObj(h) || !isStr(h.name) || h.wildcardSuspect === true) continue;
      const name = normalizeHostname(h.name);
      if (!name) {
        invalid.add(h.name);
        continue;
      }
      if (out.has(name)) continue;
      const own = hostNames(h.cnames);
      const cnames = own.length ? own : hostNames(isObj(h.lastGood) ? h.lastGood.cnames : null);
      if (cnames.length) out.set(name, { name, wildcardSuspect: false, resolution: { cnames } });
    }
  }
  return { hosts: [...out.values()], invalid: [...invalid], problem: null };
}

/**
 * The hosts `--names FILE` or `--from-subdomains FILE` give, read and checked before anything is
 * sent (a usage error names what is wrong). The invalid entries of a names file, and the host
 * names of a report that are none, are warnings.
 * @param {import('./args.mjs').DsOptions} options
 * @param {{ read: (path: string, option: string) => Promise<string>, warn: (text: string) => void,
 *   skipped: (label: string, invalid: string[], what: string) => string[] }} io `read`: a file's text
 * @returns {Promise<{ source: 'names'|'subdomains'|null, file: string|null, hosts: Array<object|string> }>}
 */
export async function takeoverInputs(options, { read, warn, skipped }) {
  const base = (p) => String(p).split(/[\\/]/).pop();
  if (options.names) {
    const { valid, invalid } = parseHostList(await read(options.names, '--names'));
    for (const w of skipped(`--names ${options.names}`, invalid, 'a host name')) warn(w);
    if (!valid.length) throw new UsageError(`--names: ${options.names} lists no host name`);
    return { source: 'names', file: base(options.names), hosts: valid };
  }
  if (options.fromSubdomains) {
    const text = await read(options.fromSubdomains, '--from-subdomains');
    let doc;
    try {
      doc = JSON.parse(text);
    } catch (err) {
      throw new UsageError(`--from-subdomains: ${options.fromSubdomains} is not JSON (${err.message})`);
    }
    const { hosts, invalid, problem } = subdomainHosts(doc);
    if (problem) throw new UsageError(`--from-subdomains: cannot read hosts from ${options.fromSubdomains}: ${problem} (give a report written by "subdomains --json")`);
    for (const w of skipped(`--from-subdomains ${options.fromSubdomains}`, invalid, 'a host name')) warn(w);
    return { source: 'subdomains', file: base(options.fromSubdomains), hosts };
  }
  return { source: null, file: null, hosts: [] };
}

/* ------------------------------------------------------------------------ */
/* The report                                                               */
/* ------------------------------------------------------------------------ */

/** The params of a reason's words (`tko.reason.<code>`): dates as days. */
const reasonParams = (risk, r) => ({
  domain: r.domain || '', date: r.expires ? isoDay(r.expires) : '', name: r.name || risk.target, service: risk.service ? risk.service.name : ''
});

/**
 * A reason in the app's words, as summary parts (its names code parts: lib/summary.js textParts).
 * @param {Function} t
 * @param {object} risk
 * @param {{ code: string }} reason
 * @returns {Array}
 */
export function reasonParts(t, risk, reason) {
  return textParts(t, `tko.reason.${reason.code}`, reasonParams(risk, reason));
}

/**
 * One finding as the report keeps it: its key and reference, the severity and reasons (codes with
 * their domain, name and expiry), the service, and the evidence and fix in the app's words.
 * @param {object} f a lib/takeover.js TakeoverFinding
 * @param {{ t: Function, fixKey: Function }} kit `fixKey`: ui/takeover-panel.js's
 * @returns {object}
 */
export function riskOf(f, { t, fixKey }) {
  const reasons = f.reasons.map((r) => ({
    code: r.code, severity: r.severity, ...(r.domain ? { domain: r.domain } : {}), ...(r.name ? { name: r.name } : {}),
    ...(r.expires ? { expires: isoTime(r.expires) } : {})
  }));
  const first = reasons.find((r) => r.domain) || {};
  const risk = {
    key: f.id, kind: f.kind, host: f.host, target: f.target, chain: [...f.chain], term: f.term || null,
    severity: f.severity, reason: f.fix, reasons, domain: first.domain || null, expires: first.expires || null,
    service: f.service ? { id: f.service.id, name: f.service.name, status: f.service.status } : null
  };
  return {
    ...risk,
    evidence: reasons.map((r) => t(`tko.reason.${r.code}`, reasonParams(risk, r))).join(' '),
    fix: t(fixKey(f), { domain: risk.domain || '', target: f.target, service: risk.service ? risk.service.name : '', host: f.host, term: f.term || '' })
  };
}

/**
 * The compared part of one domain's audit: the references and registrable domains checked, the
 * registrations read (`domains`: each with its verdict and expiry), the risks worst first — with
 * what a failed lookup hides carried from the baseline (carry.mjs carryRisks) — and the lookups
 * that gave no answer.
 * @param {string} domain
 * @param {object} result lib/takeover.js auditTakeover() result
 * @param {{ t: Function, fixKey: Function, checkedAt: Date }} kit
 * @param {{ prev?: object|null, prevAt?: string|null }} [baseline] the baseline's target and run start
 * @returns {object}
 */
export function takeoverTarget(domain, result, { t, fixKey, checkedAt }, { prev = null, prevAt = null } = {}) {
  const x = {
    target: domain,
    checkedAt: isoTime(checkedAt),
    references: result.references,
    checked: result.checked,
    hosts: result.hosts || 0,
    spfMacros: result.spfMacros || 0,
    domains: [...result.registrations].map(([d, v]) => ({ domain: d, verdict: v.verdict, expires: isoTime(v.expires) })).sort((a, b) => a.domain.localeCompare(b.domain)),
    risks: result.findings.map((f) => riskOf(f, { t, fixKey })),
    failures: result.failures.map((f) => ({
      source: f.source, name: f.name,
      error: (f.response && (f.response.error || (f.response.rcode ? `rcode ${f.response.rcode}` : null))) || null,
      errorKind: (f.response && f.response.errorKind) || null
    }))
  };
  return { ...x, risks: carryRisks(x, prev, { prevAt }) };
}

/** A risk's reference as parts: `SPF host example.com → mail.example.net`. */
const refParts = (t, r) => [`${t(`tko.kind.${r.kind}`)} `, code(r.host), ' → ', code(r.target)];

/**
 * The summary of one domain's audit: what was checked, every risk worst first (its first reason in
 * the app's words), the hosts only the app's page check can tell, the lookups that gave no answer
 * (and the risks carried for them), the SPF terms built from a macro.
 * @param {object} target {@link takeoverTarget}
 * @param {{ t: Function, now: Date }} opts
 * @returns {object} a SummaryDoc
 */
export function takeoverDoc(target, { t, now }) {
  const lines = [];
  const risks = target.risks || [];
  const atRisk = risks.filter((r) => r.severity !== 'info');
  const toCheck = risks.filter((r) => r.severity === 'info');
  lines.push([atRisk.length
    ? t('tko.found', { count: atRisk.length, checked: t('tko.checked', { count: target.references }) })
    : t('tko.none', { count: target.references, domains: t('tko.domains', { count: target.checked }) })]);
  if (target.hosts) lines.push([`Hosts asked for their CNAME chain: ${target.hosts}`]);
  for (const r of atRisk.slice(0, MAX_RISK_LINES)) {
    lines.push([strong(`${t(`tko.sev.${r.severity}`)}:`), ' ', ...refParts(t, r), ' — ', ...reasonParts(t, r, (r.reasons || [])[0] || { code: r.reason }),
      ...(r.carried ? [` (carried from ${isoDay(r.carried.from) || 'an earlier run'}: a lookup it rests on gave no answer this run)`] : [])]);
  }
  if (atRisk.length > MAX_RISK_LINES) lines.push([`${atRisk.length - MAX_RISK_LINES} more at risk (see the JSON report)`]);
  if (toCheck.length) {
    lines.push(['To check in the app (only the page tells; Subdomains › Takeover risks asks one Globalping probe per host, behind a click): ',
      ...valueParts(t, toCheck.map((r) => r.host), MAX_NAMES)]);
  }
  const failures = target.failures || [];
  if (failures.length) lines.push(['No answer: ', ...valueParts(t, failures.map((f) => f.name), MAX_NAMES), ': what they feed could not be checked this run']);
  if (target.spfMacros) lines.push([t('tko.macros', { count: target.spfMacros })]);
  return summaryDoc('takeover', [`${t('tko.title')} · `, code(target.target)], lines, { t, at: target.checkedAt, now });
}

/**
 * The warnings of one domain's audit: the lookups that gave no answer (and the risks carried).
 * The names come from DNS answers and the files read, so they are printed without control or
 * bidi characters (lib/summary.js cleanText).
 * @param {object} target {@link takeoverTarget}
 * @returns {string[]}
 */
export function takeoverWarnings(target) {
  const failures = target.failures || [];
  if (!failures.length) return [];
  const names = failures.map((f) => cleanText(f.name));
  const shown = names.slice(0, MAX_NAMES).join(', ') + (names.length > MAX_NAMES ? ` and ${names.length - MAX_NAMES} more` : '');
  const carried = (target.risks || []).filter((r) => r.carried).length;
  return [`${target.target}: no answer for ${shown}: what they feed could not be checked`
    + `${carried ? `; ${carried} risk${carried === 1 ? '' : 's'} carried from the last run that read ${carried === 1 ? 'it' : 'them'}` : ''}`];
}

/**
 * Run `takeover` over the domains (the run's DohClient, lib/rdap.js with the run's fetch).
 * @param {string[]} targets domains
 * @param {import('./args.mjs').DsOptions} options
 * @param {object} env commands.mjs runCommand's env (`inputs.takeover`: {@link takeoverInputs})
 * @returns {Promise<{ options: object, targets: object[], docs: object[], warnings: string[] }>}
 */
export async function runTakeover(targets, options, env) {
  const { auditTakeover, dkimSelectorList, TAKEOVER_DKIM_SELECTORS } = await import('../../assets/js/lib/takeover.js');
  const { rdapDomain } = await import('../../assets/js/lib/rdap.js');
  // The app's words for kinds, reasons and fixes (registered at import; render.mjs setupStrings imports it too).
  const { fixKey } = await import('../../assets/js/ui/takeover-panel.js');
  const input = (env.inputs && env.inputs.takeover) || { source: null, file: null, hosts: [] };
  const prevAt = env.baseline ? env.baseline.startedAt ?? null : null;
  const extra = dkimSelectorList(options.dkimSelectors || []).slice(TAKEOVER_DKIM_SELECTORS.length);
  const warnings = [];
  // Each host goes with the domain it is under (the longest one); a host under none is never sent.
  const byDomain = new Map(targets.map((d) => [d, []]));
  let outside = 0;
  for (const h of input.hosts) {
    const name = typeof h === 'string' ? h : h.name;
    const domain = targets.filter((d) => isSubdomainOf(name, d)).sort((a, b) => b.length - a.length)[0];
    if (domain) byDomain.get(domain).push(h);
    else outside += 1;
  }
  if (outside) warnings.push(`${outside} host${outside === 1 ? '' : 's'} of ${input.file} under none of the domains left out (never sent)`);
  // A registrable domain is looked up once a run: what one domain's audit read, the next one reuses.
  const known = new Map();
  const out = [];
  const docs = [];
  for (const [i, domain] of targets.entries()) {
    const hosts = byDomain.get(domain);
    env.progress(`takeover ${domain} (${i + 1}/${targets.length})${hosts.length ? `, ${hosts.length} host${hosts.length === 1 ? '' : 's'}` : ''}`);
    const result = await auditTakeover({ hosts, domains: [domain] }, {
      dns: env.dns, signal: env.signal, now: () => env.now().getTime(), known,
      ownDomains: targets.filter((d) => d !== domain), extraDkimSelectors: extra,
      rdap: (d, opts) => rdapDomain(d, { ...opts, fetchImpl: env.fetchImpl })
    });
    for (const [d, v] of result.registrations) if (v.verdict !== 'failed') known.set(d, v);
    const target = takeoverTarget(domain, result, { t: env.t, fixKey, checkedAt: env.now() }, { prev: targetOf(env.baseline, domain), prevAt });
    warnings.push(...takeoverWarnings(target));
    out.push(target);
    docs.push(takeoverDoc(target, { t: env.t, now: env.now() }));
  }
  return {
    options: {
      dkimSelectors: extra, hosts: input.source ? { source: input.source, file: input.file, count: input.hosts.length } : null, resolvers: [...options.chain]
    },
    targets: out, docs, warnings
  };
}

/* ------------------------------------------------------------------------ */
/* Changes since the baseline                                               */
/* ------------------------------------------------------------------------ */

/** A change in diff.mjs's model (the target first, as a code part). */
function change(tag, target, item, what, { tone = 'info', counts = true, kind = 'changed', before = null, after = null } = {}) {
  return { tag, tone, counts, target, item, kind, before, after, parts: [code(target), ': ', ...what] };
}

/** The reasons that say a domain may be registered by anyone (or soon). */
const LAPSED = new Set(['unregistered', 'unregistered-dns', 'pending-delete', 'expired']);
/**
 * The verdicts that say a domain is held now: its registry has it (registered, expiring), or it is
 * in DNS again — a TLD without RDAP (no-rdap) or an RDAP 404 the DNS contradicts (rdap-404-dns).
 */
const HELD = new Set(['registered', 'expiring', 'no-rdap', 'rdap-404-dns']);

/** Is a baseline target's list of risks what {@link diffTakeover} walks? (lib/runreport.js, the rules the Monitoring view reads reports with too.) */
export { takeoverTargetProblem };

/**
 * The takeover watch since the baseline: per domain and risk key, a risk new (RISK: bad and
 * counted at medium severity or above, listed only below), gone (GONE: good; counted when it was
 * at medium or above — "registered now" when its domain had lapsed and is held now ({@link HELD}:
 * registered, or in DNS again where RDAP cannot tell): make sure it is yours), worse or better
 * (WORSE / BETTER: counted when the worse of the two is at medium or above); a domain new
 * (counted when a risk is at medium or above) or no longer watched. A risk whose lookup failed is
 * carried in this run's report (carry.mjs), so it is compared, never gone.
 * @param {object} before the baseline report
 * @param {object} after this run's report
 * @param {{ t: Function }} kit
 * @returns {object[]}
 */
export function diffTakeover(before, after, { t }) {
  const out = [];
  const old = new Map((before.targets || []).map((x) => [x.target, x]));
  const now = new Map((after.targets || []).map((x) => [x.target, x]));
  const first = (r) => (Array.isArray(r.reasons) && r.reasons[0]) || { code: r.reason || 'nxdomain' };
  const words = (r) => reasonParts(t, r, first(r));
  for (const [domain, a] of now) {
    const b = old.get(domain);
    const risks = a.risks || [];
    if (!b) {
      const counted = risks.filter((r) => countsAt(r.severity));
      out.push(change('NEW', domain, null, [`now watched: ${counted.length} risk${counted.length === 1 ? '' : 's'} at medium severity or above, ${risks.length} in all`],
        { tone: counted.length ? 'bad' : 'info', counts: counted.length > 0, kind: 'appeared', after: counted.map((r) => r.key) }));
      continue;
    }
    const prev = new Map((b.risks || []).map((r) => [r.key, r]));
    // A domain that had lapsed is registered now while a record still names it: the owner's fix,
    // or someone else's registration — said, so a takeover does not read as good news.
    const registered = new Set((a.domains || []).filter((d) => HELD.has(d.verdict)).map((d) => d.domain));
    const takenAgain = (y) => (LAPSED.has(first(y).code) && y.domain && registered.has(y.domain) ? [code(y.domain), ' is registered now — make sure it is yours'] : null);
    for (const x of risks) {
      const y = prev.get(x.key);
      if (!y) {
        const counts = countsAt(x.severity);
        out.push(change('RISK', domain, x.key, [`${x.severity} `, ...refParts(t, x), ' — ', ...words(x)],
          { tone: counts ? 'bad' : x.severity === 'info' ? 'quiet' : 'info', counts, kind: 'appeared', after: x.severity }));
        continue;
      }
      if (x.severity === y.severity) continue;
      const worse = riskRank(x.severity) < riskRank(y.severity);
      const counts = countsAt(worse ? x.severity : y.severity);
      const again = worse ? null : takenAgain(y);
      out.push(change(worse ? 'WORSE' : 'BETTER', domain, x.key, [...refParts(t, x), `: ${y.severity} → ${x.severity} — `, ...(again ? [...again, '; '] : []), ...words(x)],
        { tone: !counts ? 'quiet' : worse ? 'bad' : 'good', counts, before: y.severity, after: x.severity }));
    }
    const keys = new Set(risks.map((r) => r.key));
    for (const y of b.risks || []) {
      if (keys.has(y.key)) continue;
      const counts = countsAt(y.severity);
      const again = takenAgain(y);
      out.push(change('GONE', domain, y.key, [`${y.severity} `, ...refParts(t, y), ...(again ? [': ', ...again] : [' no longer found'])],
        { tone: counts ? 'good' : 'quiet', counts, kind: 'disappeared', before: y.severity }));
    }
  }
  for (const [domain] of old) if (!now.has(domain)) out.push(change('GONE', domain, null, ['no longer watched'], { kind: 'disappeared' }));
  return out;
}

/**
 * What the two runs did differently, as sentences: the extra DKIM selectors, the hosts given.
 * @param {object} o the baseline's options
 * @param {object} n this run's options
 * @returns {string[]}
 */
export function takeoverNotes(o, n) {
  const notes = [];
  const list = (v) => (Array.isArray(v) && v.length ? v.join(',') : 'none');
  if (Array.isArray(o.dkimSelectors) && list(o.dkimSelectors) !== list(n.dkimSelectors)) {
    notes.push(`The extra DKIM selectors differ from the baseline's (${list(o.dkimSelectors)} → ${list(n.dkimSelectors)}): DKIM CNAME risks can appear or go because of that.`);
  }
  const hosts = (h) => (isObj(h) ? `${h.source} ${h.file}` : 'none');
  if (o.hosts !== undefined && hosts(o.hosts) !== hosts(n.hosts)) {
    notes.push(`The hosts asked differ from the baseline's (${hosts(o.hosts)} → ${hosts(n.hosts)}): CNAME risks can appear or go because of that.`);
  }
  return notes;
}
