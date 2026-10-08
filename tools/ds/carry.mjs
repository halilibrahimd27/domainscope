/**
 * tools/ds/carry.mjs — what a run could not read, carried from the last run that read it.
 *
 * A night on which a lookup fails or a source cannot be read is no night on which the domain
 * changed. Its report keeps what the last run that read the same thing found, marked as carried,
 * so the next run compares with that read and not with the gap: a warning of months is not "new"
 * the night after a failed lookup, and a certificate from a new CA issued during a crt.sh outage
 * still comes out as a new issuer once crt.sh answers again.
 * - health: for each area (a check id's first part) whose lookup failed this run, the checks of
 *   that area as last read (`carried: [{ area, from, checks }]`; `from` null when no run read it);
 * - ct: the certificates a source not read in full this run listed before (`carried: { from }`),
 *   and per source the time of its last full read (`lastFullAt`);
 * - subdomains: a host whose lookup failed keeps its last answer (`lastGood`);
 * - takeover: a risk whose lookup failed is carried as last read (`carried: { from }`), never
 *   "gone" and never better.
 * Pure: no I/O. tools/ds/commands.mjs (writing a report) and tools/ds/diff.mjs (reading a
 * baseline) share these definitions of "failed" and "read in full".
 */

import { sortHostnames } from '../../assets/js/lib/domain.js';
import { findingLookups, TAKEOVER_SEVERITIES, TAKEOVER_REF_KINDS } from '../../assets/js/lib/takeover.js';

const isStr = (v) => typeof v === 'string';
const byId = (list) => {
  const out = new Map();
  for (const c of list) if (c && isStr(c.id) && !out.has(c.id)) out.set(c.id, c);
  return out;
};

/**
 * The target of the same name in a report (a baseline), or null.
 * @param {object|null} report
 * @param {string} target
 * @returns {object|null}
 */
export function targetOf(report, target) {
  if (!report || !Array.isArray(report.targets)) return null;
  return report.targets.find((x) => x && x.target === target) || null;
}

/* ------------------------------------------------------------------------ */
/* health                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * A check that says a lookup failed: `<area>.error` (soa, ns, mx, spf, dmarc, dkim, caa, dnssec,
 * wildcard, rdap), `spf.dns-error`, `mail-identity.fcrdns-error` — not `spf.include-error`, which
 * is a broken SPF record that was read.
 * @param {string} id
 * @returns {boolean}
 */
export const isLookupError = (id) => /^[a-z-]+\.(?:error|dns-error|fcrdns-error)$/.test(String(id));

/** lib/health.js `failedLookups` keys → the areas whose checks that record feeds. */
const LOOKUP_AREAS = Object.freeze({
  soa: ['soa'], ns: ['ns'], mx: ['mx'], a: ['apex'], aaaa: ['apex', 'ipv6'], txt: ['spf'], https: ['https-rr'],
  mtaSts: ['mta-sts'], tlsRpt: ['tls-rpt'], bimi: ['bimi']
});
/** The areas a failed area also hides: the mail identity checks read the MX hosts, BIMI's weak-policy check the DMARC policy. */
const ALSO_HIDES = Object.freeze({ mx: ['mail-identity'], dmarc: ['bimi'] });
/** Checks that another area's lookup also feeds: ns.rdap-mismatch compares the registry's name servers (RDAP) with DNS. */
const ALSO_IN = Object.freeze({ 'ns.rdap-mismatch': ['rdap'] });

/**
 * The areas of a check id: its first part (lib/health.js HealthCheck.category), and the other
 * areas whose lookup it needs.
 * @param {string} id
 * @returns {string[]}
 */
export function checkAreas(id) {
  const s = String(id);
  return [s.split('.')[0], ...(ALSO_IN[s] || [])];
}

/**
 * The areas whose lookup failed in a health target — its lookup-error checks and its
 * `failedLookups` — with what each of them also hides.
 * @param {{ checks?: object[], failedLookups?: string[] }} x
 * @returns {Set<string>}
 */
export function failedAreas(x) {
  const out = new Set();
  const add = (area) => {
    out.add(area);
    for (const also of ALSO_HIDES[area] || []) out.add(also);
  };
  for (const c of (x && x.checks) || []) if (c && isLookupError(c.id)) add(String(c.id).split('.')[0]);
  for (const key of (x && x.failedLookups) || []) for (const area of LOOKUP_AREAS[key] || []) add(area);
  return out;
}

/**
 * Every check a health target knows: the ones it found, then the ones it carried (an id once).
 * @param {{ checks?: object[], carried?: object[] }} x
 * @returns {object[]}
 */
export function knownChecks(x) {
  const carried = Array.isArray(x && x.carried) ? x.carried.flatMap((c) => (c && Array.isArray(c.checks) ? c.checks : [])) : [];
  return [...byId([...((x && x.checks) || []), ...carried]).values()];
}

/**
 * When the areas whose lookup failed in a health target were last read, as it carried them:
 * area → ISO time, or null when no run read that area.
 * @param {object} x
 * @returns {Map<string, string|null>}
 */
export function carriedFrom(x) {
  const out = new Map();
  for (const area of failedAreas(x)) out.set(area, null);
  for (const c of (x && Array.isArray(x.carried) ? x.carried : [])) {
    if (c && isStr(c.area) && out.has(c.area)) out.set(c.area, isStr(c.from) ? c.from : null);
  }
  return out;
}

/**
 * What a health target carries: for each area whose lookup failed this run, the checks of that
 * area as the last run that read it found them (lookup errors left out, and the ids this run
 * found all the same), and when that was. An area that also failed in the baseline run goes on
 * with what the baseline carried for it.
 * @param {object} target this run's health target (commands.mjs healthTarget)
 * @param {object|null} prev the baseline's target of the same domain
 * @param {{ prevAt?: string|null }} [opts] the baseline run's start, for a target without `checkedAt`
 * @returns {Array<{ area: string, from: string|null, checks: object[] }>} sorted by area
 */
export function carryHealth(target, prev, { prevAt = null } = {}) {
  const areas = [...failedAreas(target)].sort();
  if (!areas.length) return [];
  const own = new Set((target.checks || []).map((c) => c.id));
  const known = prev ? knownChecks(prev) : [];
  const before = prev ? carriedFrom(prev) : new Map();
  const readAt = prev ? (isStr(prev.checkedAt) ? prev.checkedAt : prevAt) : null;
  return areas.map((area) => ({
    area,
    from: !prev ? null : before.has(area) ? before.get(area) : readAt,
    checks: known.filter((c) => checkAreas(c.id).includes(area) && !isLookupError(c.id) && !own.has(c.id))
  }));
}

/* ------------------------------------------------------------------------ */
/* ct                                                                       */
/* ------------------------------------------------------------------------ */

/**
 * Did a CT source read the domain in full: it answered, not in part (crt.sh's lighter search),
 * not cut at a page cap?
 * @param {{ ok?: boolean, state?: string, truncated?: boolean }|null} s a target's `sources` entry
 * @returns {boolean}
 */
export const fullRead = (s) => !!s && s.ok === true && s.state !== 'partial' && !s.truncated;

/**
 * When each source last read the domain in full, as a CT target says: its `lastFullAt`, else —
 * a target written without it — the target's own read when the source read in full then.
 * @param {object} x a ct target
 * @param {string|null} [fallbackAt] when the target's run started (for a target without `readAt`)
 * @returns {Map<string, string|null>} source id → ISO time (null: read in full at an unknown time)
 */
export function lastFullTimes(x, fallbackAt = null) {
  const out = new Map();
  const at = isStr(x.readAt) ? x.readAt : isStr(fallbackAt) ? fallbackAt : null;
  for (const s of Array.isArray(x.sources) ? x.sources : []) {
    if (!s || !isStr(s.source)) continue;
    if (isStr(s.lastFullAt)) out.set(s.source, s.lastFullAt);
    else if (s.lastFullAt === undefined && fullRead(s)) out.set(s.source, at);
  }
  return out;
}

/**
 * The issuers of a list of certificates, most certificates first: `{ name, count, intermediates, newest }`.
 * @param {Array<{ ca: string, intermediate: string|null, notBefore: string|null }>} certificates
 * @returns {object[]}
 */
export function ctIssuers(certificates) {
  const issuers = new Map();
  for (const c of certificates) {
    const g = issuers.get(c.ca) || { name: c.ca, count: 0, intermediates: [], newest: null };
    g.count += 1;
    if (c.intermediate && !g.intermediates.includes(c.intermediate)) g.intermediates.push(c.intermediate);
    if (!g.newest || String(c.notBefore) > g.newest) g.newest = c.notBefore;
    issuers.set(c.ca, g);
  }
  return [...issuers.values()].sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, 'en')).map((g) => ({ ...g, intermediates: g.intermediates.sort() }));
}

/** Newest first, then by id: the order of a target's certificates. */
export const ctCertOrder = (a, b) => String(b.notBefore).localeCompare(String(a.notBefore)) || a.id.localeCompare(b.id);

/**
 * This run's CT target with what it could not read carried from the baseline's: each source's
 * `lastFullAt` (this read when it read in full, else the baseline's), and the baseline's current
 * certificates this run did not list while a source that listed them was not read in full now
 * (`carried: { from }`: when they were last read). A certificate is dropped once every source
 * that listed it has read the domain in full without it, or once it has expired. `issuers` and
 * `names` then cover the carried certificates too; `recent` stays this read's.
 * @param {object} target commands.mjs ctTarget
 * @param {object|null} prev the baseline's target of the same domain
 * @param {{ now: Date, prevAt?: string|null }} opts `prevAt`: the baseline run's start
 * @returns {object}
 */
export function carryCt(target, prev, { now, prevAt = null }) {
  const before = prev ? lastFullTimes(prev, prevAt) : new Map();
  const sources = (target.sources || []).map((s) => ({
    ...s, lastFullAt: fullRead(s) ? target.readAt : (before.get(s.source) ?? null)
  }));
  if (!prev || !Array.isArray(prev.certificates)) return { ...target, sources };
  const full = new Set(sources.filter(fullRead).map((s) => s.source));
  const ids = new Set((target.certificates || []).map((c) => c.id));
  const from = isStr(prev.readAt) ? prev.readAt : prevAt;
  const carried = prev.certificates
    .filter((c) => !ids.has(c.id) && !(c.sources || []).every((s) => full.has(s)) && !(Date.parse(c.notAfter) <= now.getTime()))
    .map((c) => ({ ...c, carried: { from: c.carried && c.carried.from !== undefined ? c.carried.from : from } }));
  if (!carried.length) return { ...target, sources };
  const certificates = [...target.certificates, ...carried].sort(ctCertOrder);
  return { ...target, sources, issuers: ctIssuers(certificates), names: sortHostnames([...new Set(certificates.flatMap((c) => c.names))]), certificates };
}

/* ------------------------------------------------------------------------ */
/* subdomains                                                               */
/* ------------------------------------------------------------------------ */

/** A lookup that got no usable answer (the host may exist). */
export const LOOKUP_FAILED = new Set(['SERVFAIL', 'REFUSED', 'ERROR']);
/** Did a host's lookup fail? */
export const lookupFailed = (h) => !!h && LOOKUP_FAILED.has(h.status);

/** What a host's answer is, for `lastGood`. */
const ANSWER = ['status', 'kind', 'provider', 'providerId', 'hidesOrigin', 'dangling', 'ipv4', 'ipv6', 'cnames'];

/**
 * The hosts of this run with, on each whose lookup failed, its last answer from the baseline
 * (`lastGood: { at, status, kind, provider, … }`), or the one the baseline carried when its
 * lookup failed then too. The next run compares a host that answers again with that answer.
 * @param {object[]} hosts this run's report hosts
 * @param {object|null} prev the baseline's target of the same domain
 * @param {{ prevAt?: string|null }} [opts] the baseline run's start, for a target without `finishedAt`
 * @returns {object[]}
 */
export function carryHosts(hosts, prev, { prevAt = null } = {}) {
  if (!prev || !Array.isArray(prev.hosts)) return hosts;
  const old = new Map(prev.hosts.filter((h) => h && isStr(h.name)).map((h) => [h.name, h]));
  const at = isStr(prev.finishedAt) ? prev.finishedAt : prevAt;
  return hosts.map((h) => {
    const y = lookupFailed(h) ? old.get(h.name) : null;
    if (!y) return h;
    const last = lookupFailed(y) ? y.lastGood : { at, ...Object.fromEntries(ANSWER.map((k) => [k, y[k] ?? null])) };
    return last ? { ...h, lastGood: last } : h;
  });
}

/* ------------------------------------------------------------------------ */
/* takeover                                                                 */
/* ------------------------------------------------------------------------ */

/** A takeover severity's rank, most severe first (an unknown one last). */
export function riskRank(severity) {
  const i = TAKEOVER_SEVERITIES.indexOf(severity);
  return i === -1 ? TAKEOVER_SEVERITIES.length : i;
}

/** Worst first, then by host, target and kind: the order of a takeover target's risks. */
export const riskOrder = (a, b) => riskRank(a.severity) - riskRank(b.severity) || String(a.host).localeCompare(String(b.host))
  || String(a.target).localeCompare(String(b.target)) || TAKEOVER_REF_KINDS.indexOf(a.kind) - TAKEOVER_REF_KINDS.indexOf(b.kind);

/**
 * This run's takeover risks with what a failed lookup hides carried from the baseline: a risk of
 * the baseline one of whose lookups failed this run (lib/takeover.js findingLookups: the query
 * its reference came from, whether its target exists, the registration of a domain its chain
 * names) is kept as the last run that read it found it (`carried: { from }`) — never "gone", and
 * never better than then: this run's risk of the same key stands only when it is at least as
 * severe. A risk the baseline carried goes on with its `from`.
 * @param {{ risks?: object[], failures?: Array<{ name: string }> }} target this run's takeover target
 * @param {object|null} prev the baseline's target of the same domain
 * @param {{ prevAt?: string|null }} [opts] the baseline run's start, for a target without `checkedAt`
 * @returns {object[]} the risks, worst first ({@link riskOrder})
 */
export function carryRisks(target, prev, { prevAt = null } = {}) {
  const risks = Array.isArray(target && target.risks) ? target.risks : [];
  const failed = new Set(((target && target.failures) || []).map((f) => f && f.name).filter(isStr));
  if (!prev || !Array.isArray(prev.risks) || !failed.size) return [...risks].sort(riskOrder);
  const from = isStr(prev.checkedAt) ? prev.checkedAt : prevAt;
  const byKey = new Map(risks.map((r) => [r.key, r]));
  for (const p of prev.risks) {
    if (!p || !isStr(p.key) || !isStr(p.kind) || !isStr(p.host)) continue;
    if (!findingLookups(p).some((name) => failed.has(name))) continue;
    const now = byKey.get(p.key);
    if (now && riskRank(now.severity) <= riskRank(p.severity)) continue;
    byKey.set(p.key, { ...p, carried: { from: p.carried && p.carried.from !== undefined ? p.carried.from : from } });
  }
  return [...byKey.values()].sort(riskOrder);
}
