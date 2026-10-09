/**
 * tools/ds/watch.mjs — the runner's `watch`: the registration, delegation and record change watch
 * (a hijack watch). Per domain:
 * - what its registry says (lib/portfolio.js createPortfolio and portfolioFacts over the run's fetch,
 *   paced per registry as `audit` is): the registrar and its IANA Registrar ID, the statuses, the
 *   expiry, the name servers the registry delegates to, the DS records at the parent (DoH) and the
 *   zone's own NS records;
 * - a snapshot of its records over DoH: the apex, `www`, `_dmarc` (its TXT, read where its CNAME chain
 *   ends — a hosted DMARC record —, and that CNAME) and the names of `--names` under it, each of
 *   `--types` (SOA, DS and DNSKEY at the apex and at a delegated name only; the apex's NS and DS are
 *   the delegation's), each record set normalised by tools/ds/watchdiff.mjs rrsetOf (lib/zonediff.js
 *   valueKey; a verification token kept as a digest), the SOA as its primary name server and serial,
 *   each address name's provider class (lib/netinfo.js classifyResolution);
 * - with `--authoritative`, every name server asked directly (tools/ds/authoritative.mjs): lame
 *   servers, lagging secondaries, servers out of sync — a mismatch confirmed once the next run finds
 *   it again ({@link syncState}) —; with `--ttl`, the TTLs they agree on.
 * A lookup that failed is carried from the last run that read it (`carried: { from }`), never a
 * change. Each record set keeps the times of its last {@link FLIPS_KEPT} value changes (`flips`) and
 * whether it keeps changing (`flapping`: {@link FLAP_CHANGES} or more in the last {@link FLAP_RUNS}
 * runs, `runs`); an expiry that has not moved with fewer than 30 days left is marked (`soon`), so the
 * change is said once. The changes since the baseline: tools/ds/watchdiff.mjs. Nothing goes to
 * Globalping; the direct queries go to the domains' own name servers only.
 */

import { code, strong, isoDay, isoTime, summaryDoc } from './render.mjs';
import { targetOf } from './carry.mjs';
import { UsageError, WATCH_MAX_NAMES } from './args.mjs';
import {
  rrsetOf, sameRecord, cdnRotation, recentFlips, recordKey, displayValue, lameWhy, asked as askedIn, isDmarcName,
  ZONE_TYPES, FLIPS_KEPT, FLAP_CHANGES, FLAP_RUNS, EXPIRY_SOON_DAYS
} from './watchdiff.mjs';
import { isSubdomainOf, parseHostList } from '../../assets/js/lib/domain.js';
import { dsKey } from '../../assets/js/lib/regwatch.js';
import { hostResolutionFrom } from '../../assets/js/lib/doh.js';
import { classifyResolution } from '../../assets/js/lib/netinfo.js';
import { throwIfAborted } from '../../assets/js/lib/util.js';
import { cleanText } from '../../assets/js/lib/summary.js';

export { FLIPS_KEPT, FLAP_CHANGES, FLAP_RUNS };

/** Names a summary line quotes before "+N more". */
const MAX_NAMES = 5;
/** The run times a target keeps (the window the flapping rule counts over). */
const RUNS_KEPT = FLAP_RUNS;
const DAY_MS = 86400000;

const isStr = (v) => typeof v === 'string';
const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const sortedSet = (list) => [...new Set(list)].sort();

/* ------------------------------------------------------------------------ */
/* Inputs                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * The host names `--names FILE` gives, read and checked before anything is sent: at most
 * {@link WATCH_MAX_NAMES} (more is a usage error: a list cut short would leave names unwatched); the
 * invalid entries are warnings.
 * @param {import('./args.mjs').DsOptions} options
 * @param {{ read: (path: string, option: string) => Promise<string>, warn: (text: string) => void,
 *   skipped: (label: string, invalid: string[], what: string) => string[] }} io
 * @returns {Promise<{ file: string|null, names: string[] }>}
 */
export async function watchInputs(options, { read, warn, skipped }) {
  if (!options.names) return { file: null, names: [] };
  const { valid, invalid } = parseHostList(await read(options.names, '--names'));
  for (const w of skipped(`--names ${options.names}`, invalid, 'a host name')) warn(w);
  if (!valid.length) throw new UsageError(`--names: ${options.names} lists no host name`);
  const names = sortedSet(valid);
  if (names.length > WATCH_MAX_NAMES) {
    throw new UsageError(`--names: ${options.names} lists ${names.length} host names, at most ${WATCH_MAX_NAMES}: split the list (a run per part, each with its own --json)`);
  }
  return { file: String(options.names).split(/[\\/]/).pop(), names };
}

/**
 * The names watched under a domain: the apex, `www`, `_dmarc` (its TXT and CNAME only) and the names
 * given under it.
 * @param {string} domain
 * @param {string[]} extra
 * @returns {string[]}
 */
export function watchNames(domain, extra = []) {
  const fixed = [domain, `www.${domain}`, `_dmarc.${domain}`];
  return [...fixed, ...sortedSet(extra.filter((n) => !fixed.includes(n) && isSubdomainOf(n, domain)))];
}

/* ------------------------------------------------------------------------ */
/* The snapshot                                                             */
/* ------------------------------------------------------------------------ */

/**
 * A name's provider class from its A and AAAA answers (those --types asked): 'cloudflare:cloudflare',
 * 'cdn:<id>', 'platform:<id>', 'direct', 'private', 'dangling' (a CNAME chain that ends in no address)
 * or 'none'.
 * @param {string} name
 * @param {object|null} a DnsResponse
 * @param {object|null} aaaa DnsResponse
 * @returns {string|null} null when a lookup got no answer, or neither was asked
 */
export function classOf(name, a, aaaa) {
  const usable = (r) => r && r.ok && (r.rcode === 'NOERROR' || r.rcode === 'NXDOMAIN');
  if ((!a && !aaaa) || (a && !usable(a)) || (aaaa && !usable(aaaa))) return null;
  const c = classifyResolution(hostResolutionFrom(name, a || null, aaaa || null));
  if (c.dangling) return 'dangling';
  if (c.kind === 'cloudflare' || c.kind === 'cdn' || c.kind === 'platform') return `${c.kind}:${c.provider ? c.provider.id : 'unknown'}`;
  if (c.kind === 'direct' || c.kind === 'private') return c.kind;
  return 'none';
}

/** Did a DoH answer settle the question (NOERROR or NXDOMAIN)? */
const answered = (r) => !!r && r.ok !== false && (r.rcode === 'NOERROR' || r.rcode === 'NXDOMAIN');
/** A failed lookup's reason, in a few words. */
const failureOf = (r) => (r && r.ok !== false && r.rcode ? r.rcode : String((r && r.error) || 'no answer').replace(/\s+/g, ' ').slice(0, 120));

/**
 * Read the record sets of a domain over DoH: each name's types (SOA, DS and DNSKEY at the apex, and
 * at another name once it answers NS records of its own — a delegation), the apex's NS and DS left to
 * the delegation; `_dmarc.<domain>` its TXT and CNAME, with TXT among the types. A DMARC name's TXT
 * set is the one where its CNAME chain ends (a hosted DMARC record: the policy at the vendor's).
 * @param {string} domain
 * @param {string[]} names {@link watchNames}
 * @param {string[]} types `--types`
 * @param {{ dns: object, signal?: AbortSignal }} opts
 * @returns {Promise<{ sets: Map<string, { name: string, type: string, values: string[], serial?: number }>,
 *   failures: Array<{ name: string, type: string, error: string, errorKind: string|null }>, nxdomain: string[],
 *   delegated: string[], classes: Record<string, string>, keys: Array<{ name: string, type: string }> }>}
 */
export async function readRecords(domain, names, types, { dns, signal }) {
  const sets = new Map();
  const failures = [];
  const nx = new Map();
  const responses = new Map();
  const keys = [];
  const ask = async (name, type) => {
    throwIfAborted(signal);
    let r;
    try {
      r = await dns.query(name, type, { signal });
    } catch (err) {
      if (err && err.name === 'AbortError') throw err;
      r = { ok: false, error: String((err && err.message) || err), errorKind: null, answers: [] };
    }
    keys.push({ name, type });
    responses.set(recordKey(name, type), r);
    if (!answered(r)) {
      failures.push({ name, type, error: failureOf(r), errorKind: r.errorKind || null });
      return;
    }
    if (!nx.has(name)) nx.set(name, true);
    if (r.rcode !== 'NXDOMAIN') nx.set(name, false);
    const set = rrsetOf(name, type, r.answers, { follow: type === 'TXT' && isDmarcName(name) });
    if (set.values.length) sets.set(recordKey(name, type), { name, type, values: set.values, ...(type === 'SOA' ? { serial: set.serial } : {}) });
  };
  const delegated = [];
  await Promise.all(names.map(async (name) => {
    // _dmarc: the TXT, and the CNAME a hosted DMARC record is reached by (asked with it, whatever --types)
    const own = name === `_dmarc.${domain}` ? (types.includes('TXT') ? ['TXT', 'CNAME'] : [])
      : types.filter((t) => (name === domain ? t !== 'NS' && t !== 'DS' : !ZONE_TYPES.includes(t)));
    // a name with NS records of its own is a delegation: its SOA, DS and DNSKEY are asked too
    await Promise.all(own.map((t) => ask(name, t)));
    if (name !== domain && sets.has(recordKey(name, 'NS'))) {
      delegated.push(name);
      await Promise.all(types.filter((t) => ZONE_TYPES.includes(t)).map((t) => ask(name, t)));
    }
  }));
  const classes = {};
  for (const name of names) {
    const c = classOf(name, responses.get(recordKey(name, 'A')) || null, responses.get(recordKey(name, 'AAAA')) || null);
    if (c && c !== 'none') classes[name] = c;
  }
  const order = (x, y) => x.name.localeCompare(y.name) || x.type.localeCompare(y.type);
  return {
    sets,
    failures: failures.sort(order),
    nxdomain: [...nx].filter(([, v]) => v).map(([n]) => n).sort(),
    delegated: delegated.sort(),
    classes,
    keys: keys.sort(order)
  };
}

/* ------------------------------------------------------------------------ */
/* The report                                                               */
/* ------------------------------------------------------------------------ */

/** A day (YYYY-MM-DD) of a date, or null. */
const dayOf = (v) => (v ? isoDay(v) || null : null);

/**
 * The registration part of a target: what the registry said this run, or — when it could not be
 * read — the last read carried (`carried: { from }`, `error`: why not this run).
 * @param {object} facts portfolioFacts
 * @param {object|null} prev the baseline's target
 * @param {string|null} prevFrom when the baseline read it
 * @param {Date} now
 * @returns {object}
 */
export function registrationPart(facts, prev, prevFrom, now) {
  const reg = facts.registration || {};
  if (reg.state === 'ok') {
    const out = {
      state: 'ok',
      registrar: reg.registrar || null,
      ianaId: reg.ianaId ? String(reg.ianaId) : null,
      statuses: sortedSet((reg.statuses || []).map((s) => String(s).trim().toLowerCase().replace(/\s+/g, ' ')).filter(Boolean)),
      expires: dayOf(reg.expires),
      daysLeft: Number.isFinite(reg.daysLeft) ? reg.daysLeft : null,
      nameservers: sortedSet(reg.nameservers || []),
      dnssecSigned: typeof reg.delegationSigned === 'boolean' ? reg.delegationSigned : null
    };
    // not moved, fewer than 30 days left: marked, so the change is said once (watchdiff.mjs EXPIRY)
    const p = prev && isObj(prev.registration) ? prev.registration : null;
    if (out.expires && p && p.state === 'ok' && p.expires === out.expires && Number.isFinite(out.daysLeft) && out.daysLeft < EXPIRY_SOON_DAYS) out.soon = out.expires;
    return out;
  }
  if (reg.state === 'not-found') return { state: 'not-found' };
  // a lib/sourcestatus.js SourceStatus: the HTTP status, else the technical message, else its kind
  const f = reg.failure;
  const error = reg.state === 'unsupported' ? `no RDAP for .${reg.tld || '?'}`
    : f ? cleanText(String(f.params && f.params.status ? `HTTP ${f.params.status}` : f.detail || f.kind || 'failed')).slice(0, 120) : reg.state || 'failed';
  const p = prev && isObj(prev.registration) ? prev.registration : null;
  if (p && (p.state === 'ok' || p.state === 'not-found')) {
    // the countdown moves on from the last read's (its expiry's time of day is the registry's)
    const since = Date.parse(prev.checkedAt);
    const daysLeft = Number.isFinite(p.daysLeft) && Number.isFinite(since) ? p.daysLeft - Math.floor((now.getTime() - since) / DAY_MS)
      : p.expires ? Math.floor((Date.parse(p.expires) - now.getTime()) / DAY_MS) : null;
    return { ...p, ...(p.state === 'ok' ? { daysLeft } : {}), carried: { from: p.carried ? p.carried.from ?? null : prevFrom }, error };
  }
  return { state: reg.state === 'unsupported' ? 'unsupported' : 'failed', error };
}

/**
 * The delegation part: the zone's NS records and the DS records at the parent; a lookup that failed
 * carries the last read (`nsCarried`, `dsCarried`).
 */
export function delegationPart(facts, prev, prevFrom) {
  const p = prev && isObj(prev.delegation) ? prev.delegation : {};
  const out = { ns: null, ds: null, signed: facts.dnssec ? facts.dnssec.state ?? null : null };
  const ns = facts.ns || {};
  if (ns.state === 'ok') out.ns = sortedSet(ns.hosts || []);
  else if (ns.state === 'none' || ns.state === 'nxdomain') out.ns = [];
  else if (Array.isArray(p.ns)) Object.assign(out, { ns: [...p.ns], nsCarried: { from: p.nsCarried ? p.nsCarried.from ?? null : prevFrom } });
  const d = facts.dnssec || {};
  if (d.state && Array.isArray(d.ds)) out.ds = sortedSet(d.ds.map(dsKey));
  else if (Array.isArray(p.ds)) Object.assign(out, { ds: [...p.ds], dsCarried: { from: p.dsCarried ? p.dsCarried.from ?? null : prevFrom } });
  return out;
}

/** A mismatch's shape: each server's values, in one order. */
const shapeOf = (servers) => JSON.stringify(Object.entries(isObj(servers) ? servers : {})
  .map(([address, values]) => [address, (Array.isArray(values) ? values : []).map(String).sort()]).sort(([x], [y]) => x.localeCompare(y)));

/**
 * The name servers asked directly, with the record sets out of sync followed from run to run (SYNC):
 * each mismatch has `since`, the run that first found every server answering it as now, and is
 * `confirmed` once the next run finds it so again — an answer a provider picks per query (weighted or
 * multivalue records) is rarely found twice in a row, a server out of sync always is — or when it was
 * confirmed in the last run and the servers still disagree (tools/ds/watchdiff.mjs says SYNC once,
 * when it is confirmed). A mismatch this run did not compare — over the budget, fewer than two
 * servers answering it, the name servers not asked at all — is carried from the last run.
 * @param {object} auth tools/ds/authoritative.mjs checkAuthoritative's result
 * @param {object|null} prev the baseline's target
 * @param {{ at: string, prevFrom: string|null }} opts `at`: this run's time; `prevFrom`: when the baseline was read
 * @returns {object} `auth` with its mismatches so marked
 */
export function syncState(auth, prev, { at, prevFrom }) {
  const p = prev && isObj(prev.authoritative) ? prev.authoritative : null;
  const before = new Map((p && Array.isArray(p.mismatches) ? p.mismatches : []).filter((m) => isObj(m) && isStr(m.key)).map((m) => [m.key, m]));
  const compared = new Set(auth.view === 'authoritative' && Array.isArray(auth.compared) ? auth.compared : []);
  const mismatches = (Array.isArray(auth.mismatches) ? auth.mismatches : []).map((m) => {
    const was = before.get(m.key);
    const same = !!was && shapeOf(was.servers) === shapeOf(m.servers);
    return { ...m, since: same && isStr(was.since) ? was.since : at, ...(same || (was && was.confirmed === true) ? { confirmed: true } : {}) };
  });
  const now = new Set(mismatches.map((m) => m.key));
  for (const [key, was] of before) {
    if (now.has(key) || compared.has(key)) continue;
    mismatches.push({ ...was, carried: { from: isObj(was.carried) ? was.carried.from ?? null : prevFrom } });
  }
  return { ...auth, mismatches };
}

/**
 * One domain's report target: the registration and delegation, the record sets — with what a failed
 * lookup hides carried from the baseline, each set's flips and flapping marker —, the names' provider
 * classes, the lookups that failed and the name servers asked directly.
 * @param {string} domain
 * @param {{ facts: object, read: object, auth?: object|null, names: string[], types: string[] }} got
 * @param {{ prev?: object|null, prevAt?: string|null, runAt: Date, now: Date, ttl?: boolean }} opts `runAt`: the
 *   run's time (its flips and runs); `ttl`: TTLs compared (--ttl)
 * @returns {object}
 */
export function watchTarget(domain, { facts, read, auth = null, names, types }, { prev = null, prevAt = null, runAt, now, ttl = false }) {
  const at = runAt.toISOString();
  const prevFrom = prev ? (isStr(prev.checkedAt) ? prev.checkedAt : prevAt) : null;
  const runs = [...(prev && Array.isArray(prev.runs) ? prev.runs.filter(isStr) : []), at].slice(-RUNS_KEPT);
  const x = {
    target: domain,
    checkedAt: now.toISOString(),
    runs,
    registration: registrationPart(facts, prev, prevFrom, now),
    delegation: delegationPart(facts, prev, prevFrom),
    names: [...names],
    types: [...types],
    delegated: [...read.delegated],
    nxdomain: [...read.nxdomain],
    classes: { ...read.classes },
    records: [],
    failures: read.failures.map((f) => ({ ...f }))
  };
  // A name's class whose A or AAAA lookup failed this run: the last read's.
  if (prev && isObj(prev.classes)) {
    for (const name of names) {
      const failed = x.failures.some((f) => f.name === name && (f.type === 'A' || f.type === 'AAAA'));
      if (failed && isStr(prev.classes[name])) x.classes[name] = prev.classes[name];
    }
  }
  const old = new Map((prev && Array.isArray(prev.records) ? prev.records : []).filter((r) => isObj(r) && isStr(r.key)).map((r) => [r.key, r]));
  const failed = new Set(x.failures.map((f) => recordKey(f.name, f.type)));
  const ttls = auth && isObj(auth.ttls) ? auth.ttls : {};
  const keys = new Set([...read.sets.keys(), ...old.keys()]);
  for (const key of [...keys].sort()) {
    const p = old.get(key) || null;
    const cur = read.sets.get(key) || null;
    const [name, type] = [cur ? cur.name : p.name, cur ? cur.type : p.type];
    if (!askedIn(x, name, type)) continue;
    if (failed.has(key)) {
      // not read this run: the last read stands for it, carried
      if (p) x.records.push({ ...p, carried: { from: p.carried ? p.carried.from ?? null : prevFrom } });
      continue;
    }
    const values = cur ? cur.values : [];
    const now1 = { values, ...(ttl && Number.isFinite(ttls[key]) ? { ttl: ttls[key] } : {}) };
    // a value change since the baseline's read (one a CDN's rotating edges make is none)
    const prevKnown = !!prev && askedIn(prev, name, type) && !(Array.isArray(prev.failures) && prev.failures.some((f) => recordKey(f.name, f.type) === key) && !p);
    const changed = prevKnown && !sameRecord(p, now1, { ttl }) && !cdnRotation(type, (p && p.values) || [], values);
    const flips = [...(p && Array.isArray(p.flips) ? p.flips.filter(isStr) : []), ...(changed ? [at] : [])].slice(-FLIPS_KEPT);
    const recent = recentFlips(flips, runs);
    if (!values.length && !recent) continue;
    x.records.push({
      key, name, type, values,
      ...(type === 'SOA' && cur ? { serial: cur.serial ?? null } : {}),
      ...(now1.ttl !== undefined ? { ttl: now1.ttl } : {}),
      ...(flips.length ? { flips } : {}),
      ...(recent >= FLAP_CHANGES ? { flapping: true } : {})
    });
  }
  if (auth) x.authoritative = syncState(auth, prev, { at, prevFrom });
  return x;
}

/* ------------------------------------------------------------------------ */
/* The summary                                                              */
/* ------------------------------------------------------------------------ */

const plural = (n, one, other = `${one}s`) => `${n} ${n === 1 ? one : other}`;
/** Values as code parts, at most `max`, then "+N more". */
function namesParts(list, max = MAX_NAMES) {
  const shown = list.slice(0, max).flatMap((v, i) => (i ? [', ', code(v)] : [code(v)]));
  return [...shown, ...(list.length > max ? [` +${list.length - max} more`] : [])];
}

/**
 * The summary of one domain: its registration, its name servers (the registry's and the zone's), its
 * DS records, the record sets read, what could not be read, and with --authoritative the name servers
 * asked directly.
 * @param {object} target {@link watchTarget}
 * @param {{ t: Function, now: Date, baselined?: boolean }} opts
 * @returns {object} a SummaryDoc
 */
export function watchDoc(target, { t, now, baselined = false }) {
  const lines = [];
  const r = target.registration || {};
  const carried = r.carried ? [` (carried from ${isoDay(r.carried.from) || 'an earlier run'}: the registry could not be read this run${r.error ? `: ${r.error}` : ''})`] : [];
  if (r.state === 'ok') {
    const left = Number.isFinite(r.daysLeft) ? (r.daysLeft < 0 ? `expired ${plural(-r.daysLeft, 'day')} ago` : `${plural(r.daysLeft, 'day')} left`) : null;
    lines.push(['Registrar: ', code(r.registrar || 'unknown'), r.ianaId ? ` (IANA ${r.ianaId})` : '', r.expires ? ` · expires ${r.expires}${left ? ` (${left})` : ''}` : '', ...carried]);
    lines.push(['Statuses: ', ...(r.statuses && r.statuses.length ? namesParts(r.statuses, 8) : ['none'])]);
  } else if (r.state === 'not-found') {
    lines.push([strong('Not registered:'), ' the registry does not hold this domain (RDAP 404)', ...carried]);
  } else {
    lines.push([`Registration not known: ${r.error || 'the registry could not be read'}`]);
  }
  const d = target.delegation || {};
  // a registry that lists no name servers says nothing of them (not every one publishes them)
  const rdapNs = r.state === 'ok' && Array.isArray(r.nameservers) && r.nameservers.length ? r.nameservers : null;
  const zoneNs = Array.isArray(d.ns) ? d.ns : null;
  const nsCarried = d.nsCarried ? ` (carried from ${isoDay(d.nsCarried.from) || 'an earlier run'})` : '';
  if (rdapNs && zoneNs && rdapNs.join(' ') === zoneNs.join(' ')) {
    lines.push(['Name servers (the registry and the zone agree): ', ...namesParts(zoneNs), nsCarried]);
  } else {
    if (rdapNs) lines.push(['Name servers (the registry): ', ...namesParts(rdapNs)]);
    if (zoneNs) lines.push(['Name servers (the zone\'s NS records): ', ...(zoneNs.length ? namesParts(zoneNs) : ['none']), nsCarried]);
  }
  if (Array.isArray(d.ds)) {
    const dsCarried = d.dsCarried ? ` (carried from ${isoDay(d.dsCarried.from) || 'an earlier run'})` : '';
    lines.push(d.ds.length
      ? ['DS at the parent (key tag, algorithm, digest type): ', ...namesParts(d.ds), d.signed ? ` · ${d.signed === 'failing' ? 'broken' : d.signed}` : '', dsCarried]
      : ['DS at the parent: none (DNSSEC is off)', dsCarried]);
  }
  const live = (target.records || []).filter((x) => !x.carried && (x.values || []).length);
  const soa = (target.records || []).find((x) => x.type === 'SOA' && x.name === target.target);
  const namesWith = sortedSet(live.map((x) => x.name));
  lines.push([`Records: ${plural(live.length, 'record set')} at ${plural(namesWith.length, 'name')}`, soa && Number.isFinite(soa.serial) ? ` (SOA serial ${soa.serial})` : '']);
  const flapping = (target.records || []).filter((x) => x.flapping);
  if (flapping.length) lines.push(['Changing often (not listed while it keeps changing): ', ...namesParts(flapping.map((x) => `${x.name} ${x.type}`))]);
  const failures = target.failures || [];
  if (failures.length) {
    lines.push(['No answer: ', ...namesParts(failures.map((f) => `${f.name} ${f.type}`)), ': the last read is kept for the next comparison']);
  }
  const a = target.authoritative;
  if (a) lines.push(...authoritativeLines(a));
  if (baselined && target.firstRun) lines.push(['First run for this domain: the next run compares with this one']);
  return summaryDoc('watch', ['Domain watch · ', code(target.target)], lines, { t, at: target.checkedAt, now });
}

/** The lines of the name servers asked directly. */
export function authoritativeLines(a) {
  const lines = [];
  const servers = Array.isArray(a.servers) ? a.servers : [];
  if (a.view === 'none') return [['Name servers asked directly: none (no address for the zone\'s NS hosts)']];
  if (a.view === 'recursive') return [['Name servers asked directly: no answer over UDP or TCP port 53 from this network: the DoH snapshot alone']];
  const ok = servers.filter((s) => s.status === 'ok');
  const skipped = servers.filter((s) => s.status === 'skipped');
  const lagging = new Set(Array.isArray(a.lagging) ? a.lagging : []);
  const mismatches = (Array.isArray(a.mismatches) ? a.mismatches : []).filter((m) => isObj(m) && isStr(m.key));
  const compared = Array.isArray(a.compared) ? a.compared : [];
  const state = mismatches.length ? `${plural(mismatches.length, 'record set')} answered differently` : lagging.size ? `${lagging.size} behind`
    : compared.length ? 'in sync' : ok.length < 2 ? 'nothing to compare (fewer than two servers answer)' : 'no record set compared';
  lines.push([`Name servers asked directly: ${plural(ok.length, 'server')} answer${ok.length === 1 ? 's' : ''} for the zone`, Number.isFinite(a.serial) ? `, serial ${a.serial}` : '', `, ${state}`,
    skipped.length ? ` (${plural(skipped.length, 'IPv6 address', 'IPv6 addresses')} skipped: no IPv6 route from this machine)` : '']);
  for (const s of servers.filter((x) => x.status === 'lame' || x.status === 'unreachable').slice(0, MAX_NAMES)) {
    lines.push([strong('Lame:'), ' ', code(s.hosts && s.hosts[0] ? `${s.hosts[0]} (${s.address})` : s.address), `: ${lameWhy(s.reason)}`,
      s.reason === 'unanswered' && isStr(s.error) ? ` (${cleanText(s.error)})` : '']);
  }
  for (const s of servers.filter((x) => lagging.has(x.address)).slice(0, MAX_NAMES)) {
    lines.push([strong('Lagging secondary:'), ' ', code(s.hosts && s.hosts[0] ? `${s.hosts[0]} (${s.address})` : s.address), `: serial ${s.serial ?? '?'}`]);
  }
  for (const m of mismatches.slice(0, MAX_NAMES)) {
    const [name, type] = m.key.split('|');
    const groups = Object.entries(isObj(m.servers) ? m.servers : {});
    // said (SYNC) once the next run finds the same: an answer a provider picks per query rarely is
    const note = m.carried ? ` (carried from ${isoDay(m.carried.from) || 'an earlier run'}: not compared this run)`
      : !m.confirmed ? ' (new this run: counted if the next run finds the same)' : '';
    lines.push([strong('Out of sync:'), ' ', code(`${name} ${type}`), ': ', ...groups.slice(0, 3).flatMap(([address, values], i) => [i ? '; ' : '', code(address), ' ',
      ...namesParts((Array.isArray(values) ? values : []).map((v) => displayValue(type, v)), 3)]), note]);
  }
  if (a.cut) lines.push([`${plural(a.cut, 'record set')} not asked of the name servers: over the query budget (--max-queries)`]);
  return lines;
}

/**
 * The warnings of one domain: what could not be read (and is carried), a registry without RDAP.
 * Names come from DNS and the files read: printed without control or bidi characters.
 * @param {object} target
 * @returns {string[]}
 */
export function watchWarnings(target) {
  const out = [];
  const r = target.registration || {};
  if (r.state === 'unsupported') out.push(`${target.target}: ${r.error || 'no RDAP for this TLD'}: the registration is not watched (the registry's WHOIS has it)`);
  else if (r.carried) out.push(`${target.target}: the registry could not be read (${cleanText(r.error || 'failed')}): the last read is kept for the next comparison`);
  else if (r.state === 'failed') out.push(`${target.target}: the registry could not be read (${cleanText(r.error || 'failed')}) and no earlier run read it`);
  const failures = target.failures || [];
  if (failures.length) {
    const names = failures.map((f) => cleanText(`${f.name} ${f.type}`));
    out.push(`${target.target}: no answer for ${names.slice(0, MAX_NAMES).join(', ')}${names.length > MAX_NAMES ? ` and ${names.length - MAX_NAMES} more` : ''}: the last read is kept for the next comparison`);
  }
  const a = target.authoritative;
  if (a && a.view === 'recursive') out.push(`${target.target}: the name servers answer nothing over UDP or TCP port 53 from this machine: asked through DoH only`);
  for (const address of (a && a.view === 'authoritative' && Array.isArray(a.lagging) ? a.lagging : [])) {
    const s = (a.servers || []).find((x) => x && x.address === address) || {};
    const host = s.hosts && s.hosts[0] ? `${cleanText(s.hosts[0])} (${address})` : address;
    out.push(`${target.target}: ${host} is a lagging secondary: serial ${s.serial ?? '?'}, the others ${a.serial ?? '?'}`);
  }
  if (a && a.cut) out.push(`${target.target}: ${a.cut} record set${a.cut === 1 ? '' : 's'} not asked of the name servers: over the query budget (--max-queries)`);
  if (a && Array.isArray(a.unresolved) && a.unresolved.length) out.push(`${target.target}: no address for the name server${a.unresolved.length === 1 ? '' : 's'} ${a.unresolved.map((h) => cleanText(h)).join(', ')}`);
  return out;
}

/* ------------------------------------------------------------------------ */
/* The run                                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Run `watch` over the domains.
 * @param {string[]} targets registrable domains
 * @param {import('./args.mjs').DsOptions} options `types`, `ttl`, `authoritative`, `maxQueries`
 * @param {object} env runCommand's env (`inputs.watch`: {@link watchInputs}; `authoritative`: tests' hooks
 *   for tools/ds/authoritative.mjs: `{ port, timeoutMs, tries, transport }`)
 * @returns {Promise<{ options: object, targets: object[], docs: object[], warnings: string[] }>}
 */
export async function runWatch(targets, options, env) {
  const { createPortfolio } = await import('../../assets/js/lib/portfolio.js');
  const input = (env.inputs && env.inputs.watch) || { file: null, names: [] };
  const runAt = env.now();
  const prevAt = env.baseline ? env.baseline.startedAt ?? null : null;
  const types = [...options.types];
  const warnings = [];
  // Each name goes with the domain it is under (the longest); one under none is never sent.
  const byDomain = new Map(targets.map((d) => [d, []]));
  let outside = 0;
  for (const name of input.names) {
    const domain = targets.filter((d) => name === d || isSubdomainOf(name, d)).sort((a, b) => b.length - a.length)[0];
    if (domain) byDomain.get(domain).push(name);
    else outside += 1;
  }
  if (outside) warnings.push(`${outside} name${outside === 1 ? '' : 's'} of ${input.file} under none of the domains left out (never sent)`);

  // The registration, the zone's NS, the DS records and whether the keys validate: RDAP paced per
  // registry, as `audit` asks it.
  env.progress(`watch: ${targets.length} domain${targets.length === 1 ? '' : 's'}, RDAP and the delegation`);
  const run = createPortfolio({ domains: targets, dns: env.dns, fetchImpl: env.fetchImpl, dkim: false, lookups: ['rdap', 'ns', 'ds', 'dnskey'], nsDomains: false });
  await run.start({ signal: env.signal });
  throwIfAborted(env.signal);

  const out = [];
  const docs = [];
  for (const [i, domain] of targets.entries()) {
    const names = watchNames(domain, byDomain.get(domain));
    env.progress(`watch ${domain} (${i + 1}/${targets.length}), ${names.length} names`);
    const now = env.now();
    const facts = run.facts(domain, { now });
    const read = await readRecords(domain, names, types, { dns: env.dns, signal: env.signal });
    const prev = targetOf(env.baseline, domain);
    let auth = null;
    if (options.authoritative) {
      const { checkAuthoritative } = await import('./authoritative.mjs');
      const hosts = facts.ns && facts.ns.state === 'ok' ? facts.ns.hosts : prev && prev.delegation && Array.isArray(prev.delegation.ns) ? prev.delegation.ns : [];
      env.progress(`watch ${domain}: asking its ${hosts.length} name server${hosts.length === 1 ? '' : 's'} directly`);
      // the record sets of the snapshot, and the zone's own NS set (the snapshot leaves it to the delegation)
      const keys = [...(types.includes('NS') ? [{ name: domain, type: 'NS' }] : []), ...read.keys];
      auth = await checkAuthoritative(domain, {
        nsHosts: hosts, keys, delegated: read.delegated, dns: env.dns, signal: env.signal, maxQueries: options.maxQueries, ttl: !!options.ttl,
        ...(env.authoritative || {})
      });
      throwIfAborted(env.signal);
    }
    const target = watchTarget(domain, { facts, read, auth, names, types }, { prev, prevAt, runAt, now: env.now(), ttl: !!options.ttl });
    warnings.push(...watchWarnings(target));
    out.push(target);
    docs.push(watchDoc({ ...target, firstRun: !prev }, { t: env.t, now: env.now(), baselined: !!options.baseline }));
  }
  const skipped = out.reduce((n, x) => n + ((x.authoritative && x.authoritative.servers) || []).filter((s) => s.status === 'skipped').length, 0);
  if (skipped) warnings.push(`${skipped} IPv6 name server address${skipped === 1 ? '' : 'es'} not asked: this machine has no IPv6 route (GitHub's hosted runners have none)`);
  return {
    options: {
      types, names: input.file ? { file: input.file, count: input.names.length } : null, ttl: !!options.ttl, authoritative: !!options.authoritative,
      ...(options.authoritative ? { maxQueries: options.maxQueries } : {}), resolvers: [...options.chain]
    },
    targets: out, docs, warnings
  };
}
