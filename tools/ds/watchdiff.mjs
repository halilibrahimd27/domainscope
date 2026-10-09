/**
 * tools/ds/watchdiff.mjs — "Changes since the baseline" of the runner's `watch` (tools/ds/watch.mjs),
 * what a `watch` baseline must hold, and the record rules both share. Pure: no I/O. tools/ds/diff.mjs
 * dispatches here.
 *
 * Per domain, the registration and the delegation (lib/regwatch.js diffRegistration over the two
 * reports, never over a registration a run could not read — it was carried):
 * - REGISTRAR (bad): another registrar by its IANA ID (its name alone without one); the same ID under
 *   another name is info;
 * - LOCK: a client or server transfer prohibition removed (bad; info while another one still blocks
 *   transfers, which it names), added (good);
 * - STATUS: a hold, a pending delete, a redemption period or a pending transfer arriving (bad), the
 *   registry no longer holding the domain (bad); any other status added or removed (info);
 * - NS (bad): the registry's name servers (RDAP) or the zone's (its NS records) changed;
 * - DS: removed or changed (bad), added (info);
 * - EXPIRY: moved later (good: renewed), earlier (info); not moved with fewer than
 *   {@link EXPIRY_SOON_DAYS} days left (bad), said once (the report's `registration.soon`).
 * Per record set (apex, www, `_dmarc` — its TXT and its CNAME — and `--names`, each of `--types`; the
 * apex's NS and DS are the delegation's), RECORD:
 * - MX, NS, CAA, the SPF TXT (v=spf1), the DMARC TXT (v=DMARC1 at `_dmarc.`, read where its CNAME
 *   chain ends: a hosted DMARC record) and the CNAME at `_dmarc.` (who publishes the policy): bad;
 * - A, AAAA and CNAME: info, unless the name's provider class (lib/netinfo.js classifyResolution:
 *   Cloudflare, a CDN, a platform, a direct address, a CNAME left dangling) changed: bad; an A / AAAA
 *   set whose old and new addresses are all edges of one CDN is quiet (listed, not counted);
 * - TXT verification tokens (lib/passport.js TXT_VENDORS): info, named by their service, the token
 *   never printed (the report keeps a digest);
 * - DNSKEY: info, quiet when only zone-signing keys rolled; the rest: info;
 * - SERIAL: the SOA serial moved (quiet);
 * - FLAPPING: a record set that changed {@link FLAP_CHANGES} times or more in the last
 *   {@link FLAP_RUNS} runs (its `flips`) is said once (quiet) and its info changes are not listed while
 *   it keeps changing — a bad one always is.
 * With `--authoritative` (tools/ds/authoritative.mjs), both runs having asked the name servers:
 * - SYNC: servers at the same SOA serial answer a record set differently (bad) — said once two runs
 *   in a row found every server answering it as before (the report's `confirmed`, tools/ds/watch.mjs
 *   syncState: an answer a provider picks per query is rarely found twice), and while they disagree
 *   not again —, and agree again (good; only where this run compared the set); a server behind the
 *   others' serial, a lagging secondary (info, listed only);
 * - LAME: a server that answers without authority, REFUSED, SERVFAIL or not at all, or that stopped
 *   answering after its SOA (bad), and that answers with authority again (good).
 * A lookup that failed is never a change: the report carries its last read (tools/ds/watch.mjs).
 */

import { createHash } from 'node:crypto';
import { code } from './render.mjs';
import { diffRegistration, TRANSFER_LOCK_STATUSES } from '../../assets/js/lib/regwatch.js';
import { matchProviderByIP } from '../../assets/js/lib/netinfo.js';
import { TXT_VENDORS, txtVendorOf } from '../../assets/js/lib/passport.js';
import { valueKey, canonicalName } from '../../assets/js/lib/zonediff.js';

/** Changes a FLAPPING record set must have had within the last {@link FLAP_RUNS} runs. */
export const FLAP_CHANGES = 3;
/** The runs a record set's changes are counted over. */
export const FLAP_RUNS = 7;
/** The changes a record set's `flips` keep (their times). */
export const FLIPS_KEPT = 10;
/** Days left under which an expiry that has not moved is EXPIRY (bad, once). */
export const EXPIRY_SOON_DAYS = 30;
/** Record types asked only at the apex and at a name that has NS records of its own (a delegation). */
export const ZONE_TYPES = Object.freeze(['SOA', 'DS', 'DNSKEY']);
/** Record types whose change is bad wherever it is. */
const BAD_TYPES = new Set(['MX', 'NS', 'CAA']);
/** Record types whose provider class is compared. */
const ADDRESS_TYPES = new Set(['A', 'AAAA', 'CNAME']);
/** Values a change line quotes before "+N more". */
const MAX_VALUES = 3;
/** A value is quoted up to this many characters. */
const MAX_VALUE_CHARS = 120;

const isObj = (v) => !!v && typeof v === 'object' && !Array.isArray(v);
const isStr = (v) => typeof v === 'string';
const isStrOrNull = (v) => v === null || v === undefined || typeof v === 'string';
const isStrList = (v) => Array.isArray(v) && v.every(isStr);

/* ------------------------------------------------------------------------ */
/* Record sets: what a value is, how two compare                            */
/* ------------------------------------------------------------------------ */

/** A record set's key: 'name|TYPE'. */
export const recordKey = (name, type) => `${name}|${type}`;
/** Is a name a DMARC record's (`_dmarc.`)? Its TXT is read where its CNAME chain ends, its CNAME said as DMARC. */
export const isDmarcName = (name) => /^_dmarc\./.test(String(name));
/** CNAME hops followed in an answer before a chain counts as ending nowhere (a loop). */
const MAX_CHAIN = 8;

/**
 * One record's value as the report keeps it: lib/zonediff.js valueKey (TXT joined and compared by
 * its bytes, IPv6 canonical, CAA tags and issuer domains in lower case, MX / SRV spelled one way,
 * names without their root dot), except a TXT verification record of a known service (lib/passport.js
 * TXT_VENDORS), kept as `token <service> <digest>`: the token itself is never written or printed.
 * @param {string} type
 * @param {object} rr a lib/dnswire.js RR
 * @returns {string}
 */
export function recordValue(type, rr) {
  if (type === 'TXT') {
    const vendor = txtVendorOf(rr.data);
    if (vendor) {
      const text = Array.isArray(rr.data) ? rr.data.map(String).join('') : String(rr.data ?? '');
      return `token ${vendor.id} ${createHash('sha256').update(text).digest('hex').slice(0, 12)}`;
    }
  }
  try {
    return valueKey(rr);
  } catch {
    return `text ${String(rr.text ?? '').trim().replace(/\s+/g, ' ')}`;
  }
}

/**
 * Where the CNAME chain from `name` ends in an answer, or null for a loop.
 * @param {string} name canonical
 * @param {object[]} answers lib/dnswire.js RRs
 * @returns {string|null}
 */
function chainEnd(name, answers) {
  const next = new Map(answers.filter((rr) => rr && rr.type === 'CNAME').map((rr) => [canonicalName(rr.name), canonicalName(String(rr.data ?? ''))]));
  let at = name;
  for (let hop = 0; hop <= MAX_CHAIN; hop += 1) {
    if (!next.has(at)) return at;
    at = next.get(at);
  }
  return null;
}

/**
 * The record set of `name` and `type` in an answer: its own records only (a CNAME's target's are
 * another name's), each value once, sorted ({@link recordValue}); the SOA as its primary name server,
 * its serial apart; the smallest TTL. With `follow` (a DMARC TXT: {@link isDmarcName}), the records
 * of `type` where the name's CNAME chain ends in the answer — a hosted DMARC record's policy.
 * @param {string} name canonical
 * @param {string} type
 * @param {object[]} answers lib/dnswire.js RRs
 * @param {{ follow?: boolean }} [opts]
 * @returns {{ values: string[], serial?: number, ttl: number|null }}
 */
export function rrsetOf(name, type, answers, { follow = false } = {}) {
  const list = Array.isArray(answers) ? answers : [];
  const owner = follow && type !== 'CNAME' ? chainEnd(name, list) : name;
  const own = list.filter((rr) => rr && rr.type === type && owner !== null && canonicalName(rr.name) === owner);
  const ttls = own.map((rr) => rr.ttl).filter(Number.isFinite);
  const ttl = ttls.length ? Math.min(...ttls) : null;
  if (!own.length) return { values: [], ttl };
  if (type === 'SOA') {
    const d = own[0].data || {};
    return { values: [canonicalName(d.mname || '')], serial: Number.isFinite(d.serial) ? d.serial : null, ttl };
  }
  return { values: [...new Set(own.map((rr) => recordValue(type, rr)))].sort(), ttl };
}

/**
 * The text of a TXT value key (lib/zonediff.js valueKey: `txt "<bytes>"`), as UTF-8; null for a value
 * that is not one (a verification token's digest).
 * @param {string} value
 * @returns {string|null}
 */
export function txtText(value) {
  const m = /^txt (".*")$/s.exec(String(value));
  if (!m) return null;
  let bytes;
  try {
    bytes = JSON.parse(m[1]);
  } catch {
    return null;
  }
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i += 1) out[i] = bytes.charCodeAt(i) & 0xff;
  return new TextDecoder('utf-8').decode(out);
}

/** A verification token's stored form: `token <vendor id> <digest>`. */
const TOKEN_RE = /^token ([a-z0-9-]+) ([0-9a-f]{12})$/;

/**
 * What a TXT value is: 'spf' (v=spf1), 'dmarc' (v=DMARC1 at a `_dmarc.` name), 'token:<vendor>' (a
 * verification record of a known service, stored as a digest), or 'other'.
 * @param {string} name the owner
 * @param {string} value its stored value
 * @returns {string}
 */
export function txtKind(name, value) {
  const token = TOKEN_RE.exec(String(value));
  if (token) return `token:${token[1]}`;
  const text = (txtText(value) || '').trim();
  if (/^v=spf1(?:\s|$)/i.test(text)) return 'spf';
  if (/^v=DMARC1\b/i.test(text) && isDmarcName(name)) return 'dmarc';
  return 'other';
}

/** A stored value as a change line quotes it: a TXT value's text, a token by its service, a DNSKEY by its flags and algorithm. */
export function displayValue(type, value) {
  const s = String(value);
  const token = TOKEN_RE.exec(s);
  if (token) {
    const v = TXT_VENDORS.find((x) => x.id === token[1]);
    return `${v ? v.name : token[1]} verification (${v ? v.key : 'token'}…)`;
  }
  let out = s;
  if (type === 'TXT') out = txtText(s) ?? s;
  else if (type === 'DNSKEY') {
    const [flags, protocol, alg] = s.split(' ');
    out = `${flags} ${protocol} ${alg} ${flags === '257' ? '(key-signing key)' : flags === '256' ? '(zone-signing key)' : ''}`.trim();
  }
  return out.length > MAX_VALUE_CHARS ? `${out.slice(0, MAX_VALUE_CHARS - 1)}…` : out;
}

/** Values as code parts, at most {@link MAX_VALUES}, then "+N more"; "nothing" for none. */
function valuesParts(type, values) {
  if (!values.length) return ['nothing'];
  const shown = values.slice(0, MAX_VALUES).flatMap((v, i) => (i ? [', ', code(displayValue(type, v))] : [code(displayValue(type, v))]));
  return [...shown, ...(values.length > MAX_VALUES ? [` +${values.length - MAX_VALUES} more`] : [])];
}

/**
 * Are two reads of a record set the same: their values (as sets), the SOA's primary name (its serial
 * is SERIAL), the TTL when both runs compared TTLs?
 * @param {{ values?: string[], ttl?: number|null }|null} a
 * @param {{ values?: string[], ttl?: number|null }|null} b
 * @param {{ ttl?: boolean }} [opts]
 * @returns {boolean}
 */
export function sameRecord(a, b, { ttl = false } = {}) {
  const va = [...new Set((a && a.values) || [])].sort();
  const vb = [...new Set((b && b.values) || [])].sort();
  if (va.join('\n') !== vb.join('\n')) return false;
  if (ttl && a && b && Number.isFinite(a.ttl) && Number.isFinite(b.ttl) && a.ttl !== b.ttl) return false;
  return true;
}

/**
 * The CDN whose edges every address of both sets is (an A / AAAA set rotating among one CDN's edges:
 * quiet), or null.
 * @param {string} type
 * @param {string[]} before
 * @param {string[]} after
 * @returns {string|null} the provider's id
 */
export function cdnRotation(type, before, after) {
  if (type !== 'A' && type !== 'AAAA') return null;
  const all = [...(before || []), ...(after || [])];
  if (!(before || []).length || !(after || []).length) return null;
  let id = null;
  for (const ip of all) {
    const p = matchProviderByIP(ip);
    if (!p || p.dnsOnly || (id && p.id !== id)) return null;
    id = p.id;
  }
  return id;
}

/**
 * A name's provider class (tools/ds/watch.mjs classOf): 'cloudflare:cloudflare', 'cdn:<id>',
 * 'platform:<id>', 'direct', 'private', 'dangling' (a CNAME chain that ends in no address) or 'none'
 * (no address and no CNAME). Did it change between two reads, where both resolve or dangle?
 * @param {string|null|undefined} before
 * @param {string|null|undefined} after
 * @returns {boolean}
 */
export function classMoved(before, after) {
  return isStr(before) && isStr(after) && before !== after && before !== 'none' && after !== 'none';
}

/** "Cloudflare", "a CDN (fastly)", "a direct address" … for a class. */
function classText(c) {
  if (!isStr(c)) return 'unknown';
  if (c === 'direct') return 'a direct address';
  if (c === 'private') return 'a private address';
  if (c === 'dangling') return 'a CNAME that ends in no address (dangling)';
  if (c === 'none') return 'no address';
  const [kind, id] = c.split(':');
  return kind === 'cloudflare' ? 'Cloudflare' : `${kind === 'cdn' ? 'a CDN' : 'a platform'} (${id})`;
}

/**
 * Is a record set's change bad, info or quiet (before the flapping rule)? `kind` is a TXT value
 * group's ({@link txtKind}), or 'dmarc' for the CNAME at a `_dmarc.` name (where the policy is read).
 * @param {{ type: string, kind?: string|null, before: string[], after: string[],
 *   classBefore?: string|null, classAfter?: string|null }} c
 * @returns {{ tone: 'bad'|'info'|'quiet', why: string|null }} `why`: 'class' | 'cdn' | 'zsk' | 'ds' | null
 */
export function recordTone({ type, kind = null, before, after, classBefore = null, classAfter = null }) {
  if (BAD_TYPES.has(type) || kind === 'dmarc') return { tone: 'bad', why: null };
  if (type === 'TXT') return { tone: kind === 'spf' ? 'bad' : 'info', why: null };
  if (type === 'DS') {
    const a = new Set(after);
    return before.some((v) => !a.has(v)) ? { tone: 'bad', why: 'ds' } : { tone: 'info', why: null };
  }
  if (ADDRESS_TYPES.has(type)) {
    if (classMoved(classBefore, classAfter)) return { tone: 'bad', why: 'class' };
    if (cdnRotation(type, before, after)) return { tone: 'quiet', why: 'cdn' };
    return { tone: 'info', why: null };
  }
  if (type === 'DNSKEY') {
    const ksk = (list) => list.filter((v) => /^257 /.test(v)).sort().join('\n');
    if (ksk(before) === ksk(after)) return { tone: 'quiet', why: 'zsk' };
  }
  return { tone: 'info', why: null };
}

/**
 * The run times a FLAPPING window covers: the last {@link FLAP_RUNS} runs, this one included.
 * @param {string[]} runs ISO times, oldest first
 * @returns {string|null} the oldest
 */
export const flapWindowStart = (runs) => (Array.isArray(runs) && runs.length ? runs.slice(-FLAP_RUNS)[0] : null);

/**
 * The flips of a record set within the window of `runs`.
 * @param {string[]} flips ISO times of its value changes
 * @param {string[]} runs
 * @returns {number}
 */
export function recentFlips(flips, runs) {
  const start = flapWindowStart(runs);
  return (Array.isArray(flips) ? flips : []).filter((t) => isStr(t) && (!start || t >= start)).length;
}

/**
 * Was a record set asked in a report: its name and type among those asked, `_dmarc.` for its TXT and
 * the CNAME a hosted DMARC record is reached by (asked with the TXT, whatever the types), the apex's
 * NS and DS never (the delegation's), SOA, DS and DNSKEY at the apex and at a delegation.
 * @param {object} x a watch target
 * @param {string} name
 * @param {string} type
 * @returns {boolean}
 */
export function asked(x, name, type) {
  if (!isStrList(x.names) || !isStrList(x.types) || !x.names.includes(name)) return false;
  if (name === `_dmarc.${x.target}`) return x.types.includes('TXT') && (type === 'TXT' || type === 'CNAME');
  if (!x.types.includes(type)) return false;
  if (name === x.target) return type !== 'NS' && type !== 'DS';
  return !ZONE_TYPES.includes(type) || (isStrList(x.delegated) && x.delegated.includes(name));
}

/** Did a report's lookup of a record set fail? */
const failedIn = (x, key) => Array.isArray(x.failures) && x.failures.some((f) => isObj(f) && recordKey(f.name, f.type) === key);

/* ------------------------------------------------------------------------ */
/* Baseline validation                                                      */
/* ------------------------------------------------------------------------ */

/**
 * Why a `watch` baseline target is not what the comparison reads, or null.
 * @param {object} x
 * @returns {string|null}
 */
export function watchTargetProblem(x) {
  if (!isStrList(x.names)) return 'has no "names" list';
  if (!isStrList(x.types)) return 'has no "types" list';
  if (x.runs !== undefined && !isStrList(x.runs)) return 'has "runs" that are not a list of text';
  if (x.delegated !== undefined && !isStrList(x.delegated)) return 'has "delegated" that is not a list of text';
  if (x.nxdomain !== undefined && !isStrList(x.nxdomain)) return 'has "nxdomain" that is not a list of text';
  const r = x.registration;
  if (!isObj(r) || !isStr(r.state)) return 'has no "registration" with a "state"';
  for (const k of ['registrar', 'ianaId', 'expires', 'soon']) if (!isStrOrNull(r[k])) return `has a registration "${k}" that is not text`;
  for (const k of ['statuses', 'nameservers']) if (r[k] !== undefined && r[k] !== null && !isStrList(r[k])) return `has a registration "${k}" that is not a list of text`;
  if (r.carried !== undefined && !(isObj(r.carried) && isStrOrNull(r.carried.from))) return 'has a registration "carried" without a "from"';
  const d = x.delegation;
  if (!isObj(d)) return 'has no "delegation"';
  for (const k of ['ns', 'ds']) if (d[k] !== null && d[k] !== undefined && !isStrList(d[k])) return `has a delegation "${k}" that is not a list of text`;
  if (!Array.isArray(x.records)) return 'has no "records" list';
  for (const [i, rec] of x.records.entries()) {
    const where = `records[${i}]`;
    if (!isObj(rec)) return `${where} is not an object`;
    for (const k of ['key', 'name', 'type']) if (!isStr(rec[k])) return `${where} has no "${k}"`;
    if (!isStrList(rec.values)) return `${where} has "values" that are not a list of text`;
    if (rec.flips !== undefined && !isStrList(rec.flips)) return `${where} has "flips" that are not a list of text`;
    if (rec.carried !== undefined && !(isObj(rec.carried) && isStrOrNull(rec.carried.from))) return `${where} has a "carried" without a "from"`;
  }
  if (x.classes !== undefined && !(isObj(x.classes) && Object.values(x.classes).every(isStr))) return 'has "classes" that are not text by name';
  if (x.failures !== undefined && !(Array.isArray(x.failures) && x.failures.every((f) => isObj(f) && isStr(f.name) && isStr(f.type)))) return 'has "failures" that are not lookups';
  const a = x.authoritative;
  if (a !== undefined && a !== null) {
    if (!isObj(a) || !isStr(a.view)) return 'has an "authoritative" without a "view"';
    if (a.servers !== undefined && !(Array.isArray(a.servers) && a.servers.every((s) => isObj(s) && isStr(s.address) && isStr(s.status)))) return 'has "authoritative" servers without an address and a status';
    if (a.mismatches !== undefined && !(Array.isArray(a.mismatches) && a.mismatches.every((m) => isObj(m) && isStr(m.key)))) return 'has "authoritative" mismatches without a key';
    if (a.lagging !== undefined && !isStrList(a.lagging)) return 'has "authoritative" lagging servers that are not a list of text';
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* Changes since the baseline                                               */
/* ------------------------------------------------------------------------ */

function change(tag, target, item, what, { tone = 'info', counts = true, kind = 'changed', before = null, after = null } = {}) {
  return { tag, tone, counts, target, item, kind, before, after, parts: [code(target), ': ', ...what] };
}

/** A list of names as code parts joined with ', ' ("none" for an empty one). */
const listParts = (list) => (list && list.length ? list.flatMap((v, i) => (i ? [', ', code(v)] : [code(v)])) : ['none']);
/** A registrar as parts: its name and IANA ID. */
const registrarParts = (r) => [code(r && r.name ? r.name : 'unknown'), ...(r && r.ianaId ? [` (IANA ${r.ianaId})`] : [])];

/**
 * A watch target's registration and DS records as a lib/regwatch.js snapshot. What a run carried
 * (its lookup failed) stands for the last read in a baseline, and for nothing in this run's report.
 * @param {object} x a watch target
 * @param {{ current?: boolean }} [opts] `current`: this run's target
 * @returns {import('../../assets/js/lib/regwatch.js').RegSnapshot}
 */
function regSnapshot(x, { current = false } = {}) {
  const r = isObj(x.registration) ? x.registration : {};
  const d = isObj(x.delegation) ? x.delegation : {};
  const read = !(current && r.carried);
  const ok = read && r.state === 'ok';
  return {
    state: ok ? 'ok' : read && r.state === 'not-found' ? 'not-found' : null,
    registrar: ok ? r.registrar ?? null : null,
    ianaId: ok ? r.ianaId ?? null : null,
    statuses: ok && isStrList(r.statuses) ? r.statuses : null,
    expires: ok ? r.expires ?? null : null,
    nameservers: ok && isStrList(r.nameservers) ? r.nameservers : null,
    ds: isStrList(d.ds) && !(current && d.dsCarried) ? d.ds : null
  };
}

/** The words of one lib/regwatch.js change, as parts after the target. */
function regWords(c) {
  switch (c.code) {
    case 'unregistered': return ['the registry no longer has the domain (RDAP 404): anyone may be able to register it'];
    case 'registered': return ['the registry has the domain again'];
    case 'registrar': return ['registrar ', ...registrarParts(c.before), ' → ', ...registrarParts(c.after)];
    case 'registrar-name': return ['the registrar\'s name ', code(c.before.name), ' → ', code(c.after.name), ` (the same IANA ID ${c.after.ianaId})`];
    case 'lock-removed': return [code(c.item), ' removed: whoever has the transfer code can move the domain to another registrar'];
    case 'lock-added': return [code(c.item), ' added'];
    case 'hold': return [code(c.item), ' added', c.item === 'pending transfer' ? ': a transfer is under way — a hijack in progress if nobody here asked for it' : ''];
    case 'status': return [code(c.item), c.how === 'removed' ? ' removed' : ' added'];
    case 'ns': return ['the registry\'s name servers (RDAP) ', ...listParts(c.before), ' → ', ...listParts(c.after)];
    case 'ds-removed': return ['DS removed at the parent (', ...listParts(c.before), '): DNSSEC is off for the domain'];
    case 'ds-changed': return ['DS at the parent ', ...listParts(c.before), ' → ', ...listParts(c.after)];
    case 'ds-added': return ['DS added at the parent: ', ...listParts(c.after.filter((v) => !c.before.includes(v)))];
    case 'expiry-later': return [`renewed: expires ${c.after} (was ${c.before})`];
    case 'expiry-earlier': return [`the expiry moved earlier: ${c.after} (was ${c.before})`];
    default: return [c.code];
  }
}

/** The tag of a lib/regwatch.js change code. */
const REG_TAGS = Object.freeze({
  unregistered: 'STATUS', registered: 'STATUS', registrar: 'REGISTRAR', 'registrar-name': 'REGISTRAR', 'lock-removed': 'LOCK', 'lock-added': 'LOCK',
  hold: 'STATUS', status: 'STATUS', ns: 'NS', 'ds-removed': 'DS', 'ds-changed': 'DS', 'ds-added': 'DS', 'expiry-later': 'EXPIRY', 'expiry-earlier': 'EXPIRY'
});
/** The item of a change: what PagerDuty keys it by. */
const regItem = (c) => (c.item ? c.item : c.code === 'ns' ? 'registry' : c.code.startsWith('ds-') ? 'ds' : c.code.startsWith('expiry') ? 'expiry'
  : c.code.startsWith('registrar') ? 'registrar' : 'registration');

/** The registration and delegation changes of one domain. */
function diffRegistrationPart(domain, b, a) {
  const out = [];
  const ra = isObj(a.registration) ? a.registration : null;
  const rb = isObj(b.registration) ? b.registration : null;
  // not read this run: said once (the run after compares with the read it carried)
  if (ra && ra.carried && !(rb && rb.carried)) {
    out.push(change('FAILED', domain, 'rdap', [`the registry could not be read this run${ra.error ? ` (${ra.error})` : ''}: the registration is compared with the last read next time`],
      { tone: 'quiet', counts: false }));
  }
  // the DS records come from DNS: compared on a night the registry could not be read too
  const statusesA = ra && isStrList(ra.statuses) ? ra.statuses : [];
  for (const c of diffRegistration(regSnapshot(b), regSnapshot(a, { current: true }))) {
    const registrar = c.code === 'registrar' || c.code === 'registrar-name';
    // a transfer prohibition removed while another still blocks transfers: info, naming that one
    const still = c.code === 'lock-removed' ? TRANSFER_LOCK_STATUSES.filter((s) => statusesA.includes(s)) : [];
    out.push(change(REG_TAGS[c.code] || 'STATUS', domain, regItem(c), still.length ? [code(c.item), ' removed; ', code(still[0]), ' still blocks transfers'] : regWords(c), {
      tone: still.length ? 'info' : c.tone, kind: c.code === 'unregistered' ? 'disappeared' : 'changed',
      before: registrar ? c.before.name : c.before, after: registrar ? c.after.name : c.after
    }));
  }
  // the expiry has not moved and fewer than 30 days are left: said once (the report's marker)
  if (ra && !ra.carried && ra.state === 'ok' && isStr(ra.soon) && ra.soon !== (rb && rb.soon)) {
    const left = Number.isFinite(ra.daysLeft) ? ra.daysLeft : null;
    out.push(change('EXPIRY', domain, 'expiry', [`expires ${ra.soon}${left === null ? '' : left < 0 ? ` (${-left} day${left === -1 ? '' : 's'} ago)` : ` (${left} day${left === 1 ? '' : 's'} left)`} and has not been renewed`],
      { tone: 'bad', after: ra.soon }));
  }
  // the zone's own NS records (the registry's are compared above)
  const da = isObj(a.delegation) ? a.delegation : {};
  const db = isObj(b.delegation) ? b.delegation : {};
  if (isStrList(da.ns) && isStrList(db.ns) && !da.nsCarried && da.ns.join(' ') !== db.ns.join(' ')) {
    out.push(change('NS', domain, 'zone', ['the zone\'s name servers (NS at the apex) ', ...listParts(db.ns), ' → ', ...listParts(da.ns)],
      { tone: 'bad', before: [...db.ns], after: [...da.ns] }));
  }
  return out;
}

/** The records of a target by key. */
const recordsOf = (x) => new Map((Array.isArray(x.records) ? x.records : []).filter((r) => isObj(r) && isStr(r.key)).map((r) => [r.key, r]));

/**
 * A record set's values in the groups its change is said by: one group, or for TXT one per kind of
 * value ({@link txtKind}: SPF, DMARC, each service's token, the rest) that moved.
 * @returns {Array<{ kind: string|null, b: string[], a: string[] }>}
 */
function valueGroups(name, type, before, after) {
  // the CNAME a hosted DMARC record is reached by: said as DMARC
  if (type !== 'TXT') return [{ kind: type === 'CNAME' && isDmarcName(name) ? 'dmarc' : null, b: before, a: after }];
  return [...new Set([...before, ...after].map((v) => txtKind(name, v)))].sort().map((kind) => ({
    kind, b: before.filter((v) => txtKind(name, v) === kind), a: after.filter((v) => txtKind(name, v) === kind)
  })).filter((g) => g.b.join('\n') !== g.a.join('\n'));
}

/**
 * The change lines of one record set whose values moved: one line, or one per TXT value group.
 * While it flaps only its bad changes are listed (FLAPPING said it once).
 */
function recordLines(domain, rec, y, x, { classBefore, classAfter, flapping }) {
  const out = [];
  const { name, type } = rec;
  for (const g of valueGroups(name, type, (y && y.values) || [], (x && x.values) || [])) {
    const { tone, why } = recordTone({ type, kind: g.kind, before: g.b, after: g.a, classBefore, classAfter });
    if (flapping && tone !== 'bad') continue;
    const item = type === 'TXT' && g.kind && g.kind !== 'other' ? `${rec.key}|${g.kind}` : rec.key;
    const label = g.kind === 'spf' ? ' (SPF)' : g.kind === 'dmarc' ? ' (DMARC)' : '';
    const words = !g.b.length ? ['added ', ...valuesParts(type, g.a)]
      : !g.a.length ? ['removed ', ...valuesParts(type, g.b)]
        : [...valuesParts(type, g.b.filter((v) => !g.a.includes(v))), ' → ', ...valuesParts(type, g.a.filter((v) => !g.b.includes(v)))];
    const note = why === 'class' ? [`; it now points to ${classText(classAfter)} (was ${classText(classBefore)})`]
      : why === 'cdn' ? [' (the CDN\'s edges rotate: not counted)']
        : why === 'zsk' ? [' (a zone-signing key rolled: not counted)'] : [];
    out.push(change('RECORD', domain, item, [code(`${name} ${type}${label}`), ': ', ...words, ...note],
      { tone, counts: tone !== 'quiet', kind: !g.b.length ? 'appeared' : !g.a.length ? 'disappeared' : 'changed', before: g.b, after: g.a }));
  }
  return out;
}

/** Would removing these values be bad (the name gone)? */
const removalBad = (name, type, values) => valueGroups(name, type, values, []).some((g) => recordTone({ type, kind: g.kind, before: g.b, after: g.a }).tone === 'bad');

/** The record changes of one domain. */
function diffRecordsPart(domain, b, a, { ttl }) {
  const out = [];
  const old = recordsOf(b);
  const now = recordsOf(a);
  const classesB = isObj(b.classes) ? b.classes : {};
  const classesA = isObj(a.classes) ? a.classes : {};
  const nxNow = new Set(isStrList(a.nxdomain) ? a.nxdomain : []);
  const nxBefore = new Set(isStrList(b.nxdomain) ? b.nxdomain : []);
  // a name that answers NXDOMAIN now and had record sets: one line, as bad as the worst that went
  const goneNames = new Map();
  for (const key of [...new Set([...old.keys(), ...now.keys()])].sort()) {
    const y = old.get(key) || null;
    const x = now.get(key) || null;
    const rec = x || y;
    const { name, type } = rec;
    // compared only where both runs asked and read it (a lookup that failed carried the last read)
    if (!asked(b, name, type) || !asked(a, name, type) || failedIn(a, key) || (x && x.carried) || (failedIn(b, key) && !y)) continue;
    if (type === 'SOA' && y && x && Number.isFinite(y.serial) && Number.isFinite(x.serial) && y.serial !== x.serial) {
      out.push(change('SERIAL', domain, key, [code(`${name} SOA`), `: serial ${y.serial} → ${x.serial}`], { tone: 'quiet', counts: false, before: y.serial, after: x.serial }));
    }
    if (sameRecord(y, x, { ttl })) continue;
    if (nxNow.has(name) && !nxBefore.has(name) && y && (y.values || []).length) {
      if (!goneNames.has(name)) goneNames.set(name, []);
      goneNames.get(name).push({ type, values: y.values });
      continue;
    }
    const flapping = !!(x && x.flapping);
    if (flapping && !(y && y.flapping)) {
      out.push(change('FLAPPING', domain, key, [code(`${name} ${type}`), `: changed ${recentFlips(x.flips, a.runs)} times in the last ${FLAP_RUNS} runs: `
        + 'its changes are not listed while it keeps changing (a bad one still is)'], { tone: 'quiet', counts: false }));
    }
    if (!sameRecord(y, x)) {
      out.push(...recordLines(domain, rec, y, x, { classBefore: classesB[name], classAfter: classesA[name], flapping }));
    } else if (!flapping) {
      out.push(change('RECORD', domain, key, [code(`${name} ${type}`), `: TTL ${y.ttl} → ${x.ttl}`], { tone: 'info', before: y.ttl, after: x.ttl }));
    }
  }
  for (const [name, list] of goneNames) {
    const bad = name === domain || list.some((l) => removalBad(name, l.type, l.values));
    out.push(change('RECORD', domain, name, [code(name), ': no longer exists (NXDOMAIN); it had ', ...listParts(list.map((l) => l.type))],
      { tone: bad ? 'bad' : 'info', kind: 'disappeared', before: list.map((l) => l.type), after: 'NXDOMAIN' }));
  }
  return out;
}

/** A server as parts: its host names and address. */
const serverParts = (s) => [...((s.hosts || []).length ? [code(s.hosts[0]), ' ('] : []), code(s.address), ...((s.hosts || []).length ? [')'] : [])];
/** Why a server is lame, in words. */
const LAME_WHY = Object.freeze({
  'no-aa': 'it answers without authority for the zone', refused: 'it answers REFUSED', servfail: 'it answers SERVFAIL', 'no-answer': 'no answer over UDP or TCP',
  'no-soa': 'it has no SOA for the zone', unanswered: 'it leaves questions without an answer over UDP and TCP: not asked further this run'
});
export const lameWhy = (reason) => LAME_WHY[reason] || (isStr(reason) ? `it answers ${reason}` : 'it does not answer for the zone');

/** The name servers asked directly: LAME and SYNC. */
function diffAuthoritativePart(domain, b, a) {
  const out = [];
  const pa = isObj(a.authoritative) ? a.authoritative : null;
  const pb = isObj(b.authoritative) ? b.authoritative : null;
  if (!pa || !pb) return out;
  if (pa.view !== 'authoritative') {
    if (pb.view === 'authoritative') {
      out.push(change('FAILED', domain, 'authoritative', [pa.view === 'recursive'
        ? 'the name servers could not be asked directly this run (UDP and TCP port 53 failed): SYNC and LAME not compared'
        : 'no name server could be asked this run: SYNC and LAME not compared'], { tone: 'quiet', counts: false }));
    }
    return out;
  }
  const both = pb.view === 'authoritative';
  const serversB = new Map((both ? pb.servers || [] : []).filter(isObj).map((s) => [s.address, s]));
  const lame = (s) => s && (s.status === 'lame' || s.status === 'unreachable');
  for (const s of (both ? pa.servers || [] : []).filter(isObj)) {
    const p = serversB.get(s.address);
    if (s.status === 'skipped' || (p && p.status === 'skipped')) continue;
    if (lame(s) && !lame(p)) {
      out.push(change('LAME', domain, s.address, [...serverParts(s), `: ${lameWhy(s.reason)}`], { tone: 'bad', before: p ? p.status : null, after: s.reason || s.status }));
    } else if (!lame(s) && lame(p) && s.status === 'ok') {
      out.push(change('LAME', domain, s.address, [...serverParts(s), ': answers with authority again'], { tone: 'good', before: p.reason || p.status, after: 'ok' }));
    }
  }
  // SYNC from the mismatches' states (tools/ds/watch.mjs syncState), which a run that could not ask
  // the name servers carried: said when confirmed, its end when this run compared the set again
  const mismatched = (p) => new Map((Array.isArray(p.mismatches) ? p.mismatches : []).filter((m) => isObj(m) && isStr(m.key)).map((m) => [m.key, m]));
  const mb = mismatched(pb);
  const ma = mismatched(pa);
  for (const [key, m] of ma) {
    if (!m.confirmed || (mb.has(key) && mb.get(key).confirmed)) continue;
    const [name, type] = key.split('|');
    const groups = Object.entries(isObj(m.servers) ? m.servers : {});
    const shown = groups.slice(0, 3).flatMap(([address, values], i) => [i ? '; ' : '', code(address), ' ', ...valuesParts(type, Array.isArray(values) ? values : [])]);
    out.push(change('SYNC', domain, key, [code(`${name} ${type}`), `: the name servers answer it differently at serial ${pa.serial ?? '?'}: `, ...shown],
      { tone: 'bad', after: groups.length }));
  }
  // only where this run compared the set: nothing compared (the budget, lame servers) is not "agree"
  const comparedA = new Set(isStrList(pa.compared) ? pa.compared : []);
  for (const [key, m] of mb) {
    if (!m.confirmed || ma.has(key) || !comparedA.has(key)) continue;
    const [name, type] = key.split('|');
    out.push(change('SYNC', domain, key, [code(`${name} ${type}`), ': the name servers agree again'], { tone: 'good', before: 'mismatch', after: 'ok' }));
  }
  const lagB = new Set(both && isStrList(pb.lagging) ? pb.lagging : []);
  for (const address of both && isStrList(pa.lagging) ? pa.lagging : []) {
    if (lagB.has(address)) continue;
    const s = (pa.servers || []).find((x) => isObj(x) && x.address === address) || { address };
    out.push(change('SYNC', domain, address, [...serverParts(s), `: a lagging secondary (serial ${s.serial ?? '?'}, the others ${pa.serial ?? '?'})`],
      { tone: 'info', counts: false, after: s.serial ?? null }));
  }
  return out;
}

/**
 * The registration, delegation and record change watch since the baseline (the module header).
 * @param {object} before the baseline report
 * @param {object} after this run's report
 * @returns {object[]}
 */
export function diffWatch(before, after) {
  const out = [];
  const old = new Map((before.targets || []).map((x) => [x.target, x]));
  const now = new Map((after.targets || []).map((x) => [x.target, x]));
  const ttl = !!(isObj(before.options) && before.options.ttl && isObj(after.options) && after.options.ttl);
  for (const [domain, a] of now) {
    const b = old.get(domain);
    if (!b) {
      const r = a.registration || {};
      out.push(change('NEW', domain, null, [`now watched: ${r.state === 'ok' ? `registrar ${r.registrar || 'unknown'}, ` : ''}${(a.records || []).filter((x) => !x.carried && (x.values || []).length).length} record sets`],
        { kind: 'appeared' }));
      continue;
    }
    out.push(...diffRegistrationPart(domain, b, a), ...diffRecordsPart(domain, b, a, { ttl }), ...diffAuthoritativePart(domain, b, a));
  }
  for (const [domain] of old) if (!now.has(domain)) out.push(change('GONE', domain, null, ['no longer watched'], { kind: 'disappeared' }));
  return out;
}

/**
 * What the two runs did differently, as sentences: the record types, the names file, the TTLs, the
 * name servers asked directly.
 * @param {object} o the baseline's options
 * @param {object} n this run's options
 * @returns {string[]}
 */
export function watchNotes(o, n) {
  const notes = [];
  const list = (v) => (Array.isArray(v) ? v.join(',') : 'default');
  if (Array.isArray(o.types) && list(o.types) !== list(n.types)) {
    notes.push(`The record types differ from the baseline's (${list(o.types)} → ${list(n.types)}): only the types both runs asked are compared.`);
  }
  const names = (h) => (isObj(h) ? `${h.file} (${h.count})` : 'none');
  if (o.names !== undefined && names(o.names) !== names(n.names)) {
    notes.push(`The names file differs from the baseline's (${names(o.names)} → ${names(n.names)}): only the names both runs asked are compared.`);
  }
  if (o.ttl !== undefined && !!o.ttl !== !!n.ttl) notes.push('TTLs were compared in one run only (--ttl): their changes are compared when both runs ask.');
  if (o.authoritative !== undefined && !!o.authoritative !== !!n.authoritative) {
    notes.push('The name servers were asked directly in one run only (--authoritative): SYNC and LAME compare runs that both asked.');
  }
  return notes;
}
