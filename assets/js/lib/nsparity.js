/**
 * nsparity.js — before a DNS provider move: do the NEW provider's name servers serve what the
 * zone file says? The Zone File's live check compares the file with public DNS, which the
 * current provider still answers; this module asks the new name servers themselves, before the
 * registrar's NS records change. DOM-free; the Globalping client (lib/globalping.js) and the
 * DohClient are injected. Runs in browsers and Node 22.
 *
 * How (verified live 2026-09-28, tests/fixtures/globalping/d*.json):
 * - one Globalping DNS measurement per (name, type) and name server, `resolver` = that server's
 *   host name: the probe runs `dig @<server>` and returns the server's own answer (the `aa` flag
 *   in the dig text says it was authoritative), with the TTL it serves. One probe, one credit;
 * - the plan is lib/zonedrift.js's: names and types only, internal-looking names skipped by
 *   default, the hidden targets of proxied / flattened / alias records never queried, one query
 *   per unique (name, type). Globalping asks only its own list of types (GP_DNS_TYPES): CAA,
 *   TLSA and the rest are skipped `not-queryable` and left to the CLI (cli/dns_parity.py);
 * - batched: the full comparison runs against the first name server, and each other one is asked
 *   only for the SOA serial (one probe), which says whether it serves the same zone version.
 *   `mode: 'all'` compares every record on every server (the cost times the servers);
 * - a hard cap ({@link PARITY_MAX_PROBES}) per run: a zone that needs more is checked up to the
 *   cap (the rest is skipped `budget`, and the CLI checks it all for free). The budget is
 *   reserved before each POST, so parallel queries never overspend;
 * - the SOA of each server is asked first: a server that refuses the zone, is not authoritative
 *   for it or cannot be reached costs that one probe and nothing more.
 *
 * What it reports, per record set: same, different, missing (at the new provider), unproxied
 * (a proxied record the new server answers with its origin), extra (a record at the apex or www
 * the file does not have: a provider's parking address or default MX), skipped, error; TTL
 * differences; the apex NS set against the servers entered; the serial of every server; and a
 * runbook (lower TTLs, compare again, DNSSEC first, switch, keep the old zone).
 *
 * What is sent: to Globalping, the names and types queried and the name servers' host names
 * (public by measurement id; the answers are the new servers' public answers anyway); to the
 * DohClient, one DS query of the zone's name. Never a value of the file, an origin address or a
 * name the zone marks as internal (unless the caller turns `skipPrivate` off).
 */

import { planDrift, driftZone, DRIFT_MAX_BUDGET } from './zonedrift.js';
import { zoneIndex, proxiedSets, privateLookingNames, wildcardCovers, servedTargets } from './zoneorigins.js';
import { parseZone } from './zoneparse.js';
import { dnsQueryRequest, GP_DNS_TYPES, isProbeableHost, isProbeableDnsName, probeTarget, probeSummary } from './globalping.js';
import { normalizeHostname, sortHostnames } from './domain.js';
import { ipVersion, isGloballyRoutable, normalizeIP } from './netinfo.js';
import { quoteArg } from './cmdline.js';
import { AbortError, errorKind, abortReasonToError, randomLabel } from './util.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies and limits                                                  */
/* ------------------------------------------------------------------------ */

/** 'first': every record on the first name server, the SOA serial on the others; 'all': every record everywhere. */
export const PARITY_MODES = Object.freeze(['first', 'all']);
/** Probes one run may spend at most, whatever the zone (the CLI checks larger zones for free). */
export const PARITY_MAX_PROBES = 100;
/** Name servers one run takes (NS sets have 2–8). */
export const PARITY_MAX_NAMESERVERS = 8;
/** Measurements in flight at once (lib/verify.js uses the same). */
export const PARITY_CONCURRENCY = 4;
/** Types asked at the apex (and A / AAAA at www) that the file does not have: a provider's own records. */
export const PARITY_EXTRA_TYPES = Object.freeze(['A', 'AAAA', 'MX', 'TXT']);
export const PARITY_WWW_TYPES = Object.freeze(['A', 'AAAA']);
/** What a parity check can ask: Globalping's DNS types without ANY (minimal answers, RFC 8482). */
export const PARITY_QUERY_TYPES = Object.freeze(GP_DNS_TYPES.filter((t) => t !== 'ANY'));
/** Row statuses (closed set; the view translates `par.status.<status>`). */
export const PARITY_STATUSES = Object.freeze(['same', 'different', 'missing', 'unproxied', 'extra', 'skipped', 'error']);
export const PARITY_SEVERITY = Object.freeze({
  same: 'ok', different: 'warn', missing: 'error', unproxied: 'warn', extra: 'warn', skipped: 'info', error: 'unknown'
});
/** Reasons of this module; a row carries these and lib/zonedrift.js DRIFT_REASONS. */
export const PARITY_REASONS = Object.freeze(['ttl-differs', 'ns-new', 'ns-mismatch', 'ns-by-address', 'extra-record', 'cname-kept', 'below-cut']);
/** What the SOA question to one name server found (closed set, `par.ns.<state>`). */
export const NS_STATES = Object.freeze(['ok', 'refused', 'not-authoritative', 'no-zone', 'servfail', 'unreachable', 'failed', 'not-run']);
/** Problems of the name-server list as typed (`par.nsIssue.<code>`). */
export const NS_ISSUES = Object.freeze(['invalid', 'private', 'too-many', 'in-file']);
/** Why a run stopped before its plan was done. */
export const PARITY_STOPS = Object.freeze(['quota', 'unreachable', 'abort']);
/** The runbook, in order (`par.step.<id>`), and the states a step can be in. */
export const RUNBOOK_STEPS = Object.freeze(['ttl', 'fix', 'dnssec', 'switch', 'wait', 'after']);
export const RUNBOOK_STATES = Object.freeze(['ok', 'todo', 'warn', 'blocked', 'info']);
/** A TTL above this (s) is worth lowering before the switch. */
export const PARITY_TTL_LOW = 3600;
/** Hours the old provider's zone should keep answering after the switch (TLD NS TTLs run 1–2 days). */
export const PARITY_KEEP_OLD_HOURS = 48;
/** The CLI that checks a zone of any size, for free, from your own network. */
export const PARITY_CLI = 'dns_parity.py';

const FROM_DRIFT = Object.freeze({
  match: 'same', 'proxied-ok': 'same', 'flattened-ok': 'same', 'alias-ok': 'same', 'routing-ok': 'same',
  differs: 'different', 'missing-live': 'missing', 'origin-exposed': 'unproxied', occluded: 'skipped', skipped: 'skipped', error: 'error'
});
const RCODES = Object.freeze({ 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED' });
const QUOTA_CODES = new Set(['rate-limit', 'insufficient-credits']);
/** Refused before anything was created: nothing was spent. */
const FREE_CODES = new Set(['validation', 'private-target', 'bad-host', 'no-probes', 'unauthorized', 'rate-limit', 'insufficient-credits']);
const NETWORK_STOP_AFTER = 3;
const SAFE_OWNER = /^[A-Za-z0-9_*.\\-]+$/;
const PYTHON = Object.freeze({ posix: 'python3', powershell: 'python' });
const FILE_TOKEN = /^(?!-)[A-Za-z0-9_.-]{1,200}$/;

const canon = (v) => String(v ?? '').trim().toLowerCase().replace(/\.$/, '');

/* ------------------------------------------------------------------------ */
/* The name servers as typed                                                */
/* ------------------------------------------------------------------------ */

/**
 * The new name servers from a text box: host names (a trailing dot is dropped, IDN → punycode)
 * or public addresses, separated by spaces, commas, semicolons or lines; `#` starts a comment.
 * A private or documentation address cannot be asked through Globalping (the CLI can), a
 * duplicate is dropped, and more than {@link PARITY_MAX_NAMESERVERS} are cut off.
 * @param {string} text
 * @param {{ fileNs?: string[] }} [opts] the zone file's own apex NS (a server in it is an issue:
 *   that is the current provider)
 * @returns {{ list: string[], issues: Array<{ code: string, value: string }> }}
 */
export function parseNameservers(text, { fileNs = [] } = {}) {
  const list = [];
  const issues = [];
  const own = new Set((fileNs || []).map(canon));
  const tokens = String(text ?? '').split('\n').map((l) => l.replace(/#.*/, '')).join(' ').split(/[\s,;]+/).filter(Boolean);
  for (const raw of tokens) {
    const token = raw.trim();
    let value = null;
    if (ipVersion(token) || /^\[.*\]$/.test(token)) {
      const ip = normalizeIP(token.replace(/^\[|\]$/g, ''));
      if (ip && isGloballyRoutable(ip)) value = probeTarget(ip);
      else {
        issues.push({ code: ip ? 'private' : 'invalid', value: token });
        continue;
      }
    } else {
      const host = normalizeHostname(token);
      if (host && isProbeableHost(host)) value = host;
      else {
        issues.push({ code: 'invalid', value: token });
        continue;
      }
    }
    if (list.includes(value)) continue;
    if (list.length >= PARITY_MAX_NAMESERVERS) {
      issues.push({ code: 'too-many', value });
      continue;
    }
    if (own.has(value)) issues.push({ code: 'in-file', value });
    list.push(value);
  }
  return { list, issues };
}

/**
 * The zone file's own apex NS host names (the current provider's, in an export from it).
 * @param {object} zone
 * @returns {string[]}
 */
export function fileNameservers(zone) {
  const idx = zoneIndex(zone);
  return sortHostnames([...new Set(idx.unique.filter((r) => r.type === 'NS' && r.name === idx.origin).flatMap(servedTargets).filter(Boolean))]);
}

/* ------------------------------------------------------------------------ */
/* Plan                                                                     */
/* ------------------------------------------------------------------------ */

function clampProbes(n) {
  const v = Number.isFinite(n) ? Math.floor(n) : PARITY_MAX_PROBES;
  return Math.max(1, Math.min(PARITY_MAX_PROBES, v));
}

/**
 * The apex and www questions for records the file does not have ({@link PARITY_EXTRA_TYPES}):
 * none at a name with a CNAME, A / AAAA never at a proxied name (Cloudflare adds AAAA itself),
 * none at www when a wildcard of the file covers it, none at a skipped (internal-looking) name.
 * @param {object} zone
 * @param {{ skipPrivate?: boolean }} [opts]
 * @returns {Array<{ name: string, type: string }>}
 */
export function extraQueries(zone, { skipPrivate = true } = {}) {
  const idx = zoneIndex(zone);
  const origin = idx.origin;
  if (!origin || (zone && zone.fatal)) return [];
  const skip = skipPrivate ? privateLookingNames(zone) : new Set();
  const proxied = proxiedSets(idx).all;
  const typesAt = (name) => new Set(idx.unique.filter((r) => r.name === name).map((r) => r.type));
  const out = [];
  const add = (name, types) => {
    if (skip.has(name) || !isProbeableDnsName(name)) return;
    const have = typesAt(name);
    if (have.has('CNAME')) return;
    for (const type of types) {
      if (have.has(type) || ((type === 'A' || type === 'AAAA') && proxied.has(name))) continue;
      out.push({ name, type });
    }
  };
  add(origin, PARITY_EXTRA_TYPES);
  const www = `www.${origin}`;
  if (!wildcardCovers(idx, www) || idx.owners.has(www)) add(www, PARITY_WWW_TYPES);
  return out;
}

/**
 * What {@link runParity} will spend, without sending anything.
 *
 * Per fully compared server: the zonedrift plan's queries (the SOA + NS questions included)
 * plus the extra questions; per other server ('first' mode): one SOA question. Past the cap,
 * 'first' mode checks the record sets that fit (`capped`, the rest `budget`), and 'all' mode is
 * refused (`why: 'over-cap'`): split it, or use the CLI.
 *
 * @param {object} zone
 * @param {{ nameservers?: string[], mode?: 'first'|'all', extras?: boolean, skipPrivate?: boolean,
 *   wildcardProbes?: boolean, maxProbes?: number }} [opts]
 * @returns {{ ok: boolean, why: null|'no-origin'|'no-nameservers'|'over-cap', mode: string, full: string[], serial: string[],
 *   cap: number, needed: number, probes: number, capped: boolean, rrsets: number, checked: number, perServer: number,
 *   extras: number, driftBudget: number, skipped: object, targetsHidden: number, internalShare: number }}
 *   `needed`: probes without the cap; `probes`: what the run sends at most; `checked`: record sets
 *   compared (not skipped for their type, the name or the budget)
 */
export function planParity(zone, { nameservers = [], mode = 'first', extras = true, skipPrivate = true, wildcardProbes = true, maxProbes = PARITY_MAX_PROBES } = {}) {
  const cap = clampProbes(maxProbes);
  const m = mode === 'all' ? 'all' : 'first';
  const ns = [...new Set((nameservers || []).map(String))].slice(0, PARITY_MAX_NAMESERVERS);
  const full = m === 'all' ? ns : ns.slice(0, 1);
  const serial = m === 'all' ? [] : ns.slice(1);
  const common = { skipPrivate, wildcardProbes, queryTypes: PARITY_QUERY_TYPES };
  const whole = planDrift(zone, { ...common, maxQueries: DRIFT_MAX_BUDGET });
  const extra = extras ? extraQueries(zone, { skipPrivate }) : [];
  const idx = zoneIndex(zone);
  const base = {
    mode: m, full, serial, cap, extras: extra.length, targetsHidden: whole.targetsHidden, internalShare: whole.internalShare
  };
  const empty = (why) => ({
    ...base, ok: false, why, needed: 0, probes: 0, capped: false, rrsets: whole.rrsets, checked: 0, perServer: 0, driftBudget: 0, skipped: whole.skipped
  });
  if (!idx.origin || (zone && zone.fatal)) return empty('no-origin');
  if (!ns.length) return empty('no-nameservers');
  const needed = full.length * (whole.needed + extra.length) + serial.length;
  let plan = whole;
  let driftBudget = whole.queries;
  if (needed > cap) {
    if (m === 'all') {
      return { ...empty('over-cap'), needed, probes: 0, capped: true };
    }
    driftBudget = Math.max(2, cap - serial.length - extra.length);
    plan = planDrift(zone, { ...common, maxQueries: driftBudget });
  }
  const perServer = plan.queries + extra.length;
  const skipped = plan.skipped;
  const unchecked = skipped.private + skipped.occluded + skipped.outOfZone + skipped.unsupported + skipped.escaped
    + skipped.dnssec + skipped.synthesized + skipped.wildcard + skipped.type + skipped.budget;
  return {
    ...base,
    ok: true,
    why: null,
    needed,
    probes: full.length * perServer + serial.length,
    capped: needed > cap,
    rrsets: plan.rrsets,
    checked: Math.max(0, plan.rrsets - unchecked),
    perServer,
    driftBudget,
    skipped
  };
}

/* ------------------------------------------------------------------------ */
/* One DNS test → a DohClient-shaped response                               */
/* ------------------------------------------------------------------------ */

function rcodeOf(test) {
  if (typeof test.statusCodeName === 'string' && /^[A-Z]{3,12}$/.test(test.statusCodeName)) return test.statusCodeName;
  return Number.isInteger(test.statusCode) ? (RCODES[test.statusCode] || `RCODE${test.statusCode}`) : null;
}

/**
 * The `aa` flag of the dig text in `rawOutput` (`;; flags: qr aa rd;`): true / false, or null
 * when the text has no flags line.
 * @param {unknown} raw
 * @returns {boolean|null}
 */
export function authoritativeFlag(raw) {
  const m = /;; flags:([^;\n]*);/.exec(typeof raw === 'string' ? raw : '');
  return m ? m[1].trim().split(/\s+/).includes('aa') : null;
}

/** One answer of a DNS test as a dnswire-shaped RR (data parsed by lib/zoneparse.js), or null. */
function answerRr(a, origin) {
  if (!a || typeof a !== 'object') return null;
  const name = String(a.name ?? '');
  const type = String(a.type ?? '').toUpperCase();
  const value = String(a.value ?? '');
  const ttl = Number.isInteger(a.ttl) && a.ttl >= 0 ? a.ttl : null;
  if (!name || !SAFE_OWNER.test(name) || !/^[A-Z][A-Z0-9-]{0,15}$/.test(type) || /[\x00-\x1f\x7f]/.test(value)) return null;
  // One answer per parse: a stray parenthesis or quote can only spoil its own line.
  const z = parseZone(`${name.endsWith('.') ? name : `${name}.`} ${ttl ?? 0} IN ${type} ${value}\n`, { origin: origin || undefined, format: 'bind' });
  const r = z.records[0];
  const owner = canon(name);
  if (!r || r.invalid || r.unsupported || r.data === null || r.data === undefined) {
    return { name: owner, type, ttl, data: null, text: value, unparsed: true };
  }
  return { name: r.name || owner, type: r.type, ttl, data: r.data, text: typeof r.text === 'string' && r.text ? r.text : value };
}

const DIG_RR = /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/;

/**
 * The records of one section of the dig text in `rawOutput` (`;; AUTHORITY SECTION:`,
 * `;; ADDITIONAL SECTION:`), as Globalping's `answers` entries: the `answers` array carries the
 * answer section only, so a referral's NS records and glue are read from the text.
 * @param {unknown} raw
 * @param {'AUTHORITY'|'ADDITIONAL'} section
 * @returns {Array<{ name: string, type: string, ttl: number, class: string, value: string }>}
 */
export function digSection(raw, section) {
  const lines = (typeof raw === 'string' ? raw : '').split('\n');
  const start = lines.findIndex((l) => l.trim() === `;; ${section} SECTION:`);
  if (start < 0) return [];
  const out = [];
  for (const line of lines.slice(start + 1)) {
    if (!line.trim() || line.startsWith(';')) break;
    const m = DIG_RR.exec(line.trim());
    if (m && m[3] === 'IN') out.push({ name: m[1], type: m[4], ttl: Number(m[2]), class: m[3], value: m[5].trim() });
  }
  return out;
}

/** Why a finished-or-not test gave no DNS answer: 'unreachable' (the server's name or address) or 'timeout'. */
function testFailure(test) {
  const raw = String((test && test.rawOutput) || '');
  if (/couldn't get address|not found|network unreachable|no route|connection refused/i.test(raw)) return 'unreachable';
  if (/timed out|no servers could be reached/i.test(raw)) return 'timeout';
  return 'failed';
}

/**
 * The first test of a finished DNS measurement as the DohClient response lib/zonedrift.js reads:
 * `{ ok, rcode, aa, answers, authorities, referral, resolver, ede: [], error, errorKind,
 * measurementId, probe }`. A referral (the server is the parent of a delegation in the zone)
 * answers a cut's NS query with the authority section's NS records and a glue A / AAAA query
 * with the additional section's, as the file lists them. A test that did not finish is
 * `ok: false` with `failure` 'unreachable' | 'timeout' | 'failed' ('timeout' → `errorKind`
 * 'timeout').
 * @param {object} measurement a Globalping measurement (type 'dns')
 * @param {{ name: string, type: string, resolver: string, origin?: string, id?: string }} ctx
 * @returns {object}
 */
export function dnsResponse(measurement, { name, type, resolver, origin = null, id = null }) {
  const first = measurement && Array.isArray(measurement.results) ? measurement.results[0] : null;
  const test = first && first.result && typeof first.result === 'object' ? first.result : null;
  const base = {
    name, type, resolver, ok: false, rcode: null, aa: null, answers: [], authorities: [], referral: false, ede: [], error: null, errorKind: null,
    measurementId: id || (measurement && measurement.id) || null, probe: first ? probeSummary(first.probe) : null, unparsed: 0, failure: null
  };
  if (!test || test.status !== 'finished' || !rcodeOf(test)) {
    const failure = testFailure(test);
    const line = String((test && test.rawOutput) || '').trim().split('\n').find((l) => l && !l.startsWith(';')) || 'no answer';
    return { ...base, failure, error: line.slice(0, 200), errorKind: failure === 'timeout' ? 'timeout' : 'network' };
  }
  let unparsed = 0;
  const read = (list) => {
    const out = [];
    for (const a of list) {
      const rr = answerRr(a, origin);
      if (!rr) {
        unparsed += 1;
        continue;
      }
      if (rr.unparsed) unparsed += 1;
      out.push(rr);
    }
    return out;
  };
  let answers = read(Array.isArray(test.answers) ? test.answers : []);
  const authorities = read(digSection(test.rawOutput, 'AUTHORITY'));
  const rcode = rcodeOf(test);
  const aa = authoritativeFlag(test.rawOutput);
  // A referral (a delegation below the zone): the parent's servers answer a cut's NS records
  // and the glue of its name servers from the authority and additional sections, not the answer.
  const q = canon(name);
  const referral = aa === false && rcode === 'NOERROR' && !answers.some((rr) => canon(rr.name) === q)
    && authorities.some((rr) => rr.type === 'NS' && (q === canon(rr.name) || q.endsWith(`.${canon(rr.name)}`)));
  if (referral && type === 'NS') answers = authorities.filter((rr) => rr.type === 'NS' && canon(rr.name) === q);
  else if (referral && (type === 'A' || type === 'AAAA')) {
    answers = read(digSection(test.rawOutput, 'ADDITIONAL')).filter((rr) => rr.type === type && canon(rr.name) === q);
  }
  return { ...base, ok: true, rcode, aa, answers, authorities, referral, unparsed };
}

/**
 * What the SOA question tells about one name server (a {@link NS_STATES} value) and its serial.
 * @param {object} resp {@link dnsResponse}
 * @param {string} origin
 * @returns {{ state: string, serial: number|null, aa: boolean|null, rcode: string|null }}
 */
export function nameserverState(resp, origin) {
  const out = { state: 'failed', serial: null, aa: resp ? resp.aa ?? null : null, rcode: resp ? resp.rcode ?? null : null };
  if (!resp) return out;
  if (!resp.ok) return { ...out, state: resp.failure === 'unreachable' || resp.failure === 'timeout' ? 'unreachable' : 'failed' };
  if (resp.rcode === 'REFUSED') return { ...out, state: 'refused' };
  if (resp.rcode === 'SERVFAIL') return { ...out, state: 'servfail' };
  const soa = resp.answers.find((rr) => rr.type === 'SOA' && canon(rr.name) === origin && rr.data && typeof rr.data === 'object');
  if (resp.rcode !== 'NOERROR' || !soa) return { ...out, state: 'no-zone' };
  const serial = Number.isFinite(Number(soa.data.serial)) ? Number(soa.data.serial) : null;
  if (resp.aa === false) return { ...out, state: 'not-authoritative', serial };
  return { ...out, state: 'ok', serial };
}

/* ------------------------------------------------------------------------ */
/* The transport: a DohClient over Globalping, one name server              */
/* ------------------------------------------------------------------------ */

/** A query that got no DNS answer on Globalping's side (`failure` 'globalping'), or was not sent ('budget'). */
function failed(name, type, resolver, errorKindValue, error) {
  return {
    name, type, resolver, ok: false, rcode: null, aa: null, answers: [], authorities: [], ede: [], error, errorKind: errorKindValue,
    measurementId: null, probe: null, unparsed: 0, failure: errorKindValue === 'budget' ? 'budget' : 'globalping'
  };
}

/**
 * A DohClient-shaped `{ query(name, type, { signal }) }` that asks `nameserver` through Globalping
 * DNS measurements (what {@link runParity} hands to lib/zonedrift.js). Each (name, type) is asked
 * once (memoised). `reserve()` is called before every POST: false → the query is not sent
 * (`errorKind` 'budget'). A quota 429 or three network failures in a row call `onStop` and
 * throw an AbortError; once `stopped()` says so, every later query throws one before any POST,
 * while the queries already in flight finish (they were paid for). Any other failure is a
 * failed response (a drift row `error`). Every measurement is reported through `onMeasurement`
 * (`cost` 0 for a request that was refused for free).
 * @param {{ client: object, nameserver: string, origin?: string, reserve?: () => boolean, release?: () => void,
 *   onMeasurement?: (m: { id: string|null, cost: number, name: string, type: string, quota: object|null, ok: boolean }) => void,
 *   onStop?: (reason: 'quota'|'unreachable', err: unknown) => void, stopped?: () => (string|null) }} opts
 * @returns {{ query: (name: string, type: string, opts?: { signal?: AbortSignal }) => Promise<object>, readonly sent: number }}
 */
export function createParityDns({ client, nameserver, origin = null, reserve = () => true, release = () => {}, onMeasurement = null, onStop = null, stopped = () => null }) {
  if (!client || typeof client.measure !== 'function') throw new TypeError('createParityDns: a Globalping client is required');
  const memo = new Map();
  let sent = 0;
  let networkFailures = 0;
  const note = (m) => {
    if (typeof onMeasurement !== 'function') return;
    try {
      onMeasurement(m);
    } catch {
      /* observer errors never break the run */
    }
  };

  async function send(name, type, signal) {
    if (signal && signal.aborted) throw abortReasonToError(signal.reason);
    const stop = stopped();
    if (stop) throw new AbortError(`parity stopped: ${stop}`);
    let body;
    try {
      body = dnsQueryRequest({ name, type, resolver: nameserver });
    } catch (err) {
      return failed(name, type, nameserver, 'parse', String((err && err.message) || err));
    }
    if (!reserve()) return failed(name, type, nameserver, 'budget', 'probe budget reached');
    sent += 1;
    try {
      const { measurement, id, cost, quota } = await client.measure(body, { signal });
      networkFailures = 0;
      note({ id, cost: Number.isFinite(cost) ? cost : 1, name, type, quota: quota || null, ok: true });
      return dnsResponse(measurement, { name, type, resolver: nameserver, origin, id });
    } catch (err) {
      if (errorKind(err) === 'abort' || (signal && signal.aborted)) throw err instanceof AbortError ? err : new AbortError('parity cancelled');
      const code = err && typeof err === 'object' ? err.code : null;
      const paid = !!(err && err.measurementId);
      if (!paid && FREE_CODES.has(code)) release();
      note({ id: (err && err.measurementId) || null, cost: paid ? (Number(err.cost) || 1) : 0, name, type, quota: (err && err.quota) || null, ok: false });
      if (QUOTA_CODES.has(code)) {
        if (typeof onStop === 'function') onStop('quota', err);
        throw new AbortError('parity stopped: quota');
      }
      if (err instanceof TypeError || (err && err.name === 'TimeoutError')) {
        networkFailures += 1;
        if (networkFailures >= NETWORK_STOP_AFTER) {
          if (typeof onStop === 'function') onStop('unreachable', err);
          throw new AbortError('parity stopped: unreachable');
        }
      }
      return failed(name, type, nameserver, code === 'deadline' ? 'timeout' : 'network', String((err && err.message) || err));
    }
  }

  return {
    query(name, type, { signal } = {}) {
      const key = `${canon(name)}|${String(type).toUpperCase()}`;
      if (!memo.has(key)) {
        const p = send(canon(name), String(type).toUpperCase(), signal);
        // A rejected query (a stop, a cancel) is not kept: nothing was learned.
        p.catch(() => memo.delete(key));
        memo.set(key, p);
      }
      return memo.get(key);
    },
    get sent() { return sent; }
  };
}

/* ------------------------------------------------------------------------ */
/* Rows                                                                     */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ParityRow
 * @property {string} key `ns|name|type` (extras: `ns|name|type|extra`)
 * @property {string} ns the name server that answered
 * @property {string} name
 * @property {string} type
 * @property {string} status one of {@link PARITY_STATUSES}
 * @property {string|null} driftStatus the lib/zonedrift.js status it came from (null for extras)
 * @property {string[]} reasons DRIFT_REASONS and {@link PARITY_REASONS}
 * @property {string[]} file values in the file
 * @property {string[]} live values the new name server answered
 * @property {string[]} added values only the new name server has
 * @property {string[]} removed values only the file has
 * @property {number|null} fileTtl
 * @property {number|null} liveTtl the TTL the new name server serves
 * @property {boolean|null} proxied
 * @property {number[]} recordIds
 * @property {string|null} probe the random name asked for a wildcard record set
 */

/**
 * A lib/zonedrift.js row as a parity row: its status mapped (proxied-ok, flattened-ok, alias-ok
 * and routing-ok are `same`; origin-exposed is `unproxied`; a flattened CNAME the new provider
 * serves as a plain CNAME to the same target is `same` / `cname-kept`), `ttl-stale` replaced by
 * `ttl-differs` (any difference; an authoritative TTL is exact — never at a proxied name or an
 * automatic TTL), and the apex NS record set judged against the name servers entered (the file
 * lists the old provider's: `ns-new` when the new servers name exactly themselves).
 * @param {object} row DriftRow
 * @param {{ ns: string, origin: string, hosts: string[], autoTtl: Set<string> }} ctx
 * @returns {ParityRow}
 */
export function parityRow(row, { ns, origin, hosts, autoTtl }) {
  const out = {
    ...row,
    key: `${ns}|${row.key}`,
    ns,
    driftStatus: row.status,
    status: FROM_DRIFT[row.status] || 'error',
    reasons: row.reasons.filter((r) => r !== 'ttl-stale'),
    file: [...row.file],
    live: [...row.live],
    added: [...row.added],
    removed: [...row.removed]
  };
  // Data below a delegation: the child zone's servers answer it, the new provider never does.
  if (row.status === 'occluded') out.reasons = ['below-cut'];
  if (row.status === 'differs' && row.reasons.includes('flatten-mismatch') && row.type === 'CNAME' && row.name !== origin
    && row.live.length === 1 && row.file.length === 1 && canon(row.live[0]) === canon(row.file[0])) {
    // A provider that does not flatten serves the CNAME itself: the same answer for resolvers.
    out.status = 'same';
    out.reasons = ['cname-kept'];
  }
  if (row.type === 'NS' && row.name === origin && (out.status === 'same' || out.status === 'different') && !hosts.length) {
    // Servers typed as addresses: which names they should publish is not known here.
    out.status = 'skipped';
    out.reasons = ['ns-by-address'];
  } else if (row.type === 'NS' && row.name === origin && (out.status === 'same' || out.status === 'different')) {
    const got = sortHostnames([...new Set(row.live.map(canon).filter(Boolean))]);
    const want = sortHostnames([...new Set(hosts)]);
    const equal = got.length === want.length && got.every((n, i) => n === want[i]);
    out.reasons = out.reasons.filter((r) => r !== 'values');
    if (equal) {
      out.status = 'same';
      out.added = [];
      out.removed = [];
      out.reasons.push('ns-new');
    } else {
      out.status = 'different';
      out.added = got.filter((n) => !want.includes(n));
      out.removed = want.filter((n) => !got.includes(n));
      out.reasons.push('ns-mismatch');
    }
  }
  if ((out.status === 'same' || out.status === 'different') && row.proxied !== true && !autoTtl.has(row.key)
    && Number.isFinite(row.fileTtl) && Number.isFinite(row.liveTtl) && row.fileTtl !== row.liveTtl
    && !(row.type === 'NS' && row.name === origin)) {
    out.reasons.push('ttl-differs');
  }
  return out;
}

function extraRow(ns, q, resp) {
  const base = {
    ns, name: q.name, type: q.type, driftStatus: null, reasons: [], file: [], live: [], added: [], removed: [],
    resolver: ns, rcode: resp.rcode ?? null, fileTtl: null, liveTtl: null, proxied: null, recordIds: [], probe: null
  };
  if (!resp.ok || (resp.rcode !== 'NOERROR' && resp.rcode !== 'NXDOMAIN')) {
    const reason = !resp.ok ? (resp.errorKind === 'timeout' ? 'timeout' : resp.errorKind === 'budget' ? 'budget' : 'transport')
      : resp.rcode === 'REFUSED' ? 'refused' : 'servfail';
    return [{ ...base, key: `${ns}|${q.name}|${q.type}|extra`, status: 'error', reasons: [reason] }];
  }
  const own = resp.answers.filter((rr) => canon(rr.name) === q.name && (rr.type === q.type || rr.type === 'CNAME'));
  if (!own.length) return [];
  const type = own.some((rr) => rr.type === q.type) ? q.type : 'CNAME';
  const rrs = own.filter((rr) => rr.type === type);
  const values = rrs.map((rr) => rr.text);
  const ttls = rrs.map((rr) => rr.ttl).filter(Number.isFinite);
  return [{
    ...base, key: `${ns}|${q.name}|${type}|extra`, type, status: 'extra', reasons: ['extra-record'], live: values, added: values,
    liveTtl: ttls.length ? Math.min(...ttls) : null
  }];
}

/* ------------------------------------------------------------------------ */
/* Run                                                                      */
/* ------------------------------------------------------------------------ */

function safeCall(fn, arg) {
  if (typeof fn !== 'function') return;
  try {
    fn(arg);
  } catch {
    /* observer errors never break the run */
  }
}

/**
 * @typedef {object} NsResult
 * @property {string} ns
 * @property {'full'|'serial'} role compared record by record, or asked for its SOA serial only
 * @property {string} state one of {@link NS_STATES}
 * @property {number|null} serial
 * @property {boolean|null} aa
 * @property {string|null} rcode
 * @property {string|null} measurementId of its SOA question
 * @property {object|null} probe globalping.probeSummary of the probe that asked
 */

/**
 * Compare the zone with the new name servers. Resolves (never rejects on DNS or Globalping
 * failures, nor on a stop): `stoppedBy` says why a run ended early ('quota' — the hourly
 * Globalping quota ran out, `resetAt` when it comes back; 'unreachable' — the API could not be
 * reached three times in a row; 'abort' — the caller's signal) and the rows so far are kept.
 *
 * Order: per fully compared server, its SOA (a server that does not serve the zone ends there),
 * then every other record set (lib/zonedrift.js, at most {@link PARITY_CONCURRENCY} in flight),
 * then the extra questions; then the SOA of every other server; then one DS query of the zone's
 * name through `dns` (the DohClient: is the zone signed at the registrar?), when given.
 *
 * @param {object} zone
 * @param {object} opts
 * @param {object} opts.client lib/globalping.js client (`measure`)
 * @param {string[]} opts.nameservers {@link parseNameservers} list
 * @param {'first'|'all'} [opts.mode='first']
 * @param {boolean} [opts.extras=true]
 * @param {boolean} [opts.skipPrivate=true]
 * @param {boolean} [opts.wildcardProbes=true]
 * @param {number} [opts.maxProbes=PARITY_MAX_PROBES]
 * @param {{ query: Function }|null} [opts.dns] DohClient for the DS question (optional)
 * @param {AbortSignal} [opts.signal]
 * @param {(row: ParityRow) => void} [opts.onRow]
 * @param {(p: { done: number, total: number, spent: number }) => void} [opts.onProgress] done / total in probes
 * @param {(q: object) => void} [opts.onQuota] every quota reading of a measurement
 * @param {(ns: NsResult) => void} [opts.onServer] a name server's SOA answer
 * @param {() => string} [opts.labelFn] the wildcard probe label (tests)
 * @param {() => Date} [opts.now]
 * @returns {Promise<{ origin: string, mode: string, startedAt: Date, finishedAt: Date, nameservers: NsResult[], rows: ParityRow[],
 *   counts: Object<string, number>, spent: number, planned: number, stoppedBy: string|null, resetAt: Date|null, serials: 'same'|'differ'|'unknown',
 *   dnssec: { signedInFile: boolean, ds: 'present'|'absent'|'unknown'|null }, capped: boolean, measurementIds: string[] }>}
 * @throws {TypeError} without a client, a name server or a zone name (see {@link planParity})
 */
export async function runParity(zone, opts = {}) {
  const {
    client, nameservers = [], mode = 'first', extras = true, skipPrivate = true, wildcardProbes = true, maxProbes = PARITY_MAX_PROBES,
    dns = null, signal, onRow, onProgress, onQuota, onServer, labelFn = randomLabel, now = () => new Date()
  } = opts || {};
  if (!client || typeof client.measure !== 'function') throw new TypeError('runParity: a Globalping client is required');
  const plan = planParity(zone, { nameservers, mode, extras, skipPrivate, wildcardProbes, maxProbes });
  if (!plan.ok) throw new TypeError(`runParity: nothing to run (${plan.why})`);
  const idx = zoneIndex(zone);
  const origin = idx.origin;
  const hosts = [...plan.full, ...plan.serial].filter((n) => !ipVersion(n));
  const autoTtl = new Set(idx.unique.filter((r) => r.ttlAuto).map((r) => `${r.name}|${r.type}`));
  const startedAt = now();

  // The caller's signal ends the run at once. A stop (quota, unreachable) only refuses every later
  // POST: the measurements already created were paid for, so they are still read.
  const inner = new AbortController();
  const onOuterAbort = () => inner.abort(signal.reason);
  if (signal) {
    if (signal.aborted) inner.abort(signal.reason);
    else signal.addEventListener('abort', onOuterAbort, { once: true });
  }
  let stoppedBy = null;
  let resetAt = null;
  let reserved = 0;
  let spent = 0;
  let done = 0;
  const ids = [];
  const stop = (reason, err) => {
    if (!stoppedBy) stoppedBy = reason;
    if (reason === 'quota' && err && err.resetAt instanceof Date) resetAt = err.resetAt;
  };
  const transport = (nameserver) => createParityDns({
    client,
    nameserver,
    origin,
    reserve: () => (reserved < plan.probes ? (reserved += 1, true) : false),
    release: () => { reserved = Math.max(0, reserved - 1); },
    onMeasurement: (m) => {
      spent += m.cost;
      done += 1;
      if (m.id) ids.push(m.id);
      if (m.quota) safeCall(onQuota, m.quota);
      safeCall(onProgress, { done, total: plan.probes, spent });
    },
    onStop: stop,
    stopped: () => stoppedBy
  });

  const servers = [...plan.full.map((ns) => ({ ns, role: 'full' })), ...plan.serial.map((ns) => ({ ns, role: 'serial' }))]
    .map((s) => ({ ...s, state: 'not-run', serial: null, aa: null, rcode: null, measurementId: null, probe: null }));
  const rows = [];
  const emit = (row) => {
    rows.push(row);
    safeCall(onRow, row);
  };
  const aborted = () => inner.signal.aborted || !!stoppedBy;

  try {
    for (let i = 0; i < servers.length; i += 1) {
      const server = servers[i];
      if (aborted()) break;
      const dnsOf = transport(server.ns);
      let soa;
      try {
        soa = await dnsOf.query(origin, 'SOA', { signal: inner.signal });
      } catch (err) {
        if (errorKind(err) === 'abort' || aborted()) break;
        throw err;
      }
      Object.assign(server, nameserverState(soa, origin), { measurementId: soa.measurementId || null, probe: soa.probe || null });
      if (!soa.ok && soa.errorKind === 'budget') server.state = 'not-run';
      if (server.role === 'full' && server.state !== 'ok' && plan.mode === 'first' && servers[i + 1]) {
        // The first server does not serve the zone: the next one is compared instead (its SOA
        // probe was planned; the record sets this one never asked pay for the rest).
        servers[i + 1].role = 'full';
      }
      safeCall(onServer, { ...server });
      if (server.role !== 'full' || server.state !== 'ok') continue;
      const report = await driftZone(zone, {
        dns: dnsOf,
        signal: inner.signal,
        maxQueries: plan.driftBudget,
        concurrency: PARITY_CONCURRENCY,
        skipPrivate,
        wildcardProbes,
        queryTypes: PARITY_QUERY_TYPES,
        labelFn,
        now,
        onRow: (row) => emit(parityRow(row, { ns: server.ns, origin, hosts, autoTtl }))
      });
      if (report.aborted || aborted()) break;
      if (extras) {
        const qs = extraQueries(zone, { skipPrivate });
        const answers = await Promise.all(qs.map((q) => dnsOf.query(q.name, q.type, { signal: inner.signal }).then(
          (resp) => ({ q, resp }), (err) => (errorKind(err) === 'abort' ? null : { q, resp: failed(q.name, q.type, server.ns, 'network', String(err)) })
        )));
        const seen = new Set();
        for (const a of answers) {
          if (!a) continue;
          for (const row of extraRow(server.ns, a.q, a.resp)) {
            if (seen.has(row.key)) continue;
            seen.add(row.key);
            emit(row);
          }
        }
      }
    }
  } finally {
    if (signal) signal.removeEventListener('abort', onOuterAbort);
  }
  if (!stoppedBy && signal && signal.aborted) stoppedBy = 'abort';

  let ds = null;
  if (dns && typeof dns.query === 'function' && !stoppedBy) {
    try {
      const resp = await dns.query(origin, 'DS', { signal });
      const own = resp && resp.ok && Array.isArray(resp.answers) ? resp.answers.filter((rr) => rr.type === 'DS' && canon(rr.name) === origin) : [];
      ds = resp && resp.ok && (resp.rcode === 'NOERROR' || resp.rcode === 'NXDOMAIN') ? (own.length ? 'present' : 'absent') : 'unknown';
    } catch (err) {
      ds = 'unknown';
      if (errorKind(err) === 'abort') stoppedBy = stoppedBy || 'abort';
    }
  }

  const known = servers.filter((s) => s.state === 'ok' && Number.isFinite(s.serial)).map((s) => s.serial);
  const serials = known.length < 2 ? 'unknown' : known.every((s) => s === known[0]) ? 'same' : 'differ';
  const counts = Object.fromEntries(PARITY_STATUSES.map((s) => [s, 0]));
  for (const row of rows) counts[row.status] += 1;
  return {
    origin,
    mode: plan.mode,
    startedAt,
    finishedAt: now(),
    nameservers: servers,
    rows,
    counts,
    spent,
    planned: plan.probes,
    stoppedBy,
    resetAt,
    serials,
    dnssec: { signedInFile: signedInFile(zone), ds },
    capped: plan.capped,
    measurementIds: ids
  };
}

/* ------------------------------------------------------------------------ */
/* Summary and runbook                                                      */
/* ------------------------------------------------------------------------ */

const DNSSEC_RECORD_TYPES = new Set(['DNSKEY', 'RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'CDS', 'CDNSKEY']);

/**
 * Whether the export carries DNSSEC records of the zone itself (its keys, signatures or denial
 * records at or under the zone name): the current provider signs it.
 * @param {object} zone
 * @returns {boolean}
 */
export function signedInFile(zone) {
  const idx = zoneIndex(zone);
  return !!idx.origin && idx.unique.some((r) => DNSSEC_RECORD_TYPES.has(r.type) && idx.inZone(r.name));
}

/**
 * The headline of a finished run: `verdict` 'ready' (every compared record set is the same, and
 * every server serves the zone), 'fix' (missing or different records, or a server that does not
 * serve it), 'check' (only extra / unproxied records, TTL differences or serials out of step),
 * 'partial' (clean so far, but the run stopped or record sets were not compared) or 'blocked'
 * (no server could be compared).
 * @param {object} result {@link runParity}
 * @returns {{ verdict: 'ready'|'fix'|'check'|'partial'|'blocked', counts: Object<string, number>, ttl: number,
 *   unchecked: number, badServers: number, compared: number }}
 */
export function paritySummary(result) {
  const counts = { ...(result && result.counts) };
  const rows = (result && result.rows) || [];
  const servers = (result && result.nameservers) || [];
  const ttl = rows.filter((r) => r.reasons.includes('ttl-differs')).length;
  const unchecked = rows.filter((r) => r.status === 'skipped' && (r.reasons.includes('not-queryable') || r.reasons.includes('budget'))).length
    + rows.filter((r) => r.status === 'error').length;
  const badServers = servers.filter((s) => s.state !== 'ok' && s.state !== 'not-run').length;
  const compared = servers.filter((s) => s.role === 'full' && s.state === 'ok').length;
  let verdict;
  if (!compared) verdict = 'blocked';
  else if ((counts.missing || 0) + (counts.different || 0) > 0 || badServers) verdict = 'fix';
  else if ((counts.extra || 0) + (counts.unproxied || 0) > 0 || ttl || result.serials === 'differ') verdict = 'check';
  else if (result.stoppedBy || unchecked || result.capped || servers.some((s) => s.state === 'not-run')) verdict = 'partial';
  else verdict = 'ready';
  return { verdict, counts, ttl, unchecked, badServers, compared };
}

/**
 * The move, step by step, with the facts of this zone and this run: lower the TTLs (the apex NS
 * TTL and the longest record TTL of the file), fix and compare again, DNSSEC before the switch
 * (the DS at the registrar decides the order), switch the NS at the registrar, keep the old zone
 * answering for {@link PARITY_KEEP_OLD_HOURS} hours, then check from outside and restore the TTLs.
 * Each step: `{ id, state, params }` ({@link RUNBOOK_STEPS}, {@link RUNBOOK_STATES}); the view
 * words them (`par.step.<id>.<state>`).
 * @param {object} zone
 * @param {object|null} result {@link runParity} (null before a run)
 * @param {{ nameservers?: string[] }} [opts]
 * @returns {Array<{ id: string, state: string, params: object }>}
 */
export function parityRunbook(zone, result, { nameservers = [] } = {}) {
  const idx = zoneIndex(zone);
  const ttlOf = (r) => (Number.isFinite(r.ttl) && !r.ttlAuto ? r.ttl : null);
  const nsTtls = idx.unique.filter((r) => r.type === 'NS' && r.name === idx.origin).map(ttlOf).filter((v) => v !== null);
  const recTtls = idx.unique.filter((r) => r.type !== 'SOA' && !(r.type === 'NS' && r.name === idx.origin)).map(ttlOf).filter((v) => v !== null);
  const nsTtl = nsTtls.length ? Math.max(...nsTtls) : null;
  const maxTtl = recTtls.length ? Math.max(...recTtls) : null;
  const steps = [];
  steps.push({ id: 'ttl', state: (nsTtl ?? 0) > PARITY_TTL_LOW || (maxTtl ?? 0) > PARITY_TTL_LOW ? 'todo' : 'ok', params: { nsTtl, maxTtl, low: PARITY_TTL_LOW } });

  const sum = result ? paritySummary(result) : null;
  let fix;
  if (!sum) fix = { state: 'info', params: {} };
  else if (sum.verdict === 'blocked') fix = { state: 'blocked', params: { servers: sum.badServers } };
  else {
    const c = sum.counts;
    const params = { missing: c.missing || 0, different: c.different || 0, extra: c.extra || 0, unproxied: c.unproxied || 0, ttl: sum.ttl, unchecked: sum.unchecked, servers: sum.badServers };
    let state = 'ok';
    if (params.missing + params.different + params.servers > 0) state = 'todo';
    else if (params.extra + params.unproxied + params.unchecked > 0 || result.stoppedBy || result.capped || result.serials === 'differ') state = 'warn';
    fix = { state, params };
  }
  steps.push({ id: 'fix', ...fix });

  const signed = signedInFile(zone);
  const ds = result && result.dnssec ? result.dnssec.ds : null;
  let dnssec;
  if (signed || ds === 'present') dnssec = 'todo';
  else if (ds === 'absent') dnssec = 'ok';
  else dnssec = 'info';
  steps.push({ id: 'dnssec', state: dnssec, params: { signed, ds } });
  const list = (nameservers && nameservers.length ? nameservers : (result ? result.nameservers.map((s) => s.ns) : [])).join(', ');
  steps.push({ id: 'switch', state: sum && (sum.verdict === 'fix' || sum.verdict === 'blocked') ? 'blocked' : 'todo', params: { nameservers: list } });
  steps.push({ id: 'wait', state: 'todo', params: { hours: PARITY_KEEP_OLD_HOURS } });
  steps.push({ id: 'after', state: 'todo', params: {} });
  return steps;
}

/* ------------------------------------------------------------------------ */
/* The CLI hand-off                                                         */
/* ------------------------------------------------------------------------ */

/**
 * The zone's BIND file name for the CLI (`<zone>.parity.zone`), written by the view with
 * zoneparse.toBindText.
 * @param {string} origin
 * @returns {string}
 */
export function parityZoneFile(origin) {
  const o = canon(origin).replace(/[^a-z0-9_.-]/g, '_') || 'zone';
  return `${o}.parity.zone`;
}

/**
 * `python3 dns_parity.py <file> --ns <server> …` for the chosen shell, from validated tokens only
 * (a name server that is not a host name or an address is left out and counted, never quoted
 * into the command), each quoted for the shell (lib/cmdline.js quoteArg).
 * @param {{ file: string, nameservers: string[], shell?: 'posix'|'powershell', script?: string }} opts
 * @returns {{ command: string|null, dropped: number }}
 */
export function buildParityCommand({ file, nameservers = [], shell = 'posix', script = PARITY_CLI }) {
  const sh = shell === 'powershell' ? 'powershell' : 'posix';
  const ns = [];
  let dropped = 0;
  for (const n of nameservers || []) {
    const v = String(n ?? '');
    if (isProbeableHost(v) || (ipVersion(v) && normalizeIP(v))) ns.push(ipVersion(v) ? normalizeIP(v) : v);
    else dropped += 1;
  }
  if (!FILE_TOKEN.test(String(file ?? '')) || !FILE_TOKEN.test(String(script ?? '')) || !ns.length) return { command: null, dropped };
  const parts = [PYTHON[sh], quoteArg(script, sh), quoteArg(file, sh), '--ns', ...ns.map((n) => quoteArg(n, sh))];
  return { command: parts.join(' '), dropped };
}
