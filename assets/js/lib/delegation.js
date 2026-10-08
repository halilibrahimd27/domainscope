/**
 * delegation.js — is a zone's delegation sound? Every authoritative name server is asked
 * directly, through Globalping DNS measurements (`resolver` = that server's host name: the probe
 * runs `dig @<server>`), for the zone's SOA and NS, plus one unrelated name, and one server of
 * the parent zone is asked for the referral. DOM-free; the Globalping client (lib/globalping.js)
 * and the DohClient are injected. Runs in browsers and Node 22.
 *
 * What it finds (closed sets, worded by the UI):
 * - lame delegation: a server that refuses the zone, answers SERVFAIL, answers without the
 *   authoritative flag, has no SOA for it, times out or cannot be reached;
 * - SOA serial drift between servers that share a primary (SOA MNAME); servers of different
 *   primaries are a multi-provider setup, whose serials are not comparable (info);
 * - the NS set each server serves against the delegation the recursive resolvers return (DoH),
 *   and the parent's referral against that set;
 * - glue sanity for in-bailiwick name servers: the parent's glue against the addresses the zone
 *   itself serves (missing, stale, partial);
 * - open recursion: a server that answers an unrelated name ({@link RECURSION_PROBE_NAMES})
 *   from somewhere else than its own zones (RFC 5358);
 * - the "Sitting Ducks" risk: a lame server of a DNS provider where an account holder may create
 *   the zone without proving they own the domain ({@link SITTING_DUCKS_PROVIDERS}).
 *
 * Why AA alone proves nothing (shared providers answer with the authoritative flag from another
 * customer's zone of the same name): the SOA MNAME, the serial and the NS set are compared across
 * servers and with the delegation.
 *
 * How (verified live 2026-10-08 with one measurement): a parent server's referral comes back with
 * an empty `answers` array; its NS records are in the dig text's AUTHORITY section and the glue in
 * ADDITIONAL; the flags line carries `aa` / `ra` / `tc`, and the OPT section an `; NSID:` line.
 * One query per measurement, one probe, one credit: (2 + 1 for the recursion question) per name
 * server plus 1 for the parent — {@link planDelegationProbes}. A server whose SOA question times
 * out or fails is asked nothing more; a server that refuses the zone is still asked the unrelated
 * name (an open resolver often sits behind a lame delegation).
 *
 * What is sent: to Globalping, the zone's name, the name servers' and the parent server's host
 * names and the unrelated name (public by measurement id); to the DohClient, the NS of the zone
 * and of its parent and the A / AAAA of each name server. Never an address or an internal name.
 */

import { dnsQueryRequest, isProbeableDnsName, isProbeableHost, probeSummary } from './globalping.js';
import { normalizeIP, ipVersion } from './ip.js';
import { AbortError, abortReasonToError, errorKind } from './util.js';

/* ------------------------------------------------------------------------ */
/* Vocabularies and limits                                                  */
/* ------------------------------------------------------------------------ */

/** Name servers one run asks at most (NS sets have 2–8; the rest is listed, not asked). */
export const DELEGATION_MAX_NAMESERVERS = 8;
/** Name servers asked at once. */
export const DELEGATION_CONCURRENCY = 4;
/** Probes per name server: SOA and NS (the recursion question adds one). */
export const PROBES_PER_SERVER = 2;
/**
 * Unrelated names asked for the recursion test, the first one outside the zone is used: the
 * documentation domains (RFC 2606) exist and resolve, and say nothing about the zone checked.
 */
export const RECURSION_PROBE_NAMES = Object.freeze(['example.net', 'example.org']);
/** What the SOA question found about one server (`dlg.state.<state>`). */
export const SERVER_STATES = Object.freeze(['ok', 'refused', 'servfail', 'not-authoritative', 'no-zone', 'timeout', 'unreachable',
  'no-address', 'ipv6-only', 'not-probeable', 'failed', 'not-run']);
/** The states that make a delegation lame. */
export const LAME_STATES = Object.freeze(['refused', 'servfail', 'not-authoritative', 'no-zone', 'timeout', 'unreachable', 'no-address']);
/** The lame states where the provider answers but does not know the zone: someone else may create it there. */
export const TAKEOVER_STATES = Object.freeze(['refused', 'servfail', 'not-authoritative', 'no-zone']);
/** What the NS set of one server is, against the delegation (`dlg.nsState.<state>`). */
export const NS_SET_STATES = Object.freeze(['same', 'differs', 'unknown']);
/** The recursion test of one server (`dlg.rec.<state>`). */
export const RECURSION_STATES = Object.freeze(['closed', 'open', 'unknown', 'not-run']);
/** The parent's referral (`dlg.parent.<state>`). */
export const PARENT_STATES = Object.freeze(['ok', 'no-delegation', 'refused', 'servfail', 'timeout', 'unreachable', 'failed', 'not-run']);
/** The glue of one in-bailiwick name server (`dlg.glue.<state>`). */
export const GLUE_STATES = Object.freeze(['ok', 'missing', 'differs', 'partial', 'unknown']);
/** Findings, worst first within a run (`dlg.find.<code>.title` / `.detail`). */
export const DELEGATION_FINDINGS = Object.freeze(['lame', 'sitting-ducks', 'glue-missing', 'serial-drift', 'ns-mismatch', 'parent-child',
  'glue-differs', 'open-recursion', 'glue-partial', 'multi-provider', 'not-asked', 'consistent']);
/** Severity of each finding (the Health view's ok / info / warn / error). */
export const FINDING_SEVERITY = Object.freeze({
  lame: 'error', 'sitting-ducks': 'error', 'glue-missing': 'error', 'serial-drift': 'warn', 'ns-mismatch': 'warn', 'parent-child': 'warn',
  'glue-differs': 'warn', 'open-recursion': 'warn', 'glue-partial': 'info', 'multi-provider': 'info', 'not-asked': 'info', consistent: 'ok'
});
/** Why a run stopped before its plan was done. */
export const DELEGATION_STOPS = Object.freeze(['quota', 'unreachable', 'abort']);
/** Why nothing could be planned (`dlg.why.<why>`). */
export const PLAN_FAILURES = Object.freeze(['not-queryable', 'lookup-failed', 'no-ns', 'nothing-to-ask']);
/** How an account holder can take over a lame zone at a provider (`dlg.risk.<risk>`). */
export const TAKEOVER_RISKS = Object.freeze(['claimable', 'purchase', 'edge']);

/** Public write-ups of the Sitting Ducks attack (links the user opens; never fetched). */
export const SITTING_DUCKS_REFERENCES = Object.freeze([
  Object.freeze({ id: 'infoblox', url: 'https://blogs.infoblox.com/threat-intelligence/who-knew-domain-hijacking-is-so-easy/' }),
  Object.freeze({ id: 'eclypsium', url: 'https://eclypsium.com/blog/ducks-now-sitting-dns-internet-infrastructure-insecurity/' }),
  Object.freeze({ id: 'list', url: 'https://github.com/indianajson/can-i-take-over-dns' })
]);

/**
 * DNS providers where, by the public list ({@link SITTING_DUCKS_REFERENCES} `list`, statuses read
 * 2026-10-08, hand-curated: names and name-server patterns only), an account holder could create
 * a zone for a domain they do not own: `claimable` (any account), `purchase` (an account with a
 * paid plan) or `edge` (only when the provider hands out the same name servers again, which can
 * take many tries). `hosts` is the name-server pattern as shown. A provider can fix this at any time:
 * a match is a reason to check, not a verdict.
 */
export const SITTING_DUCKS_PROVIDERS = Object.freeze([
  { id: 'digitalocean', name: 'DigitalOcean', risk: 'claimable', hosts: 'ns1–ns3.digitalocean.com', pattern: /^ns[1-3]\.digitalocean\.com$/ },
  { id: 'dnsmadeeasy', name: 'DNS Made Easy', risk: 'claimable', hosts: 'ns<n>.dnsmadeeasy.com', pattern: /^ns\d+\.dnsmadeeasy\.com$/ },
  { id: 'he', name: 'Hurricane Electric', risk: 'claimable', hosts: 'ns1–ns5.he.net', pattern: /^ns[1-5]\.he\.net$/ },
  { id: 'linode', name: 'Linode', risk: 'claimable', hosts: 'ns1–ns5.linode.com', pattern: /^ns[1-5]\.linode\.com$/ },
  { id: 'regru', name: 'Reg.ru', risk: 'claimable', hosts: 'ns1–ns2.reg.ru', pattern: /^ns[12]\.reg\.ru$/ },
  { id: 'tierranet', name: 'TierraNet', risk: 'claimable', hosts: 'ns1–ns2.domaindiscover.com', pattern: /^ns[12]\.domaindiscover\.com$/ },
  { id: 'domaincom', name: 'Domain.com', risk: 'purchase', hosts: 'ns1–ns2.domain.com', pattern: /^ns[12]\.domain\.com$/ },
  { id: 'namecom', name: 'Name.com', risk: 'purchase', hosts: 'ns1…–ns4….name.com', pattern: /^ns[1-4][a-z0-9]*\.name\.com$/ },
  { id: 'yahoo', name: 'Yahoo Small Business', risk: 'purchase', hosts: 'yns1–yns2.yahoo.com', pattern: /^yns[12]\.yahoo\.com$/ },
  { id: 'azure', name: 'Azure DNS', risk: 'edge', hosts: 'ns1-<n>.azure-dns.com / .net / .org / .info', pattern: /^ns[1-4]-\d+\.azure-dns\.(?:com|net|org|info)$/ },
  { id: 'googlecloud', name: 'Google Cloud DNS', risk: 'edge', hosts: 'ns-cloud-<x><n>.googledomains.com', pattern: /^ns-cloud-[a-z]\d+\.googledomains\.com$/ },
  { id: 'dreamhost', name: 'DreamHost', risk: 'edge', hosts: 'ns1–ns3.dreamhost.com', pattern: /^ns[1-3]\.dreamhost\.com$/ }
].map((p) => Object.freeze(p)));

const RCODES = Object.freeze({ 0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED', 9: 'NOTAUTH' });
const QUOTA_CODES = new Set(['rate-limit', 'insufficient-credits']);
/** Refused before anything was created: nothing was spent. */
const FREE_CODES = new Set(['validation', 'private-target', 'bad-host', 'no-probes', 'unauthorized', 'rate-limit', 'insufficient-credits']);
const NETWORK_STOP_AFTER = 3;
const DIG_RR = /^(\S+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$/;
const OWNER_RE = /^[a-z0-9_*.-]{1,253}$/;

const canon = (v) => String(v ?? '').trim().toLowerCase().replace(/\.$/, '');
const sorted = (list) => [...new Set(list)].sort();
const inZone = (name, zone) => name === zone || name.endsWith(`.${zone}`);

/* ------------------------------------------------------------------------ */
/* One DNS test of a measurement                                            */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} DnsTest
 * @property {boolean} ok the server answered (any rcode)
 * @property {string|null} rcode
 * @property {boolean|null} aa the authoritative-answer flag (null: no flags line)
 * @property {boolean|null} ra recursion available
 * @property {boolean|null} tc truncated
 * @property {Array<{ name: string, type: string, ttl: number|null, value: string }>} answers
 * @property {Array<{ name: string, type: string, ttl: number|null, value: string }>} authority
 * @property {Array<{ name: string, type: string, ttl: number|null, value: string }>} additional
 * @property {string|null} nsid the server's NSID (RFC 5001) as text, when it sent one
 * @property {number|null} rttMs
 * @property {object|null} probe globalping.probeSummary
 * @property {'timeout'|'unreachable'|'failed'|null} failure why there is no answer
 * @property {string|null} error
 */

/**
 * The flags of the dig text (`;; flags: qr aa rd ra;`): each true / false, or null without a flags line.
 * @param {unknown} raw
 * @returns {{ aa: boolean|null, ra: boolean|null, tc: boolean|null }}
 */
export function digFlags(raw) {
  const m = /;; flags:([^;\n]*);/.exec(typeof raw === 'string' ? raw : '');
  if (!m) return { aa: null, ra: null, tc: null };
  const flags = m[1].trim().split(/\s+/);
  return { aa: flags.includes('aa'), ra: flags.includes('ra'), tc: flags.includes('tc') };
}

/**
 * The records of one section of the dig text (`;; AUTHORITY SECTION:`), names lowercased
 * without the trailing dot.
 * @param {unknown} raw
 * @param {'ANSWER'|'AUTHORITY'|'ADDITIONAL'} section
 * @returns {Array<{ name: string, type: string, ttl: number, value: string }>}
 */
export function digRecords(raw, section) {
  const lines = (typeof raw === 'string' ? raw : '').split('\n');
  const start = lines.findIndex((l) => l.trim() === `;; ${section} SECTION:`);
  if (start < 0) return [];
  const out = [];
  for (const line of lines.slice(start + 1)) {
    if (!line.trim() || line.startsWith(';')) break;
    const m = DIG_RR.exec(line.trim());
    if (m && m[3] === 'IN') {
      const rr = record(m[1], m[4], Number(m[2]), m[5]);
      if (rr) out.push(rr);
    }
  }
  return out;
}

/**
 * The NSID text of the dig OPT section (`; NSID: 6e 73 ("ns1-fra")`), printable characters only,
 * or null.
 * @param {unknown} raw
 * @returns {string|null}
 */
export function digNsid(raw) {
  const m = /^; NSID: [0-9a-f ]*\(\s*"([^"\n]*)"\s*\)/im.exec(typeof raw === 'string' ? raw : '');
  if (!m) return null;
  const text = m[1].replace(/[^\x20-\x7e]/g, '').trim().slice(0, 120);
  return text || null;
}

function record(name, type, ttl, value) {
  const owner = canon(name);
  const t = String(type ?? '').toUpperCase();
  const v = String(value ?? '').trim();
  if (!OWNER_RE.test(owner) || !/^[A-Z][A-Z0-9-]{0,15}$/.test(t) || /[\x00-\x1f\x7f]/.test(v) || v.length > 2000) return null;
  return { name: owner, type: t, ttl: Number.isInteger(ttl) && ttl >= 0 ? ttl : null, value: v };
}

function rcodeOf(test) {
  if (typeof test.statusCodeName === 'string' && /^[A-Z]{3,12}$/.test(test.statusCodeName)) return test.statusCodeName;
  return Number.isInteger(test.statusCode) ? (RCODES[test.statusCode] || `RCODE${test.statusCode}`) : null;
}

/** Why a test gave no DNS answer: 'unreachable' (the server's name or address), 'timeout' or 'failed'. */
function testFailure(raw) {
  if (/couldn't get address|not found|network unreachable|no route|connection refused/i.test(raw)) return 'unreachable';
  if (/timed out|no servers could be reached/i.test(raw)) return 'timeout';
  return 'failed';
}

/**
 * The first test of a finished Globalping DNS measurement, read: the rcode, the flags, the three
 * sections (the JSON `answers` carry the answer section only, so the authority and additional
 * records come from the dig text), the NSID, the round trip and the probe.
 * @param {object} measurement
 * @returns {DnsTest}
 */
export function readDnsTest(measurement) {
  const first = measurement && Array.isArray(measurement.results) ? measurement.results[0] : null;
  const test = first && first.result && typeof first.result === 'object' ? first.result : null;
  const raw = test && typeof test.rawOutput === 'string' ? test.rawOutput : '';
  const out = {
    ok: false, rcode: null, aa: null, ra: null, tc: null, answers: [], authority: [], additional: [], nsid: null,
    rttMs: test && test.timings && Number.isFinite(test.timings.total) ? test.timings.total : null,
    probe: first ? probeSummary(first.probe) : null, failure: null, error: null
  };
  const rcode = test ? rcodeOf(test) : null;
  if (!test || test.status !== 'finished' || !rcode) {
    const line = raw.trim().split('\n').find((l) => l && !l.startsWith(';')) || raw.trim().split('\n').pop() || 'no answer';
    return { ...out, failure: testFailure(raw), error: line.replace(/^;+\s*/, '').slice(0, 200) };
  }
  const answers = (Array.isArray(test.answers) ? test.answers : [])
    .map((a) => (a && typeof a === 'object' ? record(a.name, a.type, a.ttl, a.value) : null)).filter(Boolean);
  return {
    ...out, ok: true, rcode, ...digFlags(raw), answers, authority: digRecords(raw, 'AUTHORITY'), additional: digRecords(raw, 'ADDITIONAL'), nsid: digNsid(raw)
  };
}

/**
 * The MNAME and serial of an SOA value in presentation format, or null.
 * @param {string} value `ns1.example.net. hostmaster.example.com. 2026092401 7200 3600 1209600 3600`
 * @returns {{ mname: string, serial: number }|null}
 */
export function parseSoaValue(value) {
  const parts = String(value ?? '').trim().split(/\s+/);
  if (parts.length < 7 || !/^\d{1,10}$/.test(parts[2])) return null;
  const serial = Number(parts[2]);
  return serial <= 0xffffffff ? { mname: canon(parts[0]), serial } : null;
}

/**
 * What the SOA answer says about a server (a {@link SERVER_STATES} value).
 * @param {DnsTest} test
 * @param {string} zone
 * @returns {string}
 */
export function soaState(test, zone) {
  if (!test || !test.ok) return test && (test.failure === 'timeout' || test.failure === 'unreachable') ? test.failure : 'failed';
  if (test.rcode === 'REFUSED') return 'refused';
  if (test.rcode === 'SERVFAIL') return 'servfail';
  if (test.rcode === 'NOTAUTH') return 'not-authoritative';
  const soa = test.answers.find((rr) => rr.type === 'SOA' && rr.name === zone);
  if (test.rcode !== 'NOERROR' || !soa) return 'no-zone';
  return test.aa === false ? 'not-authoritative' : 'ok';
}

/**
 * The recursion test: a server that answers an unrelated name with records, without the
 * authoritative flag, resolved it from elsewhere — it is an open resolver (a {@link RECURSION_STATES} value).
 * @param {DnsTest} test
 * @param {string} name the unrelated name asked
 * @returns {'open'|'closed'|'unknown'}
 */
export function recursionState(test, name) {
  if (!test || !test.ok) return 'unknown';
  const q = canon(name);
  const answered = test.rcode === 'NOERROR' && test.answers.some((rr) => rr.name === q);
  return answered && test.aa !== true ? 'open' : 'closed';
}

/**
 * The provider of a name-server host that is known for the Sitting Ducks risk, or null.
 * @param {string} host
 * @returns {{ id: string, name: string, risk: string }|null}
 */
export function takeoverProvider(host) {
  const h = canon(host);
  const p = SITTING_DUCKS_PROVIDERS.find((x) => x.pattern.test(h));
  return p ? { id: p.id, name: p.name, risk: p.risk } : null;
}

/* ------------------------------------------------------------------------ */
/* The plan (free: DoH only)                                                */
/* ------------------------------------------------------------------------ */

/**
 * The probes a run costs at most: per name server asked, SOA + NS (+1 for the recursion
 * question), plus one for the parent's referral.
 * @param {{ servers: Array<{ skip: string|null }>, parent: object|null }} prep
 * @param {{ recursion?: boolean, parent?: boolean }} [opts]
 * @returns {number}
 */
export function planDelegationProbes(prep, { recursion = true, parent = true } = {}) {
  if (!prep || !Array.isArray(prep.servers)) return 0;
  const asked = prep.servers.filter((s) => !s.skip).length;
  return asked * (PROBES_PER_SERVER + (recursion ? 1 : 0)) + (parent && prep.parent && prep.parent.server ? 1 : 0);
}

const nsHostsOf = (resp, owner) => (resp && resp.ok && Array.isArray(resp.answers)
  ? sorted(resp.answers.filter((rr) => rr.type === 'NS' && canon(rr.name) === owner).map((rr) => canon(rr.data)).filter(Boolean))
  : []);

const addrList = (resp, type) => (resp && resp.ok && Array.isArray(resp.answers)
  ? sorted(resp.answers.filter((rr) => rr.type === type).map((rr) => normalizeIP(String(rr.data)) || String(rr.data)))
  : []);

/**
 * Prepare a run from what the recursive resolvers say (DoH, free): the zone's NS set (the
 * delegation), the addresses of each name server, the parent zone and the server of it to ask,
 * and the cost. A server is not asked when its host name cannot be a Globalping resolver
 * (`not-probeable`), has no address (`no-address`, a lame delegation in itself) or only IPv6
 * addresses (`ipv6-only`: a probe asks over IPv4). Never rejects except on an abort.
 * @param {string} zone
 * @param {{ dns: { query: Function }, signal?: AbortSignal, recursion?: boolean, parent?: boolean }} opts
 * @returns {Promise<{ ok: true, zone: string, delegation: string[], addresses: Object<string, { a: string[], aaaa: string[], known: boolean }>,
 *   servers: Array<{ ns: string, skip: string|null }>, extraServers: string[], parent: { zone: string, server: string|null, servers: string[] }|null,
 *   recursionName: string|null, probes: number }|{ ok: false, zone: string, why: string, error?: string|null }>}
 */
export async function prepareDelegation(zone, { dns, signal, recursion = true, parent = true } = {}) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('prepareDelegation: a DNS client is required');
  const z = canon(zone);
  if (!isProbeableDnsName(z)) return { ok: false, zone: z, why: 'not-queryable' };
  const nsResp = await dns.query(z, 'NS', { signal });
  if (!nsResp || !nsResp.ok) return { ok: false, zone: z, why: 'lookup-failed', error: (nsResp && nsResp.error) || null };
  const all = nsHostsOf(nsResp, z);
  if (!all.length) return { ok: false, zone: z, why: 'no-ns' };
  const delegation = all;
  const asked = delegation.slice(0, DELEGATION_MAX_NAMESERVERS);
  const addresses = {};
  await Promise.all(asked.map(async (host) => {
    const [a, aaaa] = await Promise.all([dns.query(host, 'A', { signal }), dns.query(host, 'AAAA', { signal })]);
    const known = !!(a && a.ok && (a.rcode === 'NOERROR' || a.rcode === 'NXDOMAIN') && aaaa && aaaa.ok && (aaaa.rcode === 'NOERROR' || aaaa.rcode === 'NXDOMAIN'));
    addresses[host] = { a: addrList(a, 'A'), aaaa: addrList(aaaa, 'AAAA'), known };
  }));
  if (signal && signal.aborted) throw abortReasonToError(signal.reason);
  const servers = asked.map((ns) => {
    const ad = addresses[ns];
    let skip = null;
    if (!isProbeableHost(ns)) skip = 'not-probeable';
    else if (ad.known && !ad.a.length && !ad.aaaa.length) skip = 'no-address';
    else if (ad.known && !ad.a.length) skip = 'ipv6-only';
    return { ns, skip };
  });
  let parentInfo = null;
  if (parent) parentInfo = await findParent(z, dns, signal);
  const recursionName = RECURSION_PROBE_NAMES.find((n) => !inZone(n, z) && !inZone(z, n)) || null;
  const prep = {
    ok: true, zone: z, delegation, addresses, servers, extraServers: delegation.slice(DELEGATION_MAX_NAMESERVERS), parent: parentInfo, recursionName, probes: 0
  };
  if (!servers.some((s) => !s.skip) && !(parentInfo && parentInfo.server)) return { ok: false, zone: z, why: 'nothing-to-ask' };
  prep.probes = planDelegationProbes(prep, { recursion: recursion && !!recursionName, parent });
  return prep;
}

/** The closest enclosing zone above `zone` with an NS set (DoH), and the server of it to ask: the first probeable one in order. */
async function findParent(zone, dns, signal) {
  const labels = zone.split('.');
  for (let i = 1; i < labels.length; i += 1) {
    const p = labels.slice(i).join('.');
    const resp = await dns.query(p, 'NS', { signal });
    if (!resp || !resp.ok) return { zone: p, server: null, servers: [] };
    const hosts = nsHostsOf(resp, p);
    if (hosts.length) return { zone: p, server: hosts.find((h) => isProbeableHost(h)) || null, servers: hosts };
  }
  return null;
}

/* ------------------------------------------------------------------------ */
/* The run (Globalping)                                                     */
/* ------------------------------------------------------------------------ */

/**
 * @typedef {object} ServerResult
 * @property {string} ns
 * @property {boolean} inBailiwick the host is in the zone (its address needs glue at the parent)
 * @property {{ a: string[], aaaa: string[], known: boolean }} addresses what the resolvers return for the host
 * @property {string} state one of {@link SERVER_STATES}
 * @property {string|null} rcode of the SOA question
 * @property {boolean|null} aa
 * @property {number|null} serial
 * @property {string|null} mname the SOA MNAME (the primary)
 * @property {string[]|null} nsSet the NS set the server serves (null: not asked or no answer)
 * @property {string} nsState one of {@link NS_SET_STATES}
 * @property {string[]} missing delegation names the server's set lacks
 * @property {string[]} extra names only the server's set has
 * @property {string} recursion one of {@link RECURSION_STATES}
 * @property {boolean|null} ra the recursion-available flag of the recursion answer
 * @property {string|null} nsid
 * @property {number|null} rttMs of the SOA question
 * @property {object|null} probe of the SOA question
 * @property {string[]} measurementIds
 * @property {{ id: string, name: string, risk: string }|null} provider a Sitting Ducks provider
 * @property {boolean} incomplete a question after the SOA was never sent (the budget or a stop)
 */

function safeCall(fn, arg) {
  if (typeof fn !== 'function') return;
  try {
    fn(arg);
  } catch {
    /* observer errors never break the run */
  }
}

/**
 * Ask every name server of a {@link prepareDelegation} plan, and the parent's server once.
 * Resolves (never rejects on DNS or Globalping failures, nor on a stop): `stoppedBy` says why a
 * run ended early ('quota' with `resetAt`, 'unreachable' after three network failures in a row,
 * 'abort' — the caller's signal); the answers so far are kept and the rest is `not-run`. No more
 * than `maxProbes` measurements are created (the budget is reserved before each POST).
 * @param {object} prep a successful {@link prepareDelegation} result
 * @param {{ client: { measure: Function }, signal?: AbortSignal, recursion?: boolean, parent?: boolean, maxProbes?: number,
 *   onProgress?: (p: { done: number, total: number, spent: number }) => void, onQuota?: (q: object) => void,
 *   onServer?: (s: ServerResult) => void, now?: () => Date }} opts
 * @returns {Promise<{ zone: string, startedAt: Date, finishedAt: Date, delegation: string[], extraServers: string[],
 *   parent: object|null, servers: ServerResult[], glue: object[], findings: object[], recursionName: string|null,
 *   spent: number, planned: number, stoppedBy: string|null, resetAt: Date|null, measurementIds: string[] }>}
 * @throws {TypeError} without a client or a successful plan
 */
export async function runDelegation(prep, opts = {}) {
  const {
    client, signal, recursion = true, parent = true, maxProbes = Infinity, onProgress, onQuota, onServer, now = () => new Date()
  } = opts || {};
  if (!client || typeof client.measure !== 'function') throw new TypeError('runDelegation: a Globalping client is required');
  if (!prep || prep.ok !== true) throw new TypeError('runDelegation: a prepared plan is required');
  const zone = prep.zone;
  const recursionName = recursion ? prep.recursionName : null;
  const planned = Math.min(planDelegationProbes(prep, { recursion: !!recursionName, parent }), maxProbes);
  const startedAt = now();
  let stoppedBy = null;
  let resetAt = null;
  let reserved = 0;
  let spent = 0;
  let done = 0;
  let networkFailures = 0;
  const ids = [];
  const stop = (reason, err) => {
    if (!stoppedBy) stoppedBy = reason;
    if (reason === 'quota' && err && err.resetAt instanceof Date) resetAt = err.resetAt;
  };

  /** One measurement: a DnsTest, or null when it was not sent (budget, stop, an unaskable body). */
  async function ask(name, type, resolver) {
    if (signal && signal.aborted) throw abortReasonToError(signal.reason);
    if (stoppedBy) return null;
    let body;
    try {
      body = dnsQueryRequest({ name, type, resolver });
    } catch {
      return null;
    }
    if (reserved >= planned) return null;
    reserved += 1;
    try {
      const { measurement, id, cost, quota } = await client.measure(body, { signal });
      networkFailures = 0;
      spent += Number.isFinite(cost) ? cost : 1;
      done += 1;
      if (id) ids.push(id);
      if (quota) safeCall(onQuota, quota);
      safeCall(onProgress, { done, total: planned, spent });
      return { ...readDnsTest(measurement), measurementId: id || null };
    } catch (err) {
      if (errorKind(err) === 'abort' || (signal && signal.aborted)) throw err instanceof AbortError ? err : new AbortError('delegation check cancelled');
      const code = err && typeof err === 'object' ? err.code : null;
      const paid = !!(err && err.measurementId);
      if (!paid && FREE_CODES.has(code)) reserved = Math.max(0, reserved - 1);
      spent += paid ? (Number(err.cost) || 1) : 0;
      done += 1;
      if (err && err.measurementId) ids.push(err.measurementId);
      if (err && err.quota) safeCall(onQuota, err.quota);
      safeCall(onProgress, { done, total: planned, spent });
      if (QUOTA_CODES.has(code)) {
        stop('quota', err);
        return null;
      }
      if (err instanceof TypeError || (err && err.name === 'TimeoutError')) {
        networkFailures += 1;
        if (networkFailures >= NETWORK_STOP_AFTER) stop('unreachable', err);
      }
      return { ok: false, failure: 'failed', error: String((err && err.message) || err).slice(0, 200), measurementId: (err && err.measurementId) || null };
    }
  }

  const servers = prep.servers.map(({ ns, skip }) => ({
    ns, inBailiwick: inZone(ns, zone), addresses: prep.addresses[ns] || { a: [], aaaa: [], known: false },
    state: skip || 'not-run', rcode: null, aa: null, serial: null, mname: null, nsSet: null, nsState: 'unknown', missing: [], extra: [],
    recursion: 'not-run', ra: null, nsid: null, rttMs: null, probe: null, measurementIds: [], provider: takeoverProvider(ns), incomplete: false
  }));

  async function checkServer(s) {
    if (s.state !== 'not-run') return;
    const soa = await ask(zone, 'SOA', s.ns);
    if (!soa) return;
    if (soa.measurementId) s.measurementIds.push(soa.measurementId);
    s.state = soaState(soa, zone);
    Object.assign(s, { rcode: soa.rcode || null, aa: soa.aa ?? null, nsid: soa.nsid || null, rttMs: soa.rttMs ?? null, probe: soa.probe || null });
    const soaRr = (soa.answers || []).find((rr) => rr.type === 'SOA' && rr.name === zone);
    const parsed = soaRr ? parseSoaValue(soaRr.value) : null;
    if (parsed) Object.assign(s, parsed);
    if (s.state === 'timeout' || s.state === 'unreachable' || s.state === 'failed') return;
    const jobs = [];
    if (s.state === 'ok' || s.state === 'not-authoritative') {
      jobs.push(ask(zone, 'NS', s.ns).then((resp) => {
        if (!resp) {
          s.incomplete = true;
          return;
        }
        if (resp.measurementId) s.measurementIds.push(resp.measurementId);
        if (resp.ok && resp.rcode === 'NOERROR') {
          const set = sorted(resp.answers.filter((rr) => rr.type === 'NS' && rr.name === zone).map((rr) => canon(rr.value)));
          if (set.length) s.nsSet = set;
        }
      }));
    }
    if (recursionName) {
      jobs.push(ask(recursionName, 'A', s.ns).then((resp) => {
        if (!resp) {
          s.incomplete = true;
          return;
        }
        if (resp.measurementId) s.measurementIds.push(resp.measurementId);
        s.recursion = recursionState(resp, recursionName);
        s.ra = resp.ok ? resp.ra ?? null : null;
      }));
    }
    await Promise.all(jobs);
  }

  let parentResult = null;
  if (parent && prep.parent) {
    parentResult = { zone: prep.parent.zone, server: prep.parent.server, state: 'not-run', ns: [], glue: {}, truncated: false, measurementId: null, probe: null };
  }

  try {
    const queue = servers.slice();
    const worker = async () => {
      while (queue.length) {
        const s = queue.shift();
        await checkServer(s);
        safeCall(onServer, { ...s });
      }
    };
    const parentJob = async () => {
      if (!parentResult || !parentResult.server) return;
      const resp = await ask(zone, 'NS', parentResult.server);
      if (!resp) return;
      Object.assign(parentResult, readReferral(resp, zone));
    };
    await Promise.all([parentJob(), ...Array.from({ length: Math.min(DELEGATION_CONCURRENCY, servers.length) }, worker)]);
  } catch (err) {
    if (errorKind(err) !== 'abort' && !(signal && signal.aborted)) throw err;
    stoppedBy = stoppedBy || 'abort';
  }
  if (!stoppedBy && signal && signal.aborted) stoppedBy = 'abort';

  for (const s of servers) {
    if (!s.nsSet) continue;
    s.missing = prep.delegation.filter((n) => !s.nsSet.includes(n));
    s.extra = s.nsSet.filter((n) => !prep.delegation.includes(n));
    s.nsState = s.missing.length || s.extra.length ? 'differs' : 'same';
  }
  const assessed = assessDelegation({ zone, delegation: prep.delegation, extraServers: prep.extraServers || [], servers, parent: parentResult, addresses: prep.addresses });
  return {
    zone, startedAt, finishedAt: now(), delegation: prep.delegation, extraServers: prep.extraServers || [], parent: parentResult, servers,
    glue: assessed.glue, findings: assessed.findings, recursionName, spent, planned, stoppedBy, resetAt, measurementIds: ids
  };
}

/**
 * The parent server's answer to `<zone> NS`: the NS set it delegates to (a referral's AUTHORITY
 * section, or the answer when the parent serves the zone too), the glue of the ADDITIONAL
 * section by host, and whether the answer was truncated (the glue may then be incomplete).
 * @param {DnsTest} resp
 * @param {string} zone
 * @returns {{ state: string, ns: string[], glue: Object<string, { a: string[], aaaa: string[] }>, truncated: boolean,
 *   measurementId: string|null, probe: object|null }}
 */
export function readReferral(resp, zone) {
  const base = { state: 'failed', ns: [], glue: {}, truncated: false, measurementId: (resp && resp.measurementId) || null, probe: (resp && resp.probe) || null };
  if (!resp || !resp.ok) {
    return { ...base, state: resp && (resp.failure === 'timeout' || resp.failure === 'unreachable') ? resp.failure : 'failed' };
  }
  if (resp.rcode === 'REFUSED') return { ...base, state: 'refused' };
  if (resp.rcode === 'SERVFAIL') return { ...base, state: 'servfail' };
  const nsOf = (list) => sorted(list.filter((rr) => rr.type === 'NS' && rr.name === zone).map((rr) => canon(rr.value)));
  const ns = nsOf(resp.answers).length ? nsOf(resp.answers) : nsOf(resp.authority);
  if (resp.rcode !== 'NOERROR' || !ns.length) return { ...base, state: 'no-delegation' };
  const glue = {};
  for (const rr of resp.additional) {
    if (rr.type !== 'A' && rr.type !== 'AAAA') continue;
    const ip = normalizeIP(rr.value);
    if (!ip || ipVersion(ip) !== (rr.type === 'A' ? 4 : 6)) continue;
    const g = glue[rr.name] || (glue[rr.name] = { a: [], aaaa: [] });
    const list = rr.type === 'A' ? g.a : g.aaaa;
    if (!list.includes(ip)) list.push(ip);
  }
  for (const g of Object.values(glue)) {
    g.a.sort();
    g.aaaa.sort();
  }
  return { ...base, state: 'ok', ns, glue, truncated: resp.tc === true };
}

/* ------------------------------------------------------------------------ */
/* Findings                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * The glue of one in-bailiwick name server: what the parent hands out against what the zone
 * serves for the host (a {@link GLUE_STATES} value).
 * @param {{ a: string[], aaaa: string[] }|null} glue the parent's
 * @param {{ a: string[], aaaa: string[], known: boolean }|null} child the resolvers'
 * @param {{ parentOk: boolean, truncated?: boolean }} ctx
 * @returns {string}
 */
export function glueState(glue, child, { parentOk, truncated = false }) {
  if (!parentOk) return 'unknown';
  const g = [...((glue && glue.a) || []), ...((glue && glue.aaaa) || [])];
  if (!g.length) return truncated ? 'unknown' : 'missing';
  if (!child || !child.known) return 'unknown';
  const c = [...child.a, ...child.aaaa];
  if (g.some((ip) => !c.includes(ip))) return 'differs';
  if (c.some((ip) => !g.includes(ip))) return truncated ? 'unknown' : 'partial';
  return 'ok';
}

/**
 * Glue rows and findings of a run (pure: what {@link runDelegation} returns them from).
 * @param {{ zone: string, delegation: string[], extraServers?: string[], servers: ServerResult[], parent: object|null,
 *   addresses: Object<string, { a: string[], aaaa: string[], known: boolean }> }} input
 * @returns {{ glue: Array<{ host: string, state: string, glue: { a: string[], aaaa: string[] }, child: { a: string[], aaaa: string[] } }>,
 *   findings: Array<{ code: string, severity: string, servers: string[], params: object }> }}
 */
export function assessDelegation({ zone, delegation, extraServers = [], servers, parent, addresses }) {
  const findings = [];
  const add = (code, list = [], params = {}) => findings.push({ code, severity: FINDING_SEVERITY[code], servers: list, params });
  const answered = servers.filter((s) => s.state !== 'not-run');

  const lame = servers.filter((s) => LAME_STATES.includes(s.state));
  if (lame.length) add('lame', lame.map((s) => s.ns), { count: lame.length, total: servers.length });
  const ducks = servers.filter((s) => s.provider && TAKEOVER_STATES.includes(s.state));
  if (ducks.length) {
    const providers = sorted(ducks.map((s) => s.provider.name));
    const edgeOnly = ducks.every((s) => s.provider.risk === 'edge');
    findings.push({ code: 'sitting-ducks', severity: edgeOnly ? 'warn' : 'error', servers: ducks.map((s) => s.ns), params: { providers: providers.join(', '), count: ducks.length } });
  }

  // Glue: every in-bailiwick host of the parent's NS set (else of the delegation).
  const parentOk = !!(parent && parent.state === 'ok');
  const hosts = parentOk ? parent.ns : delegation;
  const glue = hosts.filter((h) => inZone(h, zone)).map((host) => {
    const g = parentOk ? (parent.glue[host] || { a: [], aaaa: [] }) : { a: [], aaaa: [] };
    const child = addresses[host] || null;
    return { host, state: glueState(g, child, { parentOk, truncated: parentOk && parent.truncated }), glue: g, child: child ? { a: child.a, aaaa: child.aaaa } : { a: [], aaaa: [] } };
  });
  const byGlue = (st) => glue.filter((r) => r.state === st).map((r) => r.host);
  if (byGlue('missing').length) add('glue-missing', byGlue('missing'), { count: byGlue('missing').length });

  // Serials: compared among the servers of one primary (MNAME).
  const ok = servers.filter((s) => s.state === 'ok' && Number.isFinite(s.serial));
  const byPrimary = new Map();
  for (const s of ok) {
    const key = s.mname || '';
    if (!byPrimary.has(key)) byPrimary.set(key, []);
    byPrimary.get(key).push(s);
  }
  const drift = [...byPrimary.values()].filter((list) => new Set(list.map((s) => s.serial)).size > 1).flat();
  if (drift.length) {
    const serials = sorted(drift.map((s) => s.serial)).sort((a, b) => a - b);
    add('serial-drift', drift.map((s) => s.ns), { serials: serials.join(', '), count: drift.length });
  }

  const differs = servers.filter((s) => s.nsState === 'differs');
  if (differs.length) add('ns-mismatch', differs.map((s) => s.ns), { count: differs.length });
  if (parentOk) {
    const onlyParent = parent.ns.filter((n) => !delegation.includes(n) && !extraServers.includes(n));
    const onlyChild = delegation.filter((n) => !parent.ns.includes(n));
    if (onlyParent.length || onlyChild.length) {
      add('parent-child', [], { parentOnly: onlyParent.join(', ') || '—', childOnly: onlyChild.join(', ') || '—', parent: parent.zone });
    }
  }
  if (byGlue('differs').length) add('glue-differs', byGlue('differs'), { count: byGlue('differs').length });
  const open = servers.filter((s) => s.recursion === 'open');
  if (open.length) add('open-recursion', open.map((s) => s.ns), { count: open.length });
  if (byGlue('partial').length) add('glue-partial', byGlue('partial'), { count: byGlue('partial').length });
  if (byPrimary.size > 1) add('multi-provider', ok.map((s) => s.ns), { count: byPrimary.size, primaries: sorted([...byPrimary.keys()].filter(Boolean)).join(', ') });
  const notAsked = [...servers.filter((s) => ['ipv6-only', 'not-probeable', 'not-run', 'failed'].includes(s.state) || s.incomplete).map((s) => s.ns), ...extraServers];
  if (notAsked.length) add('not-asked', notAsked, { count: notAsked.length });
  const problems = findings.some((f) => f.severity === 'error' || f.severity === 'warn');
  const complete = servers.every((s) => !s.incomplete);
  if (!problems && answered.length && complete && ok.length === servers.length) add('consistent', ok.map((s) => s.ns), { count: ok.length });
  const order = (f) => DELEGATION_FINDINGS.indexOf(f.code);
  findings.sort((a, b) => order(a) - order(b));
  return { glue, findings };
}

/**
 * The verdict of a run: 'error' / 'warn' when a finding has that severity, 'ok' when every
 * server answered consistently, 'partial' when the run stopped or servers were not asked.
 * @param {{ findings: Array<{ severity: string, code: string }>, stoppedBy: string|null }} result
 * @returns {{ verdict: 'ok'|'warn'|'error'|'partial', errors: number, warnings: number }}
 */
export function delegationSummary(result) {
  const findings = (result && result.findings) || [];
  const errors = findings.filter((f) => f.severity === 'error').length;
  const warnings = findings.filter((f) => f.severity === 'warn').length;
  let verdict = 'partial';
  if (errors) verdict = 'error';
  else if (warnings) verdict = 'warn';
  else if (!result.stoppedBy && findings.some((f) => f.code === 'consistent')) verdict = 'ok';
  return { verdict, errors, warnings };
}
