/**
 * soaprobe.js — one authoritative SOA question for Global DNS's worst-case ETA (ROADMAP P0.6, the
 * part wave 6 left for Global DNS). The recursive resolvers say what they cache; this asks the
 * source:
 *
 * 1. {@link findZone} (DoH, free): the zone the name belongs to — the SOA of the name itself, else
 *    the SOA in the authority section of its answer, climbing one label at a time past a CNAME
 *    (a resolver follows an alias into the target's zone) — and the zone's NS set.
 * 2. {@link pickNameserver}: the name server to ask — the SOA's primary (MNAME) when it is one of
 *    them, else the first by name; a host Globalping cannot ask is skipped.
 * 3. One Globalping DNS measurement ({@link planSoaProbe}: one probe, one credit) asks that server
 *    for the SOA of the name itself, through `dig @<server>` on the probe.
 * 4. {@link readSoaProbe}: from the source — whether the name exists there (NOERROR / NXDOMAIN) or
 *    is an alias, whether the server answered with authority, the zone's serial and primary, and
 *    its negative-cache time min(SOA TTL, SOA minimum) (RFC 2308 §5): how long a resolver that
 *    asked before a name existed may go on saying it does not.
 *
 * What is sent: to the DohClient, the SOA and NS questions of the name and its parents; to
 * Globalping (public by measurement id), the name and the name server's host name. Never an
 * internal name (lib/ispdns.js isInternalName), an IP literal or a public suffix's zone.
 *
 * DOM-free; the DohClient and the Globalping client are injected. Runs in browsers and Node 22.
 */

import { dnsQueryRequest, isProbeableDnsName, isProbeableHost } from './globalping.js';
import { readDnsTest } from './delegation.js';
import { isPublicSuffix } from './domain.js';
import { isInternalName } from './ispdns.js';
import { ipVersion } from './ip.js';
import { abortReasonToError } from './util.js';

/** The consent purpose of the probe (ui/globalping-gate.js): its own privacy text. */
export const SOA_PROBE_PURPOSE = 'soa-probe';
/** Probes one SOA question costs. */
export const SOA_PROBE_COST = 1;
/** Labels the zone search climbs at most. */
export const SOA_ZONE_MAX_STEPS = 12;
/**
 * Why nothing is sent: a name Globalping cannot ask (`name`), an internal name (`internal`), the
 * resolvers could not be asked (`lookup`), no zone of its own (`no-zone`: only a public suffix's
 * SOA answers for it), no name server (`no-ns`), none Globalping can ask (`not-probeable`).
 */
export const SOA_PLAN_ERRORS = Object.freeze(['name', 'internal', 'lookup', 'no-zone', 'no-ns', 'not-probeable']);
/**
 * What the name server's answer is: `ok` (an authoritative answer), `not-authoritative` (an answer
 * without the authoritative flag, or NOTAUTH: a lame server), `refused`, `servfail`, `timeout`,
 * `unreachable`, `failed`.
 */
export const SOA_PROBE_STATES = Object.freeze(['ok', 'not-authoritative', 'refused', 'servfail', 'timeout', 'unreachable', 'failed']);

const canon = (v) => String(v ?? '').trim().toLowerCase().replace(/\.$/, '');
const isTtl = (v) => typeof v === 'number' && Number.isInteger(v) && v >= 0;

/**
 * The fields of an SOA value in presentation format, or null.
 * @param {string} value `ns1.example.net. hostmaster.example.com. 2026100801 7200 3600 1209600 300`
 * @returns {{ mname: string, rname: string, serial: number, refresh: number, retry: number, expire: number, minimum: number }|null}
 */
export function parseSoaRecord(value) {
  const parts = String(value ?? '').trim().split(/\s+/);
  if (parts.length < 7 || !parts.slice(2, 7).every((p) => /^\d{1,10}$/.test(p))) return null;
  const [serial, refresh, retry, expire, minimum] = parts.slice(2, 7).map(Number);
  if ([serial, refresh, retry, expire, minimum].some((n) => n > 0xffffffff)) return null;
  return { mname: canon(parts[0]), rname: canon(parts[1]), serial, refresh, retry, expire, minimum };
}

/** The fields of a DohClient SOA record (`data` is an object), or of a presentation text. */
function soaFields(rr) {
  if (!rr) return null;
  if (rr.data && typeof rr.data === 'object') {
    const d = rr.data;
    const nums = ['serial', 'refresh', 'retry', 'expire', 'minimum'].map((k) => Number(d[k]));
    if (nums.some((n) => !Number.isInteger(n) || n < 0)) return null;
    const [serial, refresh, retry, expire, minimum] = nums;
    return { mname: canon(d.mname), rname: canon(d.rname), serial, refresh, retry, expire, minimum };
  }
  return parseSoaRecord(rr.data ?? rr.value ?? rr.text);
}

/**
 * The zone `name` belongs to, from the recursive resolvers (`dns`, a DohClient): the SOA of the
 * name itself, else the authority section's SOA of its answer, else the same one label up — a
 * CNAME at the name sends a resolver into the target's zone, so an aliased name is skipped. Then
 * the zone's NS set. A public suffix (com, co.uk) is no zone of the name's own.
 * @param {string} name
 * @param {{ dns: { query: Function }, signal?: AbortSignal }} opts
 * @returns {Promise<{ ok: true, zone: string, soa: object|null, nameservers: string[] }
 *   |{ ok: false, error: 'lookup'|'no-zone'|'no-ns', zone?: string, detail?: string|null }>}
 */
export async function findZone(name, { dns, signal } = {}) {
  if (!dns || typeof dns.query !== 'function') throw new TypeError('findZone: a DNS client is required');
  let x = canon(name);
  let zone = null;
  let soa = null;
  for (let i = 0; i < SOA_ZONE_MAX_STEPS && x.includes('.') && !zone; i += 1) {
    const resp = await dns.query(x, 'SOA', { signal });
    if (signal && signal.aborted) throw abortReasonToError(signal.reason);
    if (!resp || !resp.ok || (resp.rcode !== 'NOERROR' && resp.rcode !== 'NXDOMAIN')) {
      return { ok: false, error: 'lookup', detail: (resp && (resp.error || resp.rcode)) || null };
    }
    const answers = Array.isArray(resp.answers) ? resp.answers : [];
    const own = answers.find((rr) => rr && rr.type === 'SOA' && canon(rr.name) === x);
    if (own) {
      zone = x;
      soa = { ...soaFields(own), ttl: isTtl(own.ttl) ? own.ttl : null };
      break;
    }
    const aliased = answers.some((rr) => rr && rr.type === 'CNAME' && canon(rr.name) === x);
    if (!aliased) {
      const auth = (Array.isArray(resp.authorities) ? resp.authorities : [])
        .find((rr) => rr && rr.type === 'SOA' && (x === canon(rr.name) || x.endsWith(`.${canon(rr.name)}`)));
      if (auth) {
        zone = canon(auth.name);
        soa = { ...soaFields(auth), ttl: isTtl(auth.ttl) ? auth.ttl : null };
        break;
      }
    }
    x = x.slice(x.indexOf('.') + 1);
  }
  if (!zone || !zone.includes('.') || isPublicSuffix(zone, { includePrivate: false })) return { ok: false, error: 'no-zone', zone: zone || undefined };
  const ns = await dns.query(zone, 'NS', { signal });
  if (signal && signal.aborted) throw abortReasonToError(signal.reason);
  if (!ns || !ns.ok) return { ok: false, error: 'lookup', zone, detail: (ns && ns.error) || null };
  const nameservers = [...new Set((Array.isArray(ns.answers) ? ns.answers : [])
    .filter((rr) => rr && rr.type === 'NS' && canon(rr.name) === zone).map((rr) => canon(rr.data)).filter(Boolean))].sort();
  if (!nameservers.length) return { ok: false, error: 'no-ns', zone };
  return { ok: true, zone, soa: soa && soa.mname !== undefined ? soa : null, nameservers };
}

/**
 * The name server to ask: the zone's primary (the SOA MNAME) when it is in the NS set, else the
 * first of the set by name; only a host Globalping can ask (an IP literal or a bad name is skipped).
 * @param {string[]} nameservers
 * @param {string|null} [mname]
 * @returns {string|null}
 */
export function pickNameserver(nameservers, mname = null) {
  const list = (Array.isArray(nameservers) ? nameservers : []).map(canon).filter((h) => h && isProbeableHost(h));
  const primary = canon(mname);
  if (primary && list.includes(primary)) return primary;
  return [...list].sort()[0] || null;
}

/**
 * Plan the probe: the name as Globalping takes it, refused when it is internal; its zone and name
 * servers over DoH; the server to ask; the measurement body (one probe). Nothing is sent to
 * Globalping here.
 * @param {string} name
 * @param {{ dns: { query: Function }, signal?: AbortSignal }} opts
 * @returns {Promise<{ ok: true, name: string, zone: string, ns: string, nameservers: string[], soa: object|null, body: object, probes: number }
 *   |{ ok: false, error: string, zone?: string, detail?: string|null }>}
 */
export async function planSoaProbe(name, { dns, signal } = {}) {
  const qname = canon(name);
  if (!isProbeableDnsName(qname) || ipVersion(qname)) return { ok: false, error: 'name' };
  if (isInternalName(qname)) return { ok: false, error: 'internal' };
  const found = await findZone(qname, { dns, signal });
  if (!found.ok) return found;
  if (isInternalName(found.zone)) return { ok: false, error: 'internal' };
  const ns = pickNameserver(found.nameservers, found.soa && found.soa.mname);
  if (!ns) return { ok: false, error: 'not-probeable', zone: found.zone };
  const body = dnsQueryRequest({ name: qname, type: 'SOA', resolver: ns });
  return { ok: true, name: qname, zone: found.zone, ns, nameservers: found.nameservers, soa: found.soa, body, probes: SOA_PROBE_COST };
}

/**
 * @typedef {object} SoaProbe
 * @property {string} name
 * @property {string} zone
 * @property {string} ns the name server asked
 * @property {string} state one of {@link SOA_PROBE_STATES}
 * @property {string|null} rcode
 * @property {boolean|null} aa the authoritative-answer flag
 * @property {boolean|null} exists NOERROR → true, NXDOMAIN → false (null: no usable answer)
 * @property {string|null} alias the CNAME target at the name, when it is an alias there
 * @property {{ mname: string, rname: string, serial: number, refresh: number, retry: number, expire: number, minimum: number, ttl: number|null }|null} soa
 * @property {number|null} negativeTtl min(SOA TTL, SOA minimum)
 * @property {object|null} probe lib/globalping.js probeSummary
 * @property {string|null} nsid
 * @property {number|null} rttMs
 * @property {string|null} error dig's line when there was no answer
 * @property {string|null} measurementId
 */

/**
 * The name server's answer to the SOA question of a name, read from a finished measurement.
 * @param {object} measurement a Globalping DNS measurement (one probe)
 * @param {{ name: string, zone: string, ns: string, id?: string|null }} plan
 * @returns {SoaProbe}
 */
export function readSoaProbe(measurement, { name, zone, ns, id = null }) {
  const test = readDnsTest(measurement);
  const qname = canon(name);
  const z = canon(zone);
  const base = {
    name: qname, zone: z, ns: canon(ns), state: 'failed', rcode: test.rcode, aa: test.aa ?? null, exists: null, alias: null, soa: null,
    negativeTtl: null, probe: test.probe || null, nsid: test.nsid || null, rttMs: test.rttMs ?? null, error: test.error || null,
    measurementId: id || (measurement && typeof measurement.id === 'string' ? measurement.id : null)
  };
  if (!test.ok) return { ...base, state: test.failure === 'timeout' || test.failure === 'unreachable' ? test.failure : 'failed' };
  if (test.rcode === 'REFUSED') return { ...base, state: 'refused' };
  if (test.rcode === 'SERVFAIL') return { ...base, state: 'servfail' };
  if (test.rcode === 'NOTAUTH') return { ...base, state: 'not-authoritative' };
  if (test.rcode !== 'NOERROR' && test.rcode !== 'NXDOMAIN') return { ...base, state: 'failed', error: test.rcode };
  const inZone = (owner) => owner === z || qname === owner || qname.endsWith(`.${owner}`);
  const soaRr = [...test.answers, ...test.authority].find((rr) => rr.type === 'SOA' && inZone(rr.name)) || null;
  const fields = soaRr ? parseSoaRecord(soaRr.value) : null;
  const soa = fields ? { ...fields, ttl: soaRr.ttl } : null;
  const cname = test.answers.find((rr) => rr.type === 'CNAME' && rr.name === qname);
  const negativeTtl = soa && isTtl(soa.ttl) ? Math.min(soa.ttl, soa.minimum) : (soa ? soa.minimum : null);
  return {
    ...base,
    state: test.aa === false ? 'not-authoritative' : 'ok',
    exists: test.rcode === 'NOERROR',
    alias: cname ? canon(cname.value) : null,
    soa,
    negativeTtl
  };
}

/**
 * Send a planned probe through `client` (lib/globalping.js createGlobalping, after the consent
 * gate) and read its answer. Globalping errors are thrown as they come (the caller words them;
 * one after the measurement was created carries its id and cost).
 * @param {{ name: string, zone: string, ns: string, body: object }} plan a successful {@link planSoaProbe}
 * @param {{ client: { measure: Function }, signal?: AbortSignal, onUpdate?: Function }} opts
 * @returns {Promise<{ result: SoaProbe, id: string|null, cost: number, quota: object|null }>}
 */
export async function runSoaProbe(plan, { client, signal, onUpdate } = {}) {
  if (!client || typeof client.measure !== 'function') throw new TypeError('runSoaProbe: a Globalping client is required');
  if (!plan || !plan.body) throw new TypeError('runSoaProbe: a planned probe is required');
  const { measurement, id, cost, quota } = await client.measure(plan.body, { signal, onUpdate });
  return { result: readSoaProbe(measurement, { name: plan.name, zone: plan.zone, ns: plan.ns, id }), id: id || null, cost: Number.isFinite(cost) ? cost : SOA_PROBE_COST, quota: quota || null };
}
