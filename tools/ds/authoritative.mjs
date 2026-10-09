/**
 * tools/ds/authoritative.mjs — `watch --authoritative`: every name server of a zone asked directly,
 * so a server that answers without authority (lame), a secondary that lags behind the primary's SOA
 * serial and servers that answer the same serial differently (out of sync) show — what a recursive
 * resolver, which asks one of them and caches the answer, hides.
 *
 * - The name servers' addresses come over the run's DoH client (A and AAAA of each NS host); each
 *   address is a server. GitHub's hosted runners have no IPv6 route: an IPv6 address this machine
 *   cannot reach is skipped (`no-ipv6-route`), said once per run.
 * - Each question goes over UDP (node:dgram, EDNS0 with a 1,232-byte payload, the DO bit for DS and
 *   DNSKEY, recursion not desired), and over TCP (node:net, the 2-byte length prefix) when the answer
 *   is truncated (TC=1) or UDP got no answer: {@link AUTH_TIMEOUT_MS} per attempt, {@link AUTH_TRIES}
 *   attempts per transport, {@link AUTH_CONCURRENCY} servers in flight. The wire format is
 *   lib/dnswire.js encodeQuery / decodeMessage; an answer counts only with the query's id and question.
 * - Each server is asked the zone's SOA first: no AA, REFUSED or SERVFAIL is lame, no answer over UDP
 *   and TCP unreachable; then the record sets of the DoH snapshot (the apex's DS is the parent's, a
 *   delegated name's are the child's: neither is asked), within `maxQueries` per domain.
 * - When neither of the first two servers answers over UDP or TCP (port 53 blocked on this network),
 *   nothing more is asked: the view is 'recursive' (the DoH snapshot alone).
 * - The servers at the highest serial are compared record set by record set (the values, and the TTL
 *   with --ttl): a set they answer differently is a mismatch; a server below that serial lags.
 */

import dgram from 'node:dgram';
import net from 'node:net';
import { randomInt } from 'node:crypto';
import { encodeQuery, decodeMessage } from '../../assets/js/lib/dnswire.js';
import { createLimiter, throwIfAborted, AbortError } from '../../assets/js/lib/util.js';
import { rrsetOf, recordKey } from './watchdiff.mjs';

/** Time for one attempt over UDP or TCP. */
export const AUTH_TIMEOUT_MS = 3000;
/** Attempts per transport. */
export const AUTH_TRIES = 2;
/** Servers asked at once. */
export const AUTH_CONCURRENCY = 4;
/** The EDNS UDP payload size asked for (the DNS Flag Day 2020 value). */
export const AUTH_UDP_SIZE = 1232;
/** A server's port. */
export const DNS_PORT = 53;
/** The send / connect errors of an IPv6 address this machine has no route to. */
const NO_ROUTE = new Set(['ENETUNREACH', 'EHOSTUNREACH', 'EADDRNOTAVAIL', 'EAFNOSUPPORT']);
/** Answer codes that make a server lame for the zone. */
const LAME_RCODES = Object.freeze({ REFUSED: 'refused', SERVFAIL: 'servfail', NOTAUTH: 'notauth', NOTIMP: 'notimp' });

const canon = (s) => String(s ?? '').trim().toLowerCase().replace(/\.$/, '');

/** Does a decoded message answer `query` (its id, a response, its question)? */
function answers(msg, { id, name, type }) {
  const q = msg && msg.questions && msg.questions[0];
  return !!msg && msg.id === id && msg.flags && msg.flags.qr === true && !!q && canon(q.name) === canon(name) && q.type === type;
}

/** One UDP attempt: resolves `{ message }`, `{ timeout: true }` or `{ error, code }`; rejects on an abort. */
function udpOnce({ address, port, family, query, id, name, type, timeoutMs, createSocket, signal }) {
  return new Promise((resolve, reject) => {
    let socket = null;
    let done = false;
    const finish = (value, rejected = false) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      try {
        if (socket) socket.close();
      } catch {
        /* closed already */
      }
      if (rejected) reject(value);
      else resolve(value);
    };
    const onAbort = () => finish(new AbortError('The operation was aborted'), true);
    const timer = setTimeout(() => finish({ timeout: true }), timeoutMs);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    try {
      socket = createSocket(family === 6 ? 'udp6' : 'udp4');
      socket.on('error', (err) => finish({ error: String((err && err.message) || err), code: err && err.code }));
      socket.on('message', (buf, rinfo) => {
        if (rinfo && rinfo.port !== port) return;
        let msg;
        try {
          msg = decodeMessage(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
        } catch {
          return; // not an answer: keep waiting for one
        }
        if (answers(msg, { id, name, type })) finish({ message: msg });
      });
      socket.send(query, port, address, (err) => {
        if (err) finish({ error: String(err.message || err), code: err.code });
      });
    } catch (err) {
      finish({ error: String((err && err.message) || err), code: err && err.code });
    }
  });
}

/** One TCP attempt (a 2-byte length before each message): the same results as {@link udpOnce}. */
function tcpOnce({ address, port, query, id, name, type, timeoutMs, connect, signal }) {
  return new Promise((resolve, reject) => {
    let socket = null;
    let done = false;
    let buf = Buffer.alloc(0);
    const finish = (value, rejected = false) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', onAbort);
      try {
        if (socket) socket.destroy();
      } catch {
        /* closed already */
      }
      if (rejected) reject(value);
      else resolve(value);
    };
    const onAbort = () => finish(new AbortError('The operation was aborted'), true);
    const timer = setTimeout(() => finish({ timeout: true }), timeoutMs);
    if (signal) signal.addEventListener('abort', onAbort, { once: true });
    try {
      socket = connect({ host: address, port });
      socket.on('connect', () => {
        const head = Buffer.alloc(2);
        head.writeUInt16BE(query.length, 0);
        socket.write(Buffer.concat([head, Buffer.from(query)]));
      });
      socket.on('data', (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        if (buf.length < 2) return;
        const len = buf.readUInt16BE(0);
        if (buf.length < 2 + len) return;
        let msg;
        try {
          msg = decodeMessage(new Uint8Array(buf.subarray(2, 2 + len)));
        } catch (err) {
          finish({ error: `not a DNS answer: ${String((err && err.message) || err).slice(0, 120)}`, code: 'EPROTO' });
          return;
        }
        finish(answers(msg, { id, name, type }) ? { message: msg } : { error: 'an answer to another question', code: 'EPROTO' });
      });
      socket.on('error', (err) => finish({ error: String((err && err.message) || err), code: err && err.code }));
      socket.on('close', () => finish({ error: 'the connection closed before the answer', code: 'ECONNRESET' }));
    } catch (err) {
      finish({ error: String((err && err.message) || err), code: err && err.code });
    }
  });
}

/**
 * Ask one server one question: UDP, then TCP when the answer is truncated or UDP got none.
 * @param {{ address: string, port?: number, name: string, type: string, timeoutMs?: number, tries?: number,
 *   transport?: { createSocket?: Function, connect?: Function }, signal?: AbortSignal }} opts `transport`:
 *   node:dgram's createSocket and node:net's connect (tests)
 * @returns {Promise<{ ok: true, message: object, transport: 'udp'|'tcp' } | { ok: false, skipped?: 'no-ipv6-route', error: string }>}
 *   rejects only on an abort
 */
export async function askServer({ address, port = DNS_PORT, name, type, timeoutMs = AUTH_TIMEOUT_MS, tries = AUTH_TRIES, transport = {}, signal }) {
  throwIfAborted(signal);
  const family = net.isIP(address);
  const id = randomInt(0, 0x10000);
  const query = encodeQuery(name, type, { id, rd: false, ad: false, dnssecOk: type === 'DS' || type === 'DNSKEY', udpSize: AUTH_UDP_SIZE });
  const createSocket = transport.createSocket || ((t) => dgram.createSocket(t));
  const connect = transport.connect || ((o) => net.connect(o));
  const base = { address, port, family, query, id, name, type, timeoutMs, signal };
  let why = 'no answer over UDP';
  let truncated = false;
  for (let i = 0; i < tries && !truncated; i += 1) {
    const r = await udpOnce({ ...base, createSocket });
    if (r.message) {
      if (!r.message.flags.tc) return { ok: true, message: r.message, transport: 'udp' };
      truncated = true;
    } else if (r.code && NO_ROUTE.has(r.code) && family === 6) {
      return { ok: false, skipped: 'no-ipv6-route', error: 'no IPv6 route from this machine' };
    } else if (r.error) {
      why = `UDP: ${r.error}`;
    }
  }
  for (let i = 0; i < tries; i += 1) {
    const r = await tcpOnce({ ...base, connect });
    if (r.message) return { ok: true, message: r.message, transport: 'tcp' };
    if (r.code && NO_ROUTE.has(r.code) && family === 6) return { ok: false, skipped: 'no-ipv6-route', error: 'no IPv6 route from this machine' };
    why = `${truncated ? 'truncated over UDP; ' : `${why}; `}TCP: ${r.timeout ? 'no answer' : r.error}`;
  }
  return { ok: false, error: why };
}

/**
 * What a server's answer to the zone's SOA says of it: ok (with its serial), or lame and why.
 * @param {object} message a decoded answer
 * @param {string} zone
 * @returns {{ status: 'ok'|'lame', reason: string|null, serial: number|null, mname: string|null }}
 */
export function soaStanding(message, zone) {
  const rcode = message.rcodeName;
  if (LAME_RCODES[rcode]) return { status: 'lame', reason: LAME_RCODES[rcode], serial: null, mname: null };
  if (rcode !== 'NOERROR') return { status: 'lame', reason: String(rcode).toLowerCase(), serial: null, mname: null };
  if (!message.flags.aa) return { status: 'lame', reason: 'no-aa', serial: null, mname: null };
  const soa = rrsetOf(canon(zone), 'SOA', message.answers);
  if (!soa.values.length) return { status: 'lame', reason: 'no-soa', serial: null, mname: null };
  return { status: 'ok', reason: null, serial: soa.serial ?? null, mname: soa.values[0] };
}

/**
 * The servers of a zone: each address of its NS hosts (A and AAAA over DoH), once, IPv4 first, with
 * the host names that have it.
 * @param {string[]} hosts the NS hosts
 * @param {{ dns: object, signal?: AbortSignal }} opts
 * @returns {Promise<{ servers: Array<{ address: string, family: number, hosts: string[] }>, unresolved: string[] }>}
 */
export async function nameServerAddresses(hosts, { dns, signal }) {
  const by = new Map();
  const unresolved = [];
  for (const host of [...new Set((hosts || []).map(canon).filter(Boolean))].sort()) {
    throwIfAborted(signal);
    const r = await dns.resolveHost(host, { signal });
    const ips = [...(r.ipv4 || []), ...(r.ipv6 || [])];
    if (!ips.length) unresolved.push(host);
    for (const ip of ips) {
      if (!by.has(ip)) by.set(ip, { address: ip, family: net.isIP(ip), hosts: [] });
      by.get(ip).hosts.push(host);
    }
  }
  const servers = [...by.values()].sort((a, b) => a.family - b.family || a.hosts[0].localeCompare(b.hosts[0]) || a.address.localeCompare(b.address));
  return { servers, unresolved };
}

/**
 * The record sets the name servers are asked: those of the DoH snapshot but the apex's DS (the
 * parent answers it) and a delegated name's (the child answers them, its DS but).
 * @param {string} zone
 * @param {Array<{ name: string, type: string }>} keys
 * @param {string[]} delegated non-apex names with NS records of their own
 * @returns {Array<{ name: string, type: string }>}
 */
export function askedOfServers(zone, keys, delegated = []) {
  const cut = new Set(delegated);
  return keys.filter((k) => !(k.name === zone && (k.type === 'DS' || k.type === 'SOA')) && !(cut.has(k.name) && k.type !== 'DS'));
}

/**
 * @typedef {object} AuthResult
 * @property {'authoritative'|'recursive'|'none'} view 'recursive': the first two servers did not answer
 *   over UDP or TCP (port 53 blocked here): nothing else was asked; 'none': no server address
 * @property {Array<{ address: string, family: number, hosts: string[], status: 'ok'|'lame'|'unreachable'|'skipped',
 *   reason: string|null, serial: number|null, transport: 'udp'|'tcp'|null }>} servers
 * @property {number|null} serial the highest serial a server answered
 * @property {string[]} lagging the servers below it
 * @property {Array<{ key: string, servers: Record<string, string[]> }>} mismatches the record sets the servers at that
 *   serial answer differently, each server's values
 * @property {string[]} compared the record sets compared
 * @property {Record<string, number>} ttls the TTL the servers at that serial agree on, per record set (--ttl)
 * @property {number} queries questions sent
 * @property {number} cut record sets not asked: past the budget
 * @property {string[]} unresolved NS hosts without an address
 */

/**
 * Ask every name server of a zone directly (the module header).
 * @param {string} zone
 * @param {{ nsHosts: string[], keys: Array<{ name: string, type: string }>, delegated?: string[], dns: object,
 *   signal?: AbortSignal, maxQueries: number, ttl?: boolean, port?: number|((address: string) => number),
 *   timeoutMs?: number, tries?: number, transport?: object }} opts `port`, `timeoutMs`, `tries` and
 *   `transport`: tests (a fake server on 127.0.0.1)
 * @returns {Promise<AuthResult>}
 */
export async function checkAuthoritative(zone, {
  nsHosts, keys, delegated = [], dns, signal, maxQueries, ttl = false, port = DNS_PORT, timeoutMs = AUTH_TIMEOUT_MS, tries = AUTH_TRIES, transport = {}
}) {
  const { servers: found, unresolved } = await nameServerAddresses(nsHosts, { dns, signal });
  const result = { view: 'none', servers: [], serial: null, lagging: [], mismatches: [], compared: [], ttls: {}, queries: 0, cut: 0, unresolved };
  if (!found.length) return result;
  const portOf = (address) => (typeof port === 'function' ? port(address) : port);
  const ask = (s, name, type) => {
    result.queries += 1;
    return askServer({ address: s.address, port: portOf(s.address), name, type, timeoutMs, tries, transport, signal });
  };
  const servers = found.map((s) => ({ ...s, status: 'pending', reason: null, serial: null, transport: null }));
  /** The zone's SOA from one server: ok with its serial, lame, unreachable, or skipped (no IPv6 route). */
  const standing = async (s) => {
    const r = await ask(s, zone, 'SOA');
    if (!r.ok) Object.assign(s, r.skipped ? { status: 'skipped', reason: r.skipped } : { status: 'unreachable', reason: 'no-answer', error: r.error });
    else Object.assign(s, soaStanding(r.message, zone), { transport: r.transport });
  };

  // Port 53 blocked on this network: the first two servers (an IPv6 one this machine cannot reach
  // does not count) answer nothing over UDP or TCP. They are asked first, together.
  const limit = createLimiter(AUTH_CONCURRENCY);
  const first = [];
  let next = 0;
  while (first.length < 2 && next < servers.length) {
    const batch = servers.slice(next, next + 2 - first.length);
    next += batch.length;
    await Promise.all(batch.map((s) => standing(s)));
    first.push(...batch.filter((s) => s.status !== 'skipped'));
  }
  throwIfAborted(signal);
  if (first.length && first.every((s) => s.status === 'unreachable')) {
    return { ...result, view: 'recursive', servers: servers.map(publicServer) };
  }
  await Promise.all(servers.slice(next).map((s) => limit.run(() => standing(s), { signal })));
  throwIfAborted(signal);

  // The record sets, within the budget: the SOA questions are spent already.
  const live = servers.filter((s) => s.status === 'ok');
  const sets = askedOfServers(zone, keys, delegated);
  const room = live.length ? Math.max(0, Math.floor((maxQueries - result.queries) / live.length)) : 0;
  const asked = sets.slice(0, room);
  result.cut = sets.length - asked.length;
  const answersOf = new Map(live.map((s) => [s.address, new Map()]));
  await Promise.all(live.map((s) => limit.run(async () => {
    for (const k of asked) {
      const r = await ask(s, k.name, k.type);
      if (!r.ok || (r.message.rcodeName !== 'NOERROR' && r.message.rcodeName !== 'NXDOMAIN')) continue;
      const set = rrsetOf(k.name, k.type, r.message.answers);
      answersOf.get(s.address).set(recordKey(k.name, k.type), set);
    }
  }, { signal })));
  throwIfAborted(signal);

  // Who is behind, and what the servers at the highest serial answer differently.
  const serials = live.map((s) => s.serial).filter(Number.isFinite);
  const top = serials.length ? Math.max(...serials) : null;
  const current = live.filter((s) => s.serial === top);
  result.serial = top;
  result.lagging = live.filter((s) => Number.isFinite(s.serial) && s.serial < top).map((s) => s.address);
  result.compared = asked.map((k) => recordKey(k.name, k.type));
  for (const key of result.compared) {
    const seen = current.map((s) => [s.address, answersOf.get(s.address).get(key)]).filter(([, set]) => set);
    if (!seen.length) continue;
    const sig = (set) => `${set.values.join('\n')}${ttl ? `|${set.ttl}` : ''}`;
    if (new Set(seen.map(([, set]) => sig(set))).size > 1) {
      // a server's TTL is said only where the TTLs differ (--ttl)
      const ttlsDiffer = ttl && new Set(seen.map(([, set]) => set.ttl)).size > 1;
      result.mismatches.push({ key, servers: Object.fromEntries(seen.map(([address, set]) => [address, ttlsDiffer ? [...set.values, `TTL ${set.ttl}`] : set.values])) });
    } else if (ttl && Number.isFinite(seen[0][1].ttl)) {
      result.ttls[key] = seen[0][1].ttl;
    }
  }
  return { ...result, view: 'authoritative', servers: servers.map(publicServer) };
}

/** A server as the report keeps it. */
function publicServer(s) {
  return {
    address: s.address, family: s.family, hosts: [...s.hosts], status: s.status, reason: s.reason ?? null, serial: s.serial ?? null, transport: s.transport ?? null,
    ...(s.error ? { error: String(s.error).slice(0, 200) } : {})
  };
}
