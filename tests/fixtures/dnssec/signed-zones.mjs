/**
 * signed-zones.mjs — DNSSEC-signed test zones made with node:crypto, and a fake resolver that
 * answers DoH questions from them the way a validating resolver asked with DO + CD would
 * (lib/dnssec.js unit tests, and the DNSSEC chain group of tests/e2e/lookup.e2e.mjs).
 *
 * Every zone is under the documentation TLD `example.` and holds documentation addresses only.
 * The keys are made fresh on every run (nothing is committed); the signatures are valid from
 * `now - 1 day` to `now + 30 days` unless a zone says otherwise. The signing input is built here
 * independently of lib/dnssec.js (lowercase names written by lib/dnswire.js without
 * compression, RDATA sorted as octet strings), so a canonical-form mistake in the validator does
 * not cancel out.
 *
 *   .                  RSA/SHA-256 (8), NSEC: the trust anchor of the tests (its DS from rootAnchor())
 *   example            ECDSA P-256 (13), NSEC
 *   rsa.example        RSA/SHA-256: www (A), alias (CNAME www.ecdsa.example), bad (A changed after signing),
 *                      *.wild (A), mail (MX), NSEC proofs for no data and no name
 *   ecdsa.example      ECDSA P-256: www (A, AAAA)
 *   ed.example         Ed25519 (15): www (A)
 *   n3.example         ECDSA P-256 with NSEC3 (1 iteration, salt ab12): www (A)
 *   expired.example    ECDSA P-256, every signature expired a day ago
 *   rollover.example   ECDSA P-256, its DS at `example` names a key the zone no longer serves
 *   gost.example       algorithm 12 (GOST, not checked by lib/dnssec.js): insecure, never bogus
 *   unsigned.example   no DS, no keys: the parent's NSEC proves the unsigned delegation
 *
 * DOM-free test helper; Node 22.
 */

import { generateKeyPairSync, sign as nodeSign, createHash, randomBytes } from 'node:crypto';
import {
  encodeMessage, decodeMessage, encodeName, computeKeyTag, base64Encode, hexEncode, typeToNumber
} from '../../../assets/js/lib/dnswire.js';

const DAY = 86400e3;
const TTL = 3600;

/* ------------------------------------------------------------------------ */
/* Keys                                                                     */
/* ------------------------------------------------------------------------ */

const b64u = (s) => Buffer.from(s, 'base64url');

/**
 * A DNSSEC key pair: { algorithm, flags, publicKey (base64), keyTag, rdata, sign(data) → Buffer }.
 * @param {number} algorithm 8, 13, 15 or 12 (fake GOST: random key, random signatures)
 * @param {boolean} ksk
 */
export function makeKey(algorithm, ksk) {
  let pub;
  let signer;
  if (algorithm === 8) {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 65537 });
    const jwk = publicKey.export({ format: 'jwk' });
    const e = b64u(jwk.e);
    pub = Buffer.concat([Buffer.from([e.length]), e, b64u(jwk.n)]);
    signer = (data) => nodeSign('sha256', data, privateKey);
  } else if (algorithm === 13) {
    const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    pub = Buffer.concat([b64u(jwk.x), b64u(jwk.y)]);
    signer = (data) => nodeSign('sha256', data, { key: privateKey, dsaEncoding: 'ieee-p1363' });
  } else if (algorithm === 15) {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    pub = b64u(publicKey.export({ format: 'jwk' }).x);
    signer = (data) => nodeSign(null, data, privateKey);
  } else {
    pub = randomBytes(64);
    signer = () => randomBytes(64);
  }
  const flags = ksk ? 257 : 256;
  const rdata = Buffer.concat([Buffer.from([flags >> 8, flags & 0xff, 3, algorithm]), pub]);
  return { algorithm, flags, publicKey: base64Encode(pub), keyTag: computeKeyTag(new Uint8Array(rdata)), rdata, sign: signer };
}

/** The DS data of a key at `owner` (SHA-256). */
function dsOf(owner, key) {
  const digest = createHash('sha256').update(Buffer.concat([Buffer.from(encodeName(owner)), key.rdata])).digest();
  return { keyTag: key.keyTag, algorithm: key.algorithm, digestType: 2, digest: hexEncode(digest) };
}

/* ------------------------------------------------------------------------ */
/* Names                                                                    */
/* ------------------------------------------------------------------------ */

const labels = (n) => (n === '.' ? [] : n.split('.'));
const parentOf = (n) => (n === '.' ? null : labels(n).slice(1).join('.') || '.');
const below = (n, z) => z === '.' || n === z || n.endsWith(`.${z}`);
const sigLabels = (n) => labels(n).filter((l, i) => !(i === 0 && l === '*')).length;

function compareNames(a, b) {
  const la = labels(a).reverse();
  const lb = labels(b).reverse();
  for (let i = 0; i < Math.min(la.length, lb.length); i++) {
    const c = Buffer.compare(Buffer.from(la[i]), Buffer.from(lb[i]));
    if (c) return c;
  }
  return la.length - lb.length;
}

function base32Hex(buf) {
  const A = '0123456789abcdefghijklmnopqrstuv';
  let out = '';
  let bits = 0;
  let acc = 0;
  for (const b of buf) {
    acc = ((acc << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += A[(acc >>> bits) & 31];
    }
  }
  if (bits > 0) out += A[(acc << (5 - bits)) & 31];
  return out;
}

function nsec3Hash(name, salt, iterations) {
  const s = Buffer.from(salt, 'hex');
  let x = createHash('sha1').update(Buffer.concat([Buffer.from(encodeName(name)), s])).digest();
  for (let i = 0; i < iterations; i++) x = createHash('sha1').update(Buffer.concat([x, s])).digest();
  return base32Hex(x);
}

/* ------------------------------------------------------------------------ */
/* Signing                                                                  */
/* ------------------------------------------------------------------------ */

function base32HexDecode(s) {
  const A = '0123456789abcdefghijklmnopqrstuv';
  const out = [];
  let bits = 0;
  let acc = 0;
  for (const c of s.toLowerCase()) {
    acc = (acc << 5) | A.indexOf(c);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  return Buffer.from(out);
}

function typeBitmap(types) {
  const nums = [...new Set(types.map(typeToNumber))].sort((a, b) => a - b);
  const windows = new Map();
  for (const n of nums) {
    if (!windows.has(n >> 8)) windows.set(n >> 8, Buffer.alloc(32));
    windows.get(n >> 8)[(n & 0xff) >> 3] |= 0x80 >> (n & 7);
  }
  const parts = [];
  for (const [win, bits] of windows) {
    let len = 32;
    while (len > 1 && bits[len - 1] === 0) len--;
    parts.push(Buffer.from([win, len]), bits.subarray(0, len));
  }
  return Buffer.concat(parts);
}

/** NSEC3 / NSEC3PARAM RDATA (lib/dnswire.js reads them but has no writer). */
function nsec3Rdata(type, d) {
  const salt = Buffer.from(d.salt || '', 'hex');
  const head = Buffer.from([d.hashAlgorithm, d.flags, d.iterations >> 8, d.iterations & 0xff, salt.length]);
  if (type === 'NSEC3PARAM') return Buffer.concat([head, salt]);
  const next = base32HexDecode(d.nextHashedOwner);
  return Buffer.concat([head, salt, Buffer.from([next.length]), next, typeBitmap(d.types)]);
}

/** One record for lib/dnswire.encodeMessage. */
function record(owner, type, data) {
  if (type === 'NSEC3' || type === 'NSEC3PARAM') return { name: owner, type, ttl: TTL, rdata: new Uint8Array(nsec3Rdata(type, data)) };
  return { name: owner, type, ttl: TTL, data };
}

/** RDATA octets of one record, written by lib/dnswire.js (no compression, names as given). */
function rdataOf(owner, type, data) {
  if (type === 'NSEC3' || type === 'NSEC3PARAM') return nsec3Rdata(type, data);
  const msg = decodeMessage(encodeMessage({ answers: [record(owner, type, data)] }));
  return Buffer.from(msg.answers[0].rdata);
}

/** An RRSIG over (owner, type, datas) with `key` of `zone`. */
function rrsig(zone, key, owner, type, datas, { inception, expiration }) {
  const secs = (ms) => Math.floor(ms / 1000) >>> 0;
  const head = Buffer.alloc(18);
  head.writeUInt16BE(typeToNumber(type), 0);
  head[2] = key.algorithm;
  head[3] = sigLabels(owner);
  head.writeUInt32BE(TTL, 4);
  head.writeUInt32BE(secs(expiration), 8);
  head.writeUInt32BE(secs(inception), 12);
  head.writeUInt16BE(key.keyTag, 16);
  const ownerWire = Buffer.from(encodeName(owner));
  const rrs = [...new Map(datas.map((d) => {
    const r = rdataOf(owner, type, d);
    return [r.toString('hex'), r];
  })).values()].sort(Buffer.compare);
  const parts = [head, Buffer.from(encodeName(zone))];
  for (const r of rrs) {
    const fixed = Buffer.alloc(10);
    fixed.writeUInt16BE(typeToNumber(type), 0);
    fixed.writeUInt16BE(1, 2);
    fixed.writeUInt32BE(TTL, 4);
    fixed.writeUInt16BE(r.length, 8);
    parts.push(ownerWire, fixed, r);
  }
  const signature = key.sign(Buffer.concat(parts));
  return {
    typeCovered: type, algorithm: key.algorithm, labels: sigLabels(owner), originalTtl: TTL,
    expiration: new Date(expiration), inception: new Date(inception), keyTag: key.keyTag, signerName: zone,
    signature: base64Encode(signature)
  };
}

/* ------------------------------------------------------------------------ */
/* Zones                                                                    */
/* ------------------------------------------------------------------------ */

function soa(zone) {
  const ns = zone === '.' ? 'a.root-servers.example' : `ns1.${zone}`;
  return { mname: ns, rname: `hostmaster.${zone === '.' ? 'example' : zone}`, serial: 2026100801, refresh: 7200, retry: 3600, expire: 1209600, minimum: 300 };
}

/**
 * Build the signed zones.
 * @param {{ now?: number }} [opts]
 * @returns {{ zones: Map<string, object>, now: number, rootAnchor: () => object[] }}
 */
export function buildZones({ now = Date.now() } = {}) {
  const valid = { inception: now - DAY, expiration: now + 30 * DAY };
  const expired = { inception: now - 31 * DAY, expiration: now - DAY };
  const specs = [
    { name: '.', alg: 8, denial: 'nsec', records: {} },
    { name: 'example', alg: 13, denial: 'nsec', records: {} },
    {
      name: 'rsa.example', alg: 8, denial: 'nsec', records: {
        'www.rsa.example': { A: ['192.0.2.10'] },
        'mail.rsa.example': { MX: [{ preference: 10, exchange: 'www.rsa.example' }] },
        'alias.rsa.example': { CNAME: ['www.ecdsa.example'] },
        'bad.rsa.example': { A: ['192.0.2.11'] },
        '*.wild.rsa.example': { A: ['192.0.2.12'] }
      },
      tamper: { 'bad.rsa.example|A': ['198.51.100.66'] }
    },
    { name: 'ecdsa.example', alg: 13, denial: 'nsec', records: { 'www.ecdsa.example': { A: ['192.0.2.20'], AAAA: ['2001:db8::20'] } } },
    { name: 'ed.example', alg: 15, denial: 'nsec', records: { 'www.ed.example': { A: ['192.0.2.30'] } } },
    { name: 'n3.example', alg: 13, denial: 'nsec3', salt: 'ab12', iterations: 1, records: { 'www.n3.example': { A: ['192.0.2.60'] } } },
    { name: 'expired.example', alg: 13, denial: 'nsec', window: expired, records: { 'www.expired.example': { A: ['192.0.2.40'] } } },
    { name: 'rollover.example', alg: 13, denial: 'nsec', staleDs: true, records: { 'www.rollover.example': { A: ['192.0.2.41'] } } },
    { name: 'gost.example', alg: 12, denial: 'nsec', records: { 'www.gost.example': { A: ['192.0.2.42'] } } },
    { name: 'unsigned.example', alg: null, records: { 'www.unsigned.example': { A: ['192.0.2.50'] } } }
  ];
  const zones = new Map();
  for (const spec of specs) {
    const z = {
      ...spec, window: spec.window || valid, keys: [], ksk: null, zsk: null, rrsets: new Map(), children: [],
      nsec: new Map(), nsec3: [], ds: []
    };
    if (spec.alg) {
      z.ksk = makeKey(spec.alg, true);
      z.zsk = makeKey(spec.alg, false);
      z.keys = [z.ksk, z.zsk];
    }
    const set = (owner, type, datas) => {
      if (!z.rrsets.has(owner)) z.rrsets.set(owner, new Map());
      z.rrsets.get(owner).set(type, datas);
    };
    set(spec.name, 'SOA', [soa(spec.name)]);
    set(spec.name, 'NS', [spec.name === '.' ? 'a.root-servers.example' : `ns1.${spec.name}`]);
    if (z.keys.length) set(spec.name, 'DNSKEY', z.keys.map((k) => ({ flags: k.flags, protocol: 3, algorithm: k.algorithm, publicKey: k.publicKey })));
    for (const [owner, types] of Object.entries(spec.records)) for (const [type, datas] of Object.entries(types)) set(owner, type, datas);
    zones.set(spec.name, z);
  }
  // Delegations: NS (and DS when the child is signed) in the parent.
  for (const z of zones.values()) {
    if (z.name === '.') continue;
    const parent = zones.get(parentOf(z.name));
    parent.children.push(z.name);
    const at = parent.rrsets.get(z.name) || new Map();
    parent.rrsets.set(z.name, at);
    at.set('NS', [`ns1.${z.name}`]);
    if (z.ksk) {
      z.ds = [dsOf(z.name, z.staleDs ? makeKey(z.alg, true) : z.ksk)];
      at.set('DS', z.ds);
    }
  }
  // Signatures and denial records.
  for (const z of zones.values()) {
    if (!z.keys.length) continue;
    z.sigs = new Map();
    const authoritative = (owner, type) => !(z.children.includes(owner) && type !== 'DS');
    for (const [owner, types] of z.rrsets) {
      for (const [type, datas] of types) {
        if (!authoritative(owner, type)) continue;
        const key = type === 'DNSKEY' ? z.ksk : z.zsk;
        z.sigs.set(`${owner}|${type}`, [rrsig(z.name, key, owner, type, datas, z.window)]);
      }
    }
    const owners = [...z.rrsets.keys()].sort(compareNames);
    const typesAt = (owner) => {
      const types = [...z.rrsets.get(owner).keys()];
      const signed = types.some((t) => authoritative(owner, t));
      return [...types, ...(signed || z.denial === 'nsec' ? ['RRSIG'] : [])];
    };
    if (z.denial === 'nsec') {
      owners.forEach((owner, i) => {
        const data = { nextDomain: owners[(i + 1) % owners.length], types: [...typesAt(owner), 'NSEC'] };
        z.nsec.set(owner, data);
        z.sigs.set(`${owner}|NSEC`, [rrsig(z.name, z.zsk, owner, 'NSEC', [data], z.window)]);
      });
    } else {
      // Every owner and every empty non-terminal between an owner and the apex.
      const names = new Set(owners);
      for (const o of owners) for (let p = parentOf(o); p && below(p, z.name) && p !== z.name; p = parentOf(p)) names.add(p);
      const hashed = [...names].map((n) => ({ name: n, hash: nsec3Hash(n, z.salt, z.iterations) })).sort((a, b) => (a.hash < b.hash ? -1 : 1));
      hashed.forEach((h, i) => {
        const types = z.rrsets.has(h.name) ? typesAt(h.name) : [];
        const data = {
          hashAlgorithm: 1, flags: 0, iterations: z.iterations, salt: z.salt,
          nextHashedOwner: hashed[(i + 1) % hashed.length].hash, types: h.name === z.name ? [...types, 'NSEC3PARAM'] : types
        };
        const owner = `${h.hash}.${z.name}`;
        z.nsec3.push({ name: h.name, hash: h.hash, owner, data });
        z.sigs.set(`${owner}|NSEC3`, [rrsig(z.name, z.zsk, owner, 'NSEC3', [data], z.window)]);
      });
      if (z.rrsets.has(z.name)) {
        z.rrsets.get(z.name).set('NSEC3PARAM', [{ hashAlgorithm: 1, flags: 0, iterations: z.iterations, salt: z.salt }]);
        z.sigs.set(`${z.name}|NSEC3PARAM`, [rrsig(z.name, z.zsk, z.name, 'NSEC3PARAM', [{ hashAlgorithm: 1, flags: 0, iterations: z.iterations, salt: z.salt }], z.window)]);
      }
    }
  }
  const root = zones.get('.');
  return { zones, now, rootAnchor: () => [{ zone: '.', id: 'TEST', ...dsOf('.', root.ksk), flags: 257, publicKey: root.ksk.publicKey, validFrom: '2026-01-01' }] };
}

/* ------------------------------------------------------------------------ */
/* The fake resolver                                                        */
/* ------------------------------------------------------------------------ */

/** The zone whose servers answer (qname, qtype): a DS question goes to the parent of an apex. */
function zoneFor(zones, qname, qtype) {
  let best = null;
  for (const z of zones.values()) {
    if (!below(qname, z.name)) continue;
    if (qtype === 'DS' && qname === z.name && z.name !== '.') continue;
    if (!best || labels(z.name).length > labels(best.name).length) best = z;
  }
  return best;
}

function rrsWithSigs(z, owner, type, datas) {
  const out = datas.map((data) => record(owner, type, data));
  for (const sig of (z.sigs && z.sigs.get(`${owner}|${type}`)) || []) out.push({ name: owner, type: 'RRSIG', ttl: TTL, data: sig });
  return out;
}

function nsecRecords(z, owner) {
  return rrsWithSigs(z, owner, 'NSEC', [z.nsec.get(owner)]);
}

function nsec3Records(z, entry) {
  return rrsWithSigs(z, entry.owner, 'NSEC3', [entry.data]);
}

const covers = (owner, next, name) => compareNames(owner, name) < 0 && (compareNames(name, next) < 0 || compareNames(next, owner) <= 0);
const hashCovers = (owner, next, h) => (owner < next ? owner < h && h < next : h > owner || h < next);

/**
 * Answer one question as a resolver would with DO + CD (lib/dnswire message shape).
 * @param {ReturnType<typeof buildZones>} world
 * @param {string} qname
 * @param {string} qtype
 * @returns {object} { rcode, answers, authorities } with `data` shapes for lib/dnswire.encodeMessage
 */
export function resolve(world, qname, qtype) {
  const z = zoneFor(world.zones, qname, qtype);
  const answers = [];
  const authorities = [];
  const soaRRs = () => rrsWithSigs(z, z.name, 'SOA', z.rrsets.get(z.name).get('SOA'));
  // Below a delegation of z: z itself never answers (the child zone does), except a DS question.
  const types = z.rrsets.get(qname);
  const tampered = (owner, type, datas) => (z.tamper && z.tamper[`${owner}|${type}`]) || datas;
  if (types && types.has(qtype)) {
    const datas = types.get(qtype);
    const rrs = rrsWithSigs(z, qname, qtype, datas);
    const swapped = tampered(qname, qtype, datas);
    answers.push(...rrs.filter((rr) => rr.type !== qtype), ...swapped.map((data) => record(qname, qtype, data)));
    return { rcode: 'NOERROR', answers, authorities };
  }
  if (types && types.has('CNAME') && qtype !== 'CNAME') {
    answers.push(...rrsWithSigs(z, qname, 'CNAME', types.get('CNAME')));
    return { rcode: 'NOERROR', answers, authorities };
  }
  // A wildcard owner synthesises the answer (RRSIG labels say so) with proof that qname does not exist.
  const wildcardOwner = `*.${parentOf(qname)}`;
  if (!types && z.rrsets.has(wildcardOwner) && z.rrsets.get(wildcardOwner).has(qtype)) {
    const datas = z.rrsets.get(wildcardOwner).get(qtype);
    answers.push(...datas.map((data) => ({ name: qname, type: qtype, ttl: TTL, data })));
    for (const sig of z.sigs.get(`${wildcardOwner}|${qtype}`) || []) answers.push({ name: qname, type: 'RRSIG', ttl: TTL, data: sig });
    if (z.denial === 'nsec') {
      const owner = [...z.nsec.keys()].find((o) => covers(o, z.nsec.get(o).nextDomain, qname));
      authorities.push(...nsecRecords(z, owner));
    }
    return { rcode: 'NOERROR', answers, authorities };
  }
  // An empty non-terminal exists: names below it do.
  const ent = !types && [...z.rrsets.keys()].some((o) => o !== qname && below(o, qname));
  if (!z.keys.length) {
    authorities.push(...soaRRs());
    return { rcode: types || ent ? 'NOERROR' : 'NXDOMAIN', answers, authorities };
  }
  authorities.push(...soaRRs());
  if (z.denial === 'nsec') {
    if (types) {
      authorities.push(...nsecRecords(z, qname));
      return { rcode: 'NOERROR', answers, authorities };
    }
    const owners = [...z.nsec.keys()];
    const cover = owners.find((o) => covers(o, z.nsec.get(o).nextDomain, qname));
    if (ent) {
      authorities.push(...nsecRecords(z, cover));
      return { rcode: 'NOERROR', answers, authorities };
    }
    authorities.push(...nsecRecords(z, cover));
    const ce = [cover, z.nsec.get(cover).nextDomain].map((n) => {
      const a = labels(qname).reverse();
      const b = labels(n).reverse();
      const out = [];
      for (let i = 0; i < Math.min(a.length, b.length) && a[i] === b[i]; i++) out.push(a[i]);
      return out.reverse().join('.') || '.';
    }).sort((a, b) => labels(b).length - labels(a).length)[0];
    const wild = ce === '.' ? '*' : `*.${ce}`;
    const wcover = owners.find((o) => covers(o, z.nsec.get(o).nextDomain, wild));
    if (wcover && wcover !== cover) authorities.push(...nsecRecords(z, wcover));
    return { rcode: 'NXDOMAIN', answers, authorities };
  }
  const h = (n) => nsec3Hash(n, z.salt, z.iterations);
  const match = (n) => z.nsec3.find((e) => e.hash === h(n));
  const cover = (n) => z.nsec3.find((e) => hashCovers(e.hash, e.data.nextHashedOwner, h(n)));
  if (match(qname)) {
    authorities.push(...nsec3Records(z, match(qname)));
    return { rcode: 'NOERROR', answers, authorities };
  }
  let ce = parentOf(qname);
  let next = qname;
  while (!match(ce)) {
    next = ce;
    ce = parentOf(ce);
  }
  const used = new Set([match(ce), cover(next), cover(ce === '.' ? '*' : `*.${ce}`)]);
  for (const e of used) if (e) authorities.push(...nsec3Records(z, e));
  return { rcode: 'NXDOMAIN', answers, authorities };
}

/**
 * The DoH wire answer to a question (what a resolver sends back), id 0.
 * @param {ReturnType<typeof buildZones>} world
 * @param {string} qname
 * @param {string} qtype
 * @returns {Uint8Array}
 */
export function wireAnswer(world, qname, qtype) {
  const r = resolve(world, qname, qtype);
  return encodeMessage({
    id: 0, flags: { qr: true, rd: true, ra: true, cd: true }, rcode: r.rcode, questions: [{ name: qname, type: qtype }],
    answers: r.answers, authorities: r.authorities, edns: { dnssecOk: true }
  });
}

/**
 * A fake DohClient over the zones: `query(name, type)` → a DnsResponse-like object decoded from
 * the wire answer. `asked` lists every question.
 * @param {ReturnType<typeof buildZones>} world
 * @param {{ edit?: (name: string, type: string, res: object) => object|null }} [opts] change an answer
 *   (null: the question fails like a timeout)
 * @returns {{ query: Function, asked: string[] }}
 */
export function fakeDns(world, { edit = null } = {}) {
  const asked = [];
  return {
    asked,
    async query(name, type, opts = {}) {
      if (opts.signal && opts.signal.aborted) {
        const err = new Error('aborted');
        err.name = 'AbortError';
        throw err;
      }
      asked.push(`${name}|${type}`);
      const msg = decodeMessage(wireAnswer(world, name, type));
      let res = {
        name, type, ok: true, rcode: msg.rcodeName, flags: msg.flags, answers: msg.answers, authorities: msg.authorities,
        additionals: msg.additionals, resolver: 'fake', error: null, errorKind: null
      };
      if (edit) res = edit(name, type, res);
      return res || { name, type, ok: false, rcode: null, answers: [], authorities: [], resolver: 'fake', error: 'Request timed out', errorKind: 'timeout' };
    }
  };
}

/**
 * Every question the DNSSEC chain of the fixture's names can ask, answered on the wire: the table
 * the e2e suite's in-page fake DoH serves (key `name|TYPE`, value base64).
 * @param {ReturnType<typeof buildZones>} world
 * @returns {Record<string, string>}
 */
export function answerTable(world) {
  const names = new Set();
  for (const z of world.zones.values()) {
    names.add(z.name);
    for (const owner of z.rrsets.keys()) if (!owner.startsWith('*.')) names.add(owner);
  }
  for (const extra of ['nope.rsa.example', 'host.wild.rsa.example', 'nope.n3.example']) names.add(extra);
  const out = {};
  for (const n of names) {
    for (const t of ['A', 'AAAA', 'DS', 'DNSKEY', 'SOA', 'NS', 'MX', 'CNAME', 'TXT', 'CAA', 'HTTPS']) {
      out[`${n}|${t}`] = base64Encode(wireAnswer(world, n, t));
    }
  }
  return out;
}
