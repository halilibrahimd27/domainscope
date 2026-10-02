/**
 * dohjson.js — the JSON form of DNS-over-HTTPS (`GET <base>?name=&type=&edns_client_subnet=`, the
 * format of Google's /resolve and AliDNS's /resolve) read into the message lib/dnswire.js decodes
 * from the wire, so lib/doh.js answers the same `DnsResponse` whichever form a resolver speaks.
 *
 * Only resolvers whose wire endpoint a page cannot read use it: AliDNS sends no
 * Access-Control-Allow-Origin on /dns-query but `*` on /resolve, over HTTP/2 and over HTTP/3
 * (2026-10-03: curl over HTTP/3 12/12, real Chrome 9/9 with QUIC forced and 9/9 after Alt-Svc;
 * docs/RESEARCH.md). The record data is RFC 1035 presentation text; each record is turned into the
 * dnswire `data` shape (TXT, the generic `\# n hex` form and AliDNS's bare RDATA hex as raw bytes),
 * encoded and decoded again, so its `text` is exactly what a wire answer of the same record gives
 * and answers from both kinds of resolvers group together (lib/propagation.js compares `text`). A
 * record that cannot be read keeps its presentation text as `text` and `data`.
 *
 * The JSON form carries no EDNS: an ECS subnet the resolver echoes (`edns_client_subnet`) is kept
 * with `scopePrefix: null` (AliDNS echoes the source, not a scope); no NSID, no EDE.
 *
 * DOM-free, no I/O.
 */

import { encodeMessage, decodeMessage, typeToNumber, typeToName, rcodeToName, DnsWireError } from './dnswire.js';
import { normalizeIP, ipVersion } from './netinfo.js';

/** The accept header of a JSON DoH request. */
export const DNS_JSON = 'application/dns-json';

/**
 * The canonical subnet of an ECS spec ('a.b.c.d/24', `{ subnet }` or `{ address, sourcePrefix }`):
 * host bits of an IPv4 subnet zeroed; null when it is not one.
 * @param {string|object|null} ecs
 * @returns {string|null}
 */
export function ecsSubnet(ecs) {
  if (ecs === null || ecs === undefined || ecs === false || ecs === '') return null;
  let address;
  let prefix;
  if (typeof ecs === 'string') [address, prefix] = ecs.trim().split('/');
  else if (typeof ecs === 'object' && typeof ecs.subnet === 'string') [address, prefix] = ecs.subnet.split('/');
  else if (typeof ecs === 'object') [address, prefix] = [ecs.address, ecs.sourcePrefix ?? ecs.prefix];
  const ip = normalizeIP(String(address ?? ''));
  const v = ip ? ipVersion(ip) : null;
  const max = v === 4 ? 32 : 128;
  const bits = prefix === undefined || prefix === null || prefix === '' ? (v === 4 ? 24 : 56) : Number(prefix);
  if (!ip || !Number.isInteger(bits) || bits < 0 || bits > max) return null;
  if (v === 6) return `${ip}/${bits}`;
  const n = ip.split('.').reduce((acc, o) => ((acc << 8) | Number(o)) >>> 0, 0);
  const masked = bits === 0 ? 0 : (n & (0xffffffff << (32 - bits))) >>> 0;
  return `${[24, 16, 8, 0].map((s) => (masked >>> s) & 255).join('.')}/${bits}`;
}

/**
 * The URL of a JSON DoH question. The type goes as its number (a resolver that knows no
 * mnemonic for a newer type still answers), the subnet unencoded (`/` is allowed in a query).
 * @param {string} base e.g. 'https://dns.alidns.com/resolve'
 * @param {{ name: string, type: string|number, ecs?: string|object|null }} q
 * @returns {string}
 */
export function dnsJsonUrl(base, { name, type, ecs = null }) {
  const typeNum = typeToNumber(type);
  if (typeNum === null) throw new DnsWireError(`unknown RR type "${type}"`);
  const subnet = ecsSubnet(ecs);
  return `${base}${base.includes('?') ? '&' : '?'}name=${encodeURIComponent(name)}&type=${typeNum}${subnet ? `&edns_client_subnet=${subnet}` : ''}`;
}

/* ------------------------------------------------------------------------ */
/* Presentation data → dnswire data                                         */
/* ------------------------------------------------------------------------ */

const utf8 = new TextEncoder();

/** Tokens of presentation data: `{ text, bytes, quoted }` (escapes \X and \DDD resolved in `bytes`). */
function tokens(s) {
  const out = [];
  let i = 0;
  const n = s.length;
  while (i < n) {
    if (/\s/.test(s[i])) {
      i += 1;
      continue;
    }
    const quoted = s[i] === '"';
    if (quoted) i += 1;
    const bytes = [];
    let text = '';
    while (i < n && (quoted ? s[i] !== '"' : !/\s/.test(s[i]))) {
      if (s[i] === '\\' && i + 1 < n) {
        if (/^\d{3}$/.test(s.slice(i + 1, i + 4))) {
          bytes.push(Number(s.slice(i + 1, i + 4)) & 255);
          text += s.slice(i, i + 4);
          i += 4;
        } else {
          for (const b of utf8.encode(s[i + 1])) bytes.push(b);
          text += s.slice(i, i + 2);
          i += 2;
        }
        continue;
      }
      for (const b of utf8.encode(s[i])) bytes.push(b);
      text += s[i];
      i += 1;
    }
    if (quoted) {
      if (i >= n) throw new DnsWireError('unterminated quote');
      i += 1;
    }
    out.push({ text, bytes: Uint8Array.from(bytes), quoted });
  }
  return out;
}

const name = (t) => {
  if (!t) throw new DnsWireError('missing name');
  return t.text === '.' ? '.' : t.text.replace(/\.$/, '');
};
const int = (t, max = 0xffff) => {
  const v = t && /^\d+$/.test(t.text) ? Number(t.text) : NaN;
  if (!Number.isInteger(v) || v > max) throw new DnsWireError('bad number');
  return v;
};
const joined = (toks, from) => toks.slice(from).map((t) => t.text).join('');
const isHex = (s) => /^(?:[0-9a-f]{2})+$/i.test(s);
const hexBytes = (s) => Uint8Array.from(s.match(/../g).map((b) => parseInt(b, 16)));
const charStrings = (toks) => {
  const parts = [];
  for (const t of toks) {
    if (t.bytes.length > 255) throw new DnsWireError('character-string longer than 255 bytes');
    parts.push(t.bytes.length, ...t.bytes);
  }
  return Uint8Array.from(parts);
};
const list = (t) => t.text.split(',').filter(Boolean);

/** SvcParams of SVCB / HTTPS presentation (`key=value` tokens). */
function svcParams(toks) {
  const params = {};
  for (const t of toks) {
    const eq = t.text.indexOf('=');
    const key = eq < 0 ? t.text : t.text.slice(0, eq);
    let value = eq < 0 ? '' : t.text.slice(eq + 1);
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) value = value.slice(1, -1);
    if (key === 'alpn' || key === 'mandatory') params[key] = value.split(',').filter(Boolean);
    else if (key === 'no-default-alpn' || key === 'ohttp') params[key] = true;
    else if (key === 'port') params.port = int({ text: value });
    else if (key === 'ipv4hint' || key === 'ipv6hint') params[key] = value.split(',').filter(Boolean);
    else if (key === 'ech') params.ech = value;
    else throw new DnsWireError(`unsupported SvcParam ${key}`);
  }
  return params;
}

/**
 * One record's dnswire `data` (or raw `rdata`) from its presentation text.
 * @returns {{ data?: any, rdata?: Uint8Array }}
 */
function presentation(typeNum, s) {
  const generic = /^\\#\s+(\d+)\s*([0-9a-fA-F\s]*)$/.exec(s);
  if (generic) {
    const hex = generic[2].replace(/\s+/g, '');
    if (hex.length !== Number(generic[1]) * 2 || (hex && !isHex(hex))) throw new DnsWireError('bad generic RDATA');
    return { rdata: hex ? hexBytes(hex) : new Uint8Array(0) };
  }
  const t = tokens(s);
  switch (typeToName(typeNum)) {
    case 'A': case 'AAAA': {
      const ip = normalizeIP(t[0] ? t[0].text : '');
      if (!ip || ipVersion(ip) !== (typeNum === 1 ? 4 : 6)) throw new DnsWireError('bad address');
      return { data: ip };
    }
    case 'NS': case 'CNAME': case 'PTR': case 'DNAME': return { data: name(t[0]) };
    case 'MX': return { data: { preference: int(t[0]), exchange: name(t[1]) } };
    case 'TXT': case 'SPF': return { rdata: charStrings(t) };
    case 'SOA': return {
      data: {
        mname: name(t[0]), rname: name(t[1]), serial: int(t[2], 0xffffffff), refresh: int(t[3], 0xffffffff),
        retry: int(t[4], 0xffffffff), expire: int(t[5], 0xffffffff), minimum: int(t[6], 0xffffffff)
      }
    };
    case 'SRV': return { data: { priority: int(t[0]), weight: int(t[1]), port: int(t[2]), target: name(t[3]) } };
    case 'CAA': {
      if (t.length !== 3) throw new DnsWireError('bad CAA');
      return { data: { flags: int(t[0], 255), tag: t[1].text, value: new TextDecoder().decode(t[2].bytes) } };
    }
    case 'DS': case 'CDS': {
      const digest = joined(t, 3);
      if (!isHex(digest)) throw new DnsWireError('bad digest');
      return { data: { keyTag: int(t[0]), algorithm: int(t[1], 255), digestType: int(t[2], 255), digest } };
    }
    case 'DNSKEY': case 'CDNSKEY': return { data: { flags: int(t[0]), protocol: int(t[1], 255), algorithm: int(t[2], 255), publicKey: joined(t, 3) } };
    case 'TLSA': case 'SMIMEA': {
      if (t.length === 1 && isHex(t[0].text)) return { rdata: hexBytes(t[0].text) }; // AliDNS: the whole RDATA as hex
      const data = joined(t, 3);
      if (!isHex(data)) throw new DnsWireError('bad TLSA data');
      return { data: { usage: int(t[0], 255), selector: int(t[1], 255), matchingType: int(t[2], 255), data } };
    }
    case 'SSHFP': {
      const fingerprint = joined(t, 2);
      if (!isHex(fingerprint)) throw new DnsWireError('bad SSHFP');
      return { data: { algorithm: int(t[0], 255), fpType: int(t[1], 255), fingerprint } };
    }
    case 'SVCB': case 'HTTPS': return { data: { priority: int(t[0]), target: name(t[1]), params: svcParams(t.slice(2)) } };
    case 'NAPTR': return {
      data: {
        order: int(t[0]), preference: int(t[1]), flags: t[2].text, services: t[3].text, regexp: new TextDecoder().decode(t[4].bytes),
        replacement: name(t[5])
      }
    };
    case 'HINFO': return { data: { cpu: new TextDecoder().decode(t[0].bytes), os: new TextDecoder().decode(t[1].bytes) } };
    case 'URI': return { data: { priority: int(t[0]), weight: int(t[1]), target: new TextDecoder().decode(t[2].bytes) } };
    default:
      if (t.length === 1 && isHex(t[0].text)) return { rdata: hexBytes(t[0].text) };
      throw new DnsWireError(`no presentation reader for ${typeToName(typeNum)}`);
  }
}

/** A record as the wire decoder gives it, or its presentation text when it cannot be read. */
function readRecord(rr) {
  const typeNum = Number(rr && rr.type);
  const owner = typeof (rr && rr.name) === 'string' ? rr.name : '';
  const ttl = Number.isInteger(rr && rr.TTL) && rr.TTL >= 0 ? rr.TTL : 0;
  const raw = typeof (rr && rr.data) === 'string' ? rr.data : String((rr && rr.data) ?? '');
  if (!Number.isInteger(typeNum) || typeNum < 0 || typeNum > 0xffff || !owner) throw new DnsWireError('bad record in a DNS JSON answer');
  try {
    const entry = { name: owner, type: typeNum, ttl, ...presentation(typeNum, raw) };
    return decodeMessage(encodeMessage({ answers: [entry] })).answers[0];
  } catch {
    const plainName = owner === '.' ? '.' : owner.toLowerCase().replace(/\.$/, '');
    return { name: plainName, type: typeToName(typeNum), typeNum, class: 1, className: 'IN', ttl, data: raw, text: raw };
  }
}

/**
 * A JSON DoH answer as the message lib/dnswire.js decodeMessage returns: flags, rcode, question,
 * answer / authority / additional records with `data` and `text`, and `edns.ecs` when the resolver
 * echoed a subnet (`scopePrefix: null`).
 * @param {any} json the parsed body
 * @returns {object} decodeMessage-shaped message
 * @throws {DnsWireError} when the body is not a DNS JSON answer
 */
export function decodeDnsJson(json) {
  if (!json || typeof json !== 'object' || Array.isArray(json) || !Number.isInteger(json.Status)) {
    throw new DnsWireError('not a DNS JSON answer');
  }
  const q = Array.isArray(json.Question) ? json.Question[0] : json.Question;
  const qType = q && Number.isInteger(q.type) ? q.type : null;
  const qName = q && typeof q.name === 'string' ? q.name : null;
  const msg = decodeMessage(encodeMessage({
    flags: { qr: true, tc: !!json.TC, rd: json.RD !== false, ra: !!json.RA, ad: !!json.AD, cd: !!json.CD },
    rcode: json.Status & 0xf,
    questions: qName !== null && qType !== null ? [{ name: qName, type: qType }] : []
  }));
  const section = (key) => (Array.isArray(json[key]) ? json[key].map(readRecord) : []);
  msg.rcode = json.Status;
  msg.rcodeName = rcodeToName(json.Status);
  msg.answers = section('Answer');
  msg.authorities = section('Authority');
  msg.additionals = section('Additional');
  const subnet = typeof json.edns_client_subnet === 'string' ? ecsSubnet(json.edns_client_subnet) : null;
  if (subnet) {
    const [address, prefix] = subnet.split('/');
    msg.edns = {
      udpSize: null, version: 0, dnssecOk: false, extendedRcode: 0, options: [], ede: [], nsid: null,
      ecs: { family: ipVersion(address) === 4 ? 1 : 2, sourcePrefix: Number(prefix), scopePrefix: null, address, subnet }
    };
  } else {
    msg.edns = null;
  }
  return msg;
}
