/**
 * der-builder.mjs — a minimal DER encoder and certificate builder for the fixture generators
 * (gen_x509_fixtures.mjs, gen_chainfix_fixtures.mjs). Independent of the parser under test
 * (assets/js/lib/x509.js): certificates are encoded here and signed with node:crypto. Dev tool,
 * Node only.
 */
import { sign as cryptoSign } from 'node:crypto';

export const buf = (x) => (Buffer.isBuffer(x) ? x : Buffer.from(x));
export const encLen = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
};
export const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts.map(buf));
  return Buffer.concat([Buffer.from([tag]), encLen(body.length), body]);
};
export const seq = (...p) => tlv(0x30, ...p);
export const set = (...p) => tlv(0x31, ...[...p].map(buf).sort(Buffer.compare)); // DER SET OF ordering
export const ctx = (n, constructed, ...p) => tlv(0x80 | (constructed ? 0x20 : 0) | n, ...p);
export const oid = (s) => {
  const arcs = s.split('.').map(BigInt);
  const out = [];
  const push = (v) => {
    const bytes = [Number(v & 0x7fn)];
    for (let x = v >> 7n; x > 0n; x >>= 7n) bytes.unshift(Number(x & 0x7fn) | 0x80);
    out.push(...bytes);
  };
  push(arcs[0] * 40n + arcs[1]);
  arcs.slice(2).forEach(push);
  return tlv(0x06, Buffer.from(out));
};
export const int = (hex) => {
  let b = Buffer.from(hex.length % 2 ? `0${hex}` : hex, 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return tlv(0x02, b);
};
export const bool = (v) => tlv(0x01, Buffer.from([v ? 0xff : 0]));
export const nul = () => Buffer.from([0x05, 0x00]);
export const octet = (b) => tlv(0x04, b);
export const bits = (b, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), buf(b)]));
export const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
export const printable = (s) => tlv(0x13, Buffer.from(s, 'latin1'));
export const ia5 = (s) => tlv(0x16, Buffer.from(s, 'latin1'));
export const t61 = (s) => tlv(0x14, Buffer.from(s, 'latin1'));
export const numeric = (s) => tlv(0x12, Buffer.from(s, 'latin1'));
export const bmp = (s) => tlv(0x1e, Buffer.from(s, 'utf16le').swap16());
export const universal = (s) => tlv(0x1c, Buffer.concat(Array.from(s, (ch) => {
  const b = Buffer.alloc(4);
  b.writeUInt32BE(ch.codePointAt(0));
  return b;
})));
export const utc = (s) => tlv(0x17, Buffer.from(s, 'latin1'));
export const gen = (s) => tlv(0x18, Buffer.from(s, 'latin1'));
/** rdns: Array<Array<[oid, valueDer]>> in DER order */
export const name = (rdns) => seq(...rdns.map((rdn) => set(...rdn.map(([o, v]) => seq(oid(o), v)))));
export const ext = (o, value, critical = false) => seq(oid(o), ...(critical ? [bool(true)] : []), octet(value));

export const ALG = {
  sha256Rsa: seq(oid('1.2.840.113549.1.1.11'), nul()),
  ecdsa256: seq(oid('1.2.840.10045.4.3.2')),
  ecdsa384: seq(oid('1.2.840.10045.4.3.3')),
  ecdsa512: seq(oid('1.2.840.10045.4.3.4')),
  ed25519: seq(oid('1.3.101.112')),
  ed448: seq(oid('1.3.101.113')),
  dsa256: seq(oid('2.16.840.1.101.3.4.3.2'))
};

/** Attribute type OIDs of distinguished names. */
export const A = {
  C: '2.5.4.6', ST: '2.5.4.8', L: '2.5.4.7', O: '2.5.4.10', OU: '2.5.4.11', CN: '2.5.4.3',
  title: '2.5.4.12', description: '2.5.4.13', pseudonym: '2.5.4.65', name: '2.5.4.41', DC: '0.9.2342.19200300.100.1.25',
  email: '1.2.840.113549.1.9.1', UID: '0.9.2342.19200300.100.1.1', serialNumber: '2.5.4.5',
  x121: '2.5.4.24', postalAddress: '2.5.4.16', initials: '2.5.4.43'
};

export function buildCert({ version = 3, serial, sigAlg, issuer, notBefore, notAfter, subject, spki, issuerUid, subjectUid, extensions, signer }) {
  const tbs = seq(
    ...(version > 1 ? [ctx(0, true, int((version - 1).toString(16)))] : []),
    int(serial),
    sigAlg,
    issuer,
    seq(notBefore, notAfter),
    subject,
    spki,
    ...(issuerUid ? [ctx(1, false, Buffer.concat([Buffer.from([0]), issuerUid]))] : []),
    ...(subjectUid ? [ctx(2, false, Buffer.concat([Buffer.from([0]), subjectUid]))] : []),
    ...(extensions && extensions.length ? [ctx(3, true, seq(...extensions))] : [])
  );
  return seq(tbs, sigAlg, bits(signer(tbs)));
}

export const pem = (der) => `-----BEGIN CERTIFICATE-----\n${der.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
export const spkiOf = (key) => key.export({ type: 'spki', format: 'der' });
export const signWith = (privateKey, hash) => (tbs) => cryptoSign(hash, tbs, privateKey);
