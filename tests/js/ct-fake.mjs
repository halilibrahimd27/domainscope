/**
 * tests/js/ct-fake.mjs — Certificate Transparency answers for the tests of the portfolio's CT watch
 * (tests/js/ctwatch.test.js, tests/e2e/portfolio.e2e.mjs, tests/e2e/revocation.e2e.mjs): Cert Spotter
 * rows in the shape the live API returned on 2026-10-08 (`expand=dns_names&expand=issuer
 * &expand=cert_der&expand=revocation&expand=problem_reporting`), with crafted DER
 * (a serial of its own; a precertificate carries the critical CT poison extension), and crt.sh rows
 * in the shape lib/sources.js parses (`deduplicate=Y`). Documentation names only.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCertificates } from '../../assets/js/lib/x509.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

/** The issuer DN the rows carry unless told otherwise. */
export const CT_ISSUER = 'C=US, O=Example Trust, CN=Example CA R1';

const encLen = (n) => {
  if (n < 0x80) return Buffer.from([n]);
  const b = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) b.unshift(v & 0xff);
  return Buffer.from([0x80 | b.length, ...b]);
};
const tlv = (tag, ...parts) => {
  const body = Buffer.concat(parts.map((p) => (Buffer.isBuffer(p) ? p : Buffer.from(p))));
  return Buffer.concat([Buffer.from([tag]), encLen(body.length), body]);
};
const seq = (...p) => tlv(0x30, ...p);
const set = (...p) => tlv(0x31, ...p);
const ctx = (n, constructed, ...p) => tlv(0x80 | (constructed ? 0x20 : 0) | n, ...p);
const oid = (s) => {
  const arcs = s.split('.').map(Number);
  const out = [arcs[0] * 40 + arcs[1]];
  for (const a of arcs.slice(2)) {
    const bytes = [a & 0x7f];
    for (let x = a >> 7; x > 0; x >>= 7) bytes.unshift((x & 0x7f) | 0x80);
    out.push(...bytes);
  }
  return tlv(0x06, Buffer.from(out));
};
const utf8 = (s) => tlv(0x0c, Buffer.from(s, 'utf8'));
const cn = (value) => seq(set(seq(oid('2.5.4.3'), utf8(value))));
const SHA256_RSA = seq(oid('1.2.840.113549.1.1.11'), Buffer.from([0x05, 0x00]));
const SPKI = Buffer.from(parseCertificates(readFileSync(join(FIX, 'rsa_multi_san.der'))).leaf.spkiDer);
const utcTime = (d) => d.toISOString().replace(/^\d\d(\d\d)-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d).*$/, '$1$2$3$4$5$6Z');

/**
 * DER of a certificate for `names` (dNSName SANs), valid notBefore → notAfter, with a one-byte
 * serial (1 … 127); `precert` adds the critical CT poison extension.
 * @returns {Buffer}
 */
export function certDer({ names, notBefore, notAfter, serial = 1, precert = false }) {
  const exts = [seq(oid('2.5.29.17'), tlv(0x04, seq(...names.map((n) => ctx(2, false, Buffer.from(n, 'latin1'))))))];
  if (precert) exts.push(seq(oid('1.3.6.1.4.1.11129.2.4.3'), tlv(0x01, Buffer.from([0xff])), tlv(0x04, Buffer.from([0x05, 0x00]))));
  const tbs = seq(
    ctx(0, true, tlv(0x02, Buffer.from([2]))),
    tlv(0x02, Buffer.from([serial])),
    SHA256_RSA,
    cn('Example CA R1'),
    seq(tlv(0x17, Buffer.from(utcTime(new Date(notBefore)))), tlv(0x17, Buffer.from(utcTime(new Date(notAfter))))),
    cn(names[0].replace(/^\*\./, 'wild.')),
    SPKI,
    ctx(3, true, seq(...exts))
  );
  return seq(tbs, SHA256_RSA, tlv(0x03, Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 0xab)])));
}

let nextId = 17390000000;

/** The CA's problem-reporting text of the fake rows (the shape of a real CA's, documentation names only). */
export const CT_PROBLEM_REPORTING = 'To revoke a certificate issued by Example Trust for which you hold the private key, use:\n'
  + '  · https://revoke.example.com/portal\n\nTo report abuse or a misissued certificate, e-mail:\n  · abuse[at]example[dot]com';

/**
 * A Cert Spotter issuance as the live API returns it. `revokedAt` / `reason` (an RFC 5280 code):
 * the `expand=revocation` object of a revoked certificate (`revoked` true); `problemReporting`:
 * `expand=problem_reporting` (the CA's text; null leaves both expansions out, as before 2026-10-08).
 * @returns {object}
 */
export function spotterRow({ names, notBefore = '2026-08-01T00:00:00Z', notAfter = '2026-10-30T00:00:00Z', precert = false, revoked = false, serial = 1,
  issuer = CT_ISSUER, friendly = 'Example Trust', der, revokedAt = null, reason = null, checkedAt = '2026-10-08T06:00:00Z',
  problemReporting = CT_PROBLEM_REPORTING } = {}) {
  nextId += 1;
  const isRevoked = revoked || revokedAt !== null;
  return {
    id: String(nextId),
    tbs_sha256: 'ab'.repeat(32),
    cert_sha256: (nextId % 256).toString(16).padStart(2, '0').repeat(32),
    dns_names: names,
    pubkey_sha256: 'ef'.repeat(32),
    issuer: { friendly_name: friendly, pubkey_sha256: '12'.repeat(32), name: issuer },
    not_before: notBefore,
    not_after: notAfter,
    revoked: isRevoked,
    ...(problemReporting === null ? {} : {
      revocation: { time: isRevoked ? revokedAt : null, reason: isRevoked ? reason : null, checked_at: checkedAt },
      problem_reporting: problemReporting
    }),
    cert_der: Buffer.from(der || certDer({ names, notBefore, notAfter, precert, serial })).toString('base64')
  };
}

/** The id of the last {@link spotterRow}. */
export const lastSpotterId = () => String(nextId);

/**
 * A crt.sh row (`deduplicate=Y`), dates as crt.sh writes them (UTC without a zone).
 * @returns {object}
 */
export function crtshRow({ id, names, notBefore = '2026-08-01T00:00:00', notAfter = '2026-10-30T00:00:00', serial = '01', issuer = CT_ISSUER }) {
  return {
    issuer_ca_id: 7, issuer_name: issuer, common_name: names[0], name_value: names.join('\n'), id, entry_timestamp: notBefore,
    not_before: notBefore, not_after: notAfter, serial_number: serial, result_count: 2
  };
}
