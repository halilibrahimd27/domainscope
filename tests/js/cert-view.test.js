/**
 * views/cert.js pure helpers: the copy-ready `openssl s_client` command must never carry a
 * certificate name that is not a plain host name (a hostile SAN would run in the user's shell).
 * Pure Node (the view is DOM-free at import time). Names are documentation data only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { sClientHost, sClientCommand } from '../../assets/js/views/cert.js';
import { parseCertificate, parseCertificates } from '../../assets/js/lib/x509.js';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

// Minimal DER builder (the tests/js/x509.test.js pattern) for a certificate with crafted SANs.
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

/** A certificate whose SAN holds `names` as raw (latin1) dNSName bytes. */
function certWithSans(...names) {
  const san = seq(oid('2.5.29.17'), tlv(0x04, seq(...names.map((n) => ctx(2, false, Buffer.from(n, 'latin1'))))));
  const tbs = seq(
    ctx(0, true, tlv(0x02, Buffer.from([2]))),
    tlv(0x02, Buffer.from([1])),
    SHA256_RSA,
    cn('Test Issuer'),
    seq(tlv(0x17, Buffer.from('250101000000Z')), tlv(0x17, Buffer.from('350101000000Z'))),
    cn('test.example.com'),
    SPKI,
    ctx(3, true, seq(san))
  );
  return parseCertificate(seq(tbs, SHA256_RSA, tlv(0x03, Buffer.concat([Buffer.from([0]), Buffer.alloc(16, 0xab)]))));
}

const SAFE = /^openssl s_client -connect [a-z0-9_.-]+:443 -servername [a-z0-9_.-]+ -showcerts <\/dev\/null$/;

describe('cert view: the openssl s_client command', () => {
  test('a plain certificate keeps its first name (unchanged output)', () => {
    assert.equal(sClientHost(['www.example.com', 'example.com']), 'www.example.com');
    assert.equal(sClientCommand(['www.example.com']),
      'openssl s_client -connect www.example.com:443 -servername www.example.com -showcerts </dev/null');
    assert.equal(sClientHost(['*.example.com', 'api.example.com']), 'api.example.com', 'an exact name before a wildcard');
    assert.equal(sClientHost(['*.example.com']), 'www.example.com', 'a wildcard-only certificate');
    assert.equal(sClientHost(['_svc.example.com']), '_svc.example.com');
    assert.equal(sClientHost(['xn--mnchen-3ya.example.com']), 'xn--mnchen-3ya.example.com');
    assert.equal(sClientHost([]), 'example.com');
    assert.equal(sClientHost(undefined), 'example.com');
  });

  test('a hostile name is skipped, never pasted into the command', () => {
    const cases = [
      [['shop.example.com;touch /tmp/pwned;.example.com', 'shop.example.com'], 'shop.example.com'],
      [['a.example.com\rtouch x\r.example.com'], 'example.com'],
      [['a.example.com\ntouch x'], 'example.com'],
      [['$(id).example.com', '*.cdn.example.com'], 'www.cdn.example.com'],
      [['`id`.example.com'], 'example.com'],
      [["x'y.example.com"], 'example.com'],
      [['a b.example.com'], 'example.com'],
      [['-oproxycommand=x.example.com', 'ok.example.com'], 'ok.example.com'],
      [['example.com/;id', 'good.example.net'], 'good.example.net'],
      [['a.example.com:443', 'b.example.com'], 'b.example.com'],
      [['x@a.example.com'], 'example.com'],
      [['*.a;b.example.com'], 'example.com']
    ];
    for (const [names, want] of cases) {
      assert.equal(sClientHost(names), want, JSON.stringify(names));
      assert.match(sClientCommand(names), SAFE, JSON.stringify(names));
    }
  });

  test('end to end: SAN bytes from a crafted certificate', () => {
    const hostile = certWithSans('shop.example.com;touch /tmp/pwned;.example.com', 'shop.example.com');
    // The parser keeps non-conforming SAN bytes on purpose, so the command builder must validate.
    assert.equal(hostile.hostnames[0], 'shop.example.com;touch /tmp/pwned;.example.com');
    assert.equal(sClientCommand(hostile.hostnames),
      'openssl s_client -connect shop.example.com:443 -servername shop.example.com -showcerts </dev/null');
    for (const cert of [
      certWithSans('a.example.com\rtouch x\r.example.com'),
      certWithSans('$(id).example.com'),
      certWithSans('`id`.example.com'),
      certWithSans('a b.example.com'),
      certWithSans('-o.example.com')
    ]) {
      assert.match(sClientCommand(cert.hostnames), SAFE, JSON.stringify(cert.hostnames));
      assert.equal(sClientHost(cert.hostnames), 'example.com', JSON.stringify(cert.hostnames));
    }
  });
});
