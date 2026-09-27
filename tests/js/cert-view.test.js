/**
 * views/cert.js pure helpers: the copy-ready `openssl s_client` command must never carry a
 * certificate name that is not a plain host name (a hostile SAN would run in the user's shell);
 * the bundled "Try a sample" certificate and the CertLoad of a Certificate Transparency lookup.
 * Pure Node (the view is DOM-free at import time). Names are documentation data only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  sClientHost, sClientCommand, SAMPLE_CERT_URL, loadSampleCert, ctCertLoad, dnDisplayName, analyzeChain
} from '../../assets/js/views/cert.js';
import { parseCertificate, parseCertificates } from '../../assets/js/lib/x509.js';
import { baseDomainsFromNames } from '../../assets/js/lib/domain.js';
import { caaIssuerInfo } from '../../assets/js/lib/health.js';

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

describe('cert view: the bundled sample certificate', () => {
  const SAMPLE = join(FIX, '..', '..', 'assets', 'data', 'sample-cert.pem');
  const text = readFileSync(SAMPLE, 'utf8');

  test('lives in assets/data (so the Pages bundle ships it) and is addressed relative to the module', () => {
    assert.equal(new URL(SAMPLE_CERT_URL).href, pathToFileURL(SAMPLE).href);
    assert.ok(!/PRIVATE KEY/.test(text), 'no key in the file');
  });

  test('a leaf for example.com / example.net and its intermediate, from a made-up CA, valid for years', () => {
    const r = parseCertificates(text, { now: new Date('2026-09-27T00:00:00Z') });
    assert.equal(r.certificates.length, 2);
    assert.deepEqual(r.warnings, []);
    const leaf = r.leaf;
    assert.deepEqual(leaf.hostnames, ['example.com', '*.example.com', 'example.net', 'www.example.net']);
    assert.deepEqual(baseDomainsFromNames(leaf.hostnames), ['example.com', 'example.net'], 'SSL Targets fills in only reserved domains');
    assert.deepEqual(leaf.ipAddresses, []);
    assert.equal(leaf.isCA, false);
    assert.equal(leaf.isPrecertificate, false);
    assert.deepEqual(leaf.extKeyUsage, ['serverAuth']);
    assert.equal(leaf.issuer.O, 'DomainScope Sample');
    assert.ok(leaf.notAfter >= new Date('2035-12-31T00:00:00Z'), 'does not expire on screen any time soon');
    assert.deepEqual(caaIssuerInfo(leaf.issuer), [], 'not a public CA: the CT tab never searches crt.sh for it by itself');
    const chain = analyzeChain(r.certificates, leaf);
    assert.deepEqual(chain.ordered.map((c) => c.subjectCN), ['example.com', 'DomainScope Sample Intermediate CA']);
    assert.deepEqual(chain.issues.map((i) => i.code), ['ends-at'], 'leaf + intermediate, the root left to trust stores');
  });

  test('loadSampleCert: a CertLoad with source "sample"', async () => {
    const urls = [];
    const fetchImpl = async (url) => {
      urls.push(String(url));
      return new Response(readFileSync(new URL(String(url))), { status: 200 });
    };
    const load = await loadSampleCert({ fetchImpl });
    assert.deepEqual(urls, [SAMPLE_CERT_URL]);
    assert.equal(load.source, 'sample');
    assert.equal(load.name, 'sample-cert.pem');
    assert.equal(load.result.leaf.subjectCN, 'example.com');
    await assert.rejects(loadSampleCert({ fetchImpl: async () => new Response('gone', { status: 404 }) }), { name: 'HttpError' });
  });
});

describe('cert view: a certificate from Certificate Transparency', () => {
  test('ctCertLoad: source "ct", named after the host, provenance kept', () => {
    const der = parseCertificates(readFileSync(join(FIX, 'ec_wildcard.pem'))).leaf.der;
    const issuance = { id: '17000000001', notBefore: new Date('2025-01-01T00:00:00Z'), notAfter: new Date('2051-01-01T00:00:00Z'), dnsNames: ['*.wild.example.net'], sha256: null, url: null };
    const load = ctCertLoad({ host: 'shop.wild.example.net', provider: 'certspotter', der, issuance, precertificate: false, newerPrecertificate: null, truncated: true });
    assert.equal(load.source, 'ct');
    assert.equal(load.name, 'shop.wild.example.net');
    assert.equal(load.result.leaf.subjectCN, '*.wild.example.net');
    assert.deepEqual(load.ct, { host: 'shop.wild.example.net', provider: 'certspotter', issuance, precertificate: false, newerPrecertificate: null, truncated: true });
  });

  test('dnDisplayName: "O (CN)" of a crt.sh issuer', () => {
    assert.equal(dnDisplayName('C=US, O=Example Trust, CN=Example CA R1'), 'Example Trust (Example CA R1)');
    assert.equal(dnDisplayName('C=US, O="Example, Inc.", CN=R1'), 'Example, Inc. (R1)');
    assert.equal(dnDisplayName('CN=Only CN'), 'Only CN');
    assert.equal(dnDisplayName('O=Same, CN=Same'), 'Same');
    assert.equal(dnDisplayName(''), '—');
  });
});
