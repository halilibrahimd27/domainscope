// Unit tests for the CSR part of assets/js/lib/x509.js (the Certificate view's "Does this CSR
// match?"): reading a pasted or loaded CSR, never a private key, and comparing public keys however
// they are encoded. Fixtures: tests/fixtures/bundle_* (gen_bundle_fixtures.sh: an RSA leaf for
// www.example.com and example.com with its CSR, an EC P-256 leaf for api.example.net with its CSR,
// and another key's CSR) and test.csr / test_csr.der (the CSR of rsa_multi_san.pem).
import { describe, test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  CSR_ERRORS, csrMatchesCertificate, looksLikePrivateKey, parseCertificateRequest, parseCertificates, pemEncode, publicKeyId
} from '../../assets/js/lib/x509.js';

const read = (f) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url));
const text = (f) => read(f).toString('utf8');
const leaf = (f) => parseCertificates(read(f)).leaf;
const csrOf = (f) => parseCertificateRequest(text(f)).csr;

describe('parseCertificateRequest', () => {
  test('a PEM CSR: subject, requested names, key', () => {
    const { csr, error } = parseCertificateRequest(text('bundle_leaf.csr'));
    assert.equal(error, null);
    assert.equal(csr.subjectDN, 'CN=www.example.com');
    assert.equal(csr.subjectCN, 'www.example.com');
    assert.deepEqual(csr.dnsNames, ['www.example.com', 'example.com']);
    assert.deepEqual(csr.hostnames, ['www.example.com', 'example.com']);
    assert.equal(csr.keyAlgorithm, 'RSA');
    assert.equal(csr.keyBits, 2048);
    assert.equal(csr.signatureAlgorithm, 'sha256WithRSAEncryption');
    const ec = csrOf('bundle_ec_leaf.csr');
    assert.deepEqual([ec.keyAlgorithm, ec.curve, ec.keyBits], ['EC', 'P-256', 256]);
  });

  test('DER, bytes, bare base64, NEW CERTIFICATE REQUEST, text around it and CRLF', () => {
    const der = read('test_csr.der');
    const fromDer = parseCertificateRequest(der).csr;
    assert.equal(fromDer.subjectDN, 'CN=www.example-test.com.tr,O=Ornek AS,C=TR');
    assert.deepEqual(parseCertificateRequest(new Uint8Array(der)).csr.spkiDer, fromDer.spkiDer);
    assert.equal(parseCertificateRequest(read('test.csr')).csr.subjectDN, fromDer.subjectDN, 'a file read as bytes');
    assert.equal(parseCertificateRequest(der.toString('base64')).csr.subjectDN, fromDer.subjectDN);
    const pem = pemEncode(der, 'NEW CERTIFICATE REQUEST').replace(/\n/g, '\r\n');
    assert.equal(parseCertificateRequest(`Hi, here is the CSR:\r\n\r\n${pem}\r\nThanks`).csr.subjectDN, fromDer.subjectDN);
    // the CN is the name when the request has no subjectAltName
    assert.deepEqual(fromDer.hostnames, ['www.example-test.com.tr']);
  });

  test('a private key is recognised and never read; other things say what they are', () => {
    for (const f of ['bundle_leaf.key', 'bundle_leaf.rsa.key', 'bundle_ec_leaf.key', 'bundle_leaf.enc.key']) {
      assert.deepEqual(parseCertificateRequest(text(f)), { csr: null, error: 'private-key' }, f);
    }
    const keyDer = Buffer.from(text('bundle_leaf.key').replace(/-----[^-]+-----|\s/g, ''), 'base64');
    assert.equal(parseCertificateRequest(keyDer).error, 'private-key', 'a DER key');
    assert.equal(parseCertificateRequest(text('bundle_leaf.pem')).error, 'certificate');
    assert.equal(parseCertificateRequest(read('rsa_multi_san.der')).error, 'certificate');
    assert.equal(parseCertificateRequest('').error, 'empty');
    assert.equal(parseCertificateRequest('   \n').error, 'empty');
    assert.equal(parseCertificateRequest('hello').error, 'not-csr');
    assert.equal(parseCertificateRequest('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----').error, 'not-csr');
    assert.equal(parseCertificateRequest('-----BEGIN CERTIFICATE REQUEST-----\n!!!\n-----END CERTIFICATE REQUEST-----').error, 'invalid');
    const cut = pemEncode(read('test_csr.der').subarray(0, 40), 'CERTIFICATE REQUEST');
    assert.equal(parseCertificateRequest(cut).error, 'not-csr');
    assert.equal(parseCertificateRequest(null).error, 'empty');
    for (const r of [parseCertificateRequest('x'), parseCertificateRequest(text('bundle_leaf.key'))]) assert.ok(CSR_ERRORS.includes(r.error));
  });
});

describe('looksLikePrivateKey (the CSR box drops a key as it lands)', () => {
  test('every private key PEM, a lone END line, a key’s bare base64', () => {
    for (const f of ['bundle_leaf.key', 'bundle_leaf.rsa.key', 'bundle_ec_leaf.key', 'bundle_ec_leaf.nopub.key', 'bundle_leaf.enc.key', 'bundle_other.key']) {
      assert.equal(looksLikePrivateKey(text(f)), true, f);
      assert.equal(looksLikePrivateKey(`﻿notes\r\n${text(f).replace(/\n/g, '\r\n')}`), true, `${f} with a BOM, CRLF and text around it`);
    }
    const legacy = '-----BEGIN RSA ' + 'PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00112233445566778899AABBCCDDEEFF\n\nAAAA\n';
    assert.equal(looksLikePrivateKey(legacy), true, 'the start of a legacy encrypted key');
    assert.equal(looksLikePrivateKey('-----BEGIN OPENSSH ' + 'PRIVATE KEY-----'), true, 'an OpenSSH key');
    assert.equal(looksLikePrivateKey('AAAA\n-----END PRIVATE KEY-----\n'), true, 'the end of a key only');
    for (const f of ['bundle_leaf.key', 'bundle_leaf.rsa.key', 'bundle_ec_leaf.key']) {
      assert.equal(looksLikePrivateKey(text(f).replace(/-----[^-]+-----/g, '')), true, `${f}: bare base64`);
    }
  });

  test('the first lines of a key’s bare base64 (a partial paste)', () => {
    const base64 = (f) => text(f).replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
    for (const f of ['bundle_leaf.key', 'bundle_leaf.rsa.key', 'bundle_ec_leaf.key', 'bundle_ec_leaf.nopub.key', 'bundle_leaf.enc.key', 'bundle_other.key']) {
      const b64 = base64(f);
      assert.ok(b64.length > 64, f);
      assert.equal(looksLikePrivateKey(b64.slice(0, 64)), true, `${f}: its first line`);
      const cut = b64.slice(0, -3);
      assert.equal(looksLikePrivateKey(`${cut.slice(0, 64)}\r\n${cut.slice(64)}`), true, `${f}: all but its last characters`);
    }
    // what is not a key stays: the first lines of a CSR, a certificate, a public key, a PKCS#12 file
    for (const f of ['bundle_leaf.csr', 'bundle_ec_leaf.csr', 'bundle_leaf.pem', 'bundle_root.pem', 'bundle_selfsigned_ca.pem']) {
      assert.equal(looksLikePrivateKey(`${base64(f).slice(0, 64)}\n${base64(f).slice(64, 128)}`), false, `${f}: two lines`);
    }
    const spki = parseCertificates(read('bundle_leaf.pem')).leaf.spkiDer;
    assert.equal(looksLikePrivateKey(Buffer.from(spki).toString('base64').slice(0, 64)), false, 'a public key’s first line');
    assert.equal(looksLikePrivateKey(read('p12_plain.p12').toString('base64').slice(0, 64)), false, 'a PKCS#12 file’s first line');
  });

  test('a CSR, a certificate, a public key or text is none', () => {
    for (const f of ['bundle_leaf.csr', 'bundle_ec_leaf.csr', 'bundle_leaf.pem']) assert.equal(looksLikePrivateKey(text(f)), false, f);
    assert.equal(looksLikePrivateKey(read('test_csr.der').toString('base64')), false, 'a CSR’s bare base64');
    assert.equal(looksLikePrivateKey(text('bundle_leaf.pem').replace(/-----[^-]+-----/g, '')), false, 'a certificate’s bare base64');
    assert.equal(looksLikePrivateKey('-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----'), false);
    for (const v of ['', '   ', 'MIIE', 'hello world', null, undefined]) assert.equal(looksLikePrivateKey(v), false, String(v));
  });
});

describe('publicKeyId and csrMatchesCertificate', () => {
  test('the CSR a certificate was issued from matches, another key does not', () => {
    const cert = leaf('bundle_leaf.pem');
    assert.deepEqual(csrMatchesCertificate(csrOf('bundle_leaf.csr'), cert), { match: true, missing: [], added: [] });
    const other = csrMatchesCertificate(csrOf('bundle_other.csr'), cert);
    assert.equal(other.match, false);
    assert.deepEqual(other.missing, ['shop.example.com']);
    assert.deepEqual(other.added, ['example.com']);
    assert.equal(csrMatchesCertificate(csrOf('bundle_ec_leaf.csr'), leaf('bundle_ec_leaf.pem')).match, true);
    assert.equal(csrMatchesCertificate(csrOf('bundle_ec_leaf.csr'), cert).match, false, 'EC vs RSA');
    // the CA added names the CSR did not ask for
    const tr = csrMatchesCertificate(parseCertificateRequest(read('test.csr')).csr, leaf('rsa_multi_san.pem'));
    assert.equal(tr.match, true);
    assert.ok(tr.added.includes('api.example-test.com.tr'));
    assert.equal(csrMatchesCertificate(null, cert).match, null);
  });

  test('one key whatever its encoding: RSA without leading zeros, EC compressed or not', () => {
    const cert = leaf('bundle_ec_leaf.pem');
    const id = publicKeyId(cert.spkiDer);
    assert.match(id, /^EC:1\.2\.840\.10045\.3\.1\.7:[0-9a-f]{64}:[01]$/);
    // the same point, compressed: 0x02 / 0x03 by the parity of y
    const spki = new Uint8Array(cert.spkiDer);
    const point = spki.subarray(spki.length - 65);
    assert.equal(point[0], 4);
    const x = point.subarray(1, 33);
    const parity = point[64] & 1;
    const prefix = spki.subarray(0, spki.length - 65 - 3);
    const compressed = Uint8Array.from([...prefix, 0x03, 34, 0, 2 + parity, ...x]);
    compressed[1] -= 32; // the outer SEQUENCE is 32 bytes shorter
    assert.equal(publicKeyId(compressed), id);
    const flipped = Uint8Array.from(compressed);
    flipped[flipped.length - 33] = 3 - parity;
    assert.notEqual(publicKeyId(flipped), id);
    assert.match(publicKeyId(leaf('bundle_leaf.pem').spkiDer), /^RSA:[0-9a-f]{512}:10001$/);
    assert.equal(publicKeyId(new Uint8Array([0x30, 0x00])), null);
    assert.equal(publicKeyId(null), null);
  });
});
