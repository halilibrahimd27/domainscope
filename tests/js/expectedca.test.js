/**
 * lib/expectedca.js — a workspace's expected CAs against certificate issuers and CAA issuer
 * domains: known CAs by name, id or CAA identifier (with their brands), private CAs by text, and
 * no badge without an expectation. Real certificate fixtures where there is one. No DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolveExpectedCa, expectedCaStatus, expectedCaaStatus } from '../../assets/js/lib/expectedca.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const LE = { C: 'US', O: "Let's Encrypt", CN: 'R11' };
const ZEROSSL = 'CN=ZeroSSL RSA Domain Secure Site CA,O=ZeroSSL,C=AT';
const GTS = 'CN=WE1,O=Google Trust Services,C=US';

describe('resolveExpectedCa', () => {
  test('a CA by its name, id or any of its CAA identifiers; a brand of it too', () => {
    for (const entry of ["Let's Encrypt", 'lets encrypt', 'letsencrypt', 'letsencrypt.org', 'LETSENCRYPT.ORG.', 'ISRG']) {
      assert.equal(resolveExpectedCa(entry).ca?.id, 'letsencrypt', entry);
    }
    assert.equal(resolveExpectedCa('digicert.com').ca.id, 'digicert');
    assert.equal(resolveExpectedCa('RapidSSL').ca.id, 'digicert', 'a DigiCert brand');
    assert.equal(resolveExpectedCa('ZeroSSL').ca.id, 'sectigo', 'issued from Sectigo intermediates');
    assert.equal(resolveExpectedCa('pki.goog').ca.id, 'google');
  });

  test('anything else is a private CA, matched as text', () => {
    assert.deepEqual(resolveExpectedCa('  Example   Corp Internal CA '), { entry: '  Example   Corp Internal CA ', ca: null, needle: 'example corp internal ca' });
    assert.deepEqual(resolveExpectedCa(''), { entry: '', ca: null, needle: null });
  });
});

describe('expectedCaStatus (a certificate issuer)', () => {
  test('no expectation, or no issuer: no badge', () => {
    assert.equal(expectedCaStatus(LE, []), null);
    assert.equal(expectedCaStatus(LE, ['', '  ']), null);
    assert.equal(expectedCaStatus(LE, undefined), null);
    assert.equal(expectedCaStatus('', ["Let's Encrypt"]), null);
    assert.equal(expectedCaStatus(null, ["Let's Encrypt"]), null);
  });

  test('a known CA, from a parsed issuer or a DN, by any entry that names it', () => {
    assert.deepEqual(expectedCaStatus(LE, ['letsencrypt.org']), { expected: true, entry: 'letsencrypt.org', ca: "Let's Encrypt" });
    assert.deepEqual(expectedCaStatus("CN=R11,O=Let's Encrypt,C=US", ['DigiCert', "Let's Encrypt"]), { expected: true, entry: "Let's Encrypt", ca: "Let's Encrypt" });
    assert.deepEqual(expectedCaStatus(ZEROSSL, ['Sectigo']), { expected: true, entry: 'Sectigo', ca: 'Sectigo' });
  });

  test('another CA is unexpected, and named', () => {
    assert.deepEqual(expectedCaStatus(GTS, ["Let's Encrypt"]), { expected: false, entry: null, ca: 'Google Trust Services' });
    assert.deepEqual(expectedCaStatus(LE, ['Sectigo', 'digicert.com']), { expected: false, entry: null, ca: "Let's Encrypt" });
  });

  test('a private CA by part of its name; an unknown issuer without a match is unexpected, unnamed', () => {
    const own = 'CN=Example Corp Issuing CA 2,O=Example Corp,C=TR';
    assert.deepEqual(expectedCaStatus(own, ['example corp issuing']), { expected: true, entry: 'example corp issuing', ca: null });
    assert.deepEqual(expectedCaStatus(own, ["Let's Encrypt"]), { expected: false, entry: null, ca: null });
  });

  test('real certificates: the fixtures\' test CA and a public one', () => {
    const leaf = parseCertificates(readFileSync(join(FIXTURES, 'rsa_multi_san.pem'))).leaf;
    const ca = parseCertificates(readFileSync(join(FIXTURES, 'ca.pem'))).leaf;
    const own = ca.subject.CN;
    assert.equal(expectedCaStatus(leaf.issuer, [own]).expected, true, `issued by ${own}`);
    assert.equal(expectedCaStatus(leaf.issuerDN, ["Let's Encrypt"]).expected, false);
    const github = parseCertificates(readFileSync(join(FIXTURES, 'real_github.pem'))).leaf;
    const status = expectedCaStatus(github.issuer, ['Sectigo']);
    assert.equal(status.ca, 'Sectigo');
    assert.equal(status.expected, true);
  });
});

describe('expectedCaaStatus (a CAA issuer domain)', () => {
  test('a known CA matches by any of its identifiers; others are unexpected', () => {
    assert.deepEqual(expectedCaaStatus('letsencrypt.org', ["Let's Encrypt"]), { expected: true, entry: "Let's Encrypt" });
    assert.deepEqual(expectedCaaStatus('comodoca.com', ['sectigo.com']), { expected: true, entry: 'sectigo.com' });
    assert.deepEqual(expectedCaaStatus('digicert.com', ["Let's Encrypt"]), { expected: false, entry: null });
    assert.deepEqual(expectedCaaStatus('LetsEncrypt.org.', ['letsencrypt']), { expected: true, entry: 'letsencrypt' });
  });

  test('a private CA\'s identifier must be written out; no expectation, no badge', () => {
    assert.deepEqual(expectedCaaStatus('ca.example.net', ['ca.example.net']), { expected: true, entry: 'ca.example.net' });
    assert.deepEqual(expectedCaaStatus('ca.example.net', ['example']), { expected: false, entry: null });
    assert.equal(expectedCaaStatus('letsencrypt.org', []), null);
    assert.equal(expectedCaaStatus('', ['x']), null);
  });
});
