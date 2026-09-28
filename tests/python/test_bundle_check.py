"""bundle-check: a certificate, its chain, private key and CSR checked together (stdlib unittest).

The fixtures come from tests/fixtures/gen_bundle_fixtures.sh: a throwaway root and intermediate
CA, an RSA leaf for www.example.com / example.com (its key as PKCS#8, PKCS#1 and encrypted
PKCS#8, its CSR) and an EC leaf for api.example.net (its SEC1 key with and without the public
point, its CSR), plus another key and CSR that belong to neither, and the self-signed CA:TRUE
certificate without subjectAltName that `openssl req -x509` makes by default.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import base64
import dataclasses
import os
import re
import stat
import tempfile
import unittest
from datetime import datetime, timezone
from typing import List

from test_ssl_origin_scan import FIXTURES, fixture_bytes, fixture_cert, run_main, sos

LEAF = fixture_cert('bundle_leaf.pem')
INTER = fixture_cert('bundle_inter.pem')
ROOT_CA = fixture_cert('bundle_root.pem')
EC_LEAF = fixture_cert('bundle_ec_leaf.pem')
SELF_CA = fixture_cert('bundle_selfsigned_ca.pem')


def items(*names: str) -> List:
    out = []
    for name in names:
        out.extend(sos.bundle_items(fixture_bytes(name), name))
    return out


def der_of(name: str) -> bytes:
    """The DER of a fixture's first PEM block."""
    text = fixture_bytes(name).decode('ascii')
    body = re.search(r'-----BEGIN [^-]+-----(.*?)-----END', text, re.S).group(1)
    return base64.b64decode(''.join(body.split()))


def statuses(result, topic=None):
    return [(c.status, c.topic) for c in result.checks if topic is None or c.topic == topic]


def texts(result) -> str:
    return '\n'.join(c.text for c in result.checks)


def key_body(name: str) -> str:
    """A long run of a key file's base64: must never reach the terminal."""
    lines = fixture_bytes(name).decode('ascii').splitlines()
    return lines[2]


class ClassifyTests(unittest.TestCase):

    def test_each_kind_of_file(self):
        found = {name: [(i.kind, i.key.format if i.key else None) for i in items(name)]
                 for name in ('bundle_leaf.pem', 'bundle_ca_reversed.pem', 'bundle_leaf.key',
                              'bundle_leaf.rsa.key', 'bundle_leaf.enc.key', 'bundle_ec_leaf.key',
                              'bundle_ec_leaf.nopub.key', 'bundle_leaf.csr', 'cli_bundle.p12')}
        self.assertEqual(found, {
            'bundle_leaf.pem': [('certificate', None)],
            'bundle_ca_reversed.pem': [('certificate', None), ('certificate', None)],
            'bundle_leaf.key': [('private-key', 'PKCS#8')],
            'bundle_leaf.rsa.key': [('private-key', 'PKCS#1')],
            'bundle_leaf.enc.key': [('private-key', 'encrypted PKCS#8')],
            'bundle_ec_leaf.key': [('private-key', 'SEC1')],
            'bundle_ec_leaf.nopub.key': [('private-key', 'SEC1')],
            'bundle_leaf.csr': [('csr', None)],
            'cli_bundle.p12': [('pkcs12', None)],
        })
        pkcs12 = items('cli_bundle.p12')[0]
        self.assertIn('openssl pkcs12', pkcs12.detail)

    def test_der_files_and_a_combined_pem(self):
        for name in ('bundle_leaf.pem', 'bundle_leaf.key', 'bundle_leaf.rsa.key', 'bundle_leaf.enc.key',
                     'bundle_ec_leaf.key', 'bundle_leaf.csr'):
            with self.subTest(fixture=name):
                pem_kind = [i.kind for i in items(name)]
                self.assertEqual([i.kind for i in sos.bundle_items(der_of(name), name + '.der')],
                                 pem_kind)
        der_key = sos.bundle_items(der_of('bundle_leaf.rsa.key'), 'key.der')[0]
        self.assertTrue(der_key.key.pem.startswith('-----BEGIN RSA ' + 'PRIVATE KEY-----\n'))
        combined = fixture_bytes('bundle_leaf.pem') + b'\r\nsome text\r\n' + fixture_bytes('bundle_leaf.key')
        self.assertEqual([i.kind for i in sos.bundle_items(combined, 'all.pem')],
                         ['certificate', 'private-key'])

    def test_encrypted_legacy_openssh_and_public_keys(self):
        legacy = ('-----BEGIN RSA ' + 'PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,'
                  '00112233445566778899AABBCCDDEEFF\n\nAAAA\n-----END RSA ' + 'PRIVATE KEY-----\n')
        item = sos.bundle_items(legacy, 'legacy.key')[0]
        self.assertEqual((item.kind, item.key.format, item.key.encrypted), ('private-key', 'encrypted PEM', True))
        ssh = '-----BEGIN OPENSSH ' + 'PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH ' + 'PRIVATE KEY-----\n'
        self.assertEqual(sos.bundle_items(ssh, 'id_ed25519')[0].kind, 'unknown')
        public = sos.pem_encode(LEAF.spki_der, 'PUBLIC KEY')
        item = sos.bundle_items(public, 'pub.pem')[0]
        self.assertEqual(item.kind, 'public-key')
        self.assertEqual(item.public_key, LEAF.public_key())
        self.assertEqual(sos.bundle_items('hello', 'notes.txt')[0].kind, 'unknown')
        self.assertEqual(sos.bundle_items(b'\x30\x03\x02\x01\x00', 'junk.der')[0].kind, 'unknown')

    def test_one_key_in_every_encoding_is_one_public_key(self):
        keys = [items(name)[0].key.public_key for name in ('bundle_leaf.key', 'bundle_leaf.rsa.key')]
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(keys[0], LEAF.public_key())
        self.assertEqual(keys[0].label(), 'RSA 2048')
        self.assertEqual(items('bundle_leaf.csr')[0].csr.public_key, LEAF.public_key())
        ec = items('bundle_ec_leaf.key')[0].key.public_key
        self.assertEqual(ec, EC_LEAF.public_key())
        self.assertEqual(ec.label(), 'EC P-256')
        # the same point compressed: the same key
        _algorithm, _bits, curve, ident = ec.algorithm, ec.bits, ec.curve, ec.ident
        x, parity = ident[2], ident[3]
        compressed = bytes([2 + parity]) + x.to_bytes(32, 'big')
        self.assertEqual(sos.ec_public_key('1.2.840.10045.3.1.7', compressed), ec)
        self.assertNotEqual(sos.ec_public_key('1.2.840.10045.3.1.7', bytes([3 - parity]) + x.to_bytes(32, 'big')), ec)
        self.assertNotEqual(items('bundle_other.key')[0].key.public_key, keys[0])
        self.assertNotIn('ident', repr(ec))  # the repr names the key type only

    def test_csr_subject_and_names(self):
        csr = items('bundle_leaf.csr')[0].csr
        self.assertEqual(csr.subject_dn, 'CN=www.example.com')
        self.assertEqual(csr.dns_names, ['www.example.com', 'example.com'])
        self.assertEqual(csr.signature_algorithm, 'sha256WithRSAEncryption')
        self.assertEqual(items('bundle_other.csr')[0].csr.dns_names, ['www.example.com', 'shop.example.com'])

    def test_certificates_carry_their_spki_hash_and_ca_issuers(self):
        self.assertEqual(LEAF.ca_issuers, ['http://ca.example.com/bundle-inter.crt'])
        self.assertRegex(LEAF.spki_sha256, r'^[0-9a-f]{64}$')
        self.assertEqual(LEAF.to_dict()['spkiSha256'], LEAF.spki_sha256)

    def test_key_usage_says_who_may_sign_certificates(self):
        self.assertEqual([c.key_cert_sign for c in (ROOT_CA, INTER, LEAF, SELF_CA)],
                         [True, True, False, None])  # None: no keyUsage extension at all
        self.assertEqual((SELF_CA.is_ca, SELF_CA.self_signed, SELF_CA.dns_names),
                         (True, True, []))


class CheckTests(unittest.TestCase):

    def test_everything_in_order(self):
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_inter.pem', 'bundle_leaf.key',
                                        'bundle_leaf.csr'))
        self.assertEqual(result.leaf, LEAF)
        self.assertEqual(statuses(result), [('OK', 'key'), ('OK', 'csr'), ('OK', 'chain')])
        self.assertEqual([c.sha256 for c in result.chain], [LEAF.sha256, INTER.sha256])
        self.assertTrue(result.complete)
        self.assertFalse(result.failed)
        self.assertIn('normal for a root the clients trust', texts(result))
        self.assertEqual(result.key.file, 'bundle_leaf.key')

    def test_a_reversed_ca_bundle_with_its_root(self):
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_ca_reversed.pem', 'bundle_leaf.rsa.key'))
        self.assertEqual([c.sha256 for c in result.chain], [LEAF.sha256, INTER.sha256, ROOT_CA.sha256])
        self.assertEqual([c.sha256 for c in result.fullchain], [LEAF.sha256, INTER.sha256])
        self.assertEqual([c.sha256 for c in result.intermediates], [INTER.sha256])
        self.assertIn(('WARN', 'root'), statuses(result))
        order = [c.text for c in result.checks if c.topic == 'order']
        self.assertEqual(len(order), 1)
        self.assertIn('bundle_ca_reversed.pem lists Example Test Bundle Root CA before Example Test '
                      'Bundle Intermediate CA', order[0])
        self.assertFalse(result.failed)

    def test_the_leaf_after_its_issuer_in_one_file(self):
        text = fixture_bytes('bundle_inter.pem') + fixture_bytes('bundle_leaf.pem')
        result = sos.check_bundle(sos.bundle_items(text, 'fullchain.pem'))
        self.assertEqual(result.leaf, LEAF)
        self.assertIn(('WARN', 'order'), statuses(result))

    def test_missing_intermediate(self):
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_leaf.key'))
        self.assertIn(('FAIL', 'chain'), statuses(result))
        self.assertIn('missing intermediate: no file holds Example Test Bundle Intermediate CA',
                      texts(result))
        self.assertIn('http://ca.example.com/bundle-inter.crt', texts(result))
        self.assertFalse(result.complete)
        self.assertTrue(result.failed)
        self.assertEqual(sos.bundle_outputs(result), [])

    def test_a_self_signed_certificate_has_no_chain(self):
        result = sos.check_bundle(items('cn_only.pem', 'cn_only.key'))
        self.assertEqual(statuses(result), [('OK', 'key'), ('OK', 'chain'), ('WARN', 'names')])
        self.assertIn('is self-signed: there is no chain to send', texts(result))
        # no subjectAltName: browsers look only there
        self.assertIn('legacy.example.org has no subjectAltName: browsers ignore the subject CN',
                      texts(result))
        self.assertIn('-addext "subjectAltName=DNS:legacy.example.org"', texts(result))
        self.assertFalse(result.failed)
        self.assertEqual([name for name, _t, _w in sos.bundle_outputs(result, haproxy=True)],
                         ['fullchain.pem', 'haproxy.pem'])

    def test_keys_that_do_not_belong_or_cannot_be_compared(self):
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_inter.pem', 'bundle_other.key',
                                        'bundle_leaf.enc.key', 'bundle_ec_leaf.nopub.key'))
        self.assertEqual(statuses(result, 'key'), [('FAIL', 'key'), ('SKIPPED', 'key'), ('SKIPPED', 'key')])
        text = texts(result)
        self.assertIn('bundle_other.key does not belong to the certificate www.example.com', text)
        self.assertIn('bundle_leaf.enc.key: encrypted key: cannot check without a password - skipped', text)
        self.assertIn('bundle_ec_leaf.nopub.key: the key file does not hold its public key', text)
        self.assertIsNone(result.key)
        self.assertTrue(result.failed)

    def test_a_key_that_belongs_to_another_certificate_of_the_files(self):
        ca_key = sos.BundleItem('ca.key', 'private-key', key=sos.PrivateKeyInfo(
            'PKCS#8', 'EC', INTER.public_key()))
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_inter.pem') + [ca_key])
        self.assertIn('ca.key belongs to Example Test Bundle Intermediate CA, not to the certificate '
                      'www.example.com', texts(result))

    def test_the_key_picks_the_leaf_among_several(self):
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_ec_leaf.pem', 'bundle_inter.pem',
                                        'bundle_ec_leaf.key'))
        self.assertEqual(result.leaf, EC_LEAF)
        self.assertIn('www.example.com (bundle_leaf.pem) is not part of the chain of api.example.net',
                      texts(result))
        self.assertEqual(statuses(result, 'other'), [('WARN', 'other')])

    def test_csr_against_the_certificate_and_the_key(self):
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_inter.pem', 'bundle_other.csr'))
        self.assertEqual(statuses(result, 'csr'), [('FAIL', 'csr')])
        self.assertIn('bundle_other.csr was made for another key', texts(result))
        more = sos.BundleItem('more.csr', 'csr', csr=sos.CsrInfo(
            'CN=www.example.com', 'www.example.com', ['www.example.com', 'shop.example.com'],
            LEAF.public_key(), 'sha256WithRSAEncryption'))
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_inter.pem') + [more])
        self.assertEqual(statuses(result, 'csr'), [('OK', 'csr'), ('WARN', 'csr')])
        self.assertIn('asks for names the certificate does not have: shop.example.com', texts(result))
        # no certificate: the CSR against the key, the chain skipped (checked before ordering)
        result = sos.check_bundle(items('bundle_leaf.key', 'bundle_leaf.csr', 'bundle_other.csr'))
        self.assertEqual(statuses(result), [('OK', 'csr'), ('FAIL', 'csr'), ('SKIPPED', 'chain')])
        self.assertIn('bundle_leaf.csr was made with the private key bundle_leaf.key', texts(result))
        self.assertIn('bundle_other.csr was not made with the private key bundle_leaf.key', texts(result))
        self.assertIn('no certificate in these files: only the private key and the CSR were compared',
                      texts(result))
        self.assertTrue(result.failed)  # by the CSR made with another key, not by the chain
        result = sos.check_bundle(items('bundle_leaf.csr', 'bundle_leaf.key'))
        self.assertEqual(statuses(result), [('OK', 'csr'), ('SKIPPED', 'chain')])
        self.assertFalse(result.failed)
        self.assertEqual(sos.bundle_outputs(result, haproxy=True), [])
        # nothing compared: a CSR alone, a key alone, an encrypted key, CA certificates besides
        for names in (('bundle_leaf.csr',), ('bundle_leaf.key',), ('bundle_leaf.enc.key', 'bundle_leaf.csr'),
                      ('bundle_inter.pem', 'bundle_leaf.key', 'bundle_leaf.csr')):
            with self.subTest(files=names):
                result = sos.check_bundle(items(*names))
                self.assertIn(('FAIL', 'chain'), statuses(result))
                self.assertTrue(result.failed)

    def test_ca_certificates_without_the_server_certificate(self):
        for names in (('bundle_ca_reversed.pem',), ('bundle_inter.pem', 'bundle_root.pem'),
                      ('bundle_inter.pem', 'bundle_root.pem', 'bundle_leaf.key')):
            with self.subTest(files=names):
                result = sos.check_bundle(items(*names))
                self.assertIsNone(result.leaf)
                self.assertIn(('FAIL', 'chain'), statuses(result))
                self.assertIn('no server certificate in these files, only CA certificates', texts(result))
                self.assertTrue(result.failed)
                self.assertFalse(result.complete)
                self.assertEqual(sos.bundle_outputs(result, haproxy=True), [])
        result = sos.check_bundle(items('bundle_inter.pem', 'bundle_root.pem', 'bundle_leaf.key'))
        self.assertIn('bundle_leaf.key: no server certificate to compare it with', texts(result))

    def test_a_self_signed_ca_certificate_that_names_hosts_is_the_leaf(self):
        # `openssl req -x509` marks what it makes CA:TRUE: a server certificate all the same
        result = sos.check_bundle(items('many_sans.pem'))
        self.assertEqual(result.leaf.subject_cn, 'bulk.example.com')
        self.assertEqual(statuses(result), [('OK', 'chain'), ('WARN', 'chain')])
        self.assertIn('MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY', texts(result))
        self.assertEqual([name for name, _t, _w in sos.bundle_outputs(result)], ['fullchain.pem'])
        # a root with its key in the files: the server's own CA-marked certificate
        root_key = sos.BundleItem('root.key', 'private-key', key=sos.PrivateKeyInfo(
            'SEC1', 'EC', ROOT_CA.public_key()))
        result = sos.check_bundle(items('bundle_root.pem') + [root_key])
        self.assertEqual(result.leaf, ROOT_CA)
        self.assertEqual(result.key, root_key)

    def test_what_openssl_req_x509_makes_by_default_is_the_leaf(self):
        # CA:TRUE, a host name as CN, no keyUsage and no subjectAltName, checked alone
        result = sos.check_bundle(items('bundle_selfsigned_ca.pem'))
        self.assertEqual(result.leaf, SELF_CA)
        self.assertEqual(statuses(result), [('OK', 'chain'), ('WARN', 'chain'), ('WARN', 'names')])
        text = texts(result)
        self.assertIn('MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY', text)
        self.assertIn('www.example.com has no subjectAltName', text)
        self.assertNotIn('only CA certificates', text)
        self.assertEqual([name for name, _t, _w in sos.bundle_outputs(result)], ['fullchain.pem'])
        # a CA with a host name as CN that may sign certificates stays a CA: no leaf
        signing = dataclasses.replace(ROOT_CA, subject_cn='ca.example.com')
        self.assertEqual((signing.hostnames, signing.key_cert_sign), (['ca.example.com'], True))
        result = sos.check_bundle([sos.BundleItem('ca.pem', 'certificate', cert=signing)])
        self.assertIsNone(result.leaf)
        self.assertIn('only CA certificates (ca.example.com)', texts(result))
        # without keyUsage (or without keyCertSign in it) it is the server's own certificate
        for usage in (None, False):
            plain = dataclasses.replace(signing, key_cert_sign=usage)
            result = sos.check_bundle([sos.BundleItem('ca.pem', 'certificate', cert=plain)])
            self.assertEqual(result.leaf, plain, usage)
        # a root whose CN is no host name is never the leaf alone
        self.assertIsNone(sos.check_bundle(items('bundle_root.pem')).leaf)

    def test_a_p7b_file_holds_no_order(self):
        p7b = items('cli_chain_p7b.pem')
        self.assertEqual([i.cert.subject_cn for i in p7b], ['Subdomain Scanner Test Root CA',
                                                            'www.example-test.com.tr'])
        self.assertTrue(all(i.pkcs7 for i in p7b))
        result = sos.check_bundle(p7b)
        self.assertEqual(statuses(result, 'order'), [])
        # the same certificates in that order in a PEM file: an order the file chose
        pem = ''.join(sos.pem_encode(i.cert.der) for i in p7b)
        result = sos.check_bundle(sos.bundle_items(pem, 'bundle.pem'))
        self.assertEqual(statuses(result, 'order'), [('WARN', 'order')])

    def test_openssl_ecparam_output_and_other_blocks(self):
        params = '-----BEGIN EC PARAMETERS-----\nBggqhkjOPQMBBw==\n-----END EC PARAMETERS-----\n'
        found = sos.bundle_items(params + fixture_bytes('bundle_ec_leaf.key').decode('ascii'), 'ec.key')
        self.assertEqual([i.kind for i in found], ['private-key'])
        dh = sos.bundle_items('-----BEGIN DH PARAMETERS-----\nMAA=\n-----END DH PARAMETERS-----\n', 'dh.pem')
        self.assertEqual([(i.kind, i.detail) for i in dh], [('unknown', 'a PEM block labelled DH PARAMETERS')])

    def test_an_ed25519_key_without_its_public_key(self):
        # PKCS#8 as `openssl genpkey -algorithm ed25519` writes it: no public key (a made-up seed)
        der = bytes.fromhex('302e020100300506032b657004220420') + bytes(range(32))
        key = sos.bundle_items(der, 'ed.key')[0].key
        self.assertEqual((key.algorithm, key.public_key), ('Ed25519', None))
        self.assertIn('Ed25519 key files usually do not hold the public key', key.note)
        self.assertNotIn('usually do)', key.note)
        self.assertIn('EC keys usually do', items('bundle_ec_leaf.nopub.key')[0].key.note)

    def test_expired_certificates(self):
        later = datetime(2051, 1, 1, tzinfo=timezone.utc)
        result = sos.check_bundle(items('bundle_leaf.pem', 'bundle_inter.pem'), now=later)
        expiry = [c for c in result.checks if c.topic == 'expiry']
        self.assertEqual([c.status for c in expiry], ['FAIL', 'WARN'])
        self.assertIn('www.example.com expired on 2050-01-01', expiry[0].text)


class RenderTests(unittest.TestCase):

    def test_hostile_certificate_and_file_text_is_escaped(self):
        # the AIA URL of the leaf patched in place (same length: the DER stays well formed)
        url = b'http://ca.example.com/bundle-inter.crt'
        evil = b'http://\x1b[2J\x1b]0;PWN\x07\x1b[31m.example.com/'
        evil += b'x' * (len(url) - len(evil))
        der = LEAF.der.replace(url, evil)
        self.assertEqual(len(der), len(LEAF.der))
        result = sos.check_bundle(sos.bundle_items(der, 'aia\x1b[2J.der') + items('bundle_leaf.key'))
        self.assertIn(('FAIL', 'chain'), statuses(result))  # the missing intermediate and its hint
        text = sos.render_bundle(result, written=[('out\x07/fullchain.pem', 'the certificate')],
                                 notes=['Nothing written to out\x1b[0m.'])
        self.assertNotIn('\x1b', text)
        self.assertNotIn('\x07', text)
        self.assertIn('aia\\x1b[2J.der', text)
        self.assertIn('http://\\x1b[2J\\x1b]0;PWN\\x07\\x1b[31m.example.com/', ' '.join(text.split()))

    def test_a_long_file_name_gets_a_line_of_its_own(self):
        long_dir = '/etc/letsencrypt/live/www.example.com-0001/archive'
        found = (sos.bundle_items(fixture_bytes('bundle_leaf.pem'), long_dir + '/cert1.pem')
                 + sos.bundle_items(fixture_bytes('bundle_ca_reversed.pem'), long_dir + '/chain1.pem')
                 + items('bundle_leaf.key'))
        text = sos.render_bundle(sos.check_bundle(found), width=80)
        lines = text.splitlines()
        self.assertEqual([len(line) for line in lines if len(line) > 80], [])
        self.assertIn('  %s/chain1.pem' % long_dir, lines)
        at = lines.index('  %s/chain1.pem' % long_dir)
        self.assertTrue(lines[at + 1].startswith('    certificate (root): Example Test Bundle Root CA'))
        # a short name keeps its column
        self.assertTrue(any(line.startswith('  bundle_leaf.key  private key:') for line in lines), text)

    def test_a_self_signed_leaf_is_labelled_so_not_as_a_root(self):
        text = sos.render_bundle(sos.check_bundle(items('bundle_selfsigned_ca.pem')), width=120)
        self.assertIn('bundle_selfsigned_ca.pem  certificate (self-signed): www.example.com', text)
        self.assertNotIn('(root)', text)
        text = sos.render_bundle(sos.check_bundle(items('bundle_ca_reversed.pem')), width=120)
        self.assertIn('certificate (root): Example Test Bundle Root CA', text)


class BundleCliTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_check(self, *args: str):
        files = [str(FIXTURES / a) if not a.startswith('-') and os.sep not in a
                 and (FIXTURES / a).exists() else a for a in args]
        return run_main('bundle-check', *files)

    def test_writes_fullchain_and_chain_in_order(self):
        code, out, err = self.run_check('bundle_ca_reversed.pem', 'bundle_leaf.pem', 'bundle_leaf.key',
                                        '-o', self.tmp.name)
        self.assertEqual(code, 0, err)
        with open(os.path.join(self.tmp.name, 'fullchain.pem'), encoding='ascii') as handle:
            fullchain = handle.read()
        with open(os.path.join(self.tmp.name, 'chain.pem'), encoding='ascii') as handle:
            chain = handle.read()
        self.assertEqual(fullchain, sos.pem_encode(LEAF.der) + sos.pem_encode(INTER.der))
        self.assertEqual(chain, sos.pem_encode(INTER.der))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, 'haproxy.pem')))
        self.assertNotIn('PRIVATE KEY', fullchain)
        text = ' '.join(out.split())
        self.assertIn('Bundle check: 3 files', text)
        self.assertIn('private key: RSA 2048, PKCS#8, unencrypted', text)
        self.assertIn('fullchain.pem (the certificate + 1 intermediate)', text)
        self.assertIn('extra root', text)

    def test_haproxy_pem_holds_the_key_and_says_so(self):
        code, out, err = self.run_check('bundle_leaf.pem', 'bundle_inter.pem', 'bundle_leaf.rsa.key',
                                        '-o', self.tmp.name, '--write-haproxy')
        self.assertEqual(code, 0, err)
        path = os.path.join(self.tmp.name, 'haproxy.pem')
        with open(path, encoding='ascii') as handle:
            haproxy = handle.read()
        key = fixture_bytes('bundle_leaf.rsa.key').decode('ascii').replace('\r\n', '\n')
        self.assertEqual(haproxy, sos.pem_encode(LEAF.der) + sos.pem_encode(INTER.der) + key)
        if os.name != 'nt':
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertIn('haproxy.pem holds the private key', ' '.join(out.split()))
        for name in ('bundle_leaf.rsa.key',):
            self.assertNotIn(key_body(name), out + err)

    def test_key_material_is_never_printed(self):
        names = ('bundle_leaf.key', 'bundle_leaf.rsa.key', 'bundle_leaf.enc.key', 'bundle_ec_leaf.key',
                 'bundle_ec_leaf.nopub.key', 'bundle_other.key')
        code, out, err = self.run_check('bundle_leaf.pem', 'bundle_inter.pem', *names)
        self.assertEqual(code, 1, err)  # bundle_other.key does not belong
        for name in names:
            self.assertNotIn(key_body(name), out + err, name)
        self.assertNotIn('PRIVATE KEY-----', out + err)

    def test_haproxy_without_a_matching_key_fails(self):
        code, out, err = self.run_check('bundle_leaf.pem', 'bundle_inter.pem', 'bundle_leaf.enc.key',
                                        '-o', self.tmp.name, '--write-haproxy')
        self.assertEqual(code, 1, err)
        self.assertIn('haproxy.pem not written', ' '.join(out.split()))
        self.assertFalse(os.path.exists(os.path.join(self.tmp.name, 'haproxy.pem')))
        self.assertTrue(os.path.exists(os.path.join(self.tmp.name, 'fullchain.pem')))

    def test_a_key_and_its_csr_before_ordering_pass(self):
        code, out, err = self.run_check('bundle_leaf.key', 'bundle_leaf.csr', '-o', self.tmp.name)
        self.assertEqual(code, 0, out + err)
        text = ' '.join(out.split())
        self.assertIn('bundle_leaf.csr was made with the private key', text)
        self.assertIn('SKIPPED no certificate in these files: only the private key and the CSR were '
                      'compared', text)
        self.assertIn('Nothing written to', text)
        self.assertEqual(os.listdir(self.tmp.name), [])
        self.assertEqual(self.run_check('bundle_other.key', 'bundle_leaf.csr')[0], 1)

    def test_a_file_given_twice_is_read_once(self):
        code, out, err = self.run_check('bundle_leaf.pem', 'bundle_inter.pem', 'bundle_leaf.key',
                                        'bundle_leaf.pem', 'bundle_leaf.key')
        self.assertEqual(code, 0, err)
        self.assertIn('Bundle check: 3 files', out)
        self.assertEqual(out.count('private key: RSA 2048'), 1, out)
        self.assertEqual(out.count('belongs to the certificate'), 1, out)
        text = ' '.join(out.split())
        self.assertEqual(text.count('was given twice: read once.'), 2, out)
        self.assertIn('bundle_leaf.key was given twice: read once.', text)

    def test_options_before_the_word(self):
        # an alias that adds --no-color: moved after the word
        code, out, err = run_main('--no-color', 'bundle-check', str(FIXTURES / 'bundle_leaf.pem'),
                                  str(FIXTURES / 'bundle_inter.pem'))
        self.assertEqual(code, 0, err)
        self.assertIn('Bundle check: 2 files', out)
        self.assertNotIn('\x1b[', out)
        # an option of the scan before it: the usage error says where the word goes
        code, out, err = run_main('-p', '443', 'bundle-check', str(FIXTURES / 'bundle_leaf.pem'))
        self.assertEqual(code, 2)
        self.assertEqual(out, '')
        self.assertIn('bundle-check must be the first argument', err)
        # the word as the value of an option is the scan's
        code, _out, err = run_main('--timeout', '1', '-n', 'bundle-check')
        self.assertEqual(code, 2)
        self.assertIn('-t/--targets', err)

    def test_nothing_is_written_for_an_incomplete_chain(self):
        code, out, _err = self.run_check('bundle_leaf.pem', 'bundle_leaf.key', '-o', self.tmp.name)
        self.assertEqual(code, 1)
        self.assertEqual(os.listdir(self.tmp.name), [])
        self.assertIn('Nothing written', out)

    def test_ca_certificates_alone_write_nothing(self):
        for names in (('bundle_ca_reversed.pem',), ('bundle_inter.pem', 'bundle_root.pem')):
            with self.subTest(files=names):
                code, out, _err = self.run_check(*names, '-o', self.tmp.name, '--write-haproxy')
                self.assertEqual(code, 1)
                self.assertEqual(os.listdir(self.tmp.name), [])
                text = ' '.join(out.split())
                self.assertIn('no server certificate in these files', text)
                self.assertIn('no server certificate.', text)

    def test_usage_errors_and_a_file_that_cannot_be_written(self):
        self.assertEqual(self.run_check('bundle_leaf.pem', '--write-haproxy')[0], 2)
        code, _out, err = self.run_check('bundle_leaf.pem', '-o', os.path.join(self.tmp.name, 'nope'))
        self.assertEqual(code, 2)
        self.assertIn('directory does not exist', err)
        code, _out, err = self.run_check(os.path.join(self.tmp.name, 'missing.pem'))
        self.assertEqual(code, 2)
        self.assertIn('cannot read', err)
        self.assertEqual(run_main('bundle-check')[0], 2)  # no file at all
        os.mkdir(os.path.join(self.tmp.name, 'chain.pem'))
        code, _out, err = self.run_check('bundle_leaf.pem', 'bundle_inter.pem', '-o', self.tmp.name)
        self.assertEqual(code, 3, err)
        self.assertIn('cannot write', err)

    def test_help_and_the_scan_still_needs_targets(self):
        code, out, _err = run_main('bundle-check', '--help')
        self.assertEqual(code, 0)
        text = ' '.join(out.split())
        for needle in ('fullchain.pem', 'missing intermediate', 'extra root', '--write-haproxy',
                       'sertifikayı, zincirini'):
            self.assertIn(needle, text)
        code, _out, err = run_main()
        self.assertEqual(code, 2)
        self.assertIn('-t/--targets', err)


if __name__ == '__main__':
    unittest.main()
