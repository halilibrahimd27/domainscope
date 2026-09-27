"""ORIGIN_CERT / PRIVATE_CERT and targets with their own port (stdlib unittest; no network).

The CLI tells a Cloudflare Origin CA certificate (ORIGIN_CERT) and a self-signed or
--private-ca one (PRIVATE_CERT) apart from a certificate that still needs replacing
(NEEDS_UPDATE), and scans an address written with a port (203.0.113.10:8443,
[2001:db8::1]:8443, web01.example.net:8443) on that port instead of -p. The fixtures come
from tests/fixtures/gen_cli_kind_fixtures.sh (a throwaway PKI; the "CloudFlare" DN is on a
test key) plus the two real Cloudflare Origin CA roots.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import os
import tempfile
import unittest
from typing import Dict, List, Optional, Tuple

from test_ssl_origin_scan import (FIXTURES, FakeNetwork, TlsServer, _free_port, fixture_bytes,
                                  fixture_cert, read_json, run_main, sos)

X509_EXPECTED = json.loads((FIXTURES / 'x509_expected.json').read_text(encoding='utf-8'))
PUBLIC = fixture_cert('cli_public_wild.pem')        # issued by a CA nobody lists: kind "other"
ORIGIN = fixture_cert('cli_origin_wild.pem')        # the Origin CA issuer DN, a test key
PRIVATE = fixture_cert('cli_private_wild.pem')      # issued by cli_private_ca.pem
PRIVATE_CA = fixture_cert('cli_private_ca.pem')
REKEYED_CA = fixture_cert('cli_private_ca_rekeyed.pem')  # same DN, another key
SELF_SIGNED = fixture_cert('ec_wildcard.pem')
RENEWED = fixture_cert('cli_renewed_wild.pem')      # self-signed as well
NAMES = ['a.wild.example.net', 'wild.example.net']


def all_certs(name: str):
    certs, warnings = sos.load_certificates(fixture_bytes(name))
    assert certs, (name, warnings)
    return certs


# ============================================================================ certificates

class KeyIdentifierTests(unittest.TestCase):
    """SubjectKeyIdentifier / AuthorityKeyIdentifier against OpenSSL (x509_expected.json)."""

    def test_key_identifiers_match_openssl(self):
        checked = 0
        for label, expected in X509_EXPECTED.items():
            name, _, index = label.partition('#')
            certs = all_certs(name)
            cert = certs[int(index)] if index else certs[0]
            with self.subTest(fixture=label):
                self.assertEqual(cert.subject_key_id, expected['subjectKeyId'])
                self.assertEqual(cert.authority_key_id, expected['authorityKeyId'])
            checked += 1
        self.assertGreaterEqual(checked, 20)

    def test_self_signed_needs_matching_key_identifiers(self):
        self.assertTrue(SELF_SIGNED.self_signed)
        self.assertTrue(PRIVATE_CA.self_signed)
        self.assertFalse(PRIVATE.self_signed)
        self.assertEqual(PRIVATE.authority_key_id, PRIVATE_CA.subject_key_id)
        self.assertNotEqual(REKEYED_CA.subject_key_id, PRIVATE_CA.subject_key_id)
        data = PRIVATE_CA.to_dict()
        self.assertEqual(data['subjectKeyId'], PRIVATE_CA.subject_key_id)
        self.assertEqual(data['authorityKeyId'], PRIVATE_CA.authority_key_id)


class CertificateKindTests(unittest.TestCase):

    def test_the_real_origin_ca_roots_are_recognised(self):
        # Checked 2026-09-27: neither root has a CN; O + OU name the Origin CA.
        for name, ou in (('cloudflare_origin_ca_rsa.pem',
                          'CloudFlare Origin SSL Certificate Authority'),
                         ('cloudflare_origin_ca_ecc.pem',
                          'CloudFlare Origin SSL ECC Certificate Authority')):
            root = fixture_cert(name)
            with self.subTest(root=name):
                self.assertIsNone(root.issuer_cn)
                self.assertEqual(root.issuer['O'], 'CloudFlare, Inc.')
                self.assertEqual(root.issuer['OU'], ou)
                self.assertTrue(sos.is_origin_ca_certificate(root))
                self.assertEqual(sos.certificate_kind(root), (sos.KIND_ORIGIN_CA, None))

    def test_kinds(self):
        self.assertEqual(sos.certificate_kind(ORIGIN), (sos.KIND_ORIGIN_CA, None))
        self.assertEqual(sos.certificate_kind(SELF_SIGNED), (sos.KIND_SELF_SIGNED, None))
        self.assertEqual(sos.certificate_kind(PUBLIC), (sos.KIND_OTHER, None))
        self.assertEqual(sos.certificate_kind(fixture_cert('real_cloudflare.pem')),
                         (sos.KIND_OTHER, None), "Cloudflare's own edge certificate is public")
        # a private CA counts only when listed, and only with the right key identifier
        self.assertEqual(sos.certificate_kind(PRIVATE), (sos.KIND_OTHER, None))
        self.assertEqual(sos.certificate_kind(PRIVATE, [PRIVATE_CA]),
                         (sos.KIND_PRIVATE_CA, PRIVATE_CA))
        self.assertEqual(sos.certificate_kind(PRIVATE, [REKEYED_CA]), (sos.KIND_OTHER, None))
        self.assertEqual(sos.certificate_kind(PRIVATE, [REKEYED_CA, PRIVATE_CA])[1], PRIVATE_CA)

    def test_origin_match_is_case_insensitive_but_needs_org_and_name(self):
        base = ORIGIN

        def with_issuer(**attrs):
            return dataclasses.replace(base, issuer=attrs)

        self.assertTrue(sos.is_origin_ca_certificate(with_issuer(
            O='Cloudflare, Inc.', OU='cloudflare origin ssl ecc certificate authority')))
        self.assertTrue(sos.is_origin_ca_certificate(with_issuer(
            O='CloudFlare, Inc.', CN='CloudFlare Origin SSL Certificate Authority')))
        self.assertFalse(sos.is_origin_ca_certificate(with_issuer(
            O='Cloudflare, Inc.', CN='Cloudflare Inc ECC CA-3')))   # public edge CA
        self.assertFalse(sos.is_origin_ca_certificate(with_issuer(
            O='Example Corp', OU='CloudFlare Origin SSL Certificate Authority')))

    def test_issuer_dn_comparison_ignores_case_and_spacing(self):
        spaced = dataclasses.replace(PRIVATE, issuer_dn='cn=example  internal test ca,'
                                                        'o=EXAMPLE CORP', authority_key_id=None)
        self.assertTrue(sos.issued_by(spaced, PRIVATE_CA))
        self.assertTrue(sos.issued_by(spaced, REKEYED_CA), 'no AKI: the DN decides')


class HostedClassifierTests(unittest.TestCase):

    def status(self, served, new=(), cas=(), strict=False):
        return sos.HostedClassifier(new, cas, strict).status(served)

    def test_a_public_rollout_keeps_origin_and_private_certificates_apart(self):
        self.assertEqual(self.status(ORIGIN, [PUBLIC]), sos.ORIGIN_CERT)
        self.assertEqual(self.status(SELF_SIGNED, [PUBLIC]), sos.PRIVATE_CERT)
        self.assertEqual(self.status(PRIVATE, [PUBLIC], [PRIVATE_CA]), sos.PRIVATE_CERT)
        self.assertEqual(self.status(PRIVATE, [PUBLIC]), sos.NEEDS_UPDATE, 'CA not listed')
        self.assertEqual(self.status(fixture_cert('real_cloudflare.pem'), [PUBLIC]),
                         sos.NEEDS_UPDATE)

    def test_strict_public_counts_every_one(self):
        for served in (ORIGIN, SELF_SIGNED, PRIVATE):
            self.assertEqual(self.status(served, [PUBLIC], [PRIVATE_CA], strict=True),
                             sos.NEEDS_UPDATE)

    def test_a_rollout_of_the_same_kind_still_needs_the_new_certificate(self):
        self.assertEqual(self.status(ORIGIN, [ORIGIN]), sos.NEEDS_UPDATE)  # Origin CA renewal
        self.assertEqual(self.status(SELF_SIGNED, [RENEWED]), sos.NEEDS_UPDATE)
        self.assertEqual(self.status(PRIVATE, [RENEWED], [PRIVATE_CA]), sos.NEEDS_UPDATE,
                         'self-signed and private-CA certificates are one family')
        self.assertEqual(self.status(SELF_SIGNED, [PRIVATE], [PRIVATE_CA]), sos.NEEDS_UPDATE)
        # but another kind keeps its status
        self.assertEqual(self.status(ORIGIN, [RENEWED]), sos.ORIGIN_CERT)
        self.assertEqual(self.status(SELF_SIGNED, [ORIGIN]), sos.PRIVATE_CERT)

    def test_same_issuer_as_the_new_certificate_is_never_apart(self):
        # a self-signed certificate whose issuer DN is the new one's issuer
        twin = dataclasses.replace(SELF_SIGNED, issuer_dn=PUBLIC.issuer_dn, sha256='00' * 32)
        self.assertEqual(self.status(twin, [PUBLIC]), sos.NEEDS_UPDATE)

    def test_without_a_new_certificate(self):
        self.assertEqual(self.status(ORIGIN), sos.ORIGIN_CERT)
        self.assertEqual(self.status(SELF_SIGNED), sos.PRIVATE_CERT)
        self.assertEqual(self.status(PUBLIC), sos.NEEDS_UPDATE)


class LoadPrivateCaTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name: str, data: bytes) -> str:
        path = os.path.join(self.tmp.name, name)
        with open(path, 'wb') as handle:
            handle.write(data)
        return path

    def test_every_certificate_of_every_file_counts(self):
        bundle = self.write('bundle.pem', fixture_bytes('cli_private_ca.pem')
                            + fixture_bytes('cli_private_ca_rekeyed.pem'))
        cas, messages = sos.load_private_cas([bundle, str(FIXTURES / 'cli_private_ca.pem')])
        self.assertEqual([ca.sha256 for ca in cas], [PRIVATE_CA.sha256, REKEYED_CA.sha256])
        self.assertEqual(messages, [])

    def test_warnings_and_errors(self):
        cas, messages = sos.load_private_cas([str(FIXTURES / 'cli_private_wild.pem')])
        self.assertEqual(len(cas), 1)
        self.assertIn('is not a CA certificate', messages[0])
        with_key = self.write('ca+key.pem', fixture_bytes('cli_private_ca.pem')
                              + fixture_bytes('cli_private_wild.key'))
        _cas, messages = sos.load_private_cas([with_key])
        self.assertTrue(any('PRIVATE KEY - ignored' in m for m in messages), messages)
        empty = self.write('notes.txt', b'nothing here\n')
        with self.assertRaisesRegex(sos.UsageError, 'no certificate found'):
            sos.load_private_cas([empty])
        with self.assertRaisesRegex(sos.UsageError, 'cannot read --private-ca'):
            sos.load_private_cas([os.path.join(self.tmp.name, 'missing.pem')])


def kinds_network(extra: Optional[Dict[str, object]] = None) -> FakeNetwork:
    tls = {'10.0.0.1': lambda sni: ORIGIN.der, '10.0.0.2': lambda sni: SELF_SIGNED.der,
           '10.0.0.3': lambda sni: PRIVATE.der, '10.0.0.4': lambda sni: PUBLIC.der,
           '10.0.0.5': lambda sni: fixture_cert('cn_only.pem').der}
    tls.update(extra or {})
    return FakeNetwork({}, tls)


KIND_SERVERS = [('origin', '10.0.0.1'), ('selfsigned', '10.0.0.2'), ('internal', '10.0.0.3'),
                ('new', '10.0.0.4'), ('elsewhere', '10.0.0.5')]


def kinds_scan(new=(PUBLIC,), cas=(PRIVATE_CA,), strict=False, names=NAMES, network=None):
    network = network or kinds_network()
    servers = [sos.Server(name, [ip]) for name, ip in KIND_SERVERS]
    return sos.run_scan(servers, sos.build_probe_names(names), [443], new_certs=list(new),
                        timeout=1, workers=4, connect_fn=network.connect_fn,
                        tls_fn=network.tls_fn, private_cas=list(cas), strict_public=strict)


class EngineKindTests(unittest.TestCase):

    def statuses(self, report) -> Dict[str, str]:
        return {s.server.name: s.status for s in report.server_summaries()}

    def test_rows_servers_and_the_exit_code_rule(self):
        report = kinds_scan()
        rows = {(r.server, r.probe): r.status for r in report.results if r.name == NAMES[0]
                or r.probe == sos.PROBE_DEFAULT}
        self.assertEqual(rows[('origin', sos.PROBE_SNI)], sos.ORIGIN_CERT)
        self.assertEqual(rows[('origin', sos.PROBE_DEFAULT)], sos.ORIGIN_CERT)
        self.assertEqual(rows[('selfsigned', sos.PROBE_SNI)], sos.PRIVATE_CERT)
        self.assertEqual(rows[('internal', sos.PROBE_SNI)], sos.PRIVATE_CERT)
        self.assertEqual(rows[('new', sos.PROBE_SNI)], sos.UPDATED)
        self.assertEqual(self.statuses(report), {
            'origin': sos.ORIGIN_CERT, 'selfsigned': sos.PRIVATE_CERT,
            'internal': sos.PRIVATE_CERT, 'new': sos.UPDATED, 'elsewhere': sos.NOT_HOSTED})
        self.assertFalse(report.needs_update())
        counts = report.status_counts()
        self.assertEqual((counts[sos.ORIGIN_CERT], counts[sos.PRIVATE_CERT]), (2, 4))

    def test_strict_public_and_an_unlisted_ca(self):
        strict = kinds_scan(strict=True)
        self.assertEqual(self.statuses(strict)['origin'], sos.NEEDS_UPDATE)
        self.assertEqual(self.statuses(strict)['internal'], sos.NEEDS_UPDATE)
        self.assertTrue(strict.needs_update())
        unlisted = kinds_scan(cas=())
        self.assertEqual(self.statuses(unlisted)['internal'], sos.NEEDS_UPDATE)
        self.assertEqual(self.statuses(unlisted)['selfsigned'], sos.PRIVATE_CERT)

    def test_roll_up_order(self):
        def rows(*statuses, covers=True):
            return [sos.ProbeResult('s', '10.0.0.1', 443, sos.PROBE_SNI, 'n%d.example.com' % i,
                                    'n%d.example.com' % i, status, new_cert_covers=covers)
                    for i, status in enumerate(statuses)]
        self.assertEqual(sos.server_status(rows(sos.ORIGIN_CERT, sos.NEEDS_UPDATE)),
                         sos.NEEDS_UPDATE)
        self.assertEqual(sos.server_status(rows(sos.ORIGIN_CERT, sos.UPDATED)), sos.UPDATED)
        self.assertEqual(sos.server_status(rows(sos.PRIVATE_CERT, sos.ORIGIN_CERT)),
                         sos.ORIGIN_CERT)
        self.assertEqual(sos.server_status(rows(sos.PRIVATE_CERT, sos.TLS_ERROR)),
                         sos.PRIVATE_CERT)
        self.assertEqual(sos.server_status(rows(sos.ORIGIN_CERT, covers=False)), sos.NOT_HOSTED,
                         'a name outside the new certificate does not count')

    def test_json_csv_and_summary(self):
        report = kinds_scan()
        doc = json.loads(sos.render_json(report))
        servers = {s['name']: s for s in doc['servers']}
        self.assertEqual(servers['origin']['originCert'], NAMES)
        self.assertEqual(servers['internal']['privateCert'], NAMES)
        self.assertEqual(servers['origin']['needsUpdate'], [])
        self.assertEqual(servers['origin']['ports'], {})
        self.assertEqual((doc['summary']['serversWithOriginCert'],
                          doc['summary']['serversWithPrivateCert'],
                          doc['summary']['serversNeedingUpdate']), (1, 2, 0))
        self.assertEqual(doc['summary']['statusCounts']['ORIGIN_CERT'], 2)
        self.assertEqual(doc['options']['strictPublic'], False)
        self.assertEqual(doc['options']['privateCa'], [{
            'subjectDN': PRIVATE_CA.subject_dn, 'sha256': PRIVATE_CA.sha256,
            'subjectKeyId': PRIVATE_CA.subject_key_id}])
        certs = doc['certificates']
        self.assertEqual(certs[ORIGIN.sha256]['kind'], 'origin-ca')
        self.assertEqual(certs[SELF_SIGNED.sha256]['kind'], 'self-signed')
        self.assertEqual(certs[PRIVATE.sha256]['kind'], 'private-ca')
        self.assertEqual(certs[PRIVATE.sha256]['privateCa'], PRIVATE_CA.subject_dn)
        self.assertEqual(certs[PUBLIC.sha256]['kind'], 'other')
        self.assertIsNone(certs[PUBLIC.sha256]['privateCa'])

        records = list(csv.DictReader(io.StringIO(sos.render_csv(report).lstrip('\ufeff'))))
        self.assertEqual({r['status'] for r in records if r['server'] == 'origin'},
                         {'ORIGIN_CERT'})
        self.assertEqual(list(records[0]), list(sos.CSV_COLUMNS), 'the columns are unchanged')

        text = sos.render_summary(report, width=100)
        flat = ' '.join(text.split())  # the explanations wrap
        self.assertIn('Servers that need the new certificate: 0', text)
        self.assertIn('Serving a Cloudflare Origin CA certificate: 1', text)
        self.assertIn('Only Cloudflare trusts a Cloudflare Origin CA certificate: right for an '
                      'origin behind Cloudflare Full (strict)', flat)
        self.assertIn('Serving a self-signed or private-CA certificate: 2', text)
        self.assertIn('usual on internal hosts', flat)
        self.assertIn('--strict-public counts them as NEEDS_UPDATE', flat)
        self.assertIn('ORIGIN_CERT   a.wild.example.net, wild.example.net  (Cloudflare Origin CA)',
                      text)
        self.assertIn('PRIVATE_CERT  a.wild.example.net, wild.example.net  (self-signed)', text)
        self.assertIn('(private CA: Example Internal Test CA)', text)
        self.assertIn('Private CAs (--private-ca): Example Internal Test CA', text)
        self.assertIn('default certificate (no SNI): ORIGIN_CERT', text)
        self.assertIn('Results (server/port/name): NEEDS_UPDATE 0, UPDATED 2, ORIGIN_CERT 2, '
                      'PRIVATE_CERT 4, NOT_HOSTED 2', text)
        order = [text.index(t) for t in ('need the new', 'Already serving', 'Origin CA cert',
                                         'self-signed or private-CA cert')]
        self.assertEqual(order, sorted(order))

        strict = sos.render_summary(kinds_scan(strict=True))
        self.assertIn('NEEDS_UPDATE  a.wild.example.net, wild.example.net  (Cloudflare Origin CA)',
                      strict)
        self.assertNotIn('Serving a Cloudflare Origin CA certificate', strict)
        plain = sos.render_summary(kinds_scan(new=(), cas=()))
        self.assertNotIn('--strict-public counts', ' '.join(plain.split()))
        self.assertIn('Servers hosting the names: 2', plain)  # "new" and the unlisted CA's

    def test_a_certificate_the_new_one_does_not_cover(self):
        report = kinds_scan(names=['www.example-test.com.tr'] + NAMES, network=kinds_network(
            {'10.0.0.1': lambda sni: (fixture_cert('rsa_multi_san.pem').der
                                      if sni and sni.startswith('www.') else ORIGIN.der)}))
        text = sos.render_summary(report)
        self.assertIn('ORIGIN_CERT   a.wild.example.net', text)
        doc = json.loads(sos.render_json(report))
        origin = next(s for s in doc['servers'] if s['name'] == 'origin')
        self.assertEqual(origin['hostedNotInNewCert'], ['www.example-test.com.tr'])


# ================================================================== targets with a port

class SplitEndpointTests(unittest.TestCase):

    def test_forms(self):
        cases = {
            '203.0.113.10:8443': ('203.0.113.10', 8443),
            '[2001:db8::1]:8443': ('2001:db8::1', 8443),
            '[2001:DB8:0::1]:443': ('2001:db8::1', 443),
            '[203.0.113.10]:8443': ('203.0.113.10', 8443),
            '[2001:db8::1]': ('2001:db8::1', None),
            '203.0.113.10:': ('203.0.113.10', None),
            'web01.example.net:8443': ('web01.example.net', 8443),
            'web01:08443': ('web01', 8443),
        }
        for token, want in cases.items():
            with self.subTest(token=token):
                self.assertEqual(sos.split_endpoint(token), want)
        for token in ('203.0.113.10', '2001:db8::1:8443', 'web01.example.net', 'web01:',
                      'ansible_host: web', '[prod]', 'C:/inventory.txt', 'x.example.net:https'):
            with self.subTest(token=token):
                self.assertIsNone(sos.split_endpoint(token))

    def test_errors(self):
        for token, message in (('203.0.113.10:0', 'outside 1-65535'),
                               ('203.0.113.10:65536', 'outside 1-65535'),
                               ('[2001:db8::1]:https', 'not a port number'),
                               ('203.0.113.10:8443x', 'not a port number'),
                               ('203.0.113.300:443', 'not a valid IP address'),
                               ('010.0.0.1:443', 'not a valid IP address'),
                               ('[2001:db8::zz]:443', 'not a valid IP address'),
                               ('203.0.113.0/24:443', 'CIDR or IP range'),
                               ('203.0.113.5-9:443', 'CIDR or IP range')):
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, message):
                    sos.split_endpoint(token)

    def test_format_endpoint(self):
        self.assertEqual(sos.format_endpoint('203.0.113.10', 8443), '203.0.113.10:8443')
        self.assertEqual(sos.format_endpoint('2001:db8::1', 8443), '[2001:db8::1]:8443')
        self.assertEqual(sos.format_endpoint('2001:db8::1', None), '2001:db8::1')


def by_name(inventory) -> Dict[str, Tuple[List[str], List[str], Dict]]:
    return {s.name: (list(s.ips), list(s.hostnames), dict(s.ports)) for s in inventory.servers}


class InventoryPortTests(unittest.TestCase):

    def test_lines(self):
        inventory = sos.parse_inventory('\n'.join([
            'web01 203.0.113.10:8443',
            '[2001:db8::1]:8443',
            'web02 203.0.113.11 203.0.113.11:9443',
            '203.0.113.12:8443 web03',
            'web04 web04.example.net:8443',
            'web05.example.net:8443',
            '203.0.113.13: gateway-box',
            '[prod]',
            'web06 203.0.113.16:8443',
        ]), 'inv.txt')
        self.assertEqual(inventory.warnings, [])
        self.assertEqual(by_name(inventory), {
            'web01': (['203.0.113.10'], [], {'203.0.113.10': [8443]}),
            '2001:db8::1': (['2001:db8::1'], [], {'2001:db8::1': [8443]}),
            'web02': (['203.0.113.11'], [], {'203.0.113.11': [None, 9443]}),
            'web03': (['203.0.113.12'], [], {'203.0.113.12': [8443]}),
            'web04': ([], ['web04.example.net'], {'web04.example.net': [8443]}),
            'web05.example.net': ([], ['web05.example.net'], {'web05.example.net': [8443]}),
            'gateway-box': (['203.0.113.13'], [], {}),
            'web06': (['203.0.113.16'], [], {'203.0.113.16': [8443]}),
        })
        self.assertEqual(inventory.servers[-1].groups, ['prod'])

    def test_a_token_that_cannot_be_read_is_a_warning_never_dropped_silently(self):
        inventory = sos.parse_inventory('\n'.join([
            'web01 203.0.113.10:99999',
            'web02 [2001:db8::2]:https',
            'web03 203.0.113.0/24:8443',
            'web04.example.net:8443 203.0.113.14',
            'web05 203.0.113.15 203.0.113.15:0',
        ]), 'inv.txt')
        warnings = [(w.line, w.code, w.text) for w in inventory.warnings]
        self.assertEqual([w[:2] for w in warnings], [(1, 'INVALID_IP'), (2, 'INVALID_IP'),
                                                     (3, 'INVALID_IP'), (4, 'PARSE'),
                                                     (5, 'INVALID_IP')])
        self.assertIn('port 99999 is outside 1-65535', warnings[0][2])
        self.assertIn('a server name takes no port', warnings[3][2])
        # a mistyped port never makes "web01" a host name to resolve
        self.assertEqual(by_name(inventory), {
            'web04.example.net': (['203.0.113.14'], [], {}),
            'web05': (['203.0.113.15'], [], {}),
        })

    def test_a_host_name_with_a_port_next_to_an_address_is_a_warning(self):
        inventory = sos.parse_inventory('\n'.join([
            'web01 203.0.113.10 db.example.net:5432',
            'web02 203.0.113.11 web02.example.net:8443',
            'web03 203.0.113.12 web03.example.net',
            'web04 web04.example.net:8443',
        ]), 'inv.txt')
        warnings = [(w.line, w.code, w.text) for w in inventory.warnings]
        self.assertEqual([w[:2] for w in warnings], [(1, 'PARSE'), (2, 'PARSE')])
        self.assertTrue(warnings[0][2].startswith('db.example.net:5432: a host name with a port '
                                                  'next to an address is not resolved'))
        self.assertIn('ADDRESS:PORT', warnings[1][2])
        # the address is kept; a host name without a port there is a hosts-file alias, as before
        self.assertEqual(by_name(inventory), {
            'web01': (['203.0.113.10'], [], {}),
            'web02': (['203.0.113.11'], [], {}),
            'web03': (['203.0.113.12'], [], {}),
            'web04': ([], ['web04.example.net'], {'web04.example.net': [8443]}),
        })

    def test_name_equals_host_as_the_first_token_is_a_target_as_with_t(self):
        inventory = sos.parse_inventory('\n'.join([
            'web01=web01.example.net:8443',
            'web02=web02.example.net',
            'web03=web03.example.net:8443 203.0.113.13',
            'user=root',
            'version=1.2',
            'timeout=30',
            'web04=2026092401:8443',
        ]), 'inv.txt')
        self.assertEqual(by_name(inventory), {
            'web01': ([], ['web01.example.net'], {'web01.example.net': [8443]}),
            'web02': ([], ['web02.example.net'], {}),
            'web03': (['203.0.113.13'], [], {}),
        })
        self.assertEqual([(w.line, w.code) for w in inventory.warnings],
                         [(3, 'PARSE'), (7, 'INVALID_IP')])
        self.assertIn('reads it as the IPv4 address', inventory.warnings[1].text)
        # the same token on the command line
        self.assertEqual(by_name(sos.parse_target_tokens('web01=web01.example.net:8443')),
                         by_name(sos.parse_inventory('web01=web01.example.net:8443', 'inv.txt')))

    def test_a_time_of_day_is_no_host_and_port(self):
        inventory = sos.parse_inventory('backup 10:30 203.0.113.10\nweb01 203.0.113.11 12:00\n'
                                        'web02 203.0.113.12 10:30:00\n', 'inv.txt')
        self.assertEqual(inventory.warnings, [])
        self.assertEqual(by_name(inventory), {'backup': (['203.0.113.10'], [], {}),
                                              'web01': (['203.0.113.11'], [], {}),
                                              'web02': (['203.0.113.12'], [], {})})
        with self.assertRaisesRegex(sos.UsageError, 'invalid target'):
            sos.parse_target_tokens('10:30')

    def test_csv_json_and_yaml(self):
        csv_inv = sos.parse_inventory('name,ip\nweb01,203.0.113.10:8443\n'
                                      '203.0.113.11:9443,\n', 'x.csv')
        self.assertEqual(by_name(csv_inv), {
            'web01': (['203.0.113.10'], [], {'203.0.113.10': [8443]}),
            '203.0.113.11': (['203.0.113.11'], [], {'203.0.113.11': [9443]})})
        json_inv = sos.parse_inventory(json.dumps([
            {'name': 'web01', 'ip': '203.0.113.10:8443'},
            {'ip': '[2001:db8::1]:8443'},
            {'web02': '203.0.113.12:9443'}]), 'x.json')
        self.assertEqual(by_name(json_inv), {
            'web01': (['203.0.113.10'], [], {'203.0.113.10': [8443]}),
            '2001:db8::1': (['2001:db8::1'], [], {'2001:db8::1': [8443]}),
            'web02': (['203.0.113.12'], [], {'203.0.113.12': [9443]})})
        yaml_inv = sos.parse_inventory('all:\n  hosts:\n    web01:\n'
                                       '      ansible_host: 203.0.113.10:8443\n', 'x.yml')
        self.assertEqual(by_name(yaml_inv), {
            'web01': (['203.0.113.10'], [], {'203.0.113.10': [8443]})})


class TargetTokenPortTests(unittest.TestCase):

    def test_command_line_tokens(self):
        for token, want in (
                ('203.0.113.10:8443', {'203.0.113.10': (['203.0.113.10'], [],
                                                        {'203.0.113.10': [8443]})}),
                ('[2001:db8::1]:8443', {'2001:db8::1': (['2001:db8::1'], [],
                                                        {'2001:db8::1': [8443]})}),
                ('web01=203.0.113.10:8443', {'web01': (['203.0.113.10'], [],
                                                       {'203.0.113.10': [8443]})}),
                ('web01.example.net:8443', {'web01.example.net': (
                    [], ['web01.example.net'], {'web01.example.net': [8443]})})):
            with self.subTest(token=token):
                self.assertEqual(by_name(sos.parse_target_tokens(token)), want)

    def test_bad_tokens_are_usage_errors(self):
        for token, message in (('203.0.113.10:0', 'outside 1-65535'),
                               ('203.0.113.0/24:443', 'CIDR or IP range'),
                               ('web=203.0.113.5-9:443', 'CIDR or IP range'),
                               ('web=203.0.113.10:x1', 'not a port number'),
                               ('2026092401:443', 'reads it as the IPv4 address'),
                               ('bad_host!.example.net:443', 'before the port')):
            with self.subTest(token=token):
                with self.assertRaisesRegex(sos.UsageError, message):
                    sos.parse_target_tokens(token)

    def test_load_targets_merges_ports_and_resolves_with_them(self):
        servers, warnings = sos.load_targets(
            ['203.0.113.10:8443', '203.0.113.10', 'web.example.net:8443',
             'web.example.net:9443'], resolver=lambda host: ['198.51.100.7'])
        self.assertEqual(warnings, [])
        got = {s.name: (s.ips, s.ports) for s in servers}
        self.assertEqual(got['203.0.113.10'], (['203.0.113.10'], {'203.0.113.10': [8443, None]}))
        self.assertEqual(got['web.example.net'][0], ['198.51.100.7'])
        self.assertEqual(got['web.example.net'][1]['198.51.100.7'], [8443, 9443])
        server = next(s for s in servers if s.name == '203.0.113.10')
        self.assertEqual(server.ports_for('203.0.113.10', [443, 8443]), [8443, 443])

    def test_exclude_keeps_the_ports_of_what_is_left(self):
        server = sos.Server('web', [])
        server.add_ip('203.0.113.10', 8443)
        server.add_ip('203.0.113.11', 9443)
        kept, excluded = sos.apply_excludes([server], ['203.0.113.10'])
        self.assertEqual([e.ip for e in excluded], ['203.0.113.10'])
        self.assertEqual(kept[0].ports, {'203.0.113.11': [9443]})
        self.assertEqual(server.ports, {'203.0.113.10': [8443], '203.0.113.11': [9443]})


class EnginePortTests(unittest.TestCase):

    def test_an_address_with_a_port_is_scanned_on_that_port_only(self):
        network = FakeNetwork({}, {ip: (lambda sni: PUBLIC.der) for ip in
                                   ('203.0.113.10', '203.0.113.11', '2001:db8::1')})
        inventory = sos.parse_inventory('web01 203.0.113.10:8443\n'
                                        'web02 203.0.113.11 203.0.113.11:9443\n'
                                        '[2001:db8::1]:8443\n', 'inv.txt')
        report = sos.run_scan(inventory.servers, sos.build_probe_names(NAMES), [443, 4443],
                              new_certs=[PUBLIC], timeout=1, workers=4,
                              connect_fn=network.connect_fn, tls_fn=network.tls_fn)
        dialled = {(ip, port) for ip, port, _sni in network.calls}
        self.assertEqual(dialled, {('203.0.113.10', 8443), ('203.0.113.11', 443),
                                   ('203.0.113.11', 4443), ('203.0.113.11', 9443),
                                   ('2001:db8::1', 8443)})
        self.assertEqual({(e.ip, e.port) for e in report.endpoints}, dialled)
        self.assertEqual({s.server.name: s.status for s in report.server_summaries()},
                         {'web01': 'UPDATED', 'web02': 'UPDATED', '2001:db8::1': 'UPDATED'})
        doc = json.loads(sos.render_json(report))
        servers = {s['name']: s for s in doc['servers']}
        self.assertEqual(servers['web01']['ports'], {'203.0.113.10': [8443]})
        self.assertEqual(servers['web02']['ports'], {'203.0.113.11': [None, 9443]})
        self.assertEqual(doc['options']['ports'], [443, 4443])
        text = sos.render_summary(report, show_all=True)
        self.assertIn('ports 8443,443,4443,9443', text.splitlines()[0])
        self.assertIn('[2001:db8::1]:8443', text)


# ================================================================ the command, end to end

WILD_ORIGIN = [('wild.example.net', 'cli_origin_wild')]
WILD_PRIVATE = [('wild.example.net', 'cli_private_wild')]
WILD_PUBLIC = [('wild.example.net', 'cli_public_wild')]


class CommandLineTests(unittest.TestCase):
    """Real TLS servers on 127.0.0.1 serving the kind fixtures."""

    @classmethod
    def setUpClass(cls):
        cls.origin = TlsServer('cn_only', WILD_ORIGIN)
        cls.private = TlsServer('cn_only', WILD_PRIVATE)
        cls.public = TlsServer('cn_only', WILD_PUBLIC)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.new = str(FIXTURES / 'cli_public_wild.pem')
        cls.ca = str(FIXTURES / 'cli_private_ca.pem')

    @classmethod
    def tearDownClass(cls):
        for server in (cls.origin, cls.private, cls.public):
            server.close()
        cls.tmp.cleanup()

    def scan(self, *extra: str) -> Tuple[int, Dict, str]:
        path = os.path.join(self.tmp.name, 'r%d.json' % len(os.listdir(self.tmp.name)))
        # every server on its own port; -p points at a closed port nobody uses
        targets = ['origin=127.0.0.1:%d' % self.origin.port,
                   'internal=127.0.0.1:%d' % self.private.port,
                   'public=127.0.0.1:%d' % self.public.port]
        code, _out, err = run_main('-t', *targets, '-p', str(_free_port()), '-n', *NAMES,
                                   '--cert', self.new, '--timeout', '4', '--json', path,
                                   '--fail-on-needs-update', '-q', *extra)
        return code, read_json(path), err

    @staticmethod
    def statuses(doc) -> Dict[str, str]:
        return {s['name']: s['status'] for s in doc['servers']}

    def test_origin_and_private_certificates_do_not_fail_the_run(self):
        code, doc, err = self.scan('--private-ca', self.ca)
        self.assertEqual(code, sos.EXIT_OK, err)
        self.assertEqual(self.statuses(doc), {'origin': 'ORIGIN_CERT', 'internal': 'PRIVATE_CERT',
                                              'public': 'UPDATED'})
        # only the ports written with the addresses were dialled: no CLOSED row for -p
        self.assertEqual({r['port'] for r in doc['results']},
                         {self.origin.port, self.private.port, self.public.port})
        self.assertNotIn('CLOSED', {r['status'] for r in doc['results']})

    def test_without_the_private_ca_and_with_strict_public(self):
        code, doc, err = self.scan()
        self.assertEqual(code, sos.EXIT_NEEDS_UPDATE, err)
        self.assertEqual(self.statuses(doc)['internal'], 'NEEDS_UPDATE')
        self.assertEqual(self.statuses(doc)['origin'], 'ORIGIN_CERT')
        code, doc, err = self.scan('--private-ca', self.ca, '--strict-public')
        self.assertEqual(code, sos.EXIT_NEEDS_UPDATE, err)
        self.assertEqual(self.statuses(doc), {'origin': 'NEEDS_UPDATE',
                                              'internal': 'NEEDS_UPDATE', 'public': 'UPDATED'})
        self.assertTrue(doc['options']['strictPublic'])

    def test_bad_options(self):
        code, _out, err = run_main('-t', '127.0.0.1', '-n', NAMES[0], '--private-ca',
                                   os.path.join(self.tmp.name, 'missing.pem'))
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn('cannot read --private-ca', err)
        code, _out, err = run_main('-t', '127.0.0.1:0', '-n', NAMES[0])
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn("invalid target '127.0.0.1:0': port 0 is outside 1-65535", err)

    def test_the_scanning_line_counts_endpoints(self):
        code, _out, err = run_main('-t', 'web=127.0.0.1:%d' % self.public.port, '-n', NAMES[0],
                                   '--timeout', '4', '--json',
                                   os.path.join(self.tmp.name, 'scanning.json'))
        self.assertEqual(code, 0, err)
        self.assertIn('Scanning 1 server(s) / 1 IP(s), 1 ip:port endpoint(s) for', err)

    def test_help_documents_the_statuses_and_the_port_rule(self):
        code, out, _err = run_main('--help')
        self.assertEqual(code, 0)
        for needle in ('ORIGIN_CERT', 'PRIVATE_CERT', '--private-ca', '--strict-public',
                       '[2001:db8::5]:8443', 'instead of -p'):
            self.assertIn(needle, out)


if __name__ == '__main__':
    unittest.main()
