"""Tests for cli/ssl_origin_scan.py (stdlib unittest; no Internet access needed).

Run from the repository root:
    python -m unittest discover -s tests/python -v

The integration tests start real TLS servers on 127.0.0.1 (and ::1 when available)
on ephemeral ports, using the test-only fixture keys in tests/fixtures/.
"""

from __future__ import annotations

import base64
import codecs
import contextlib
import csv
import hashlib
import importlib.util
import io
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'ssl_origin_scan.py'
FIXTURES = ROOT / 'tests' / 'fixtures'


def _load_cli():
    spec = importlib.util.spec_from_file_location('ssl_origin_scan', str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules['ssl_origin_scan'] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


sos = _load_cli()

EXPECTED = json.loads((FIXTURES / 'expected.json').read_text(encoding='utf-8'))
RENEWED_WILD_SHA256 = '773223c65605a70c8fef4da270b24e8ce1874cf142e64ba827d2ba7ac134003f'
NOW = datetime(2026, 9, 23, 12, 0, 0, tzinfo=timezone.utc)


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_cert(name: str):
    certs, warnings = sos.load_certificates(fixture_bytes(name))
    assert certs, (name, warnings)
    return sos.select_leaf(certs)


def read_json(path: str):
    with open(path, encoding='utf-8') as handle:
        return json.load(handle)


def run_main(*args: str) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = sos.main(list(args))
    return code, out.getvalue(), err.getvalue()


# ======================================================================= DER parser

class DerParserTests(unittest.TestCase):
    """The built-in X.509 parser against openssl-derived ground truth (expected.json)."""

    def assert_matches_expected(self, cert, expected: Dict, label: str) -> None:
        got = {
            'subjectCN': cert.subject_cn, 'subjectDN': cert.subject_dn,
            'issuerCN': cert.issuer_cn, 'issuerDN': cert.issuer_dn,
            'dnsNames': cert.dns_names, 'ipAddresses': cert.ip_addresses, 'emails': cert.emails,
            'serialHex': cert.serial_hex, 'notBefore': sos.iso_utc(cert.not_before),
            'notAfter': sos.iso_utc(cert.not_after), 'sha256': cert.sha256, 'sha1': cert.sha1,
            'keyAlgorithm': cert.key_algorithm, 'keyBits': cert.key_bits, 'curve': cert.curve,
            'isCA': cert.is_ca, 'selfSigned': cert.self_signed,
        }
        for key, value in got.items():
            with self.subTest(fixture=label, field=key):
                self.assertEqual(value, expected[key])

    def test_all_fixtures_match_expected_json(self):
        self.assertGreaterEqual(len(EXPECTED), 5)
        for name, expected in EXPECTED.items():
            certs, warnings = sos.load_certificates(fixture_bytes(name))
            self.assertEqual(warnings, [], name)
            self.assertEqual(len(certs), 1, name)
            self.assert_matches_expected(certs[0], expected, name)

    def test_parse_certificate_on_raw_der_file(self):
        cert = sos.parse_certificate(fixture_bytes('rsa_multi_san.der'))
        self.assert_matches_expected(cert, EXPECTED['rsa_multi_san.pem'], 'rsa_multi_san.der')
        self.assertEqual(cert.version, 3)
        self.assertEqual(cert.signature_algorithm, 'sha256WithRSAEncryption')
        self.assertEqual(cert.issuer_o, 'Test CA')
        self.assertEqual(cert.subject, {'C': 'TR', 'O': 'Ornek AS',
                                        'CN': 'www.example-test.com.tr'})

    def test_der_file_via_load_certificates(self):
        certs, warnings = sos.load_certificates(fixture_bytes('rsa_multi_san.der'))
        self.assertEqual(warnings, [])
        self.assertEqual(certs[0].sha256, EXPECTED['rsa_multi_san.pem']['sha256'])

    def test_crlf_pem_and_pem_inside_email_text(self):
        for name in ('rsa_multi_san_crlf.pem', 'pasted_with_text.txt'):
            certs, warnings = sos.load_certificates(fixture_bytes(name))
            self.assertEqual(warnings, [], name)
            self.assertEqual([c.sha256 for c in certs], [EXPECTED['rsa_multi_san.pem']['sha256']])

    def test_str_input_is_accepted(self):
        text = fixture_bytes('rsa_multi_san.pem').decode('ascii')
        certs, _ = sos.load_certificates(text)
        self.assertEqual(certs[0].serial_hex, 'f1e2d3c4b5a69788')

    def test_generalized_time_after_2049(self):
        cert = fixture_cert('ec_wildcard.pem')
        self.assertEqual(cert.not_after, datetime(2051, 1, 1, tzinfo=timezone.utc))
        renewed = fixture_cert('cli_renewed_wild.pem')
        self.assertEqual(renewed.not_after, datetime(2052, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(renewed.not_before, datetime(2026, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(renewed.serial_hex, '0a0b0c')
        self.assertEqual(renewed.sha256, RENEWED_WILD_SHA256)
        self.assertEqual(renewed.issuer_o, 'Renewed Test')

    def test_long_form_lengths_and_many_sans(self):
        cert = fixture_cert('many_sans.pem')
        self.assertEqual(len(cert.dns_names), 81)
        self.assertEqual(cert.serial_hex, '7fffffffffffffff01')

    def test_serial_sign_byte_is_stripped(self):
        der = fixture_bytes('rsa_multi_san.der')
        self.assertIn(bytes.fromhex('0209' + '00f1e2d3c4b5a69788'), der)  # DER keeps 00
        self.assertEqual(sos.parse_certificate(der).serial_hex, 'f1e2d3c4b5a69788')

    def test_chains_select_the_leaf_in_any_order(self):
        for name in ('chain.pem', 'chain_reversed.pem', 'cli_chain.p7b', 'cli_chain_p7b.pem'):
            certs, warnings = sos.load_certificates(fixture_bytes(name))
            self.assertEqual(warnings, [], name)
            self.assertEqual(len(certs), 2, name)
            self.assertEqual(sos.select_leaf(certs).subject_cn, 'www.example-test.com.tr', name)

    def test_select_leaf_edge_cases(self):
        self.assertIsNone(sos.select_leaf([]))
        ca = fixture_cert('ca.pem')
        self.assertIs(sos.select_leaf([ca]), ca)  # only a CA: first cert

    def test_private_key_is_reported_not_parsed(self):
        certs, warnings = sos.load_certificates(fixture_bytes('with_key.pem'))
        self.assertEqual(len(certs), 1)
        self.assertEqual([code for code, _ in warnings], ['PRIVATE_KEY_PRESENT'])
        certs, warnings = sos.load_certificates(fixture_bytes('ec_wildcard.key'))
        self.assertEqual(certs, [])
        self.assertEqual([c for c, _ in warnings], ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE'])

    def test_pkcs12_is_detected(self):
        certs, warnings = sos.load_certificates(fixture_bytes('cli_bundle.p12'))
        self.assertEqual(certs, [])
        self.assertEqual(warnings[0][0], 'PKCS12_UNSUPPORTED')
        self.assertIn('openssl pkcs12', warnings[0][1])

    def test_csr_is_detected(self):
        pem = '-----BEGIN CERTIFICATE REQUEST-----\nMIIBAA==\n-----END CERTIFICATE REQUEST-----\n'
        certs, warnings = sos.load_certificates(pem)
        self.assertEqual(certs, [])
        self.assertEqual(warnings, [('CSR_NOT_CERT', 'CERTIFICATE REQUEST')])

    def test_bare_base64_der(self):
        b64 = base64.b64encode(fixture_bytes('rsa_multi_san.der')).decode('ascii')
        wrapped = '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
        certs, warnings = sos.load_certificates(wrapped)
        self.assertEqual(warnings, [])
        self.assertEqual(certs[0].serial_hex, 'f1e2d3c4b5a69788')

    def test_garbage_and_empty_input_never_raise(self):
        for data in (b'', b'   \n', b'hello world, not a cert', b'\x30\x03\x02\x01',
                     b'\x30\x82\xff\xff' + b'\x00' * 10, '\u00fcnicode text'.encode('utf-8')):
            certs, warnings = sos.load_certificates(data)
            self.assertEqual(certs, [], data)
            self.assertTrue(warnings, data)
            self.assertIn(warnings[-1][0], ('PARSE_ERROR', 'NO_CERTIFICATE'), data)

    def test_bad_base64_inside_pem(self):
        pem = '-----BEGIN CERTIFICATE-----\n!!!notbase64!!!\n-----END CERTIFICATE-----'
        certs, warnings = sos.load_certificates(pem)
        self.assertEqual(certs, [])
        self.assertEqual(warnings[0][0], 'PARSE_ERROR')

    def test_truncated_der_raises_der_error(self):
        der = fixture_bytes('rsa_multi_san.der')
        for cut in (0, 1, 2, 4, 50, len(der) // 2, len(der) - 1):
            with self.subTest(cut=cut):
                with self.assertRaises(sos.DerError):
                    sos.parse_certificate(der[:cut])

    def test_trailing_bytes_are_ignored_for_fingerprint(self):
        der = fixture_bytes('rsa_multi_san.der')
        cert = sos.parse_certificate(der + b'\x00\x00garbage')
        self.assertEqual(cert.sha256, EXPECTED['rsa_multi_san.pem']['sha256'])
        self.assertEqual(cert.der, der)

    def test_indefinite_and_oversized_lengths_are_rejected(self):
        with self.assertRaisesRegex(sos.DerError, 'indefinite'):
            sos.parse_certificate(b'\x30\x80\x00\x00')
        with self.assertRaisesRegex(sos.DerError, 'too long'):
            sos.parse_certificate(b'\x30\x85\x00\x00\x00\x00\x01\x00')
        with self.assertRaisesRegex(sos.DerError, 'exceeds'):
            sos.parse_certificate(b'\x30\x05\x00')
        with self.assertRaises(sos.DerError):
            sos.parse_certificate(b'\x04\x00')  # not a SEQUENCE

    def test_high_tag_number_form_is_skipped(self):
        tlv = sos._read_tlv(b'\x1f\x81\x01\x01\xaa', 0, 5)
        self.assertEqual(tlv[2:], (4, 5))
        with self.assertRaises(sos.DerError):
            sos._read_tlv(b'\x1f\x81\x81\x81\x81\x01\x00', 0, 7)

    def test_oid_decoding(self):
        self.assertEqual(sos._decode_oid(bytes.fromhex('2a864886f70d010101')),
                         '1.2.840.113549.1.1.1')
        self.assertEqual(sos._decode_oid(bytes.fromhex('551d11')), '2.5.29.17')
        self.assertEqual(sos._decode_oid(bytes.fromhex('8837')), '2.999')
        with self.assertRaises(sos.DerError):
            sos._decode_oid(b'')
        with self.assertRaises(sos.DerError):
            sos._decode_oid(b'\x2a\x86')

    def test_time_parsing(self):
        utc, gen = 0x17, 0x18
        cases = [
            (utc, b'491231235959Z', datetime(2049, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
            (utc, b'500101000000Z', datetime(1950, 1, 1, tzinfo=timezone.utc)),
            (utc, b'2501010000Z', datetime(2025, 1, 1, tzinfo=timezone.utc)),
            (gen, b'20510101000000Z', datetime(2051, 1, 1, tzinfo=timezone.utc)),
            (gen, b'20250101000000.5Z', datetime(2025, 1, 1, 0, 0, 0, 500000,
                                                 tzinfo=timezone.utc)),
            (gen, b'20250101030000+0300', datetime(2025, 1, 1, tzinfo=timezone.utc)),
            (gen, b'20241231210000-0300', datetime(2025, 1, 1, tzinfo=timezone.utc)),
            (gen, b'99991231235959Z', datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)),
        ]
        for tag, raw, expected in cases:
            with self.subTest(raw=raw):
                self.assertEqual(sos._parse_time(tag, raw), expected)
        for tag, raw in ((utc, b'251301000000Z'), (gen, b'2025'), (utc, b'abc'),
                         (gen, b'20250230000000Z'), (0x04, b'20250101000000Z'),
                         (utc, b'\xff\xfe')):
            with self.subTest(raw=raw):
                with self.assertRaises(sos.DerError):
                    sos._parse_time(tag, raw)

    def test_ip_san_formatting(self):
        self.assertEqual(sos._format_ip_bytes(bytes([10, 0, 0, 5])), '10.0.0.5')
        self.assertEqual(sos._format_ip_bytes(bytes.fromhex('20010db8' + '00' * 11 + '01')),
                         '2001:db8::1')
        self.assertEqual(sos._format_ip_bytes(bytes.fromhex('00' * 10 + 'ffff' + '01020304')),
                         '::ffff:1.2.3.4')
        self.assertEqual(sos._format_ip_bytes(bytes.fromhex('0a000000ffffff00')),
                         '0a000000ffffff00')

    def test_dn_escaping(self):
        self.assertEqual(sos._escape_dn_value('a,b+c"d\\e<f>g;h'),
                         'a\\,b\\+c\\"d\\\\e\\<f\\>g\\;h')
        self.assertEqual(sos._escape_dn_value('#lead'), '\\#lead')
        self.assertEqual(sos._escape_dn_value(' both '), '\\ both\\ ')
        self.assertEqual(sos._escape_dn_value('\u00d6rnek A.\u015e.'), '\u00d6rnek A.\u015e.')

    def test_string_types(self):
        self.assertEqual(sos._decode_string(0x0C, 'T\u00fcrk'.encode('utf-8')), 'T\u00fcrk')
        self.assertEqual(sos._decode_string(0x1E, 'ab'.encode('utf-16-be')), 'ab')
        self.assertEqual(sos._decode_string(0x1C, 'ab'.encode('utf-32-be')), 'ab')
        self.assertEqual(sos._decode_string(0x14, b'\xe9'), '\u00e9')
        self.assertIsNone(sos._decode_string(0x04, b'x'))

    def test_hostnames_and_cn_fallback(self):
        self.assertEqual(fixture_cert('cn_only.pem').hostnames, ['legacy.example.org'])
        self.assertEqual(fixture_cert('ca.pem').hostnames, [])  # CN with spaces
        self.assertEqual(fixture_cert('ec_wildcard.pem').hostnames,
                         ['*.wild.example.net', 'wild.example.net'])

    def test_to_dict(self):
        cert = fixture_cert('rsa_multi_san.pem')
        data = cert.to_dict(NOW)
        self.assertEqual(data['notAfter'], '2034-06-01T00:00:00.000Z')
        self.assertEqual(data['daysLeft'], (datetime(2034, 6, 1, tzinfo=timezone.utc) - NOW).days)
        self.assertEqual(data['issuerO'], 'Test CA')
        self.assertEqual(data['ipAddresses'], ['10.0.0.5', '2001:db8::1'])
        self.assertNotIn('der', data)
        json.dumps(data)  # serialisable

    def test_days_left_and_labels(self):
        cert = fixture_cert('cn_only.pem')
        self.assertEqual(cert.days_left(datetime(2034, 12, 31, tzinfo=timezone.utc)), 1)
        self.assertEqual(cert.days_left(datetime(2035, 1, 2, tzinfo=timezone.utc)), -1)
        self.assertEqual(cert.short_label(), 'legacy.example.org')
        self.assertEqual(cert.issuer_label(), 'legacy.example.org (Legacy)')
        self.assertEqual(fixture_cert('ec_wildcard.pem').issuer_label(), '*.wild.example.net')

    def test_real_world_certificates_if_present(self):
        paths = sorted(FIXTURES.glob('real_*.pem'))
        if not paths:
            self.skipTest('no real_*.pem fixtures')
        for path in paths:
            text = path.read_text(encoding='ascii')
            blocks = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
                                text, re.S)
            certs, warnings = sos.load_certificates(text)
            self.assertEqual(warnings, [], path.name)
            self.assertEqual(len(certs), len(blocks), path.name)
            for block, cert in zip(blocks, certs):
                der = base64.b64decode(''.join(block.split()))
                self.assertEqual(cert.sha256, hashlib.sha256(der).hexdigest())
                self.assertTrue(cert.hostnames or cert.is_ca, path.name)
                self.assertLess(cert.not_before, cert.not_after)


# ================================================================ names & coverage

class HostnameTests(unittest.TestCase):

    def test_normalize_hostname(self):
        cases = {
            'WWW.Example.COM': 'www.example.com',
            'https://user:pw@api.example.com:8443/path?q=1#x': 'api.example.com',
            'example.com.': 'example.com',
            'm\u00fcnchen.example-test.com.tr': 'xn--mnchen-3ya.example-test.com.tr',
            '_dmarc.example.com': '_dmarc.example.com',
            'localhost': 'localhost',
            '  spaced.example.com  ': 'spaced.example.com',
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(sos.normalize_hostname(raw), expected)
        for raw in ('', ' ', '10.0.0.1', '::1', '[2001:db8::1]', 'a..b', '-a.com', 'a-.com',
                    'a b.com', '*.example.com', 'x' * 64 + '.com', 'host:port',
                    '.'.join(['a' * 63] * 4) + '.com', 'exa$mple.com'):
            with self.subTest(raw=raw):
                self.assertIsNone(sos.normalize_hostname(raw))

    def test_normalize_hostname_wildcards(self):
        self.assertEqual(sos.normalize_hostname('*.Example.com', allow_wildcard=True),
                         '*.example.com')
        self.assertIsNone(sos.normalize_hostname('*.*.example.com', allow_wildcard=True))
        self.assertIsNone(sos.normalize_hostname('w*.example.com', allow_wildcard=True))
        self.assertIsNone(sos.normalize_hostname('*', allow_wildcard=True))

    def test_normalize_ip(self):
        self.assertEqual(sos.normalize_ip(' 10.0.0.1 '), '10.0.0.1')
        self.assertEqual(sos.normalize_ip('2001:DB8:0:0:0:0:0:1'), '2001:db8::1')
        self.assertEqual(sos.normalize_ip('[2001:db8::1]'), '2001:db8::1')
        self.assertEqual(sos.normalize_ip('fe80::1%eth0'), 'fe80::1')
        self.assertEqual(sos.normalize_ip('::ffff:10.0.0.1'), '::ffff:10.0.0.1')
        for raw in ('10.0.0.256', 'example.com', '', '1.2.3', '10.0.0.1/24'):
            self.assertIsNone(sos.normalize_ip(raw), raw)

    def test_is_scannable_ip(self):
        self.assertTrue(sos.is_scannable_ip('10.0.0.1'))
        self.assertTrue(sos.is_scannable_ip('::1'))
        for ip in ('0.0.0.0', '::', '224.0.0.1', 'ff02::1', '255.255.255.255'):
            self.assertFalse(sos.is_scannable_ip(ip), ip)

    def test_wildcard_matches_rfc6125(self):
        yes = [('*.a.com', 'x.a.com'), ('*.A.com', 'X.a.COM'), ('*.a.com.', 'x.a.com'),
               ('*.wild.example.net', 'ssl-origin-scan-wildcard-probe.wild.example.net')]
        no = [('*.a.com', 'a.com'), ('*.a.com', 'x.y.a.com'), ('*.com', 'a.com'),
              ('w*.a.com', 'www.a.com'), ('*.*.a.com', 'x.y.a.com'), ('a.com', 'a.com'),
              ('*.a.com', '*.a.com'), ('*.a.com', 'xa.com'), ('*.', 'a'), ('*.a.com', '.a.com')]
        for pattern, host in yes:
            self.assertTrue(sos.wildcard_matches(pattern, host), (pattern, host))
        for pattern, host in no:
            self.assertFalse(sos.wildcard_matches(pattern, host), (pattern, host))

    def test_cert_covers(self):
        names = ['example.com', '*.example.com', 'www.other.org']
        self.assertEqual(sos.cert_covers(names, 'example.com'), (True, 'example.com'))
        self.assertEqual(sos.cert_covers(names, 'API.example.com.'), (True, '*.example.com'))
        self.assertEqual(sos.cert_covers(names, 'www.other.org'), (True, 'www.other.org'))
        self.assertEqual(sos.cert_covers(names, 'a.b.example.com'), (False, None))
        self.assertEqual(sos.cert_covers([], 'example.com'), (False, None))
        # an exact SAN wins over a wildcard even when listed later
        self.assertEqual(sos.cert_covers(['*.example.com', 'www.example.com'], 'www.example.com'),
                         (True, 'www.example.com'))

    def test_cert_covers_with_fixture(self):
        cert = fixture_cert('rsa_multi_san.pem')
        self.assertEqual(cert.covers('x.cdn.example-test.com.tr'),
                         (True, '*.cdn.example-test.com.tr'))
        self.assertEqual(cert.covers('cdn.example-test.com.tr'), (False, None))
        self.assertEqual(cert.covers('xn--mnchen-3ya.example-test.com.tr'),
                         (True, 'xn--mnchen-3ya.example-test.com.tr'))


class NamesTests(unittest.TestCase):

    def test_parse_names_text(self):
        text = ('\ufeffwww.Example.com\n*.example.com   # the wildcard\n'
                'https://api.example.com:8443/health, m\u00fcnchen.example.com;dup.example.com\n'
                'dup.example.com\n10.0.0.1\nsingle\n; comment line\n// another\n')
        valid, invalid = sos.parse_names_text(text)
        self.assertEqual(valid, ['www.example.com', '*.example.com', 'api.example.com',
                                 'xn--mnchen-3ya.example.com', 'dup.example.com'])
        self.assertEqual(invalid, ['10.0.0.1', 'single'])

    def test_load_names_from_args_and_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'names.txt')
            with open(path, 'w', encoding='utf-16') as handle:  # PowerShell-style UTF-16
                handle.write('a.example.com\nb.example.com\n')
            names, warnings = sos.load_names([path, 'c.example.com a.example.com', '10.1.1.1'])
            self.assertEqual(names, ['a.example.com', 'b.example.com', 'c.example.com'])
            self.assertEqual(len(warnings), 1)
            self.assertIn('IP address', warnings[0])
            with self.assertRaises(sos.UsageError):
                sos.load_names([os.path.join(tmp, 'missing.txt')])
            names, _ = sos.load_names(['-'], stdin=io.StringIO('x.example.com\n'))
            self.assertEqual(names, ['x.example.com'])
            names, _ = sos.load_names(['https://url.example.com/x.txt'])
            self.assertEqual(names, ['url.example.com'])

    def test_build_probe_names(self):
        probes = sos.build_probe_names(['*.example.com', 'example.com', 'WWW.example.com',
                                        'www.example.com'])
        self.assertEqual([(p.name, p.sni, p.wildcard) for p in probes], [
            ('example.com', 'example.com', False),
            ('*.example.com', 'ssl-origin-scan-wildcard-probe.example.com', True),
            ('www.example.com', 'www.example.com', False),
        ])
        probes = sos.build_probe_names(['*.example.com'], wildcard_probe=False)
        self.assertEqual([p.name for p in probes], ['example.com'])
        long_base = '.'.join(['a' * 60] * 4)  # 243 chars: synthetic SNI would exceed 253
        probes = sos.build_probe_names(['*.' + long_base])
        self.assertEqual([p.name for p in probes], [long_base])


# ======================================================================== inventory

def servers_by_name(inventory) -> Dict[str, object]:
    return {server.name: server for server in inventory.servers}


class InventoryTests(unittest.TestCase):

    def test_plain_lines_and_merging(self):
        text = ('# my servers\nweb01 10.0.0.1 10.0.0.2\n10.0.0.3\n10.0.0.4 web04\n'
                '; ini comment\n// js comment\nweb01, 10.0.0.9  # inline comment\n'
                'WEB01 10.0.0.2\nweb05;10.0.0.5\n')
        inv = sos.parse_inventory(text)
        servers = servers_by_name(inv)
        self.assertEqual(list(servers), ['web01', '10.0.0.3', 'web04', 'web05'])
        self.assertEqual(servers['web01'].ips, ['10.0.0.1', '10.0.0.2', '10.0.0.9'])
        self.assertEqual(servers['web01'].line, 2)
        self.assertEqual(servers['web04'].ips, ['10.0.0.4'])
        self.assertEqual(inv.stats, {'lines': 9, 'servers': 4, 'ips': 6})
        self.assertEqual(inv.warnings, [])

    def test_hosts_file(self):
        text = ('127.0.0.1\tlocalhost\n::1     localhost ip6-localhost ip6-loopback\n'
                'ff02::1 ip6-allnodes\n10.1.1.1 app.corp.local app\n'
                '2001:db8::10 v6.corp.local\n')
        inv = sos.parse_inventory(text, 'hosts')
        servers = servers_by_name(inv)
        self.assertEqual(servers['localhost'].ips, ['127.0.0.1', '::1'])
        self.assertEqual(servers['app.corp.local'].ips, ['10.1.1.1'])
        self.assertEqual(servers['v6.corp.local'].ips, ['2001:db8::10'])
        self.assertNotIn('ip6-allnodes', servers)
        self.assertEqual([w.code for w in inv.warnings], ['INVALID_IP'])
        self.assertIn('hosts:3', str(inv.warnings[0]))

    def test_csv_with_header(self):
        text = ('Name,Public IP,PrivateIpAddress,Env,Notes\n'
                'web01,203.0.113.10,10.0.0.10,prod,"has, comma"\n'
                'web02,,10.0.0.11,stage,\n'
                'db01.example.com,,,prod,\n'
                '10.0.0.12,,,,\n'
                ',,10.0.0.13,,\n'
                'bad,300.1.1.1,,,\n')
        inv = sos.parse_inventory(text)
        servers = servers_by_name(inv)
        self.assertEqual(servers['web01'].ips, ['203.0.113.10', '10.0.0.10'])
        self.assertEqual(servers['web01'].groups, ['prod'])
        self.assertEqual(servers['web02'].ips, ['10.0.0.11'])
        self.assertEqual(servers['db01.example.com'].ips, [])
        self.assertEqual(servers['db01.example.com'].hostnames, ['db01.example.com'])
        self.assertEqual(servers['10.0.0.12'].ips, ['10.0.0.12'])
        self.assertEqual(servers['10.0.0.13'].ips, ['10.0.0.13'])
        self.assertNotIn('bad', servers)
        self.assertIn('INVALID_IP', [w.code for w in inv.warnings])

    def test_tsv_semicolon_and_multi_ip_cells(self):
        tsv = sos.parse_inventory('hostname\tip_address\nweb01\t10.0.0.1\n')
        self.assertEqual(servers_by_name(tsv)['web01'].ips, ['10.0.0.1'])
        semi = sos.parse_inventory('server;ipv4;ipv6\nweb01;10.0.0.1;2001:db8::1\n')
        self.assertEqual(servers_by_name(semi)['web01'].ips, ['10.0.0.1', '2001:db8::1'])
        multi = sos.parse_inventory('name,ips\n"web01","10.0.0.1, 10.0.0.2 | 10.0.0.3"\n')
        self.assertEqual(servers_by_name(multi)['web01'].ips,
                         ['10.0.0.1', '10.0.0.2', '10.0.0.3'])
        hostish = sos.parse_inventory('name,ansible_host\nweb01,web01.internal\n')
        self.assertEqual(servers_by_name(hostish)['web01'].hostnames, ['web01.internal'])

    def test_csv_detection_does_not_hijack_data_lines(self):
        inv = sos.parse_inventory('web01,10.0.0.1\nweb02,10.0.0.2\n')
        self.assertEqual(sorted(servers_by_name(inv)), ['web01', 'web02'])

    def test_ansible_ini(self):
        text = ('[web]\nweb01 ansible_host=10.0.0.1 ansible_user=deploy\nweb02.example.com\n'
                '10.0.0.3\n\n[db]\ndb01 ansible_host=10.0.0.5 ansible_port=2222\n'
                'db02 ansible_host=db02.internal\n\n'
                '[web:vars]\nhttp_port=80\n\n[prod:children]\nweb\ndb\n\n'
                '[monitoring]\nmon01 ansible_host=[2001:db8::99]\n')
        servers = servers_by_name(sos.parse_inventory(text))
        self.assertEqual(servers['web01'].ips, ['10.0.0.1'])
        self.assertEqual(servers['web01'].groups, ['web'])
        self.assertEqual(servers['web02.example.com'].hostnames, ['web02.example.com'])
        self.assertEqual(servers['10.0.0.3'].groups, ['web'])
        self.assertEqual(servers['db01'].ips, ['10.0.0.5'])
        self.assertEqual(servers['db01'].groups, ['db'])
        self.assertEqual(servers['db02'].hostnames, ['db02.internal'])
        self.assertEqual(servers['mon01'].ips, ['2001:db8::99'])
        for skipped in ('http_port=80', 'web', 'db', 'prod'):
            self.assertNotIn(skipped, servers)

    def test_ansible_yaml(self):
        text = ('---\nall:\n  children:\n    web:\n      hosts:\n        web01:\n'
                '          ansible_host: 10.0.0.1\n        web02.example.com:\n'
                '    db:\n      hosts:\n        db01:\n          ansible_host: "10.0.0.5"\n'
                '          ansible_user: root   # comment\n')
        servers = servers_by_name(sos.parse_inventory(text))
        self.assertEqual(servers['web01'].ips, ['10.0.0.1'])
        self.assertEqual(servers['web01'].groups, ['web'])
        self.assertEqual(servers['web02.example.com'].hostnames, ['web02.example.com'])
        self.assertEqual(servers['web02.example.com'].groups, ['web'])
        self.assertEqual(servers['db01'].ips, ['10.0.0.5'])
        self.assertEqual(servers['db01'].groups, ['db'])
        simple = servers_by_name(sos.parse_inventory('web01:\n  ansible_host: 10.9.9.9\n'))
        self.assertEqual(simple['web01'].ips, ['10.9.9.9'])

    def test_json_formats(self):
        array = sos.parse_inventory(json.dumps([
            {'name': 'web01', 'ip': '10.0.0.1', 'netmask': '255.255.255.0',
             'gateway': '10.0.0.254', 'dns_servers': ['8.8.8.8']},
            {'hostname': 'web02', 'addresses': ['10.0.0.2', '2001:db8::2']},
            {'Name': 'web03'},
            '10.0.0.4', 'web05 10.0.0.5', 'free text without address']))
        servers = servers_by_name(array)
        self.assertEqual(servers['web01'].ips, ['10.0.0.1'])
        self.assertEqual(servers['web02'].ips, ['10.0.0.2', '2001:db8::2'])
        self.assertEqual(servers['web03'].hostnames, ['web03'])
        self.assertEqual(servers['10.0.0.4'].ips, ['10.0.0.4'])
        self.assertEqual(servers['web05'].ips, ['10.0.0.5'])

        aws = sos.parse_inventory(json.dumps({'Reservations': [{'Instances': [{
            'InstanceId': 'i-1', 'PrivateIpAddress': '10.0.0.1', 'PublicIpAddress': '203.0.113.1',
            'Tags': [{'Key': 'Env', 'Value': 'prod'}, {'Key': 'Name', 'Value': 'web01'}]}]}]}))
        self.assertEqual(servers_by_name(aws)['web01'].ips, ['10.0.0.1', '203.0.113.1'])

        mapping = sos.parse_inventory(json.dumps({'web01': '10.0.0.1',
                                                  'web02': ['10.0.0.2', '10.0.0.3'],
                                                  'web03': {'ansible_host': '10.0.0.4'},
                                                  'web04': 'web04.internal'}))
        servers = servers_by_name(mapping)
        self.assertEqual(servers['web01'].ips, ['10.0.0.1'])
        self.assertEqual(servers['web02'].ips, ['10.0.0.2', '10.0.0.3'])
        self.assertEqual(servers['web03'].ips, ['10.0.0.4'])
        self.assertEqual(servers['web04'].hostnames, ['web04.internal'])

        ansible = sos.parse_inventory(json.dumps({
            '_meta': {'hostvars': {'web01': {'ansible_host': '10.0.0.1'},
                                   'web02': {'ansible_host': 'web02.internal'}}},
            'web': {'hosts': ['web01', 'web02']}}))
        servers = servers_by_name(ansible)
        self.assertEqual(servers['web01'].ips, ['10.0.0.1'])
        self.assertEqual(servers['web02'].hostnames, ['web02.internal'])

        tags = sos.parse_inventory(json.dumps({'servers': [
            {'tags': {'Name': 'tagged'}, 'network': {'public_ip': '198.51.100.7'}}]}))
        self.assertEqual(servers_by_name(tags)['tagged'].ips, ['198.51.100.7'])

    def test_invalid_json_falls_back_to_lines(self):
        inv = sos.parse_inventory('[web]\nweb01 ansible_host=10.0.0.1\n')
        self.assertEqual(servers_by_name(inv)['web01'].ips, ['10.0.0.1'])

    def test_warnings(self):
        inv = sos.parse_inventory('a 10.0.0.1\nb 10.0.0.1\nweb 10.0.0.300\n0.0.0.0\n$$$\n')
        codes = [w.code for w in inv.warnings]
        self.assertIn('INVALID_IP', codes)
        self.assertIn('DUPLICATE_IP', codes)
        self.assertIn('NO_IP', codes)
        servers = servers_by_name(inv)
        self.assertNotIn('web', servers)  # typo'd IP: not silently resolved by name
        self.assertEqual(servers['a'].ips, servers['b'].ips)

    def test_cidr_and_ranges(self):
        servers = servers_by_name(sos.parse_inventory('dmz 10.0.1.0/30\n'))
        self.assertEqual(list(servers), ['10.0.1.1', '10.0.1.2'])
        self.assertEqual(servers['10.0.1.1'].groups, ['dmz'])
        self.assertEqual(sos.expand_ip_block('10.0.0.5/32'), ['10.0.0.5'])
        self.assertEqual(sos.expand_ip_block('10.0.0.4/31'), ['10.0.0.4', '10.0.0.5'])
        self.assertEqual(sos.expand_ip_block('10.0.0.7/30'),
                         ['10.0.0.5', '10.0.0.6'])  # host bits tolerated
        self.assertEqual(len(sos.expand_ip_block('2001:db8::/126')), 3)
        self.assertEqual(sos.expand_ip_block('10.0.0.5-7'), ['10.0.0.5', '10.0.0.6', '10.0.0.7'])
        self.assertEqual(len(sos.expand_ip_block('10.0.0.250-10.0.1.2')), 9)
        self.assertEqual(sos.expand_ip_block('2001:db8::1-2001:db8::2'),
                         ['2001:db8::1', '2001:db8::2'])
        self.assertEqual(len(sos.expand_ip_block('10.0.0.0/16')), 65534)
        self.assertIsNone(sos.expand_ip_block('10.0.0.1'))
        self.assertIsNone(sos.expand_ip_block('some-name'))
        self.assertIsNone(sos.expand_ip_block('dir/file'))
        self.assertTrue(sos.is_ip_block('10.0.0.0/8'))
        self.assertFalse(sos.is_ip_block('web-01'))

    def test_large_blocks_need_allow_large(self):
        with self.assertRaisesRegex(sos.UsageError, 'allow-large'):
            sos.expand_ip_block('10.0.0.0/15')
        with self.assertRaisesRegex(sos.UsageError, 'allow-large'):
            sos.parse_inventory('10.0.0.0/8\n')
        self.assertEqual(len(sos.expand_ip_block('10.0.0.0/15', allow_large=True)), 131070)
        with self.assertRaisesRegex(sos.UsageError, 'maximum'):
            sos.expand_ip_block('10.0.0.0/11', allow_large=True)
        with self.assertRaisesRegex(sos.UsageError, 'range'):
            sos.expand_ip_block('10.0.0.9-10.0.0.1')

    def test_read_text_file_encodings(self):
        with tempfile.TemporaryDirectory() as tmp:
            for encoding in ('utf-8', 'utf-8-sig', 'utf-16', 'utf-16-be'):
                path = os.path.join(tmp, encoding + '.txt')
                with open(path, 'w', encoding=encoding, newline='\n') as handle:
                    handle.write('sunucu-\u00e7 10.0.0.1\n')
                if encoding == 'utf-16-be':  # add a BOM manually
                    Path(path).write_bytes(b'\xfe\xff' + Path(path).read_bytes())
                self.assertEqual(sos.read_text_file(path), 'sunucu-\u00e7 10.0.0.1\n', encoding)
            path = os.path.join(tmp, 'latin1.txt')
            Path(path).write_bytes(b'caf\xe9 10.0.0.1\n')
            self.assertEqual(sos.read_text_file(path), 'caf\u00e9 10.0.0.1\n')


class LoadTargetsTests(unittest.TestCase):

    def fake_resolver(self, host: str) -> List[str]:
        table = {'web01.internal': ['10.1.1.1', 'fd00::1', '10.1.1.1'],
                 'app.internal': ['10.2.2.2'], 'zero.internal': ['0.0.0.0']}
        if host not in table:
            raise socket.gaierror(11001, 'getaddrinfo failed')
        return table[host]

    def test_mixed_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'inv.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('web01 10.0.0.1\napp.internal\n')
            servers, warnings = sos.load_targets(
                [path, '10.0.0.9,10.0.0.12/31', 'web01.internal', 'db=10.0.0.20',
                 'missing.internal', 'zero.internal', 'WEB01=10.0.0.2'],
                resolver=self.fake_resolver)
        by_name = {s.name: s for s in servers}
        self.assertEqual(by_name['web01'].ips, ['10.0.0.1', '10.0.0.2'])
        self.assertEqual(by_name['app.internal'].ips, ['10.2.2.2'])
        self.assertEqual(by_name['web01.internal'].ips, ['10.1.1.1', 'fd00::1'])
        self.assertEqual(by_name['db'].ips, ['10.0.0.20'])
        self.assertEqual(by_name['10.0.0.12'].groups, ['10.0.0.12/31'])
        self.assertIn('10.0.0.13', by_name)
        self.assertNotIn('missing.internal', by_name)
        self.assertNotIn('zero.internal', by_name)
        messages = [str(w) for w in warnings]
        self.assertTrue(any('missing.internal' in m and 'RESOLVE' in m for m in messages))
        self.assertTrue(any('zero.internal' in m for m in messages))

    def test_stdin_and_errors(self):
        servers, _ = sos.load_targets(['-'], stdin=io.StringIO('s1 10.0.0.1\n'),
                                      resolver=self.fake_resolver)
        self.assertEqual([s.name for s in servers], ['s1'])
        with self.assertRaisesRegex(sos.UsageError, 'not found'):
            sos.load_targets(['nope/targets.txt'])
        with self.assertRaisesRegex(sos.UsageError, 'not found'):
            sos.load_targets(['targets.csv'])
        with self.assertRaisesRegex(sos.UsageError, 'invalid target'):
            sos.load_targets(['bad!token'])
        with self.assertRaisesRegex(sos.UsageError, 'invalid target'):
            sos.load_targets(['10.0.0.300'])
        with self.assertRaisesRegex(sos.UsageError, 'allow-large'):
            sos.load_targets(['10.0.0.0/8'])

    def test_browser_cli_suggestion_targets(self):
        # The web app's cliSuggestion `-t` tokens: an IPv4 /24 where origins cluster, exact IPv4
        # addresses otherwise, and exact IPv6 addresses (never the /48 it only displays).
        servers, warnings = sos.load_targets(['198.51.100.0/24', '203.0.113.10', '2001:db8:1234::1'],
                                             resolver=self.fake_resolver)
        ips = {ip for s in servers for ip in s.ips}
        self.assertIn('198.51.100.7', ips)
        self.assertIn('203.0.113.10', ips)
        self.assertIn('2001:db8:1234::1', ips)
        self.assertEqual(warnings, [])
        with self.assertRaisesRegex(sos.UsageError, 'allow-large'):
            sos.load_targets(['2001:db8:1234::/48'])

    def test_real_resolver_for_localhost(self):
        ips = sos.resolve_host('localhost')  # served from the hosts file, no network
        self.assertTrue(set(ips) & {'127.0.0.1', '::1'}, ips)


# ================================================================ engine (mocked I/O)

RSA_DER = sos.parse_certificate(fixture_bytes('rsa_multi_san.der')).der
EC_DER = fixture_cert('ec_wildcard.pem').der
RENEWED_DER = fixture_cert('cli_renewed_wild.pem').der
CN_ONLY_DER = fixture_cert('cn_only.pem').der


class FakeNetwork:
    """Scriptable connect/TLS functions: {ip: behaviour}."""

    def __init__(self, connect: Dict[str, object], tls: Dict[str, object]) -> None:
        self.connect = connect
        self.tls = tls
        self.calls = []  # type: List[Tuple[str, int, Optional[str]]]
        self.lock = threading.Lock()

    def connect_fn(self, ip: str, port: int, timeout: float) -> None:
        outcome = self.connect.get(ip)
        if isinstance(outcome, BaseException):
            raise outcome

    def tls_fn(self, ip: str, port: int, sni: Optional[str], timeout: float):
        with self.lock:
            self.calls.append((ip, port, sni))
        behaviour = self.tls[ip]
        if callable(behaviour):
            behaviour = behaviour(sni)
        if isinstance(behaviour, BaseException):
            raise behaviour
        if isinstance(behaviour, sos.TlsResult):
            return behaviour
        return sos.TlsResult(der=behaviour, version='TLSv1.3')


def by_old_or_new(old_der: bytes, default: Optional[bytes] = None):
    def pick(sni):
        if sni is None:
            return default or CN_ONLY_DER
        if sni.endswith('example-test.com.tr'):
            return RSA_DER
        if sni.endswith('wild.example.net'):
            return old_der
        return CN_ONLY_DER
    return pick


class EngineTests(unittest.TestCase):

    def scan(self, servers, names, network, new_certs=(), ports=(443,), **kwargs):
        probes = sos.build_probe_names(names)
        return sos.run_scan(servers, probes, list(ports), new_certs=new_certs, timeout=1,
                            workers=4, connect_fn=network.connect_fn, tls_fn=network.tls_fn,
                            **kwargs)

    def rows(self, report, server=None, probe=None):
        return {(r.server, r.port, r.name): r for r in report.results
                if (server is None or r.server == server) and (probe is None or r.probe == probe)}

    def test_statuses(self):
        renewed = fixture_cert('cli_renewed_wild.pem')
        servers = [sos.Server('old', ['10.0.0.1']), sos.Server('new', ['10.0.0.2']),
                   sos.Server('closed', ['10.0.0.3']), sos.Server('slow', ['10.0.0.4']),
                   sos.Server('broken', ['10.0.0.5']), sos.Server('strict', ['10.0.0.6']),
                   sos.Server('unreach', ['10.0.0.7'])]
        network = FakeNetwork(
            connect={'10.0.0.3': ConnectionRefusedError(), '10.0.0.4': None,
                     '10.0.0.7': OSError(113, 'No route to host')},
            tls={'10.0.0.1': by_old_or_new(EC_DER), '10.0.0.2': by_old_or_new(RENEWED_DER),
                 '10.0.0.4': socket.timeout('timed out'),
                 '10.0.0.5': ssl.SSLError(1, '[SSL: WRONG_VERSION_NUMBER] wrong version number '
                                             '(_ssl.c:1000)'),
                 '10.0.0.6': sos.TlsResult(status=sos.NOT_HOSTED, error='rejected')})
        report = self.scan(servers, ['a.wild.example.net', 'www.example-test.com.tr',
                                     'nothere.example.com'] + renewed.hostnames,
                           network, new_certs=[renewed])
        rows = self.rows(report)
        self.assertEqual(rows[('old', 443, 'a.wild.example.net')].status, sos.NEEDS_UPDATE)
        self.assertEqual(rows[('old', 443, 'a.wild.example.net')].covered_by,
                         '*.wild.example.net')
        self.assertEqual(rows[('old', 443, '*.wild.example.net')].status, sos.NEEDS_UPDATE)
        self.assertEqual(rows[('old', 443, '*.wild.example.net')].probe, sos.PROBE_WILDCARD)
        self.assertEqual(rows[('old', 443, 'wild.example.net')].status, sos.NEEDS_UPDATE)
        self.assertEqual(rows[('old', 443, 'nothere.example.com')].status, sos.NOT_HOSTED)
        www = rows[('old', 443, 'www.example-test.com.tr')]
        self.assertEqual(www.status, sos.NEEDS_UPDATE)
        self.assertIs(www.new_cert_covers, False)
        self.assertIs(rows[('old', 443, 'a.wild.example.net')].new_cert_covers, True)
        for name in ('a.wild.example.net', '*.wild.example.net', 'wild.example.net'):
            self.assertEqual(rows[('new', 443, name)].status, sos.UPDATED, name)
        self.assertEqual(rows[('closed', 443, None)].status, sos.CLOSED)
        self.assertEqual(rows[('closed', 443, None)].probe, sos.PROBE_CONNECT)
        self.assertEqual(rows[('unreach', 443, None)].status, sos.CLOSED)
        self.assertEqual(rows[('unreach', 443, None)].error, 'No route to host')
        self.assertEqual(rows[('slow', 443, 'a.wild.example.net')].status, sos.TIMEOUT)
        broken = rows[('broken', 443, 'a.wild.example.net')]
        self.assertEqual(broken.status, sos.TLS_ERROR)
        self.assertEqual(broken.error, '[SSL: WRONG_VERSION_NUMBER] wrong version number')
        self.assertEqual(rows[('strict', 443, 'a.wild.example.net')].status, sos.NOT_HOSTED)

        # "new" still serves another cert for www.example-test.com.tr (row NEEDS_UPDATE),
        # but the new cert does not cover that name, so the server counts as UPDATED.
        self.assertEqual(rows[('new', 443, 'www.example-test.com.tr')].status, sos.NEEDS_UPDATE)
        statuses = {s.server.name: s.status for s in report.server_summaries()}
        self.assertEqual(statuses, {'old': sos.NEEDS_UPDATE, 'new': sos.UPDATED,
                                    'closed': sos.CLOSED, 'slow': sos.TIMEOUT,
                                    'broken': sos.TLS_ERROR, 'strict': sos.NOT_HOSTED,
                                    'unreach': sos.CLOSED})
        self.assertTrue(report.needs_update())

    def test_names_outside_the_new_cert_do_not_make_a_server_need_it(self):
        renewed = fixture_cert('cli_renewed_wild.pem')
        network = FakeNetwork({}, {
            # hosts www.example-test.com.tr (not in the new cert) and nothing else
            '10.0.0.1': lambda sni: RSA_DER if sni and sni.startswith('www.') else CN_ONLY_DER,
            # default (no SNI) cert covers only a name outside the new cert
            '10.0.0.2': lambda sni: RSA_DER if sni is None else CN_ONLY_DER})
        servers = [sos.Server('legacy', ['10.0.0.1']), sos.Server('default-rsa', ['10.0.0.2'])]
        report = self.scan(servers, ['www.example-test.com.tr', 'a.wild.example.net'], network,
                           new_certs=[renewed])
        rows = self.rows(report)
        self.assertEqual(rows[('legacy', 443, 'www.example-test.com.tr')].status,
                         sos.NEEDS_UPDATE)
        self.assertEqual(rows[('default-rsa', 443, None)].status, sos.NOT_HOSTED)
        statuses = {s.server.name: s.status for s in report.server_summaries()}
        self.assertEqual(statuses, {'legacy': sos.NOT_HOSTED, 'default-rsa': sos.NOT_HOSTED})
        self.assertFalse(report.needs_update())
        doc = sos.report_to_dict(report)
        legacy = next(s for s in doc['servers'] if s['name'] == 'legacy')
        self.assertEqual(legacy['needsUpdate'], [])
        self.assertEqual(legacy['hostedNotInNewCert'], ['www.example-test.com.tr'])
        text = sos.render_summary(report)
        self.assertIn('Hosting only names the new certificate does not cover: 1', text)
        self.assertIn('(not covered by the new certificate)', text)
        self.assertIn('Servers that need the new certificate: 0', text)

    def test_handshakes_are_shared_per_sni(self):
        network = FakeNetwork({}, {'10.0.0.1': by_old_or_new(EC_DER)})
        servers = [sos.Server('a', ['10.0.0.1']), sos.Server('b', ['10.0.0.1'])]  # same IP
        report = self.scan(servers, ['x.wild.example.net', 'X.wild.example.net',
                                     '*.wild.example.net'], network, ports=(443, 8443))
        # 2 ports x (no-SNI + x.wild + base + wildcard probe) handshakes, not per server
        self.assertEqual(len(network.calls), 2 * 4)
        self.assertEqual(len({(ip, port, sni) for ip, port, sni in network.calls}), 8)
        self.assertEqual(len(report.endpoints), 2)
        # rows are per server
        self.assertEqual(len([r for r in report.results if r.server == 'a']), 2 * 4)

    def test_default_certificate_verdicts(self):
        renewed = fixture_cert('cli_renewed_wild.pem')
        network = FakeNetwork({}, {
            '10.0.0.1': by_old_or_new(RENEWED_DER, default=EC_DER),   # partially updated
            '10.0.0.2': by_old_or_new(RENEWED_DER, default=RENEWED_DER),
            '10.0.0.3': by_old_or_new(RENEWED_DER, default=CN_ONLY_DER),
            '10.0.0.4': lambda sni: (ssl.SSLError(1, 'sni required') if sni is None
                                     else RENEWED_DER)})
        servers = [sos.Server('partial', ['10.0.0.1']), sos.Server('full', ['10.0.0.2']),
                   sos.Server('other-default', ['10.0.0.3']),
                   sos.Server('sni-only', ['10.0.0.4'])]
        report = self.scan(servers, ['a.wild.example.net'], network, new_certs=[renewed])
        defaults = {r.server: r for r in report.results if r.probe == sos.PROBE_DEFAULT}
        self.assertEqual(defaults['partial'].status, sos.NEEDS_UPDATE)
        self.assertEqual(defaults['partial'].covered_by, '*.wild.example.net')
        self.assertEqual(defaults['full'].status, sos.UPDATED)
        self.assertEqual(defaults['other-default'].status, sos.NOT_HOSTED)
        self.assertEqual(defaults['sni-only'].status, sos.TLS_ERROR)
        statuses = {s.server.name: s.status for s in report.server_summaries()}
        self.assertEqual(statuses, {'partial': sos.NEEDS_UPDATE, 'full': sos.UPDATED,
                                    'other-default': sos.UPDATED, 'sni-only': sos.UPDATED})
        counts = report.status_counts()  # no-SNI rows are not counted
        self.assertEqual(counts[sos.UPDATED], 4)
        self.assertEqual(counts[sos.TLS_ERROR], 0)

    def test_refused_name_on_a_working_endpoint_is_not_hosted(self):
        def alert(reason):
            exc = ssl.SSLError(1, '[SSL: %s] alert' % reason)
            exc.reason = reason
            return exc

        network = FakeNetwork({}, {
            # Cloudflare-like: unknown SNI and missing SNI -> handshake_failure alert
            '10.0.0.1': lambda sni: (RSA_DER if sni and sni.endswith('example-test.com.tr')
                                     else alert('SSLV3_ALERT_HANDSHAKE_FAILURE')),
            # HAProxy strict-sni-like: closes the connection for unknown names
            '10.0.0.2': lambda sni: (RSA_DER if sni and sni.endswith('example-test.com.tr')
                                     else ssl.SSLEOFError(8, 'EOF occurred')),
            # nothing works at all: cannot tell, stays TLS_ERROR
            '10.0.0.3': lambda sni: alert('SSLV3_ALERT_HANDSHAKE_FAILURE')})
        servers = [sos.Server('cf', ['10.0.0.1']), sos.Server('haproxy', ['10.0.0.2']),
                   sos.Server('broken', ['10.0.0.3'])]
        report = self.scan(servers, ['www.example-test.com.tr', 'other.example.com'], network)
        rows = self.rows(report)
        for server in ('cf', 'haproxy'):
            self.assertEqual(rows[(server, 443, 'www.example-test.com.tr')].status,
                             sos.NEEDS_UPDATE)
            other = rows[(server, 443, 'other.example.com')]
            self.assertEqual(other.status, sos.NOT_HOSTED, server)
            self.assertIn('server refused this name', other.error)
            default = rows[(server, 443, None)]
            self.assertEqual(default.status, sos.NOT_HOSTED, server)
            self.assertIn('server requires SNI', default.error)
        self.assertEqual(rows[('broken', 443, 'other.example.com')].status, sos.TLS_ERROR)
        self.assertEqual(rows[('broken', 443, None)].status, sos.TLS_ERROR)
        self.assertTrue(sos.is_refusal(ssl.SSLEOFError()))
        self.assertTrue(sos.is_refusal(ConnectionResetError()))
        self.assertFalse(sos.is_refusal(socket.timeout()))
        self.assertFalse(sos.is_refusal(ssl.SSLError(1, 'no reason')))

    def test_without_new_cert_every_hit_is_needs_update(self):
        network = FakeNetwork({}, {'10.0.0.1': by_old_or_new(EC_DER)})
        report = self.scan([sos.Server('s', ['10.0.0.1'])], ['www.example-test.com.tr'],
                           network)
        row = self.rows(report, probe=sos.PROBE_SNI)[('s', 443, 'www.example-test.com.tr')]
        self.assertEqual(row.status, sos.NEEDS_UPDATE)
        self.assertIsNone(row.new_cert_covers)

    def test_default_probe_can_be_disabled(self):
        network = FakeNetwork({}, {'10.0.0.1': by_old_or_new(EC_DER)})
        report = self.scan([sos.Server('s', ['10.0.0.1'])], ['a.wild.example.net'], network,
                           default_probe=False)
        self.assertNotIn(None, [sni for _, _, sni in network.calls])
        self.assertEqual({r.probe for r in report.results}, {sos.PROBE_SNI})

    def test_unparseable_certificate_and_unexpected_errors(self):
        network = FakeNetwork({}, {'10.0.0.1': b'\x30\x03\x02\x01\x01',
                                   '10.0.0.2': RuntimeError('boom'),
                                   '10.0.0.3': sos.TlsResult(der=None, status=sos.TLS_ERROR,
                                                             error='server sent no certificate')})
        servers = [sos.Server('a', ['10.0.0.1']), sos.Server('b', ['10.0.0.2']),
                   sos.Server('c', ['10.0.0.3'])]
        report = self.scan(servers, ['x.example.com'], network)
        rows = self.rows(report, probe=sos.PROBE_SNI)
        self.assertEqual(rows[('a', 443, 'x.example.com')].status, sos.TLS_ERROR)
        self.assertIn('unparseable certificate', rows[('a', 443, 'x.example.com')].error)
        self.assertEqual(rows[('b', 443, 'x.example.com')].error, 'RuntimeError: boom')
        self.assertEqual(rows[('c', 443, 'x.example.com')].error, 'server sent no certificate')

    def test_connect_timeouts(self):
        network = FakeNetwork({'10.0.0.1': socket.timeout('timed out'),
                               '10.0.0.2': TimeoutError(10060, 'timed out')}, {})
        report = self.scan([sos.Server('a', ['10.0.0.1', '10.0.0.2'])], ['x.example.com'],
                           network)
        self.assertEqual({r.status for r in report.results}, {sos.TIMEOUT})
        self.assertEqual(report.server_summaries()[0].status, sos.TIMEOUT)
        self.assertEqual(network.calls, [])

    def test_progress_callback(self):
        events = []
        network = FakeNetwork({}, {'10.0.0.1': by_old_or_new(EC_DER)})
        self.scan([sos.Server('a', ['10.0.0.1'])], ['x.wild.example.net'], network,
                  ports=(443, 8443), progress=lambda *args: events.append(args))
        connect = [e for e in events if e[0] == 'connect']
        tls = [e for e in events if e[0] == 'tls']
        self.assertEqual(connect[-1][1:3], (2, 2))
        self.assertEqual(connect[-1][3], {'open': 2})
        self.assertEqual(tls[-1][1:3], (4, 4))

    def test_keyboard_interrupt_propagates(self):
        network = FakeNetwork({}, {'10.0.0.1': KeyboardInterrupt()})
        with self.assertRaises(KeyboardInterrupt):
            self.scan([sos.Server('a', ['10.0.0.1'])], ['x.example.com'], network)

    def test_parallel_bounded_and_ordered_callbacks(self):
        seen, active, peak = [], [0], [0]
        lock = threading.Lock()

        def work(item):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            time.sleep(0.005)
            with lock:
                active[0] -= 1
            return item * 2

        sos._parallel(work, list(range(50)), 3, lambda item, res: seen.append((item, res)),
                      threading.Event())
        self.assertEqual(sorted(seen), [(i, i * 2) for i in range(50)])
        self.assertLessEqual(peak[0], 3)

    def test_classify_exception(self):
        cases = [
            (socket.timeout('x'), sos.TIMEOUT), (TimeoutError(), sos.TIMEOUT),
            (ConnectionRefusedError(), sos.CLOSED), (ConnectionResetError(), sos.TLS_ERROR),
            (ssl.SSLEOFError(8, 'eof'), sos.TLS_ERROR), (OSError(5, 'io'), sos.TLS_ERROR),
            (UnicodeError('label too long'), sos.TLS_ERROR), (RuntimeError('x'), sos.TLS_ERROR),
        ]
        for exc, status in cases:
            self.assertEqual(sos.classify_exception(exc)[0], status, repr(exc))
        unrecognized = ssl.SSLError(1, 'x')
        unrecognized.reason = 'TLSV1_UNRECOGNIZED_NAME'
        self.assertEqual(sos.classify_exception(unrecognized)[0], sos.NOT_HOSTED)
        self.assertEqual(sos.classify_connect_exception(OSError(101, 'Network is unreachable')),
                         (sos.CLOSED, 'Network is unreachable'))

    def test_client_context_is_permissive(self):
        context = sos.make_client_context()
        self.assertEqual(context.verify_mode, ssl.CERT_NONE)
        self.assertFalse(context.check_hostname)


# ============================================================================ output

def sample_report():
    renewed = fixture_cert('cli_renewed_wild.pem')
    network = FakeNetwork(
        {'10.0.0.3': ConnectionRefusedError()},
        {'10.0.0.1': by_old_or_new(EC_DER),
         '10.0.0.2': lambda sni: (RENEWED_DER if sni and sni.endswith('wild.example.net')
                                  else CN_ONLY_DER),
         '10.0.0.4': by_old_or_new(RENEWED_DER, default=CN_ONLY_DER),
         '2001:db8::5': ssl.SSLError(1, 'handshake failure'),
         '10.0.0.6': lambda sni: RSA_DER if sni and sni.startswith('www.') else CN_ONLY_DER,
         '10.0.0.7': by_old_or_new(RENEWED_DER, default=EC_DER)})
    servers = [sos.Server('web-old', ['10.0.0.1'], ['prod']),     # NEEDS_UPDATE
               sos.Server('web-new', ['10.0.0.2']),               # UPDATED
               sos.Server('10.0.0.3', ['10.0.0.3']),              # unreachable
               sos.Server('mail', ['10.0.0.4']),                  # UPDATED (+ www elsewhere)
               sos.Server('v6', ['2001:db8::5']),                 # handshake errors
               sos.Server('legacy-app', ['10.0.0.6']),            # only names outside new cert
               sos.Server('partial', ['10.0.0.7'])]               # old default cert
    probes = sos.build_probe_names(['a.wild.example.net', 'b.wild.example.net',
                                    'www.example-test.com.tr'])
    report = sos.run_scan(servers, probes, [443], new_certs=[renewed], timeout=1, workers=4,
                          connect_fn=network.connect_fn, tls_fn=network.tls_fn,
                          warnings=['example warning'])
    return report


class OutputTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = sample_report()

    def test_json_document_shape(self):
        doc = json.loads(sos.render_json(self.report))
        self.assertEqual(set(doc), {'tool', 'version', 'startedAt', 'finishedAt',
                                    'elapsedSeconds', 'options', 'newCertificates', 'names',
                                    'summary', 'servers', 'endpoints', 'results',
                                    'certificates', 'warnings'})
        self.assertEqual(doc['tool'], 'ssl_origin_scan')
        self.assertEqual(doc['version'], sos.__version__)
        self.assertTrue(doc['finishedAt'].endswith('Z'))
        self.assertEqual(doc['options'], {'ports': [443], 'timeoutSeconds': 1, 'workers': 4})
        self.assertEqual(doc['newCertificates'][0]['sha256'], RENEWED_WILD_SHA256)
        self.assertEqual(doc['summary']['servers'], 7)
        self.assertEqual(doc['summary']['endpoints'], 7)
        self.assertEqual(doc['summary']['openEndpoints'], 6)
        self.assertEqual(doc['summary']['serversNeedingUpdate'], 2)
        self.assertEqual(doc['summary']['serversUpdated'], 2)
        partial = next(s for s in doc['servers'] if s['name'] == 'partial')
        self.assertEqual(partial['status'], 'NEEDS_UPDATE')
        self.assertTrue(partial['defaultCertNeedsUpdate'])
        self.assertEqual(partial['needsUpdate'], [])
        mail = next(s for s in doc['servers'] if s['name'] == 'mail')
        self.assertEqual(mail['status'], 'UPDATED')
        self.assertEqual(mail['hostedNotInNewCert'], ['www.example-test.com.tr'])
        self.assertEqual([p['name'] for p in doc['names']],
                         ['a.wild.example.net', 'b.wild.example.net', 'www.example-test.com.tr'])
        self.assertEqual(doc['warnings'], ['example warning'])
        server_old = next(s for s in doc['servers'] if s['name'] == 'web-old')
        self.assertEqual(server_old['status'], 'NEEDS_UPDATE')
        self.assertEqual(server_old['groups'], ['prod'])
        self.assertIn('a.wild.example.net', server_old['needsUpdate'])
        row = next(r for r in doc['results'] if r['server'] == 'web-old'
                   and r['name'] == 'a.wild.example.net')
        self.assertEqual(set(row), {'server', 'ip', 'port', 'probe', 'name', 'sni', 'status',
                                    'coveredBy', 'newCertCovers', 'certSha256', 'certSubjectCN',
                                    'certIssuer', 'certSerial', 'certNotAfter', 'certDaysLeft',
                                    'tlsVersion', 'error', 'elapsedMs'})
        self.assertEqual(row['certSha256'], EXPECTED['ec_wildcard.pem']['sha256'])
        self.assertEqual(row['certNotAfter'], '2051-01-01T00:00:00.000Z')
        self.assertIn(row['certSha256'], doc['certificates'])
        self.assertFalse(doc['certificates'][row['certSha256']]['isNewCert'])
        self.assertTrue(doc['certificates'][RENEWED_WILD_SHA256]['isNewCert'])
        closed = next(r for r in doc['results'] if r['server'] == '10.0.0.3')
        self.assertEqual((closed['probe'], closed['status'], closed['name']),
                         ('connect', 'CLOSED', None))
        self.assertEqual(sum(doc['summary']['statusCounts'].values()),
                         len([r for r in doc['results'] if r['probe'] != 'default']))

    def test_csv(self):
        text = sos.render_csv(self.report)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(tuple(rows[0]), sos.CSV_COLUMNS)
        self.assertEqual(len(rows) - 1, len(self.report.results))
        self.assertTrue(text.endswith('\r\n'))
        header = rows[0]
        match = next(r for r in rows[1:] if r[0] == 'web-new' and r[4] == 'a.wild.example.net')
        record = dict(zip(header, match))
        self.assertEqual(record['status'], 'UPDATED')
        self.assertEqual(record['new_cert_covers'], 'yes')
        self.assertEqual(record['cert_sha256'], RENEWED_WILD_SHA256)
        self.assertTrue(sos.render_csv(self.report, lineterminator='\n').endswith('\n'))

    def test_human_summary_plain(self):
        text = sos.render_summary(self.report, color=False, width=100)
        self.assertNotIn('\x1b[', text)
        need_idx = text.index('Servers that need the new certificate: 2')
        updated_idx = text.index('Already serving the new certificate: 2')
        errors_idx = text.index('Handshake errors: 1')
        other_idx = text.index('Hosting only names the new certificate does not cover: 1')
        self.assertLess(need_idx, updated_idx)
        self.assertLess(updated_idx, errors_idx)
        self.assertLess(errors_idx, other_idx)
        need_block = text[need_idx:updated_idx]
        self.assertIn('web-old', need_block)
        self.assertIn('[prod]', need_block)
        self.assertIn('partial', need_block)
        self.assertIn('default certificate (no SNI): NEEDS_UPDATE  *.wild.example.net',
                      need_block)
        self.assertIn('current: *.wild.example.net | expires 2051-01-01 (', need_block)
        self.assertIn('days left) | issuer: *.wild.example.net', need_block)
        self.assertIn('serial 07 | sha256 1f7337a33d046c66...', need_block)
        updated_block = text[updated_idx:errors_idx]
        self.assertIn('web-new', updated_block)
        self.assertIn('mail', updated_block)
        self.assertIn('www.example-test.com.tr  (not covered by the new certificate)',
                      updated_block)
        self.assertIn('legacy-app', text[other_idx:])
        self.assertIn('handshake failure', text[errors_idx:other_idx])
        self.assertIn('all 3 names', text[errors_idx:other_idx])
        self.assertIn('1 unreachable (no open port)', text)
        self.assertIn('--show-all', text)
        self.assertIn('New certificate: *.wild.example.net | expires 2052-01-01', text)
        self.assertRegex(text, r'Results \(server/port/name\): NEEDS_UPDATE \d+, UPDATED \d+')

    def test_human_summary_show_all_and_color(self):
        text = sos.render_summary(self.report, color=True, show_all=True)
        self.assertIn('\x1b[', text)
        plain = re.sub(r'\x1b\[[0-9;]*m', '', text)
        self.assertIn('Unreachable (no open port): 1', plain)
        self.assertIn('10.0.0.3:443  CLOSED', plain)
        self.assertIn('default certificate (no SNI): NOT_HOSTED', plain)

    def test_summary_without_new_cert(self):
        network = FakeNetwork({}, {'10.0.0.1': by_old_or_new(EC_DER)})
        report = sos.run_scan([sos.Server('s', ['10.0.0.1'])],
                              sos.build_probe_names(['a.wild.example.net']), [443], timeout=1,
                              workers=2, connect_fn=network.connect_fn, tls_fn=network.tls_fn)
        text = sos.render_summary(report)
        self.assertIn('No --cert given', text)
        self.assertIn('Servers hosting the names: 1', text)
        self.assertNotIn('Already serving', text)

    def test_days_text(self):
        style = sos.Style(False)
        cert = fixture_cert('cn_only.pem')
        self.assertEqual(sos._days_text(cert, datetime(2035, 1, 4, tzinfo=timezone.utc), style),
                         'EXPIRED 3 days ago')
        self.assertEqual(sos._days_text(cert, datetime(2034, 12, 31, tzinfo=timezone.utc),
                                        style), '1 day left')
        colored = sos._days_text(cert, datetime(2034, 12, 15, tzinfo=timezone.utc), sos.Style(True))
        self.assertIn('\x1b[31;1m', colored)

    def test_use_color(self):
        class FakeTty(io.StringIO):
            def isatty(self):
                return True

        self.assertFalse(sos.use_color(False, io.StringIO(), env={}))
        self.assertFalse(sos.use_color(True, FakeTty(), env={}))
        self.assertFalse(sos.use_color(False, FakeTty(), env={'NO_COLOR': '1'}))
        if os.name != 'nt':
            self.assertTrue(sos.use_color(False, FakeTty(), env={'NO_COLOR': ''}))
        else:  # no real console behind the fake stream: VT mode cannot be enabled
            self.assertFalse(sos.use_color(False, FakeTty(), env={}))

    def test_progress_printer(self):
        stream = io.StringIO()
        printer = sos.ProgressPrinter(stream, enabled=True)
        printer.update('connect', 1, 4, {'open': 1})
        printer.update('connect', 4, 4, {'open': 3})
        printer.finish()
        self.assertIn('Checking ports: 4/4 (100%) - 3 open', stream.getvalue())
        self.assertTrue(stream.getvalue().endswith('\r'))
        silent = io.StringIO()
        sos.ProgressPrinter(silent, enabled=False).update('tls', 1, 2, {})
        self.assertEqual(silent.getvalue(), '')

    def test_iso_and_endpoint_labels(self):
        self.assertEqual(sos.iso_utc(datetime(2025, 1, 2, 3, 4, 5, 678901, tzinfo=timezone.utc)),
                         '2025-01-02T03:04:05.678Z')
        self.assertEqual(sos.iso_utc(datetime(2025, 1, 2, 3, 0, tzinfo=timezone(
            timedelta(hours=3)))), '2025-01-02T00:00:00.000Z')
        self.assertIsNone(sos.iso_utc(None))
        self.assertEqual(sos._endpoint_label('2001:db8::1', 443), '[2001:db8::1]:443')
        self.assertEqual(sos._endpoint_label('10.0.0.1', 8443), '10.0.0.1:8443')


# ============================================================================== CLI

class CliArgumentTests(unittest.TestCase):

    def test_version(self):
        code, out, _ = run_main('--version')
        self.assertEqual(code, 0)
        self.assertIn(sos.__version__, out)

    def test_help_has_examples_and_turkish(self):
        code, out, _ = run_main('--help')
        self.assertEqual(code, 0)
        for needle in ('examples:', '--fail-on-needs-update', 'NEEDS_UPDATE', 'ansible_host',
                       'T\u00fcrk\u00e7e', '--allow-large', 'exit codes'):
            self.assertIn(needle, out)

    def test_parse_ports(self):
        self.assertEqual(sos.parse_ports('443, 8443,443 9440-9442'),
                         [443, 8443, 9440, 9441, 9442])
        for bad in ('', 'abc', '0', '70000', '10-5', '1-2000', '44 3x'):
            with self.assertRaises(sos.UsageError, msg=bad):
                sos.parse_ports(bad)

    def test_usage_errors_exit_2(self):
        missing_dir = os.path.join(tempfile.gettempdir(), 'no-such-dir-8d1f', 'x.json')
        cases = [
            (),                                                    # -t is required
            ('-t', '127.0.0.1'),                                   # nothing to probe
            ('-t', '127.0.0.1', '-n', 'a.example.com', '-p', '70000'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '-w', '0'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--timeout', '0'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--json', '-', '--csv', '-'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--json', missing_dir),
            ('-t', '127.0.0.1', '-n', 'missing-names.txt'),
            ('-t', 'missing-targets.txt', '-n', 'a.example.com'),
            ('-t', '10.0.0.0/8', '-n', 'a.example.com'),
            ('-t', '10.0.0.0/8', '-n', 'a.example.com', '--allow-large'),
            ('-t', '-', '-n', '-'),
            ('-t', '127.0.0.1', '--cert', str(FIXTURES / 'does-not-exist.pem')),
            ('-t', '127.0.0.1', '--cert', str(FIXTURES / 'ec_wildcard.key')),
            ('-t', '127.0.0.1', '--bogus-option'),
        ]
        for args in cases:
            with self.subTest(args=args):
                code, _, err = run_main(*args)
                self.assertEqual(code, 2)
                self.assertTrue(err.strip())
                self.assertNotIn('Traceback', err)

    def test_pkcs12_and_csr_messages(self):
        code, _, err = run_main('-t', '127.0.0.1', '--cert', str(FIXTURES / 'cli_bundle.p12'))
        self.assertEqual(code, 2)
        self.assertIn('openssl pkcs12 -in', err)
        with tempfile.TemporaryDirectory() as tmp:
            csr = os.path.join(tmp, 'req.pem')
            with open(csr, 'w') as handle:
                handle.write('-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n'
                             '-----END CERTIFICATE REQUEST-----\n')
            code, _, err = run_main('-t', '127.0.0.1', '--cert', csr)
        self.assertEqual(code, 2)
        self.assertIn('signing request', err)

    def test_no_scannable_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'empty.txt')
            with open(path, 'w') as handle:
                handle.write('# nothing here\n')
            code, _, err = run_main('-t', path, '-n', 'a.example.com')
        self.assertEqual(code, 2)
        self.assertIn('no scannable targets', err)

    def test_keyboard_interrupt_returns_130(self):
        with mock.patch.object(sos, 'run_scan', side_effect=KeyboardInterrupt):
            code, out, err = run_main('-t', '127.0.0.1', '-n', 'a.example.com', '-q')
        self.assertEqual(code, 130)
        self.assertIn('interrupted', err)
        self.assertEqual(out, '')

    def test_json_on_non_utf8_stdout_is_ascii_escaped(self):
        report = sample_report()
        report.warnings.append('Türkçe uyarı')
        escaped = sos.render_json(report, ensure_ascii=True)
        self.assertTrue(escaped.isascii())
        self.assertIn('\\u0131', escaped)
        self.assertEqual(json.loads(escaped), json.loads(sos.render_json(report)))
        self.assertIn('Türkçe uyarı', sos.render_json(report))

    def test_load_new_certificate_messages(self):
        leaf, messages = sos.load_new_certificate(str(FIXTURES / 'with_key.pem'), NOW)
        self.assertEqual(leaf.subject_cn, 'www.example-test.com.tr')
        self.assertTrue(any('PRIVATE KEY' in m for m in messages))
        leaf, messages = sos.load_new_certificate(str(FIXTURES / 'chain_reversed.pem'), NOW)
        self.assertEqual(leaf.subject_cn, 'www.example-test.com.tr')
        self.assertTrue(any('using the leaf' in m for m in messages))
        _, messages = sos.load_new_certificate(str(FIXTURES / 'cn_only.pem'),
                                               datetime(2036, 1, 1, tzinfo=timezone.utc))
        self.assertTrue(any('EXPIRED' in m for m in messages))
        _, messages = sos.load_new_certificate(str(FIXTURES / 'cli_renewed_wild.pem'),
                                               datetime(2025, 1, 1, tzinfo=timezone.utc))
        self.assertTrue(any('not valid before' in m for m in messages))


TURKISH_HELP_LINE = ('Türkçe: yeni sertifikanın hangi sunuculara '
                     'yüklenmesi gerektiğini bulur, örnek:')


class StreamEncodingTests(unittest.TestCase):
    """stdout / stderr encodings that avoid mojibake ('T³rkþe') on Windows consoles."""

    def choose(self, current, kind, env=None, cp=857, windows=True, utf8_mode=False):
        return sos._choose_stream_encoding(current, kind, env=env or {}, console_cp=cp,
                                           windows=windows, utf8_mode=utf8_mode)

    def test_windows_matrix(self):
        cases = [
            # (current, kind, env, console cp) -> target (None = keep)
            (('cp1254', 'pipe', {}, 857), 'cp857'),       # cmd `| more`, PowerShell pipes
            (('cp1252', 'pipe', {}, 437), 'cp437'),
            (('cp857', 'pipe', {}, 857), None),           # already the console code page
            (('cp1254', 'pipe', {}, 65001), 'utf-8'),     # chcp 65001 / UTF-8 console
            (('cp1254', 'pipe', {}, 0), 'utf-8'),         # no console (service, CI runner)
            (('cp1254', 'pipe', {}, 12345), 'utf-8'),     # unknown code page
            (('cp1254', 'pipe', {'MSYSTEM': 'MINGW64'}, 857), 'utf-8'),  # Git Bash / mintty
            (('cp1254', 'pipe', {'TERM': 'xterm-256color'}, 857), 'utf-8'),
            (('cp1254', 'pipe', {'TERM': 'cygwin'}, 857), 'utf-8'),
            (('cp1254', 'file', {}, 857), 'utf-8'),       # `> out.txt`
            (('cp1254', 'other', {}, 857), 'utf-8'),
            (('utf-8', 'console', {}, 857), None),        # the console API writes UTF-16
            (('UTF-8', 'pipe', {}, 857), None),
            (('cp1254', 'pipe', {'PYTHONIOENCODING': 'cp1254'}, 857), None),  # explicit wins
        ]
        for (current, kind, env, cp), want in cases:
            with self.subTest(current=current, kind=kind, env=env, cp=cp):
                self.assertEqual(self.choose(current, kind, env, cp), want)
        self.assertIsNone(self.choose('cp1254', 'pipe', utf8_mode=True))

    def test_posix(self):
        self.assertEqual(self.choose('ascii', 'pipe', windows=False), 'utf-8')
        self.assertEqual(self.choose('ANSI_X3.4-1968', 'console', windows=False), 'utf-8')
        self.assertIsNone(self.choose('utf-8', 'pipe', windows=False))
        self.assertIsNone(self.choose('iso8859-9', 'console', windows=False))

    def test_transliteration_instead_of_mojibake_or_crash(self):
        codecs.register_error(sos._TRANSLIT_ERRORS, sos._translit_errors)
        text = 'Türkçe ışİĞ → ’x’ ✓ 中'
        # cp437 has ü and ç but no ı ş İ Ğ: look-alikes instead of '?' (unknown CJK -> '?')
        self.assertEqual(text.encode('cp437', sos._TRANSLIT_ERRORS),
                         b"T\x81rk\x87e isIG -> 'x' v ?")
        self.assertEqual(text.encode('cp857', sos._TRANSLIT_ERRORS).decode('cp857'),
                         "Türkçe ışİĞ -> 'x' v ?")
        with self.assertRaises(UnicodeDecodeError):
            b'\xff'.decode('utf-8', sos._TRANSLIT_ERRORS)

    @unittest.skipIf(sys.flags.utf8_mode, 'Python UTF-8 mode keeps UTF-8 on purpose')
    def test_configure_streams_switches_a_pipe_to_the_console_code_page(self):
        out = io.TextIOWrapper(io.BytesIO(), encoding='cp1254')
        err = io.TextIOWrapper(io.BytesIO(), encoding='cp1254')
        env = {k: v for k, v in os.environ.items()
               if k not in ('PYTHONIOENCODING', 'MSYSTEM', 'TERM')}
        with mock.patch.object(sos, '_IS_WINDOWS', True), \
                mock.patch.object(sos, '_stream_kind', return_value='pipe'), \
                mock.patch.object(sos, '_console_output_cp', return_value=857), \
                mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(sys, 'stdout', out), mock.patch.object(sys, 'stderr', err):
            sos._configure_streams()
            sys.stdout.write(TURKISH_HELP_LINE + ' 中')
            sys.stdout.flush()
        self.assertEqual(out.encoding, 'cp857')
        self.assertEqual(err.encoding, 'cp857')
        self.assertEqual(out.buffer.getvalue().decode('cp857'), TURKISH_HELP_LINE + ' ?')

    def test_help_redirected_to_a_file_is_utf8(self):
        env = {k: v for k, v in os.environ.items() if k != 'PYTHONIOENCODING'}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'help.txt')
            with open(path, 'wb') as handle:
                proc = subprocess.run([sys.executable, str(CLI_PATH), '--help'], stdout=handle,
                                      stderr=subprocess.PIPE, env=env, timeout=60)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(path, 'rb') as handle:
                data = handle.read()
        self.assertIn(TURKISH_HELP_LINE, data.decode('utf-8'))


# ===================================================================== integration

def _server_context(fixture: str) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(FIXTURES / (fixture + '.pem')), str(FIXTURES / (fixture + '.key')))
    return context


class _Listener:
    """Base: accept loop on its own thread; subclasses implement ``handle(conn)``."""

    def __init__(self, host: str = '127.0.0.1', port: int = 0) -> None:
        family = socket.AF_INET6 if ':' in host else socket.AF_INET
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.bind((host, port))
        self.sock.listen(128)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._conns = []  # type: List[socket.socket]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(5)
            self._conns.append(conn)
            threading.Thread(target=self._safe_handle, args=(conn,), daemon=True).start()

    def _safe_handle(self, conn: socket.socket) -> None:
        try:
            self.handle(conn)
        except (OSError, ssl.SSLError, ValueError):
            pass  # phase-1 port checks connect and hang up immediately

    def handle(self, conn: socket.socket) -> None:
        raise NotImplementedError

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        for conn in self._conns:
            try:
                conn.close()
            except OSError:
                pass
        self._thread.join(2)


class TlsServer(_Listener):
    """TLS server choosing a fixture certificate by SNI suffix (``sni_callback``)."""

    def __init__(self, default: str, rules: Sequence[Tuple[str, str]] = (),
                 reject_unknown: bool = False, host: str = '127.0.0.1', port: int = 0,
                 alert: int = ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME,
                 require_sni: bool = False) -> None:
        self.context = _server_context(default)
        self.rules = [(suffix, _server_context(name)) for suffix, name in rules]
        self.reject_unknown = reject_unknown
        self.alert = alert
        self.require_sni = require_sni
        self.seen = []  # type: List[Optional[str]]
        self.context.sni_callback = self._on_sni
        super().__init__(host, port)

    def _on_sni(self, sslobj, server_name, _context):
        self.seen.append(server_name)
        if not server_name:
            return self.alert if self.require_sni else None
        for suffix, context in self.rules:
            if server_name == suffix or server_name.endswith('.' + suffix):
                sslobj.context = context
                return None
        return self.alert if self.reject_unknown else None

    def handle(self, conn: socket.socket) -> None:
        with self.context.wrap_socket(conn, server_side=True):
            pass


class PlainServer(_Listener):
    """Speaks HTTP, not TLS -> the client handshake fails (TLS_ERROR)."""

    def handle(self, conn: socket.socket) -> None:
        conn.recv(4096)
        conn.sendall(b'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n')
        conn.close()


class SilentServer(_Listener):
    """Accepts and never answers -> handshake TIMEOUT."""

    def handle(self, conn: socket.socket) -> None:
        self._stop.wait(30)


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


WILD_OLD = [('example-test.com.tr', 'rsa_multi_san'), ('wild.example.net', 'ec_wildcard')]
WILD_NEW = [('example-test.com.tr', 'rsa_multi_san'), ('wild.example.net', 'cli_renewed_wild')]


class IntegrationTests(unittest.TestCase):
    """Real TLS handshakes against local servers (default cert = cn_only)."""

    @classmethod
    def setUpClass(cls):
        cls.old = TlsServer('cn_only', WILD_OLD)
        cls.new = TlsServer('cn_only', WILD_NEW)
        cls.partial = TlsServer('ec_wildcard', WILD_NEW)          # old cert as default
        cls.strict = TlsServer('cn_only', WILD_OLD, reject_unknown=True)
        cls.plain = PlainServer()
        cls.silent = SilentServer()
        cls.closed_port = _free_port()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.renewed = str(FIXTURES / 'cli_renewed_wild.pem')

    @classmethod
    def tearDownClass(cls):
        for server in (cls.old, cls.new, cls.partial, cls.strict, cls.plain, cls.silent):
            server.close()
        cls.tmp.cleanup()

    def path(self, name: str) -> str:
        return os.path.join(self.tmp.name, name)

    @staticmethod
    def index(doc) -> Dict[Tuple[int, Optional[str]], Dict]:
        return {(row['port'], row['name'] if row['probe'] != 'default' else '(default)'): row
                for row in doc['results']}

    def test_needs_update_updated_not_hosted_closed(self):
        json_path, csv_path = self.path('a.json'), self.path('a.csv')
        ports = '%d,%d,%d' % (self.old.port, self.new.port, self.closed_port)
        code, out, err = run_main(
            '-t', '127.0.0.1', '-p', ports, '--timeout', '4', '-w', '16',
            '-n', 'a.wild.example.net', 'www.example-test.com.tr', 'nothere.example.com',
            '--cert', self.renewed, '--json', json_path, '--csv', csv_path)
        self.assertEqual(code, 0, err)
        doc = read_json(json_path)
        rows = self.index(doc)
        old, new, closed = self.old.port, self.new.port, self.closed_port

        self.assertEqual(rows[(old, 'a.wild.example.net')]['status'], 'NEEDS_UPDATE')
        self.assertEqual(rows[(old, 'a.wild.example.net')]['coveredBy'], '*.wild.example.net')
        self.assertEqual(rows[(old, 'a.wild.example.net')]['certSha256'],
                         EXPECTED['ec_wildcard.pem']['sha256'])
        self.assertEqual(rows[(old, '*.wild.example.net')]['status'], 'NEEDS_UPDATE')
        self.assertEqual(rows[(old, 'wild.example.net')]['status'], 'NEEDS_UPDATE')
        self.assertEqual(rows[(old, 'nothere.example.com')]['status'], 'NOT_HOSTED')
        self.assertEqual(rows[(old, 'nothere.example.com')]['certSubjectCN'],
                         'legacy.example.org')
        self.assertEqual(rows[(old, '(default)')]['status'], 'NOT_HOSTED')

        for name in ('a.wild.example.net', '*.wild.example.net', 'wild.example.net'):
            self.assertEqual(rows[(new, name)]['status'], 'UPDATED', name)
            self.assertEqual(rows[(new, name)]['certSha256'], RENEWED_WILD_SHA256)
        self.assertEqual(rows[(new, 'www.example-test.com.tr')]['status'], 'NEEDS_UPDATE')
        self.assertIs(rows[(new, 'www.example-test.com.tr')]['newCertCovers'], False)
        self.assertEqual(rows[(closed, None)]['status'], 'CLOSED')
        self.assertEqual(rows[(closed, None)]['probe'], 'connect')
        self.assertTrue(rows[(new, 'a.wild.example.net')]['tlsVersion'].startswith('TLS'))

        # the synthetic wildcard SNI really reached the server
        self.assertIn('ssl-origin-scan-wildcard-probe.wild.example.net', self.old.seen)
        self.assertIn(None, self.old.seen)  # the no-SNI probe

        with open(csv_path, encoding='utf-8') as handle:
            self.assertEqual(handle.read(1), '\ufeff')  # BOM for Excel
        with open(csv_path, encoding='utf-8-sig', newline='') as handle:
            records = list(csv.DictReader(handle))
        self.assertEqual(len(records), len(doc['results']))
        self.assertEqual(set(records[0]), set(sos.CSV_COLUMNS))

        self.assertIn('Servers that need the new certificate: 1', out)
        self.assertIn('Results (server/port/name):', out)
        self.assertNotIn('\x1b[', out)  # not a TTY -> no colours
        self.assertIn('JSON report written to', err)
        self.assertIn('not covered by the new certificate: www.example-test.com.tr', err)

    def test_served_cert_passed_as_cert_is_updated(self):
        json_path = self.path('b.json')
        code, _, err = run_main('-t', 'local=127.0.0.1', '-p', str(self.old.port),
                                '--cert', str(FIXTURES / 'rsa_multi_san.pem'),
                                '--json', json_path, '--fail-on-needs-update', '-q')
        self.assertEqual(code, 0, err)
        self.assertEqual(err, '')  # -q
        doc = read_json(json_path)
        rows = self.index(doc)
        port = self.old.port
        for name in ('example-test.com.tr', 'www.example-test.com.tr', 'api.example-test.com.tr',
                     'xn--mnchen-3ya.example-test.com.tr', '*.cdn.example-test.com.tr'):
            self.assertEqual(rows[(port, name)]['status'], 'UPDATED', name)
        # the wildcard's base is probed but is not covered by "*.cdn..." (RFC 6125)
        self.assertEqual(rows[(port, 'cdn.example-test.com.tr')]['status'], 'NOT_HOSTED')
        self.assertEqual(doc['servers'][0]['name'], 'local')
        self.assertEqual(doc['servers'][0]['status'], 'UPDATED')
        self.assertEqual(doc['summary']['serversUpdated'], 1)

    def test_partially_updated_server_via_default_cert(self):
        code, out, err = run_main('-t', '127.0.0.1', '-p', str(self.partial.port),
                                  '-n', 'a.wild.example.net', '--cert', self.renewed,
                                  '--json', '-', '-q')
        self.assertEqual(code, 0, err)
        doc = json.loads(out)  # --json - : only JSON on stdout
        rows = self.index(doc)
        port = self.partial.port
        self.assertEqual(rows[(port, 'a.wild.example.net')]['status'], 'UPDATED')
        self.assertEqual(rows[(port, '(default)')]['status'], 'NEEDS_UPDATE')
        self.assertEqual(doc['servers'][0]['status'], 'NEEDS_UPDATE')
        self.assertTrue(doc['servers'][0]['defaultCertNeedsUpdate'])

    def test_unrecognized_name_alert_is_not_hosted(self):
        code, out, err = run_main('-t', '127.0.0.1', '-p', str(self.strict.port),
                                  '-n', 'nothere.example.com', 'www.example-test.com.tr',
                                  '--csv', '-', '-q')
        self.assertEqual(code, 0, err)
        records = {r['name']: r for r in csv.DictReader(io.StringIO(out))}
        self.assertEqual(records['nothere.example.com']['status'], 'NOT_HOSTED')
        self.assertIn('unrecognized_name', records['nothere.example.com']['error'])
        self.assertEqual(records['www.example-test.com.tr']['status'], 'NEEDS_UPDATE')
        self.assertEqual(records['']['status'], 'NOT_HOSTED')  # no-SNI probe: default cert

    def test_cloudflare_style_handshake_failure_alert(self):
        server = TlsServer('cn_only', WILD_OLD, reject_unknown=True, require_sni=True,
                           alert=ssl.ALERT_DESCRIPTION_HANDSHAKE_FAILURE)
        try:
            code, out, err = run_main('-t', 'edge=127.0.0.1', '-p', str(server.port),
                                      '-n', 'www.example-test.com.tr', 'nothere.example.com',
                                      '--json', '-', '-q')
        finally:
            server.close()
        self.assertEqual(code, 0, err)
        rows = self.index(json.loads(out))
        port = server.port
        self.assertEqual(rows[(port, 'www.example-test.com.tr')]['status'], 'NEEDS_UPDATE')
        self.assertEqual(rows[(port, 'nothere.example.com')]['status'], 'NOT_HOSTED')
        self.assertIn('server refused this name', rows[(port, 'nothere.example.com')]['error'])
        self.assertIn('HANDSHAKE_FAILURE', rows[(port, 'nothere.example.com')]['error'])
        self.assertEqual(rows[(port, '(default)')]['status'], 'NOT_HOSTED')
        self.assertIn('server requires SNI', rows[(port, '(default)')]['error'])

    def test_tls_error_and_handshake_timeout(self):
        json_path = self.path('e.json')
        ports = '%d,%d' % (self.plain.port, self.silent.port)
        code, out, err = run_main('-t', '127.0.0.1', '-p', ports,
                                  '-n', 'a.example.com', '--timeout', '1', '--json', json_path,
                                  '-q')
        self.assertEqual(code, 0, err)
        rows = self.index(read_json(json_path))
        self.assertEqual(rows[(self.plain.port, 'a.example.com')]['status'], 'TLS_ERROR')
        self.assertTrue(rows[(self.plain.port, 'a.example.com')]['error'])
        self.assertEqual(rows[(self.silent.port, 'a.example.com')]['status'], 'TIMEOUT')
        self.assertIn('Handshake errors: 1', out)

    def test_ctrl_c_during_scan_exits_130_quickly(self):
        import _thread
        timer = threading.Timer(0.5, _thread.interrupt_main)  # simulates SIGINT / Ctrl-C
        started = time.monotonic()
        timer.start()
        try:
            code, out, err = run_main('-t', '127.0.0.1', '-p', str(self.silent.port),
                                      '-n', 'a.example.com', '--timeout', '10',
                                      '--json', self.path('never.json'))
        finally:
            timer.cancel()
        elapsed = time.monotonic() - started
        self.assertEqual(code, 130)
        self.assertLess(elapsed, 5)  # did not wait for the 10 s handshake timeout
        self.assertIn('interrupted', err)
        self.assertNotIn('Traceback', err)
        self.assertEqual(out, '')
        self.assertFalse(os.path.exists(self.path('never.json')))

    def test_show_all_lists_not_hosted(self):
        code, out, _ = run_main('-t', 'box=127.0.0.1', '-p', str(self.old.port),
                                '-n', 'nothere.example.com', '-q')
        self.assertEqual(code, 0)
        self.assertIn('1 not hosting any of the names', out)
        self.assertNotIn('legacy.example.org', out)
        code, out, _ = run_main('-t', 'box=127.0.0.1', '-p', str(self.old.port),
                                '-n', 'nothere.example.com', '-q', '--show-all')
        self.assertIn('Not hosting any of the names: 1', out)
        self.assertIn('current: legacy.example.org', out)

    def test_fail_on_needs_update_in_subprocess(self):
        env = dict(os.environ, PYTHONIOENCODING='utf-8', NO_COLOR='1')
        proc = subprocess.run(
            [sys.executable, str(CLI_PATH), '-t', 'web-old=127.0.0.1', '-p', str(self.old.port),
             '-n', 'a.wild.example.net', '--cert', self.renewed, '--fail-on-needs-update'],
            capture_output=True, text=True, encoding='utf-8', env=env, timeout=60)
        self.assertEqual(proc.returncode, 1, proc.stderr)
        self.assertIn('Servers that need the new certificate: 1', proc.stdout)
        self.assertIn('web-old', proc.stdout)
        self.assertNotIn('Traceback', proc.stderr)
        proc = subprocess.run([sys.executable, str(CLI_PATH), '-t', '127.0.0.1'],
                              capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(proc.returncode, 2)
        self.assertIn('nothing to probe', proc.stderr)

    def test_ipv6_and_server_grouping(self):
        try:
            v6_new = TlsServer('cn_only', WILD_NEW, host='::1', port=self.old.port)
        except OSError as exc:
            self.skipTest('IPv6 loopback not available: %s' % exc)
        try:
            with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False,
                                             dir=self.tmp.name) as handle:
                handle.write('web-a 127.0.0.1\nweb-b ::1\n')
            code, out, err = run_main('-t', handle.name, '-p', str(self.old.port),
                                      '-n', 'a.wild.example.net', '--cert', self.renewed,
                                      '--json', self.path('v6.json'), '-q')
        finally:
            v6_new.close()
        self.assertEqual(code, 0, err)
        doc = read_json(self.path('v6.json'))
        statuses = {s['name']: s['status'] for s in doc['servers']}
        self.assertEqual(statuses, {'web-a': 'NEEDS_UPDATE', 'web-b': 'UPDATED'})
        self.assertEqual(doc['summary']['serversNeedingUpdate'], 1)
        need = out.index('Servers that need the new certificate: 1')
        updated = out.index('Already serving the new certificate: 1')
        self.assertIn('web-a', out[need:updated])
        self.assertIn('web-b', out[updated:])
        self.assertIn('[::1]:%d' % self.old.port, out)


class CompatibilityTests(unittest.TestCase):
    """The CLI must stay runnable on Python 3.8."""

    def test_py_compile(self):
        import py_compile
        with tempfile.TemporaryDirectory() as tmp:
            py_compile.compile(str(CLI_PATH), cfile=os.path.join(tmp, 'x.pyc'), doraise=True)

    def test_no_py39_plus_syntax_or_apis(self):
        import ast
        source = CLI_PATH.read_text(encoding='utf-8')
        tree = ast.parse(source, feature_version=(3, 8))
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, getattr(ast, 'Match', ()))
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                # builtin generics (list[str]) only appear inside string annotations
                self.assertNotIn(node.value.id, ('list', 'dict', 'tuple', 'set', 'type'),
                                 ast.dump(node))
        for api in ('removeprefix', 'removesuffix', 'functools.cache', 'zoneinfo', ' | None',
                    'strict=True)', 'BooleanOptionalAction'):
            self.assertNotIn(api, source, api)
        self.assertIn('from __future__ import annotations', source)

    def test_shebang_and_stdlib_only(self):
        source = CLI_PATH.read_text(encoding='utf-8')
        self.assertTrue(source.startswith('#!/usr/bin/env python3'))
        imports = set(re.findall(r'^(?:from|import) ([a-zA-Z_][\w.]*)', source, re.M))
        stdlib = {'__future__', 'argparse', 'base64', 'binascii', 'csv', 'hashlib', 'io',
                  'ipaddress', 'json', 'math', 'os', 're', 'shutil', 'socket', 'ssl', 'sys',
                  'textwrap', 'threading', 'time', 'concurrent.futures', 'dataclasses',
                  'datetime', 'typing', 'ctypes', 'msvcrt', 'codecs', 'stat', 'unicodedata'}
        self.assertLessEqual(imports, stdlib, imports - stdlib)


if __name__ == '__main__':
    unittest.main()
