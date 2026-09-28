"""--estate: an inventory of every certificate the servers serve (stdlib unittest; no network).

Every ip:port is asked without SNI and for every -n name and every host name among the
targets; the estate lists each distinct certificate served (fingerprint, names, issuer,
expiry, key, SPKI SHA-256, kind) with where it is served, and what needs a look: expiry
buckets, kinds, one name served with different certificates (a forgotten load-balancer
member), one key on several hosts or certificates, weak keys or signatures, certificates
covering none of the names asked.

tests/fixtures/estate/ holds two reports written by this CLI (a fake network, a fixed clock):
this file checks that they are exactly what the CLI writes, and tests/js/estate.test.js that
the web app's Estate view computes the same estate from them.

Run from the repository root:
    python -m unittest discover -s tests/python -v
Regenerate the fixtures after a deliberate change of the report:
    python tests/python/test_estate.py --write-fixtures
"""

from __future__ import annotations

import contextlib
import csv
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from typing import Dict, List, Optional
from unittest import mock

from test_ssl_origin_scan import (CN_ONLY_DER, EC_DER, FIXTURES, RENEWED_DER, RSA_DER, WILD_NEW,
                                  WILD_OLD, FakeNetwork, TlsServer, _free_port, der_tlv,
                                  fixture_cert, read_json, run_main, sos)

ESTATE_DIR = FIXTURES / 'estate'
WWW = 'www.example-test.com.tr'
WILD = 'a.wild.example.net'
NOW_A = datetime(2026, 9, 28, 12, 0, 0, tzinfo=timezone.utc)
NOW_B = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)
ORIGIN_DER = fixture_cert('cli_origin_wild.pem').der
PRIVATE_DER = fixture_cert('cli_private_wild.pem').der
PRIVATE_CA = fixture_cert('cli_private_ca.pem')

_OID_RSA = bytes.fromhex('2a864886f70d010101')
_SIG_SHA1_RSA = bytes.fromhex('2a864886f70d010105')
_SIG_MD5_RSA = bytes.fromhex('2a864886f70d010104')
_SIG_SHA256_RSA = bytes.fromhex('2a864886f70d01010b')


def rsa_spki(bits: int, seed: int = 0) -> bytes:
    """A SubjectPublicKeyInfo with a made-up RSA modulus of ``bits`` bits (never a real key)."""
    modulus = (1 << (bits - 1)) | (0x5DEECE66D * (seed + 1)) | 1
    body = der_tlv(0x02, b'\x00' + modulus.to_bytes(bits // 8, 'big')) + der_tlv(0x02, b'\x01\x00\x01')
    return der_tlv(0x30, der_tlv(0x30, der_tlv(0x06, _OID_RSA) + der_tlv(0x05, b''))
                   + der_tlv(0x03, b'\x00' + der_tlv(0x30, body)))


def crafted_cert(cn: str, spki: bytes, sig_oid: bytes, not_before: bytes, not_after: bytes,
                 serial: int = 1) -> bytes:
    """An unsigned, self-issued v3 certificate: subject = issuer = CN=``cn``, no extensions."""
    alg = der_tlv(0x30, der_tlv(0x06, sig_oid) + der_tlv(0x05, b''))
    name = der_tlv(0x30, der_tlv(0x31, der_tlv(0x30, der_tlv(0x06, b'\x55\x04\x03')
                                              + der_tlv(0x0C, cn.encode('ascii')))))
    validity = der_tlv(0x30, der_tlv(0x18, not_before) + der_tlv(0x18, not_after))
    tbs = der_tlv(0x30, der_tlv(0xA0, der_tlv(0x02, b'\x02')) + der_tlv(0x02, bytes([serial]))
                  + alg + name + validity + name + spki)
    return der_tlv(0x30, tbs + alg + der_tlv(0x03, b'\x00'))


# An RSA 1024 key signed with SHA-1, 5 days before its end on NOW_A; the same key again in an
# MD5-signed certificate (one key in two certificates).
WEAK_SPKI = rsa_spki(1024)
WEAK_DER = crafted_cert(WWW, WEAK_SPKI, _SIG_SHA1_RSA, b'20260901000000Z', b'20261003120000Z')
MD5_DER = crafted_cert('legacy.example.net', WEAK_SPKI, _SIG_MD5_RSA, b'20260101000000Z',
                       b'20261020000000Z', serial=2)
# A certificate that expired before NOW_A, served without SNI only.
EXPIRED_DER = crafted_cert('old.example.net', rsa_spki(2048, 7), _SIG_SHA256_RSA,
                           b'20240101000000Z', b'20260901000000Z', serial=3)


def serve(**by_sni):
    """A TLS behaviour: ``None`` = the no-SNI handshake; other keys are SNI names."""
    def pick(sni):
        value = by_sni.get('default' if sni is None else sni, by_sni.get('other'))
        return value
    return pick


def refused():
    return sos.TlsResult(status=sos.TLS_ERROR, error='sslv3 alert handshake failure',
                         refused=True)


def estate_scan(servers, tls, connect=None, names=(WWW, WILD), now=NOW_A, private_cas=()):
    network = FakeNetwork(connect or {}, tls)
    with mock.patch.object(sos, '_utcnow', return_value=now):
        return sos.run_scan(servers, sos.build_probe_names(list(names)), [443], timeout=1,
                            workers=4, connect_fn=network.connect_fn, tls_fn=network.tls_fn,
                            private_cas=list(private_cas))


def fleet_a():
    """Site A: two load-balanced web servers where the renewal reached only one, an IPv6 host
    with a weak certificate, an origin behind Cloudflare, an internal host, a legacy box and a
    closed port."""
    return estate_scan(
        [sos.Server('web01', ['192.0.2.10']), sos.Server('web02', ['192.0.2.11']),
         sos.Server('web03', ['2001:db8::13']), sos.Server('origin', ['198.51.100.20']),
         sos.Server('closed', ['198.51.100.21']), sos.Server('intranet', ['198.51.100.22']),
         sos.Server('legacy-a', ['198.51.100.23']), sos.Server('legacy-b', ['198.51.100.23'])],
        {'192.0.2.10': serve(default=CN_ONLY_DER, **{WWW: RSA_DER, WILD: EC_DER}),
         '192.0.2.11': serve(default=CN_ONLY_DER, **{WWW: RSA_DER, WILD: RENEWED_DER}),
         '2001:db8::13': serve(default=WEAK_DER, **{WWW: WEAK_DER, WILD: refused()}),
         '198.51.100.20': serve(default=ORIGIN_DER, **{WWW: refused(), WILD: ORIGIN_DER}),
         '198.51.100.22': serve(default=PRIVATE_DER, **{WWW: PRIVATE_DER, WILD: refused()}),
         '198.51.100.23': serve(default=MD5_DER, other=EXPIRED_DER)},
        connect={'198.51.100.21': ConnectionRefusedError()}, private_cas=[PRIVATE_CA])


def fleet_b():
    """Site B, a week later: web02 again (now without SNI the renewed certificate too), a
    server of its own and a name site A did not ask for."""
    return estate_scan(
        [sos.Server('web02', ['192.0.2.11']), sos.Server('web05', ['203.0.113.5'])],
        {'192.0.2.11': serve(default=RENEWED_DER, **{WWW: RSA_DER, WILD: RENEWED_DER}),
         '203.0.113.5': serve(default=RSA_DER, other=RSA_DER)},
        names=(WWW, 'api.example-test.com.tr'), now=NOW_B)


def normalized(doc):
    """A report dict without the timings that differ from run to run."""
    doc = json.loads(json.dumps(doc))
    for row in doc.get('results') or []:
        row['elapsedMs'] = 0
    for endpoint in doc.get('endpoints') or []:
        endpoint['connectMs'] = 0 if endpoint.get('connectMs') is not None else None
    return doc


def fixture_docs() -> Dict[str, dict]:
    return {'report-a.json': normalized(sos.report_to_dict(fleet_a(), estate=True)),
            'report-b.json': normalized(sos.report_to_dict(fleet_b(), estate=True))}


def certs_by_cn(estate) -> Dict[str, List[dict]]:
    out = {}  # type: Dict[str, List[dict]]
    for cert in estate['certificates']:
        out.setdefault(cert['subjectCN'], []).append(cert)
    return out


class EstateOfReportTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.report = fleet_a()
        cls.doc = sos.report_to_dict(cls.report, estate=True)
        cls.estate = cls.doc['estate']

    def cert(self, sha: str) -> dict:
        return next(c for c in self.estate['certificates'] if c['sha256'] == sha)

    def test_every_distinct_certificate_served_with_where_and_for_what(self):
        estate = self.estate
        self.assertTrue(self.doc['options']['estate'])
        self.assertEqual(estate['namesAsked'], [WWW, WILD])
        shas = {sos.parse_certificate(der).sha256 for der in (
            RSA_DER, EC_DER, RENEWED_DER, CN_ONLY_DER, WEAK_DER, ORIGIN_DER, PRIVATE_DER, MD5_DER,
            EXPIRED_DER)}
        self.assertEqual({c['sha256'] for c in estate['certificates']}, shas)
        self.assertEqual(estate['counts']['certificates'], 9)
        self.assertEqual(estate['counts']['endpoints'], 7)
        self.assertEqual(estate['counts']['openEndpoints'], 6)
        self.assertEqual(estate['counts']['endpointsWithCertificate'], 6)
        rsa = self.cert(sos.parse_certificate(RSA_DER).sha256)
        self.assertEqual([(e['servers'], e['ip'], e['port'], e['defaultCert'], e['names'])
                          for e in rsa['endpoints']],
                         [(['web01'], '192.0.2.10', 443, False, [WWW]),
                          (['web02'], '192.0.2.11', 443, False, [WWW])])
        self.assertEqual(rsa['coversAsked'], [WWW])
        self.assertEqual(rsa['key'], 'RSA 2048')
        self.assertEqual(rsa['spkiSha256'], sos.parse_certificate(RSA_DER).spki_sha256)
        self.assertEqual(rsa['issuer'], 'Subdomain Scanner Test Root CA (Test CA)')
        # one address, two servers: one endpoint naming both; the fallback for every name
        md5 = self.cert(sos.parse_certificate(MD5_DER).sha256)
        self.assertEqual(md5['endpoints'], [{'servers': ['legacy-a', 'legacy-b'],
                                             'ip': '198.51.100.23', 'port': 443,
                                             'defaultCert': True, 'names': []}])
        expired = self.cert(sos.parse_certificate(EXPIRED_DER).sha256)
        self.assertEqual(expired['endpoints'][0]['names'], [WWW, WILD])
        self.assertFalse(expired['endpoints'][0]['defaultCert'])
        # soonest expiry first
        days = [c['daysLeft'] for c in estate['certificates']]
        self.assertEqual(days, sorted(days))

    def test_expiry_buckets_and_kinds(self):
        counts = self.estate['counts']
        self.assertEqual(counts['expiry'], {'expired': 1, '7d': 1, '30d': 1, '90d': 0, 'later': 6})
        self.assertEqual(self.cert(sos.parse_certificate(WEAK_DER).sha256)['expiry'], '7d')
        self.assertEqual(self.cert(sos.parse_certificate(WEAK_DER).sha256)['daysLeft'], 5)
        self.assertEqual(self.cert(sos.parse_certificate(EXPIRED_DER).sha256)['expiry'], 'expired')
        self.assertEqual(counts['kinds'], {'origin-ca': 1, 'self-signed': 6, 'private-ca': 1,
                                           'other': 1})
        private = self.cert(sos.parse_certificate(PRIVATE_DER).sha256)
        self.assertEqual(private['kind'], 'private-ca')
        self.assertEqual(private['privateCa'], PRIVATE_CA.subject_dn)
        self.assertEqual(self.cert(sos.parse_certificate(ORIGIN_DER).sha256)['kind'], 'origin-ca')
        for days, bucket in ((-1, 'expired'), (0, '7d'), (6, '7d'), (7, '30d'), (29, '30d'),
                             (30, '90d'), (89, '90d'), (90, 'later')):
            self.assertEqual(sos.expiry_bucket(days), bucket, days)

    def test_one_name_served_with_different_certificates(self):
        conflicts = {c['name']: c for c in self.estate['nameConflicts']}
        self.assertEqual(list(conflicts), [WWW, WILD])
        wild = conflicts[WILD]['certificates']
        old, new, origin = (sos.parse_certificate(der).sha256
                            for der in (EC_DER, RENEWED_DER, ORIGIN_DER))
        # newest first (the same notBefore: the later notAfter first); the old self-signed one
        # is stale next to its renewal, the Origin CA certificate (another kind) is not
        self.assertEqual([(c['sha256'], c['stale']) for c in wild],
                         [(new, False), (old, True), (origin, False)])
        self.assertEqual(wild[1]['endpoints'], [{'servers': ['web01'], 'ip': '192.0.2.10',
                                                 'port': 443}])
        # an RSA 2048 public certificate and a self-signed RSA 1024 one: other kinds, no stale side
        self.assertEqual({c['stale'] for c in conflicts[WWW]['certificates']}, {False})
        self.assertIn('name-conflict', self.cert(old)['flags'])
        self.assertIn('stale', self.cert(old)['flags'])
        self.assertNotIn('stale', self.cert(new)['flags'])
        # a fallback certificate that does not cover the name is no conflict
        self.assertNotIn(sos.parse_certificate(EXPIRED_DER).sha256,
                         [c['sha256'] for c in conflicts[WWW]['certificates']])

    def test_one_key_on_several_hosts_or_certificates(self):
        shared = {g['spkiSha256']: g for g in self.estate['sharedKeys']}
        weak_spki = sos.parse_certificate(WEAK_DER).spki_sha256
        self.assertEqual(shared[weak_spki]['certificates'],
                         [sos.parse_certificate(WEAK_DER).sha256,
                          sos.parse_certificate(MD5_DER).sha256])
        self.assertEqual(shared[weak_spki]['hosts'], 3)  # web03, legacy-a, legacy-b
        self.assertEqual(shared[weak_spki]['addresses'], ['2001:db8::13', '198.51.100.23'])
        rsa_spki_hash = sos.parse_certificate(RSA_DER).spki_sha256
        self.assertEqual(shared[rsa_spki_hash]['servers'], ['web01', 'web02'])
        self.assertEqual(shared[rsa_spki_hash]['key'], 'RSA 2048')
        # one certificate on one host: not shared
        self.assertNotIn(sos.parse_certificate(ORIGIN_DER).spki_sha256, shared)
        hosts = [g['hosts'] for g in self.estate['sharedKeys']]
        self.assertEqual(hosts, sorted(hosts, reverse=True))

    def test_weak_keys_and_signatures(self):
        weak = {w['sha256']: w['reasons'] for w in self.estate['weakKeys']}
        self.assertEqual(weak, {sos.parse_certificate(WEAK_DER).sha256: ['rsa-short', 'sha1'],
                                sos.parse_certificate(MD5_DER).sha256: ['rsa-short', 'md5']})
        self.assertEqual(sos.weak_reasons('RSA', 2048, 'sha256WithRSAEncryption'), [])
        self.assertEqual(sos.weak_reasons('EC', 256, 'ecdsa-with-SHA1'), ['sha1'])
        self.assertEqual(sos.weak_reasons('RSA', 1024, 'md2WithRSAEncryption'), ['rsa-short', 'md5'])
        self.assertEqual(sos.parse_certificate(MD5_DER).signature_algorithm, 'md5WithRSAEncryption')

    def test_certificates_covering_none_of_the_names(self):
        none = self.estate['coversNone']
        self.assertEqual(set(none), {sos.parse_certificate(der).sha256
                                     for der in (CN_ONLY_DER, MD5_DER, EXPIRED_DER)})
        legacy = self.cert(sos.parse_certificate(CN_ONLY_DER).sha256)
        self.assertEqual(legacy['coversAsked'], [])
        self.assertIn('covers-none', legacy['flags'])
        # the internal wildcard covers a.wild.example.net although it was served for www only
        private = self.cert(sos.parse_certificate(PRIVATE_DER).sha256)
        self.assertEqual(private['coversAsked'], [WILD])
        self.assertNotIn('covers-none', private['flags'])

    def test_no_names_asked_leaves_coverage_open(self):
        report = estate_scan([sos.Server('web01', ['192.0.2.10'])],
                             {'192.0.2.10': serve(default=CN_ONLY_DER)}, names=())
        estate = sos.estate_from_report(sos.report_to_dict(report), NOW_A)
        self.assertEqual(estate['namesAsked'], [])
        self.assertIsNone(estate['coversNone'])
        self.assertEqual([c['subjectCN'] for c in estate['certificates']], ['legacy.example.org'])
        self.assertEqual(estate['certificates'][0]['flags'], [])
        text = sos.render_estate(report, estate)
        self.assertIn('No names asked', text)
        self.assertNotIn('Covering none of the names asked', text)

    def test_a_report_of_an_older_version_still_gives_an_estate(self):
        doc = json.loads(json.dumps(sos.report_to_dict(fleet_a())))
        del doc['names']
        del doc['endpoints']
        for entry in doc['certificates'].values():
            for key in ('kind', 'spkiSha256', 'privateCa'):
                entry.pop(key, None)
        estate = sos.estate_from_report(doc, NOW_A)
        self.assertEqual(estate['namesAsked'], [WWW, WILD])  # from the rows
        self.assertEqual(estate['sharedKeys'], [])  # no key hashes to compare
        self.assertEqual(estate['counts']['kinds'], {'origin-ca': 0, 'self-signed': 6,
                                                     'private-ca': 0, 'other': 3})
        self.assertEqual(estate['counts']['endpoints'], 7)
        self.assertEqual(estate['counts']['openEndpoints'], 6)
        self.assertEqual(len(estate['nameConflicts']), 2)

    def test_csv_rows_one_per_certificate_endpoint_and_server(self):
        rows = sos.estate_csv_rows(self.estate)
        md5 = [r for r in rows if r['sha256'] == sos.parse_certificate(MD5_DER).sha256]
        self.assertEqual([r['server'] for r in md5], ['legacy-a', 'legacy-b'])
        self.assertEqual(md5[0]['default_cert'], 'yes')
        self.assertEqual(md5[0]['flags'], 'shared-key weak covers-none')
        self.assertEqual(md5[0]['weak'], 'rsa-short md5')
        text = sos.render_estate_csv(self.estate)
        records = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(text.splitlines()[0].split(','), list(sos.ESTATE_CSV_COLUMNS))
        self.assertEqual(len(records), len(rows))
        self.assertEqual(sum(len(e['servers']) for c in self.estate['certificates']
                             for e in c['endpoints']), len(rows))

    def test_csv_cells_stay_text_in_a_spreadsheet(self):
        evil = crafted_cert('=HYPERLINK("x").example.com', rsa_spki(2048, 3), _SIG_SHA256_RSA,
                            b'20250101000000Z', b'20300101000000Z')
        report = estate_scan([sos.Server('@web', ['192.0.2.10'])],
                             {'192.0.2.10': serve(default=evil)}, names=())
        estate = sos.estate_from_report(sos.report_to_dict(report), NOW_A)
        record = next(csv.DictReader(io.StringIO(sos.render_estate_csv(estate))))
        self.assertEqual(record['subject_cn'], '\'=HYPERLINK("x").example.com')
        self.assertEqual(record['server'], "'@web")

    def test_summary_names_what_needs_a_look(self):
        text = ' '.join(sos.render_estate(self.report, self.estate, width=160).split())
        for needle in (
                'SSL estate: 8 server(s), 7 endpoint(s) (6 open), 2 name(s) asked',
                'Certificates served: 9 - expired 1, < 7 days 1, < 30 days 1, < 90 days 0, later 6',
                'Kinds: Cloudflare Origin CA 1, self-signed 6, private CA 1, other CA 1',
                'Private CAs (--private-ca): Example Internal Test CA',
                'Same name, different certificates: 2', 'OLDER',
                'Same key on several hosts or certificates: 4', 'RSA 1024 key',
                '3 hosts, 2 certificates', 'Weak keys or signatures: 2',
                'RSA key shorter than 2048 bits (RSA 1024); SHA-1 signature (sha1WithRSAEncryption)',
                'Covering none of the names asked: 3',
                'Every certificate served (9), soonest expiry first',
                'web03 [2001:db8::13]:443 (default; www.example-test.com.tr)',
                'legacy-a, legacy-b 198.51.100.23:443 (default)',
                'No certificate from 1 endpoint: 1 closed or not answering - --show-all lists them.'):
            self.assertIn(needle, text)
        full = sos.render_estate(self.report, self.estate, show_all=True, width=160)
        self.assertIn('198.51.100.21:443  CLOSED  connection refused', full)
        self.assertNotIn('\x1b[', text)
        self.assertIn('\x1b[', sos.render_estate(self.report, self.estate, color=True))

    def test_hostile_certificate_text_is_escaped_in_the_summary(self):
        hostile = crafted_cert('x\x1b[2J.example.com', rsa_spki(2048, 5), _SIG_SHA256_RSA,
                               b'20250101000000Z', b'20300101000000Z')
        report = estate_scan([sos.Server('web\x07', ['192.0.2.10'])],
                             {'192.0.2.10': serve(default=hostile)}, names=())
        estate = sos.estate_from_report(sos.report_to_dict(report), NOW_A)
        text = sos.render_estate(report, estate)
        self.assertNotIn('\x1b', text)
        self.assertNotIn('\x07', text)


class InventoryNamesTests(unittest.TestCase):

    def test_host_names_among_the_targets(self):
        servers = [sos.Server('web01.example.com', ['192.0.2.10']), sos.Server('web02', ['192.0.2.11']),
                   sos.Server('192.0.2.12', ['192.0.2.12']), sos.Server('Web Server 1', ['192.0.2.13']),
                   sos.Server('2026092401', ['192.0.2.14']),
                   sos.Server('app', ['192.0.2.15'], hostnames=['App.Example.NET']),
                   sos.Server('WEB01.example.com.', ['192.0.2.16'])]
        self.assertEqual(sos.inventory_names(servers), ['web01.example.com', 'app.example.net'])


class FixtureTests(unittest.TestCase):
    """tests/fixtures/estate: exactly what this CLI writes (also read by tests/js/estate.test.js)."""

    def test_committed_reports_are_what_the_cli_writes(self):
        for name, doc in fixture_docs().items():
            with self.subTest(fixture=name):
                self.assertEqual(normalized(read_json(str(ESTATE_DIR / name))), doc,
                                 'regenerate: python tests/python/test_estate.py --write-fixtures')


class EstateCliTests(unittest.TestCase):
    """Real TLS handshakes against local servers, through main()."""

    @classmethod
    def setUpClass(cls):
        cls.old = TlsServer('cn_only', WILD_OLD)       # the old wildcard; no SNI: legacy.example.org
        cls.new = TlsServer('ec_wildcard', WILD_NEW)   # the renewed one; no SNI: the old wildcard
        cls.closed_port = _free_port()
        cls.tmp = tempfile.TemporaryDirectory()

    @classmethod
    def tearDownClass(cls):
        for server in (cls.old, cls.new):
            server.close()
        cls.tmp.cleanup()

    def run_estate(self, *args: str):
        base = os.path.join(self.tmp.name, 'e%d' % len(os.listdir(self.tmp.name)))
        code, out, err = run_main(*args, '--estate', '--timeout', '4', '--json', base + '.json',
                                  '--csv', base + '.csv')
        with open(base + '.csv', encoding='utf-8-sig', newline='') as handle:
            records = list(csv.DictReader(handle))
        return code, out, err, read_json(base + '.json'), records

    def test_several_certificates_one_name_on_two_servers_and_the_default(self):
        code, out, err, doc, records = self.run_estate(
            '-t', 'old=127.0.0.1:%d' % self.old.port, 'new=127.0.0.1:%d' % self.new.port,
            'gone=127.0.0.1:%d' % self.closed_port, '-n', WILD, WWW)
        self.assertEqual(code, 0, err)
        estate = doc['estate']
        by_cn = certs_by_cn(estate)
        self.assertEqual(sorted(by_cn), ['*.wild.example.net', 'legacy.example.org', WWW])
        self.assertEqual(len(by_cn['*.wild.example.net']), 2)  # the old one and its renewal
        conflict = estate['nameConflicts'][0]
        self.assertEqual(conflict['name'], WILD)
        renewed, old = conflict['certificates']
        self.assertEqual(renewed['sha256'], fixture_cert('cli_renewed_wild.pem').sha256)
        self.assertFalse(renewed['stale'])
        self.assertTrue(old['stale'])
        self.assertEqual(old['endpoints'][0]['servers'], ['old'])
        # the old wildcard is also the new server's default certificate
        old_cert = next(c for c in estate['certificates'] if c['sha256'] == old['sha256'])
        self.assertEqual([(e['servers'], e['defaultCert'], e['names']) for e in old_cert['endpoints']],
                         [(['old'], False, [WILD]), (['new'], True, [])])
        legacy = by_cn['legacy.example.org'][0]
        self.assertEqual(legacy['flags'], ['covers-none'])
        self.assertEqual(legacy['kind'], 'self-signed')
        www = by_cn[WWW][0]
        self.assertIn('shared-key', www['flags'])  # served by old and new
        self.assertEqual(estate['counts']['endpoints'], 3)
        self.assertEqual(estate['counts']['openEndpoints'], 2)
        self.assertEqual(set(records[0]), set(sos.ESTATE_CSV_COLUMNS))
        self.assertEqual(len(records), sum(len(e['servers']) for c in estate['certificates']
                                           for e in c['endpoints']))
        text = ' '.join(out.split())
        self.assertIn('Same name, different certificates: 1', text)
        self.assertIn('No certificate from 1 endpoint', text)
        self.assertNotIn('Servers hosting the names', text)  # the estate replaces that summary

    def test_host_names_among_the_targets_are_asked_without_n(self):
        code, _out, err, doc, _records = self.run_estate(
            '-t', '%s=127.0.0.1:%d' % (WWW, self.old.port))
        self.assertEqual(code, 0, err)
        self.assertEqual(doc['estate']['namesAsked'], [WWW])
        self.assertIn(WWW, self.old.seen)
        cns = sorted(certs_by_cn(doc['estate']))
        self.assertEqual(cns, ['legacy.example.org', WWW])

    def test_no_names_at_all_asks_without_sni(self):
        code, out, err, doc, records = self.run_estate('-t', '127.0.0.1:%d' % self.new.port)
        self.assertEqual(code, 0, err)
        self.assertEqual(doc['estate']['namesAsked'], [])
        self.assertIsNone(doc['estate']['coversNone'])
        self.assertEqual([c['subjectCN'] for c in doc['estate']['certificates']],
                         ['*.wild.example.net'])
        self.assertEqual(records[0]['default_cert'], 'yes')
        self.assertIn('No names asked', out)

    def test_without_estate_the_reports_are_unchanged(self):
        path = os.path.join(self.tmp.name, 'plain.json')
        code, out, err = run_main('-t', '127.0.0.1:%d' % self.old.port, '-n', WILD,
                                  '--timeout', '4', '--json', path)
        self.assertEqual(code, 0, err)
        doc = read_json(path)
        self.assertNotIn('estate', doc)
        self.assertNotIn('estate', doc['options'])
        self.assertIn('Servers hosting the names', out)
        # every certificate entry names its public key hash (the web Estate view reads it)
        for entry in doc['certificates'].values():
            self.assertRegex(entry['spkiSha256'], r'^[0-9a-f]{64}$')
        code, _out, err = run_main('-t', '127.0.0.1:%d' % self.old.port, '--timeout', '4')
        self.assertEqual(code, 2)
        self.assertIn('nothing to probe', err)
        self.assertIn('--estate', err)

    def test_help_explains_estate(self):
        code, out, _err = run_main('--help')
        self.assertEqual(code, 0)
        text = ' '.join(out.split())
        for needle in ('--estate', 'inventory of every certificate', 'bundle-check'):
            self.assertIn(needle, text)


def write_fixtures() -> None:
    ESTATE_DIR.mkdir(exist_ok=True)
    for name, doc in fixture_docs().items():
        with open(str(ESTATE_DIR / name), 'w', encoding='utf-8', newline='\n') as handle:
            handle.write(json.dumps(doc, indent=2, ensure_ascii=False) + '\n')
        print('wrote', ESTATE_DIR / name)


if __name__ == '__main__':
    if '--write-fixtures' in sys.argv:
        write_fixtures()
    else:
        unittest.main()
