"""--ari and --revocation: the issuing CA's renewal window (ACME Renewal Information, RFC 9773)
and revocation list of every certificate a scan found served (stdlib unittest; no network).

The CA's ARI server and the CRL are fakes (the CLI's ``http_get`` patched; one test reads a
local plain-HTTP server), the scan a fake network serving tests/fixtures/crl_leaf.pem (a test
CA's leaf with a CRL distribution point); the CRLs are the OpenSSL-made DER fixtures of
tests/fixtures/gen_crl_fixtures.sh: two revoked serials with reason codes, an empty CRL and
another CA's CRL. The tool cannot check a CRL's signature (stdlib): the report says so.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import csv
import http.server
import io
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple
from unittest import mock

from test_ssl_origin_scan import FIXTURES, FakeNetwork, fixture_bytes, fixture_cert, read_json, run_main, sos

DP = 'http://crl.example.com/test-ca.crl'
DIR = 'https://acme.example.org/directory'
RI = 'https://acme.example.org/renewal-info'
TEST_DIRS = {'letsencrypt': ({'url': DIR, 'hosts': ('acme.example.org',)},)}
LEAF = fixture_cert('crl_leaf.pem')
LEAF2 = fixture_cert('crl_leaf2.pem')
NOW = datetime(2026, 10, 9, 3, 0, 0, tzinfo=timezone.utc)
LATER = datetime(2026, 10, 20, 0, 0, 0, tzinfo=timezone.utc)


def window(start: str, end: str, **extra) -> bytes:
    return json.dumps(dict({'suggestedWindow': {'start': start, 'end': end}}, **extra)).encode()


class FakeFetch:
    """A ``http_get`` from routes: url -> (status, headers, body) or an exception; others 404."""

    def __init__(self, routes: Dict[str, object]) -> None:
        self.routes = routes
        self.calls = []  # type: List[str]
        self.lock = threading.Lock()

    def __call__(self, url: str, timeout: float, max_bytes: Optional[int] = None
                 ) -> Tuple[int, Dict[str, str], bytes]:
        with self.lock:
            self.calls.append(url)
        route = self.routes.get(url)
        if route is None:
            return 404, {}, b'not found'
        if isinstance(route, BaseException):
            raise route
        status, headers, body = route
        if max_bytes is not None and len(body) > max_bytes:
            raise sos.StatusFetchError('too-large', '', status)
        return status, headers, body


def leaf_scan(der: bytes = LEAF.der, now: datetime = NOW):
    """A scan of one server serving ``der`` for www.example.com and without SNI."""
    network = FakeNetwork({}, {'192.0.2.10': lambda sni: der})
    with mock.patch.object(sos, '_utcnow', return_value=now):
        return sos.run_scan([sos.Server('web01', ['192.0.2.10'])],
                            sos.build_probe_names(['www.example.com']), [443], timeout=1, workers=2,
                            connect_fn=network.connect_fn, tls_fn=network.tls_fn)


class CertIdAndCaTests(unittest.TestCase):

    def test_cert_id_is_rfc_9773s(self):
        cert = sos.CertInfo(der=b'', version=3, serial_hex='87654321', signature_algorithm='',
                            subject={}, subject_dn='', subject_cn=None, issuer={}, issuer_dn='',
                            issuer_cn=None, not_before=NOW, not_after=NOW, dns_names=[],
                            ip_addresses=[], emails=[], uris=[], key_algorithm='EC',
                            key_bits=256, curve='P-256', is_ca=False, self_signed=False,
                            sha256='', sha1='',
                            authority_key_id='69885b6b87464041e1b37b847ba0ae2cde01c8d4')
        self.assertEqual(sos.ari_cert_id(cert), 'aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE')
        self.assertEqual(sos.ari_cert_id(cert.__class__(**dict(cert.__dict__, serial_hex='1'))),
                         sos.ari_cert_id(cert.__class__(**dict(cert.__dict__, serial_hex='01'))))
        self.assertIsNone(sos.ari_cert_id(cert.__class__(**dict(cert.__dict__, authority_key_id=None))))
        self.assertTrue(sos.ari_cert_id(LEAF).endswith('.DBAB'), 'serial 0c1001')

    def test_the_issuer_maps_to_a_ca_with_ari(self):
        cases = {"CN=YE2,O=Let's Encrypt,C=US": 'letsencrypt', 'CN=R12,O=ISRG': 'letsencrypt',
                 'CN=WE2,O=Google Trust Services,C=US': 'google',
                 'CN=ZeroSSL ECC DV SSL CA 2,O=ZeroSSL GmbH,C=AT': 'zerossl',
                 'CN=Sectigo Public Server Authentication CA DV R36,O=Sectigo Limited,C=GB': 'sectigo',
                 'CN=SSL.com TLS Issuing RSA CA R1,O=SSL Corporation,C=US': 'sslcom',
                 'CN=DigiCert Global G2 TLS RSA SHA256 2020 CA1,O=DigiCert Inc,C=US': None,
                 'CN=GlobalSign GCC R6 AlphaSSL CA 2025,O=GlobalSign nv-sa': None,
                 LEAF.issuer_dn: None, '': None}
        for dn, ca in cases.items():
            self.assertEqual(sos.ari_ca_for_issuer(dn), ca, dn)
        self.assertEqual(sos.ari_directory_for('sslcom', 'RSA')['url'], 'https://acme.ssl.com/sslcom-dv-rsa')
        self.assertEqual(sos.ari_directory_for('sslcom', 'EC')['url'], 'https://acme.ssl.com/sslcom-dv-ecc')
        self.assertIsNone(sos.ari_directory_for('sslcom', 'Ed25519'))
        self.assertEqual(sos.ari_directory_for('zerossl', 'EC')['hosts'], ('ari.trust-provider.com',))
        self.assertIsNone(sos.ari_directory_for(None, 'RSA'))
        self.assertEqual(sorted(sos.ARI_DIRECTORIES), ['google', 'letsencrypt', 'sectigo', 'sslcom', 'zerossl'])

    def test_the_certificate_names_its_crl(self):
        self.assertEqual(LEAF.crl_urls, [DP])
        self.assertEqual(sos.crl_urls_of(LEAF), [DP])
        odd = LEAF.__class__(**dict(LEAF.__dict__, crl_urls=['ldap://ldap.example.com/x', DP, DP]))
        self.assertEqual(sos.crl_urls_of(odd), [DP])
        self.assertEqual(fixture_cert('crl_ca.pem').crl_urls, [])


class CrlTests(unittest.TestCase):

    def test_two_revoked_serials_with_their_reasons(self):
        crl = sos.parse_crl(fixture_bytes('crl_revoked.der'))
        self.assertEqual(crl['version'], 2)
        self.assertEqual(crl['issuerDN'], LEAF.issuer_dn)
        self.assertEqual(crl['thisUpdate'], datetime(2026, 10, 1, tzinfo=timezone.utc))
        self.assertEqual(crl['nextUpdate'], datetime(2026, 10, 15, tzinfo=timezone.utc))
        self.assertEqual(crl['count'], 2)
        self.assertEqual([(e['serialHex'], e['reasonCode'], e['reason'], e['revocationDate'])
                          for e in crl['entries']],
                         [('0c1001', 1, 'keyCompromise', datetime(2026, 9, 1, 12, tzinfo=timezone.utc)),
                          ('0c1002', 4, 'superseded', datetime(2026, 8, 15, 8, 30, tzinfo=timezone.utc))])
        self.assertEqual(crl['crlNumber'], '10')
        self.assertEqual(crl['authorityKeyId'], fixture_cert('crl_ca.pem').subject_key_id)
        self.assertEqual(crl['idp'], {'urls': [DP], 'onlyUser': True, 'onlyCA': False,
                                      'onlySomeReasons': False, 'indirect': False,
                                      'onlyAttribute': False})
        self.assertFalse(crl['delta'])
        filtered = sos.parse_crl(fixture_bytes('crl_revoked.der'), serials=['0C1001'])
        self.assertEqual([e['serialHex'] for e in filtered['entries']], ['0c1001'])
        self.assertEqual(filtered['count'], 2)

    def test_what_each_crl_says_about_the_leaf(self):
        revoked = sos.parse_crl(fixture_bytes('crl_revoked.der'))
        empty = sos.parse_crl(fixture_bytes('crl_empty.der'))
        other = sos.parse_crl(fixture_bytes('crl_other.der'))
        verdict = sos.crl_status(revoked, LEAF, DP, NOW)
        self.assertEqual((verdict['status'], verdict['reason'], verdict['reasonCode'], verdict['time']),
                         ('revoked', 'keyCompromise', 1, datetime(2026, 9, 1, 12, tzinfo=timezone.utc)))
        self.assertEqual(sos.crl_status(revoked, LEAF2, DP, NOW)['reason'], 'superseded')
        self.assertEqual(sos.crl_status(empty, LEAF, DP, NOW)['status'], 'good')
        self.assertEqual(sos.crl_status(other, LEAF, None, NOW)['code'], 'issuer-mismatch',
                         "the same serial on another CA's CRL")
        self.assertEqual(sos.crl_status(revoked, LEAF, 'http://crl.example.com/other.crl', NOW)['code'], 'scope')
        self.assertEqual(sos.crl_status(empty, LEAF, DP, LATER)['code'], 'stale')
        self.assertEqual(sos.crl_status(revoked, LEAF, DP, LATER)['status'], 'revoked', 'revoked stays revoked')
        rekeyed = LEAF.__class__(**dict(LEAF.__dict__, authority_key_id='ab' * 20))
        self.assertEqual(sos.crl_status(revoked, rekeyed, DP, NOW)['code'], 'issuer-mismatch')
        with self.assertRaises(ValueError):
            sos.crl_status(sos.parse_crl(fixture_bytes('crl_revoked.der'), serials=['ff']), LEAF, DP, NOW)

    def test_input_that_is_no_crl(self):
        good = fixture_bytes('crl_empty.der')
        for bad in (b'', b'<!doctype html>', good[:-5], good + b'\x00', fixture_bytes('crl_leaf.pem'),
                    LEAF.der):
            with self.assertRaises(sos.DerError):
                sos.parse_crl(bad)


class AriClientTests(unittest.TestCase):

    def client(self, fetch, now=NOW):
        return sos.AriClient(fetch=fetch, directories=TEST_DIRS, ca_of=lambda cert: 'letsencrypt',
                             now=lambda: now)

    def test_the_window_retry_after_and_404(self):
        cert_id = sos.ari_cert_id(LEAF)
        fetch = FakeFetch({
            DIR: (200, {}, json.dumps({'renewalInfo': RI}).encode()),
            '%s/%s' % (RI, cert_id): (200, {'retry-after': '21600'},
                                      window('2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z',
                                             explanationURL='https://status.example.org/x')),
        })
        client = self.client(fetch)
        record = client.check(LEAF)
        self.assertEqual(record, {'ca': 'letsencrypt', 'certId': cert_id, 'start': '2026-11-01T00:00:00.000Z',
                                  'end': '2026-11-03T00:00:00.000Z', 'explanationURL': 'https://status.example.org/x',
                                  'checkedAt': '2026-10-09T03:00:00.000Z', 'retryAfter': '2026-10-09T09:00:00.000Z',
                                  'status': 200, 'error': None})
        self.assertIs(client.check(LEAF), record, 'asked once')
        nf = client.check(LEAF2)
        self.assertEqual((nf['error'], nf['status'], nf['start']), ('not-found', 404, None))
        self.assertEqual(fetch.calls.count(DIR), 1, 'the directory read once')
        unsupported = sos.AriClient(fetch=fetch, now=lambda: NOW).check(LEAF)
        self.assertEqual((unsupported['ca'], unsupported['error']), (None, 'unsupported'))

    def test_not_asked_before_the_retry_after_and_a_rate_limit(self):
        cert_id = sos.ari_cert_id(LEAF)
        prev = {'ca': 'letsencrypt', 'certId': cert_id, 'start': '2026-11-01T00:00:00.000Z',
                'end': '2026-11-03T00:00:00.000Z', 'explanationURL': None,
                'checkedAt': '2026-10-09T01:00:00.000Z', 'retryAfter': '2026-10-09T07:00:00.000Z',
                'status': 200, 'error': None}
        fetch = FakeFetch({DIR: (200, {}, json.dumps({'renewalInfo': RI}).encode()),
                           '%s/%s' % (RI, cert_id): (429, {'retry-after': '120'}, b'{}')})
        carried = self.client(fetch).check(LEAF, prev)
        self.assertEqual(carried, dict(prev, carried={'from': '2026-10-09T01:00:00.000Z'}))
        self.assertEqual(fetch.calls, [], 'nothing sent before the Retry-After')
        later = self.client(fetch, datetime(2026, 10, 9, 8, 0, tzinfo=timezone.utc))
        limited = later.check(LEAF, prev)
        self.assertEqual((limited['error'], limited['status'], limited['retryAfter']),
                         ('rate-limit', 429, '2026-10-09T08:02:00.000Z'))
        benched = later.check(LEAF2)
        self.assertEqual((benched['error'], benched['retryAfter']), ('rate-limit', '2026-10-09T08:02:00.000Z'))
        self.assertEqual(len([u for u in fetch.calls if u.startswith(RI)]), 1, 'the CA benched for the run')

    def test_a_directory_elsewhere_a_bad_window_and_no_answer(self):
        cert_id = sos.ari_cert_id(LEAF)
        elsewhere = FakeFetch({DIR: (200, {}, json.dumps({'renewalInfo': 'https://ari.example.net/x'}).encode())})
        self.assertEqual(self.client(elsewhere).check(LEAF)['error'], 'no-renewal-info')
        self.assertEqual(elsewhere.calls, [DIR], 'nothing sent to a host the table does not name')
        backwards = FakeFetch({DIR: (200, {}, json.dumps({'renewalInfo': RI}).encode()),
                               '%s/%s' % (RI, cert_id): (200, {}, window('2026-11-03T00:00:00Z', '2026-11-01T00:00:00Z'))})
        self.assertEqual(self.client(backwards).check(LEAF)['error'], 'bad-window')
        down = FakeFetch({DIR: sos.StatusFetchError('network', 'unreachable')})
        self.assertEqual(self.client(down).check(LEAF)['error'], 'network')
        forbidden = FakeFetch({DIR: (200, {}, json.dumps({'renewalInfo': RI}).encode()),
                               '%s/%s' % (RI, cert_id): (403, {}, b'{"message":"Missing Authentication Token"}')})
        record = self.client(forbidden).check(LEAF)
        self.assertEqual((record['error'], record['status']), ('http', 403))
        self.assertEqual(sos.window_state(record, NOW), None)


class RevocationCheckerTests(unittest.TestCase):

    def test_revoked_good_another_cas_and_failures(self):
        fetch = FakeFetch({DP: (200, {}, fixture_bytes('crl_revoked.der'))})
        checker = sos.RevocationChecker(fetch=fetch, now=lambda: NOW)
        out = checker.check({'a': LEAF, 'b': LEAF2})
        self.assertEqual(out['a'], {'status': 'revoked', 'reason': 'keyCompromise', 'reasonCode': 1,
                                    'time': '2026-09-01T12:00:00.000Z', 'crl': DP,
                                    'checkedAt': '2026-10-09T03:00:00.000Z', 'thisUpdate': '2026-10-01T00:00:00.000Z',
                                    'nextUpdate': '2026-10-15T00:00:00.000Z', 'signature': 'not-verified',
                                    'error': None})
        self.assertEqual(out['b']['reason'], 'superseded')
        self.assertEqual(fetch.calls, [DP], 'one download for both')
        good = sos.RevocationChecker(fetch=FakeFetch({DP: (200, {}, fixture_bytes('crl_empty.der'))}),
                                     now=lambda: NOW).check({'a': LEAF})['a']
        self.assertEqual((good['status'], good['signature'], good['error']), ('good', 'not-verified', None))
        other = sos.RevocationChecker(fetch=FakeFetch({DP: (200, {}, fixture_bytes('crl_other.der'))}),
                                      now=lambda: NOW).check({'a': LEAF})['a']
        self.assertEqual((other['status'], other['error'], other['signature']), ('unknown', 'issuer-mismatch', None))
        cases = {'too-large': sos.RevocationChecker(fetch=FakeFetch({DP: (200, {}, fixture_bytes('crl_revoked.der'))}),
                                                    now=lambda: NOW, max_bytes=100),
                 'http': sos.RevocationChecker(fetch=FakeFetch({}), now=lambda: NOW),
                 'parse': sos.RevocationChecker(fetch=FakeFetch({DP: (200, {}, b'<!doctype html>')}), now=lambda: NOW),
                 'timeout': sos.RevocationChecker(fetch=FakeFetch({DP: sos.StatusFetchError('timeout')}), now=lambda: NOW)}
        for code, checker in cases.items():
            record = checker.check({'a': LEAF})['a']
            self.assertEqual((record['status'], record['error'], record['crl']), ('unknown', code, DP), code)
        no_crl = LEAF.__class__(**dict(LEAF.__dict__, crl_urls=[]))
        record = sos.RevocationChecker(fetch=FakeFetch({}), now=lambda: NOW).check({'a': no_crl})['a']
        self.assertEqual((record['error'], record['crl']), ('no-crl', None))

    def test_http_get_reads_a_local_server(self):
        body = fixture_bytes('crl_empty.der')

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - the stdlib's name
                if self.path == '/crl':
                    self.send_response(200)
                    self.send_header('Content-Type', 'application/pkix-crl')
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == '/big':
                    self.send_response(200)
                    self.send_header('Content-Length', str(50 << 20))
                    self.end_headers()
                else:
                    self.send_response(404)
                    self.send_header('Retry-After', '60')
                    self.end_headers()

            def log_message(self, *args):  # quiet
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = 'http://127.0.0.1:%d' % server.server_address[1]
            status, headers, got = sos.http_get(base + '/crl', 5, sos.CRL_MAX_BYTES)
            self.assertEqual((status, got, headers.get('content-type')), (200, body, 'application/pkix-crl'))
            status, headers, _ = sos.http_get(base + '/missing', 5)
            self.assertEqual((status, headers.get('retry-after')), (404, '60'))
            with self.assertRaises(sos.StatusFetchError) as caught:
                sos.http_get(base + '/big', 5, 1000)
            self.assertEqual(caught.exception.code, 'too-large')
            with self.assertRaises(sos.StatusFetchError):
                sos.http_get('file:///etc/passwd', 5)
        finally:
            server.shutdown()
            server.server_close()


def night_fetch(window_body: bytes, crl: str, retry_after: str = '86400') -> FakeFetch:
    return FakeFetch({DIR: (200, {}, json.dumps({'renewalInfo': RI}).encode()),
                      '%s/%s' % (RI, sos.ari_cert_id(LEAF)): (200, {'retry-after': retry_after}, window_body),
                      DP: (200, {}, fixture_bytes(crl))})


class ScanTests(unittest.TestCase):
    """--ari / --revocation through main(): the JSON, the CSV, the summary and the baseline."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.json = os.path.join(self.dir, 'last.json')

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def night(self, fetch: FakeFetch, now: datetime, *extra: str):
        """main() over the scan and the fakes; the summary with its line wrapping undone."""
        with mock.patch.object(sos, 'run_scan', return_value=leaf_scan(now=now)), \
                mock.patch.object(sos, 'http_get', fetch), \
                mock.patch.dict(sos.ARI_DIRECTORIES, TEST_DIRS, clear=True), \
                mock.patch.object(sos, 'ari_ca_for_issuer', return_value='letsencrypt'):
            code, out, err = run_main('-t', '192.0.2.10', '-n', 'www.example.com', '--ari', '--revocation',
                                      '--no-color', '--baseline', self.json, '--json', self.json, *extra, now=now)
        return code, ' '.join(out.split()), err

    def test_three_nights(self):
        fetch1 = night_fetch(window('2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'), 'crl_empty.der')
        code, out, err = self.night(fetch1, NOW, '--csv', os.path.join(self.dir, 'last.csv'))
        self.assertEqual(code, sos.EXIT_OK, err)
        doc = read_json(self.json)
        self.assertEqual((doc['options']['ari'], doc['options']['revocation']), (True, True))
        entry = doc['certificates'][LEAF.sha256]
        self.assertEqual((entry['ari']['start'], entry['ari']['retryAfter'], entry['ari']['error']),
                         ('2026-11-01T00:00:00.000Z', '2026-10-10T03:00:00.000Z', None))
        self.assertEqual((entry['revocation']['status'], entry['revocation']['signature']), ('good', 'not-verified'))
        self.assertIn('Renewal windows and revocation (ARI and revocation): 1 certificate(s) served', out)
        self.assertIn('ARI (letsencrypt): renew between 2026-11-01 00:00 UTC and 2026-11-03 00:00 UTC - opens in 23 days', out)
        self.assertIn('Not revoked (CRL of 2026-10-01 00:00 UTC; CRL signature not verified)', out)
        with open(os.path.join(self.dir, 'last.csv'), encoding='utf-8-sig') as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(list(rows[0])[-8:], list(sos.ARI_CSV_COLUMNS + sos.REVOCATION_CSV_COLUMNS))
        self.assertEqual({(r['ari_start'], r['revocation']) for r in rows}, {('2026-11-01T00:00:00.000Z', 'good')})

        # night 2: the window moved into today with an explanation, and the CRL lists the leaf
        later = datetime(2026, 10, 10, 3, 0, tzinfo=timezone.utc)
        fetch2 = night_fetch(window('2026-10-09T12:00:00Z', '2026-10-11T00:00:00Z',
                                    explanationURL='https://status.example.org/incident'), 'crl_revoked.der')
        code, out, err = self.night(fetch2, later, '--fail-on-change')
        self.assertEqual(code, sos.EXIT_CHANGED, err)
        changes = read_json(self.json)['changes']
        self.assertEqual([sos.change_tag(c) for c in changes], ['RENEW-NOW', 'MOVED-UP', 'CA-NOTICE', 'REVOKED'])
        self.assertTrue(all(sos.counts_as_change(c) for c in changes))
        self.assertIn("RENEW-NOW CN www.example.com (sha256 %s): the CA's renewal window opened "
                      '(2026-10-09 - 2026-10-11): renew it now; served by web01 192.0.2.10:443' % LEAF.sha256[:8], out)
        self.assertIn('MOVED-UP CN www.example.com', out)
        self.assertIn('the CA moved its renewal window 23 days earlier (starts 2026-10-09, was 2026-11-01)', out)
        self.assertIn('CA-NOTICE CN www.example.com (sha256 %s): the CA explains its renewal window: '
                      'https://status.example.org/incident' % LEAF.sha256[:8], out)
        self.assertIn('REVOKED CN www.example.com (sha256 %s): revoked by its CA on 2026-09-01 (keyCompromise), still served' % LEAF.sha256[:8], out)
        self.assertIn('REVOKED on 2026-09-01 12:00 UTC (keyCompromise); CRL of 2026-10-01 00:00 UTC, CRL signature not verified', out)

        # night 3, before night 2's Retry-After: the CA is not asked, nothing new
        fetch3 = night_fetch(window('2026-12-01T00:00:00Z', '2026-12-03T00:00:00Z'), 'crl_revoked.der')
        code, out, err = self.night(fetch3, datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc), '--fail-on-change')
        self.assertEqual(code, sos.EXIT_OK, err)
        self.assertFalse([u for u in fetch3.calls if u.startswith(RI)], 'renewalInfo not asked before its Retry-After')
        ari = read_json(self.json)['certificates'][LEAF.sha256]['ari']
        self.assertEqual((ari['start'], ari['carried']), ('2026-10-09T12:00:00.000Z', {'from': '2026-10-10T03:00:00.000Z'}))
        self.assertIn('(as of 2026-10-10 03:00 UTC; not asked again before 2026-10-11 03:00 UTC, as the CA asked)', out)

    def test_estate_carries_both_and_its_csv_has_the_columns(self):
        fetch = night_fetch(window('2026-11-01T00:00:00Z', '2026-11-03T00:00:00Z'), 'crl_revoked.der')
        csv_path = os.path.join(self.dir, 'estate.csv')
        with mock.patch.object(sos, 'run_scan', return_value=leaf_scan()), \
                mock.patch.object(sos, 'http_get', fetch), \
                mock.patch.dict(sos.ARI_DIRECTORIES, TEST_DIRS, clear=True), \
                mock.patch.object(sos, 'ari_ca_for_issuer', return_value='letsencrypt'):
            code, out, err = run_main('-t', '192.0.2.10', '-n', 'www.example.com', '--estate', '--ari',
                                      '--revocation', '--no-color', '--json', self.json, '--csv', csv_path, now=NOW)
        out = ' '.join(out.split())
        self.assertEqual(code, sos.EXIT_OK, err)
        cert = read_json(self.json)['estate']['certificates'][0]
        self.assertEqual((cert['ari']['start'], cert['revocation']['status']), ('2026-11-01T00:00:00.000Z', 'revoked'))
        self.assertIn('Renewal windows and revocation: 1 revoked, 0 to renew now (ARI)', out)
        self.assertIn('ARI (letsencrypt): renew between 2026-11-01 00:00 UTC and 2026-11-03 00:00 UTC', out)
        with open(csv_path, encoding='utf-8-sig') as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(list(rows[0]), list(sos.ESTATE_CSV_COLUMNS + sos.ARI_CSV_COLUMNS + sos.REVOCATION_CSV_COLUMNS))
        self.assertEqual({(r['revocation'], r['revoked_at'], r['revocation_reason']) for r in rows},
                         {('revoked', '2026-09-01T12:00:00.000Z', 'keyCompromise')})
        # without the options, the estate and its CSV are as before
        plain = sos.estate_from_report(sos.report_to_dict(leaf_scan()), NOW)
        self.assertNotIn('ari', plain['certificates'][0])
        self.assertEqual(sos.estate_status_columns(plain), ())

    def test_not_with_compare(self):
        code, _out, err = run_main('--compare', '192.0.2.1', '192.0.2.2', '-n', 'www.example.com', '--ari')
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn('--compare does not take --ari', err)


if __name__ == '__main__':
    unittest.main()
