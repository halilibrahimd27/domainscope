"""--compare OLD_IP NEW_IP -n NAME of cli/ssl_origin_scan.py (stdlib unittest; no network).

Two local HTTPS servers on the same port of 127.0.0.1 and 127.0.0.2 (the loopback network)
stand in for the old and the new server of a name: one TLS connection with SNI and one GET
over it per address, then a verifying handshake. The certificates are the test-only fixtures
(cli_private_wild.pem, issued by cli_private_ca.pem; rsa_multi_san.pem for a wrong name).

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import dataclasses
import json
import os
import socket
import ssl
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from test_ssl_origin_scan import FIXTURES, _Listener, fixture_cert, read_json, run_main, sos

NAME = 'a.wild.example.net'
PRIVATE_CA = str(FIXTURES / 'cli_private_ca.pem')
PAGE = b'<!doctype html><html><head><title>Example &amp; Co</title></head><body>hello</body></html>'


class HttpsServer(_Listener):
    """Answers one GET per TLS connection: ``status``, ``headers`` and ``body``."""

    def __init__(self, fixture: str, host: str, port: int = 0, status: int = 200,
                 headers: Optional[Dict[str, str]] = None, body: bytes = PAGE) -> None:
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(FIXTURES / (fixture + '.pem')), str(FIXTURES / (fixture + '.key')))
        self.context.sni_callback = self._on_sni
        self.status = status
        self.headers = headers if headers is not None else {
            'Content-Type': 'text/html; charset=utf-8', 'Strict-Transport-Security': 'max-age=31536000', 'Server': 'nginx'}
        self.body = body
        self.sni = []  # type: List[Optional[str]]
        self.requests = []  # type: List[bytes]
        super().__init__(host, port)

    def _on_sni(self, _sslobj, server_name, _context):
        self.sni.append(server_name)

    def handle(self, conn: socket.socket) -> None:
        with self.context.wrap_socket(conn, server_side=True) as tls:
            data = b''
            while b'\r\n\r\n' not in data:
                chunk = tls.recv(4096)
                if not chunk:
                    return
                data += chunk
            self.requests.append(data)
            head = 'HTTP/1.1 %d X\r\n' % self.status + ''.join('%s: %s\r\n' % kv for kv in self.headers.items())
            head += 'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(self.body)
            tls.sendall(head.encode('latin-1') + self.body)


def _pair(new_kwargs: Optional[Dict] = None, new_fixture: str = 'cli_private_wild') -> Tuple[HttpsServer, Optional[HttpsServer]]:
    old = HttpsServer('cli_private_wild', '127.0.0.1')
    try:
        new = HttpsServer(new_fixture, '127.0.0.2', old.port, **(new_kwargs or {}))
    except OSError:
        old.close()
        raise unittest.SkipTest('127.0.0.2 is not a loopback address here')
    return old, new


class CompareIntegrationTests(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.servers = []  # type: List[HttpsServer]

    def tearDown(self):
        for server in self.servers:
            server.close()
        self.tmp.cleanup()

    def pair(self, **kwargs) -> Tuple[HttpsServer, HttpsServer]:
        old, new = _pair(**kwargs)
        self.servers += [old, new]
        return old, new

    def compare(self, port: int, *extra: str, private_ca: bool = True) -> Tuple[int, str, str]:
        return run_main('--compare', '127.0.0.1', '127.0.0.2', '-n', NAME, '-p', str(port), '--timeout', '3',
                        *(('--private-ca', PRIVATE_CA) if private_ca else ()), '--no-color', *extra)

    def test_the_same_site_on_both(self):
        old, new = self.pair()
        path = os.path.join(self.tmp.name, 'compare.json')
        code, out, err = self.compare(old.port, '--json', path, '--path', '/healthz?x=1', '--fail-on-change')
        self.assertEqual(code, 0, out + err)
        self.assertIn('SAME: The new server answers like the old one', out)
        doc = read_json(path)
        self.assertEqual(doc['schema'], 'domainscope.compare/1')
        self.assertEqual([doc['verdict'], doc['name'], doc['path']], ['same', NAME, '/healthz?x=1'])
        self.assertEqual(doc['old']['title'], 'Example & Co')
        self.assertEqual(doc['old']['body']['bytes'], len(PAGE))
        self.assertEqual([doc['new']['certTrusted'], doc['new']['trustDetail']], [True, 'issued by a --private-ca'])
        self.assertTrue(all(f['same'] for f in doc['fields']))
        names = next(f for f in doc['fields'] if f['key'] == 'cert_subject')
        self.assertEqual([names['old'], names['new']], ['*.wild.example.net, wild.example.net'] * 2)
        for server in (old, new):
            self.assertEqual(server.sni, [NAME, NAME], 'the GET connection and the verifying handshake')
            self.assertEqual(len(server.requests), 1, 'one GET, over the first TLS connection')
            request = server.requests[0].decode('latin-1')
            self.assertTrue(request.startswith('GET /healthz?x=1 HTTP/1.1\r\n'), request)
            self.assertIn('\r\nHost: %s:%d\r\n' % (NAME, old.port), request)
            self.assertIn('\r\nAccept-Encoding: identity\r\n', request)

    def test_the_same_untrusted_certificate_on_both_is_no_difference(self):
        # Without --private-ca this machine trusts neither: the same private-CA certificate on
        # both servers (an origin CA certificate behind a CDN is the usual case) is SAME.
        old, _new = self.pair()
        path = os.path.join(self.tmp.name, 'compare.json')
        code, out, err = self.compare(old.port, '--json', path, '--fail-on-change', private_ca=False)
        self.assertEqual(code, 0, out + err)
        self.assertIn('SAME: The new server answers like the old one', out)
        self.assertIn('WARNING: Both servers serve a certificate this machine does not trust', out)
        self.assertNotIn('DIFFERS', out)
        line = next(l for l in out.splitlines() if l.strip().startswith('cert trusted'))
        self.assertTrue(line.rstrip().endswith('WARNING'), line)
        doc = read_json(path)
        self.assertEqual([doc['verdict'], doc['shared']], ['same', ['cert-untrusted']])
        trusted = next(f for f in doc['fields'] if f['key'] == 'cert_trusted')
        self.assertEqual([trusted['same'], trusted['shared'], trusted['severity']], [True, True, 'warn'])
        # The certificates each server sent (Python 3.13+ tells): the leaf alone here.
        sent = 1 if hasattr(ssl.SSLSocket, 'get_unverified_chain') else None
        self.assertEqual([doc['old']['chainLength'], doc['new']['chainLength']], [sent, sent])

    def test_an_internal_ca_certificate_then_a_self_signed_one_fails_the_check(self):
        # Without --private-ca this machine trusts neither, but the new certificate is not from
        # the old one's CA: what trusts the internal CA refuses it.
        old, _new = self.pair(new_fixture='ec_wildcard')
        code, out, err = self.compare(old.port, '--fail-on-change', private_ca=False)
        self.assertEqual(code, sos.EXIT_CHANGED, out + err)
        self.assertIn('DIFFERS: The new server answers differently', out)
        self.assertNotIn('WARNING: Both servers', out)
        line = next(l for l in out.splitlines() if l.strip().startswith('cert trusted'))
        self.assertTrue(line.rstrip().endswith('DIFFERS'), line)

    def test_a_new_server_that_answers_differently(self):
        old, _new = self.pair(new_kwargs={'status': 301, 'headers': {'Location': 'https://www.example.net/', 'Server': 'caddy'},
                                          'body': b'moved'})
        code, out, _ = self.compare(old.port, '--fail-on-change')
        self.assertEqual(code, sos.EXIT_CHANGED)
        self.assertIn('DIFFERS: The new server answers differently', out)
        for label in ('HTTP status', 'Location', 'Content-Type', '<title>', 'HSTS'):
            line = next(l for l in out.splitlines() if l.strip().startswith(label))
            self.assertTrue(line.rstrip().endswith('DIFFERS'), line)
        self.assertIn('visitors that never saw the header lose HTTPS-only', out)
        body = next(l for l in out.splitlines() if l.strip().startswith('body SHA-256'))
        self.assertTrue(body.rstrip().endswith('differs'), body)

    def test_a_certificate_for_another_name_is_an_error(self):
        old, _new = self.pair(new_fixture='rsa_multi_san')
        code, out, _ = self.compare(old.port, '--fail-on-change')
        self.assertEqual(code, sos.EXIT_CHANGED)
        self.assertIn('BROKEN', out)
        self.assertIn('the certificate does not cover the name', out)
        line = next(l for l in out.splitlines() if l.strip().startswith('cert covers name'))
        self.assertTrue(line.rstrip().endswith('ERROR'), line)

    def test_a_new_server_that_does_not_answer(self):
        old = HttpsServer('cli_private_wild', '127.0.0.1')
        self.servers.append(old)
        code, out, _ = self.compare(old.port)
        self.assertEqual(code, 0, 'no --fail-on-change')
        self.assertIn('BROKEN', out)
        self.assertIn('CLOSED', out)
        self.assertNotIn('HTTP status', out, 'nothing else is compared')

    def test_neither_server_answering_fails_the_check(self):
        probe = socket.socket()
        probe.bind(('127.0.0.1', 0))
        port = probe.getsockname()[1]
        probe.close()
        code, out, _ = self.compare(port, '--fail-on-change')
        self.assertEqual(code, sos.EXIT_CHANGED, 'nothing could be confirmed')
        self.assertIn('UNREACHABLE', out)
        self.assertNotIn('BROKEN', out)


class CompareUnitTests(unittest.TestCase):

    def side(self, **kwargs):
        base = dict(ip='192.0.2.1', port=443, status=200, content_type='text/html', title='t', body_sha256='aa',
                    body_bytes=2, hsts='max-age=1', server='nginx')
        base.update(kwargs)
        return sos.CompareSide(**base)

    def test_rules(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        same = sos.compare_sides(self.side(), self.side(ip='192.0.2.2'), now)
        self.assertEqual([same['verdict'], same['differences']], ['same', 0])
        err = sos.compare_sides(self.side(), self.side(status=503), now)
        self.assertEqual([err['verdict'], err['fields'][1]['note']], ['broken', 'new-error-status'])
        both_bad = sos.compare_sides(self.side(status=500), self.side(status=500), now)
        self.assertEqual(both_bad['verdict'], 'same', 'not a regression')
        gone = sos.compare_sides(self.side(status=None, failure='TIMEOUT', detail='timed out'), self.side(), now)
        self.assertEqual(gone['verdict'], 'incomplete')
        self.assertTrue(all(f['severity'] in ('ok', 'info') for f in gone['fields']))
        cert = fixture_cert('cli_private_wild.pem')
        expiring = sos.compare_sides(self.side(), self.side(cert=cert, covers=True, trusted=True),
                                     cert.not_after.replace(tzinfo=timezone.utc) if cert.not_after.tzinfo is None else cert.not_after)
        self.assertIn('cert-expiring', [f['note'] for f in expiring['fields']])
        untrusted = sos.compare_sides(self.side(cert=cert, covers=True, trusted=True), self.side(cert=cert, covers=True, trusted=False), now)
        self.assertEqual(untrusted['verdict'], 'broken')
        fixed = sos.compare_sides(self.side(cert=cert, covers=True, trusted=False), self.side(cert=cert, covers=True, trusted=True), now)
        self.assertEqual([fixed['verdict'], fixed['shared']], ['same', []], 'untrusted -> trusted is information')

    def test_a_problem_both_servers_share_is_no_difference(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        cert = fixture_cert('cli_private_wild.pem')
        other = fixture_cert('rsa_multi_san.pem')
        untrusted = dict(cert=cert, covers=True, trusted=False)
        both = sos.compare_sides(self.side(**untrusted), self.side(ip='192.0.2.2', **untrusted), now)
        self.assertEqual([both['verdict'], both['shared'], both['worst']], ['same', ['cert-untrusted'], 'ok'])
        field = next(f for f in both['fields'] if f['key'] == 'cert_trusted')
        self.assertEqual([field['same'], field['shared'], field['severity']], [True, True, 'warn'])
        text = sos.render_compare(NAME, '/', self.side(**untrusted), self.side(ip='192.0.2.2', **untrusted), both, width=160, now=now)
        self.assertIn('SAME: ', text)
        self.assertIn('WARNING: Both servers serve a certificate this machine does not trust', text)
        # The same certificate, expiring within 14 days on both.
        soon = cert.not_after if cert.not_after.tzinfo else cert.not_after.replace(tzinfo=timezone.utc)
        valid = dict(cert=cert, covers=True, trusted=True)
        expiring = sos.compare_sides(self.side(**valid), self.side(ip='192.0.2.2', **valid), soon)
        self.assertEqual([expiring['verdict'], expiring['shared']], ['same', ['cert-expiring']])
        text = sos.render_compare(NAME, '/', self.side(**valid), self.side(ip='192.0.2.2', **valid), expiring, width=160, now=soon)
        self.assertIn('WARNING: Both servers serve a certificate that expires within 14 days', text)
        # A default certificate that covers the name on neither server.
        wrong = dict(cert=other, covers=False, trusted=False)
        neither = sos.compare_sides(self.side(**wrong), self.side(ip='192.0.2.2', **wrong), now)
        self.assertEqual([neither['verdict'], sorted(neither['shared'])], ['same', ['cert-name', 'cert-untrusted']])
        # Next to a real difference, the verdict follows the difference.
        moved = sos.compare_sides(self.side(**untrusted), self.side(ip='192.0.2.2', status=301, location='https://www.example.net/', **untrusted), now)
        self.assertEqual([moved['verdict'], moved['shared']], ['differs', ['cert-untrusted']])

    def test_an_untrusted_certificate_from_another_issuer_is_a_difference(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        origin, internal = fixture_cert('cli_origin_wild.pem'), fixture_cert('cli_private_wild.pem')
        self_signed, other_self = fixture_cert('ec_wildcard.pem'), fixture_cert('cli_renewed_wild.pem')
        self.assertTrue(self_signed.self_signed and not origin.self_signed and not internal.self_signed)

        def side(cert, ip='192.0.2.1'):
            return self.side(ip=ip, cert=cert, covers=True, trusted=False)

        # An origin CA certificate (a CDN trusts it) on the old server, a self-signed one on the new.
        for old in (origin, internal):
            result = sos.compare_sides(side(old), side(self_signed, '192.0.2.2'), now)
            self.assertEqual([result['verdict'], result['shared']], ['differs', []], old.issuer_label())
            field = next(f for f in result['fields'] if f['key'] == 'cert_trusted')
            self.assertEqual([field['same'], field['shared'], field['severity'], field['note']],
                             [False, False, 'warn', 'cert-untrusted-other'])
            text = sos.render_compare(NAME, '/', side(old), side(self_signed, '192.0.2.2'), result, width=160, now=now)
            self.assertIn('DIFFERS: ', text)
            self.assertNotIn('WARNING: Both servers', text)
            line = next(l for l in text.splitlines() if l.strip().startswith('cert trusted'))
            self.assertTrue(line.rstrip().endswith('DIFFERS'), line)
            self.assertIn('from another issuer', text)
        # A renewed certificate from the same CA: no difference.
        renewed = dataclasses.replace(internal, sha256='ee' * 32)
        same_ca = sos.compare_sides(side(internal), side(renewed, '192.0.2.2'), now)
        self.assertEqual([same_ca['verdict'], same_ca['shared']], ['same', ['cert-untrusted']])
        # A self-signed certificate is its own issuer: only the same one is shared.
        regenerated = dataclasses.replace(self_signed, sha256='ff' * 32)
        self.assertEqual(sos.compare_sides(side(self_signed), side(regenerated, '192.0.2.2'), now)['verdict'], 'differs')
        self.assertEqual(sos.compare_sides(side(self_signed), side(other_self, '192.0.2.2'), now)['verdict'], 'differs')
        self.assertEqual(sos.compare_sides(side(self_signed), side(self_signed, '192.0.2.2'), now)['shared'], ['cert-untrusted'])

    def test_hsts_turned_off_or_weaker_on_the_new_server_is_a_warning(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        old = self.side(hsts='max-age=31536000; includeSubDomains; preload')

        def hsts(new_value, old_side=old):
            result = sos.compare_sides(old_side, self.side(ip='192.0.2.2', hsts=new_value), now)
            item = next(f for f in result['fields'] if f['key'] == 'hsts')
            return [result['verdict'], item['severity'], item['note']]
        self.assertEqual(hsts('max-age=0'), ['differs', 'warn', 'hsts-off'], 'browsers forget the policy')
        self.assertEqual(hsts('max-age=31536000'), ['differs', 'warn', 'hsts-weaker'], 'includeSubDomains dropped')
        self.assertEqual(hsts('Max-Age="31536000"; includeSubDomains')[2], 'hsts-weaker', 'preload dropped')
        self.assertEqual(hsts('max-age=63072000; includesubdomains; preload'), ['same', 'info', None])
        self.assertEqual(hsts(None), ['differs', 'warn', 'hsts-lost'])
        # An old max-age=0 is no policy to lose; a new header after it is one added.
        self.assertEqual(hsts(None, self.side(hsts='max-age=0')), ['same', 'info', None])
        self.assertEqual(hsts('max-age=600', self.side(hsts='max-age=0'))[2], 'hsts-new')
        result = sos.compare_sides(old, self.side(ip='192.0.2.2', hsts='max-age=0'), now)
        text = sos.render_compare(NAME, '/', old, self.side(ip='192.0.2.2', hsts='max-age=0'), result, width=160, now=now)
        line = next(l for l in text.splitlines() if l.strip().startswith('HSTS'))
        self.assertTrue(line.rstrip().endswith('DIFFERS'), line)
        self.assertIn('max-age=0: browsers that kept the old header forget it', text)

    def test_two_untrusted_certificates_are_shared_only_when_they_fail_alike(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        internal, origin = fixture_cert('cli_private_wild.pem'), fixture_cert('cli_origin_wild.pem')
        local = 'unable to get local issuer certificate'

        def compare(ca, cb, old_detail=local, new_detail=local):
            result = sos.compare_sides(self.side(cert=ca, covers=True, trusted=False, trust_detail=old_detail),
                                       self.side(ip='192.0.2.2', cert=cb, covers=True, trusted=False, trust_detail=new_detail), now)
            item = next(f for f in result['fields'] if f['key'] == 'cert_trusted')
            return [result['verdict'], item['note'], result['shared']]
        shared, other = ['same', 'cert-untrusted', ['cert-untrusted']], ['differs', 'cert-untrusted-other', []]
        renewed = dataclasses.replace(internal, sha256='b2' * 32)
        self.assertEqual(compare(internal, renewed), shared, 'renewed by the same CA')
        # The new server sends the leaf without its intermediate: a client that trusts only the root refuses it.
        self.assertEqual(compare(internal, renewed, new_detail='unable to verify the first certificate'), other)
        # Python stops at the first error, so both say "unable to get local issuer certificate":
        # the chain each server sent (Python 3.13+) tells them apart.
        def chained(old_length, new_length):
            result = sos.compare_sides(
                self.side(cert=internal, covers=True, trusted=False, trust_detail=local, chain_length=old_length),
                self.side(ip='192.0.2.2', cert=renewed, covers=True, trusted=False, trust_detail=local, chain_length=new_length), now)
            return [result['verdict'], result['shared']]
        self.assertEqual(chained(2, 1), ['differs', []], 'the intermediate lost')
        self.assertEqual(chained(3, 2), ['same', ['cert-untrusted']], 'only the root dropped: clients have it')
        self.assertEqual(chained(None, 1), ['same', ['cert-untrusted']], 'not known before Python 3.13')
        # A new certificate that is not valid yet, whatever this machine reports first.
        self.assertEqual(compare(internal, dataclasses.replace(renewed, not_before=now + timedelta(days=30))), other)
        # The issuer DN as issued_by compares it; an empty one says nothing; another CA key is another CA.
        self.assertEqual(compare(internal, dataclasses.replace(renewed, issuer_dn=internal.issuer_dn.upper())), shared)
        self.assertEqual(compare(dataclasses.replace(internal, issuer_dn=''), dataclasses.replace(renewed, issuer_dn=' ')), other)
        self.assertEqual(compare(internal, dataclasses.replace(renewed, authority_key_id='00' * 20)), other, 'a re-created CA of the same name')
        # Cloudflare's RSA and ECC origin CAs: Cloudflare trusts both (the web app sees 'CloudFlare, Inc.' on both).
        ecc_name = 'CloudFlare Origin SSL ECC Certificate Authority'
        ecc = dataclasses.replace(origin, sha256='e1' * 32, issuer=dict(origin.issuer, OU=ecc_name),
                                  issuer_dn=origin.issuer_dn.replace('CloudFlare Origin SSL Certificate Authority', ecc_name),
                                  authority_key_id='11' * 20)
        self.assertTrue(sos.is_origin_ca_certificate(ecc))
        first = 'unable to verify the first certificate'
        self.assertEqual(compare(origin, ecc, first, first), shared, 'RSA -> ECC origin CA')

    def test_hsts_as_a_browser_reads_it(self):
        self.assertEqual(sos.hsts_policy('max-age="600"'), (600, False, False, True))
        self.assertEqual(sos.hsts_policy('max-age=0, max-age=31536000; includeSubDomains'), (0, False, False, True),
                         'joined headers: only the first counts (RFC 6797 8.1)')
        for bad in ('includeSubDomains', 'max-age=abc', 'max_age=600', 'max-age=600; max-age=0', 'max-age="600',
                    'max-age=600; includeSubDomains=1', 'max-age=600; includeSubDomains; includeSubDomains', 'max-age=600 600'):
            policy = sos.hsts_policy(bad)
            self.assertEqual([policy[0], policy[3]], [None, False], bad)
        self.assertEqual(sos.hsts_policy('MAX-AGE = "31536000" ; INCLUDESUBDOMAINS;; preload'), (31536000, True, True, True))
        self.assertIsNone(sos.hsts_policy('  '))
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        old = self.side(hsts='max-age=31536000; includeSubDomains; preload')

        def hsts(new_value, old_side=old):
            result = sos.compare_sides(old_side, self.side(ip='192.0.2.2', hsts=new_value), now)
            item = next(f for f in result['fields'] if f['key'] == 'hsts')
            return [result['verdict'], item['severity'], item['note']]
        for bad in ('includeSubDomains; preload', 'max-age=abc; includeSubDomains; preload', 'max_age=31536000; includeSubDomains; preload',
                    'max-age=31536000; max-age=0; includeSubDomains; preload',
                    'max-age=31536000; includeSubDomains; includesubdomains; preload'):
            self.assertEqual(hsts(bad), ['differs', 'warn', 'hsts-invalid'], bad)
        self.assertEqual(hsts('max-age=0, max-age=31536000; includeSubDomains; preload'), ['differs', 'warn', 'hsts-off'])
        self.assertEqual(hsts('max-age=31536000; includeSubDomains; preload, max-age=0'), ['same', 'info', None])
        self.assertEqual(hsts('MAX-AGE="31536000"; INCLUDESUBDOMAINS; PRELOAD'), ['same', 'info', None])
        self.assertEqual(hsts('max-age = 300; includeSubDomains; preload'), ['differs', 'warn', 'hsts-weaker'], 'a much shorter max-age')
        # An old header no browser applies is no policy to lose.
        self.assertEqual(hsts('max-age=31536000', self.side(hsts='max-age=31536000; max-age=0')), ['same', 'info', 'hsts-new'])
        result = sos.compare_sides(old, self.side(ip='192.0.2.2', hsts='includeSubDomains'), now)
        text = sos.render_compare(NAME, '/', old, self.side(ip='192.0.2.2', hsts='includeSubDomains'), result, width=160, now=now)
        self.assertIn('not a valid header', text)

    def test_certificate_names_side_by_side(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        wild, multi = fixture_cert('cli_private_wild.pem'), fixture_cert('rsa_multi_san.pem')
        self.assertEqual(sos.cert_names_text(wild), '*.wild.example.net, wild.example.net')
        many = sos.cert_names_text(multi)
        self.assertEqual(many, '%s +2' % ', '.join([multi.subject_cn] + [n for n in multi.hostnames if n != multi.subject_cn][:2]),
                         'the CN first, three names, then +N')
        result = sos.compare_sides(self.side(cert=wild, covers=True, trusted=True), self.side(cert=multi, covers=False, trusted=True), now)
        names = next(f for f in result['fields'] if f['key'] == 'cert_subject')
        self.assertEqual([names['old'], names['new'], names['same'], names['severity']], [sos.cert_names_text(wild), many, False, 'info'])
        self.assertEqual([f['key'] for f in result['fields']][8:], ['cert_subject', 'cert_covers', 'cert_trusted', 'cert_issuer',
                                                                     'cert_expires', 'cert_sha256'])
        text = sos.render_compare(NAME, '/', self.side(cert=wild, covers=True, trusted=True),
                                  self.side(ip='192.0.2.2', cert=multi, covers=False, trusted=True), result, width=200, now=now)
        line = next(l for l in text.splitlines() if l.strip().startswith('cert names'))
        self.assertIn('*.wild.example.net, wild.example.net', line)
        self.assertIn(many, line)
        self.assertTrue(line.rstrip().endswith('differs'), line)

    def test_neither_server_answering_is_unreachable_not_broken(self):
        now = datetime(2026, 9, 28, tzinfo=timezone.utc)
        down = dict(status=None, failure='TIMEOUT', detail='no answer in 3s')
        result = sos.compare_sides(self.side(**down), self.side(ip='192.0.2.2', **down), now)
        self.assertEqual(result['verdict'], 'unreachable')
        self.assertEqual([(f['key'], f['severity'], f['note']) for f in result['fields']], [('reach', 'warn', 'both-unreachable')])
        text = sos.render_compare(NAME, '/', self.side(**down), self.side(ip='192.0.2.2', **down), result, width=160, now=now)
        self.assertIn('UNREACHABLE: Neither server answered', text)
        self.assertNotIn('BROKEN', text)
        line = next(l for l in text.splitlines() if l.strip().startswith('reached'))
        self.assertTrue(line.rstrip().endswith('WARNING'), 'the same on both: a warning, never "differs"')
        cert = fixture_cert('cli_private_wild.pem')
        expiring = sos.compare_sides(self.side(cert=cert, covers=True, trusted=True), self.side(cert=cert, covers=True, trusted=True),
                                     cert.not_after.replace(tzinfo=timezone.utc) if cert.not_after.tzinfo is None else cert.not_after)
        text = sos.render_compare(NAME, '/', self.side(cert=cert, covers=True, trusted=True), self.side(cert=cert, covers=True, trusted=True),
                                  expiring, width=160, now=now)
        line = next(l for l in text.splitlines() if l.strip().startswith('cert expires'))
        self.assertTrue(line.rstrip().endswith('WARNING'), line)

    def test_page_title(self):
        self.assertEqual(sos.page_title(b'<TITLE lang=en>\n A &#8212; B &amp; C </title>'), 'A — B & C')
        self.assertEqual(sos.page_title('<title>\xe7</title>'.encode('cp1254'), 'windows-1254'), '\xe7')
        self.assertIsNone(sos.page_title(b'<p>no title</p>'))
        self.assertEqual(len(sos.page_title(b'<title>' + b'x' * 300 + b'</title>')), 200)


class CompareUsageTests(unittest.TestCase):

    def test_usage_errors(self):
        cases = [
            (['--compare', '192.0.2.1', '192.0.2.2', '-n', NAME, '-t', '192.0.2.3'], '--compare does not take -t/--targets'),
            (['--compare', 'old', '192.0.2.2', '-n', NAME], 'two IP addresses'),
            (['--compare', '192.0.2.1', '192.0.2.1', '-n', NAME], 'the same'),
            (['--compare', '192.0.2.1', '192.0.2.2', '-n', NAME, 'b.example.net'], 'exactly one host name'),
            (['--compare', '192.0.2.1', '192.0.2.2'], 'exactly one host name'),
            (['--compare', '192.0.2.1', '192.0.2.2', '-n', NAME, '-p', '443,8443'], 'one port'),
            (['--compare', '192.0.2.1', '192.0.2.2', '-n', NAME, '--path', 'nope'], '--path'),
            (['--compare', '192.0.2.1', '192.0.2.2', '-n', NAME, '--cert', 'x.pem'], '--cert'),
        ]
        for args, message in cases:
            code, _, err = run_main(*args)
            self.assertEqual(code, 2, args)
            self.assertIn(message, err, args)

    def test_a_scan_still_needs_targets(self):
        code, _, err = run_main('-n', NAME)
        self.assertEqual(code, 2)
        self.assertIn('the following arguments are required: -t/--targets', err)


if __name__ == '__main__':
    unittest.main()
