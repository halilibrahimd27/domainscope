"""--compare OLD_IP NEW_IP -n NAME of cli/ssl_origin_scan.py (stdlib unittest; no network).

Two local HTTPS servers on the same port of 127.0.0.1 and 127.0.0.2 (the loopback network)
stand in for the old and the new server of a name: one TLS connection with SNI and one GET
over it per address, then a verifying handshake. The certificates are the test-only fixtures
(cli_private_wild.pem, issued by cli_private_ca.pem; rsa_multi_san.pem for a wrong name).

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import tempfile
import unittest
from datetime import datetime, timezone
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

    def compare(self, port: int, *extra: str) -> Tuple[int, str, str]:
        return run_main('--compare', '127.0.0.1', '127.0.0.2', '-n', NAME, '-p', str(port), '--timeout', '3',
                        '--private-ca', PRIVATE_CA, '--no-color', *extra)

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
        for server in (old, new):
            self.assertEqual(server.sni, [NAME, NAME], 'the GET connection and the verifying handshake')
            self.assertEqual(len(server.requests), 1, 'one GET, over the first TLS connection')
            request = server.requests[0].decode('latin-1')
            self.assertTrue(request.startswith('GET /healthz?x=1 HTTP/1.1\r\n'), request)
            self.assertIn('\r\nHost: %s:%d\r\n' % (NAME, old.port), request)
            self.assertIn('\r\nAccept-Encoding: identity\r\n', request)

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
