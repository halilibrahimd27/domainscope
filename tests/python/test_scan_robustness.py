"""cli/ssl_origin_scan.py when servers misbehave or cannot be read (stdlib unittest; no network).

Exit 6 when servers could not be read (none at all with --fail-on-needs-update, any with
--fail-on-error), exit 70 with the traceback on a bug, a server that drips its STARTTLS
greeting cut at the timeout, a --private-ca trusted only when OpenSSL verifies the
signature, the chain check without VERIFY_X509_PARTIAL_CHAIN, and --revocation reading the
CRLs of your own certificates only, never following a redirect to another host. Local
servers on 127.0.0.1 and fakes; the suite's fixed clock.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import http.server
import os
import socket
import ssl
import tempfile
import threading
import time
import unittest
from unittest import mock

from test_ssl_origin_scan import FakeNetwork, _Listener, fixed_clock, fixture_cert, run_main, sample_report, sos
from test_ari_revocation import DP, LEAF, NOW, FakeFetch, fixture_bytes, leaf_scan
from test_compare_origins import NAME, HttpsServer


def unreadable_report():
    """Two servers, one refusing the connection and one failing every handshake."""
    network = FakeNetwork({'192.0.2.10': ConnectionRefusedError()},
                          {'192.0.2.11': ssl.SSLError(1, 'handshake failure')})
    with fixed_clock():
        return sos.run_scan([sos.Server('web01', ['192.0.2.10']), sos.Server('web02', ['192.0.2.11'])],
                            sos.build_probe_names(['www.example.com']), [443], timeout=1, workers=2,
                            connect_fn=network.connect_fn, tls_fn=network.tls_fn)


class UncheckedExitTests(unittest.TestCase):
    def run_with(self, report, *flags):
        with mock.patch.object(sos, 'run_scan', return_value=report):
            return run_main('-t', '192.0.2.10', '-n', 'www.example.com', '--no-color', *flags)

    def test_nothing_read_is_never_a_finished_rollout(self):
        report = unreadable_report()
        self.assertEqual(len(report.unread_servers()), 2)
        code, _, err = self.run_with(report, '--fail-on-needs-update')
        self.assertEqual(code, sos.EXIT_UNCHECKED)
        self.assertEqual(code, 6)
        self.assertIn('no server could be read', err)
        self.assertEqual(self.run_with(report)[0], sos.EXIT_OK)  # no flag: a report, exit 0
        self.assertEqual(self.run_with(report, '--fail-on-error', '-q')[0], sos.EXIT_UNCHECKED)
        self.assertEqual(self.run_with(report, '--fail-on-needs-update', '-q')[2], '')  # -q: silent

    def test_fail_on_error_counts_any_server_and_comes_after_needs_update(self):
        report = sample_report()  # one server refuses, one fails its handshakes, one needs the cert
        unread = sorted(s.server.name for s in report.unread_servers())
        self.assertEqual(unread, ['10.0.0.3', 'v6'])
        code, _, err = self.run_with(report, '--fail-on-error')
        self.assertEqual(code, sos.EXIT_UNCHECKED)
        self.assertIn('2 of 7 servers could not be read', err)
        self.assertEqual(self.run_with(report, '--fail-on-error', '--fail-on-needs-update', '-q')[0],
                         sos.EXIT_NEEDS_UPDATE)
        # some read, some not: --fail-on-needs-update alone keeps its meaning
        self.assertEqual(self.run_with(report, '--fail-on-needs-update', '-q')[0], sos.EXIT_NEEDS_UPDATE)

    def test_a_server_that_was_read_is_not_unread(self):
        self.assertEqual(leaf_scan().unread_servers(), [])

    def test_not_with_compare(self):
        code, _, err = run_main('--compare', '192.0.2.1', '192.0.2.2', '-n', 'www.example.com', '--fail-on-error')
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn('--fail-on-error', err)


class InternalErrorTests(unittest.TestCase):
    def test_a_bug_exits_70_with_the_traceback_and_no_webhook_secret(self):
        hook = 'https://hooks.example.com/services/T0000/B0000/' + 'S3cr3tT0ken' * 2
        with mock.patch.object(sos, 'run_scan', side_effect=RuntimeError('failed near ' + hook)):
            code, out, err = run_main('-t', '192.0.2.10', '-n', 'www.example.com', '--notify', hook,
                                      '--notify-always', '-q')
        self.assertEqual(code, sos.EXIT_INTERNAL_ERROR)
        self.assertEqual(code, 70)
        self.assertIn('Traceback', err)
        self.assertIn('ssl_origin_scan.py: internal error: RuntimeError: failed near', err)
        self.assertNotIn('S3cr3tT0ken', err)

    def test_a_bug_in_bundle_check_is_70_not_a_failed_check(self):
        with mock.patch.object(sos, '_run_bundle', side_effect=KeyError('x')):
            code, _, err = run_main('bundle-check', 'some.pem')
        self.assertEqual(code, 70)
        self.assertIn("internal error: KeyError: 'x'", err)


class ReportPathTests(unittest.TestCase):
    def test_json_and_csv_on_one_file_are_refused_before_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            same = os.path.join(tmp, 'report')
            with mock.patch.object(sos, 'run_scan', side_effect=AssertionError('must not scan')):
                code, _, err = run_main('-t', '192.0.2.10', '-n', 'www.example.com', '--json', same, '--csv', same)
            self.assertEqual(os.listdir(tmp), [])
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn('name the same file', err)


class DripServer(_Listener):
    """Sends an SMTP greeting one byte every 0.3 s: no single read ever times out."""

    def handle(self, conn: socket.socket) -> None:
        for byte in b'220-mail.example.com ESMTP slow\r\n' * 4 + b'220 ready\r\n':
            if self._stop.is_set():
                return
            conn.sendall(bytes([byte]))
            time.sleep(0.3)


class StartTlsDeadlineTests(unittest.TestCase):
    def test_a_dripping_greeting_is_cut_at_the_timeout(self):
        server = DripServer()
        try:
            started = time.monotonic()
            result = sos.TlsProber()('127.0.0.1', server.port, None, 1.0, sos.PROTO_SMTP)
            elapsed = time.monotonic() - started
        finally:
            server.close()
        self.assertEqual(result.status, sos.TIMEOUT, result.error)
        self.assertLess(elapsed, 2.0)

    def test_the_socket_keeps_its_timeout_after_a_read(self):
        left, right = socket.socketpair()
        try:
            left.settimeout(4.0)
            right.sendall(b'220 ready\r\n')
            channel = sos._PlainChannel(left, sos.PROTO_SMTP)
            self.assertEqual(channel.reply(), (220, ['ready']))
            self.assertEqual(left.gettimeout(), 4.0)
        finally:
            left.close()
            right.close()


class PrivateCaTrustTests(unittest.TestCase):
    def test_the_issuer_s_name_alone_never_makes_a_certificate_trusted(self):
        # The same DN on another key, and a leaf whose authority key id is gone: the names
        # match (issued_by), but the signature is the other key's, which OpenSSL checks.
        server = HttpsServer('cli_private_wild', '127.0.0.1')
        try:
            cert = fixture_cert('cli_private_wild.pem')
            no_aki = cert.__class__(**dict(cert.__dict__, authority_key_id=None))
            impostor = fixture_cert('cli_private_ca_rekeyed.pem')
            self.assertTrue(sos.issued_by(no_aki, impostor))
            with fixed_clock():
                trusted, detail = sos._verify_side('127.0.0.1', server.port, NAME, 3, no_aki, [impostor])
                real = sos._verify_side('127.0.0.1', server.port, NAME, 3, cert,
                                        [fixture_cert('cli_private_ca.pem')])
        finally:
            server.close()
        self.assertFalse(trusted)
        self.assertNotIn('--private-ca', detail)
        self.assertEqual(real, (True, 'issued by a --private-ca'))

    def test_the_chain_check_needs_a_root(self):
        real = ssl.create_default_context
        partial = getattr(ssl, 'VERIFY_X509_PARTIAL_CHAIN', 0x80000)

        def with_partial_chain(*args, **kwargs):
            context = real(*args, **kwargs)
            context.verify_flags |= partial  # Python 3.13's default
            return context

        with mock.patch.object(sos.ssl, 'create_default_context', side_effect=with_partial_chain):
            context = sos.verify_context(True)
        self.assertFalse(context.verify_flags & partial)
        self.assertTrue(sos.private_ca_context([fixture_cert('cli_private_ca.pem')]).verify_flags & partial)


class RevocationScopeTests(unittest.TestCase):
    def test_only_your_certificates_have_their_crl_read(self):
        report = leaf_scan()
        self.assertEqual(sos.revocation_candidates(report), {LEAF.sha256})  # no trust check: hosted
        report.trust_checked = True
        for row in report.results:
            row.trusted = False  # this machine does not trust what is served
        self.assertEqual(sos.revocation_candidates(report), set())
        fetch = FakeFetch({DP: (200, {}, fixture_bytes('crl_empty.der'))})
        status = sos.check_certificate_status(report, revocation=True,
                                              revocation_checker=sos.RevocationChecker(fetch=fetch, now=lambda: NOW))
        self.assertEqual(fetch.calls, [])
        self.assertEqual(status[LEAF.sha256]['revocation']['error'], 'not-checked')
        self.assertIn('neither your new certificate', sos._REVOCATION_WHY['not-checked'])
        for row in report.results:
            if row.probe == sos.PROBE_SNI:
                row.trusted = True
        self.assertEqual(sos.revocation_candidates(report), {LEAF.sha256})

    def test_a_redirect_to_another_host_is_not_followed(self):
        body = fixture_bytes('crl_empty.der')

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                if self.path == '/moved':
                    self.send_response(302)
                    self.send_header('Location', '/crl')
                    self.end_headers()
                elif self.path == '/away':
                    self.send_response(302)
                    self.send_header('Location', 'http://localhost:%d/crl' % self.server.server_address[1])
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header('Content-Length', str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = 'http://127.0.0.1:%d' % server.server_address[1]
            with mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'}):
                self.assertEqual(sos.http_get(base + '/moved', 5)[2], body)
                with self.assertRaises(sos.StatusFetchError) as caught:
                    sos.http_get(base + '/away', 5)
            self.assertEqual((caught.exception.code, caught.exception.status), ('redirect', 302))
        finally:
            server.shutdown()
            server.server_close()


if __name__ == '__main__':
    unittest.main()
