"""STARTTLS endpoints and the --tls-audit of cli/ssl_origin_scan.py.

Minimal SMTP, IMAP and POP3 responders on 127.0.0.1 threads speak the plain-text part and then
TLS with the fixture certificates (tests/fixtures/bundle_leaf.pem, starttls_ec_leaf.pem); FTP,
LDAP, XMPP and PostgreSQL are checked over a socket pair up to where TLS starts. The audit runs
once with a fake handshake (every outcome, the fleet summary, the JSON) and once against local
servers: the version-pinning and cipher tests skip themselves where the local OpenSSL / LibreSSL
cannot offer a version or a suite.

Run from the repository root:

    python3 -m unittest discover -s tests/python -p 'test_starttls_audit.py' -v
"""

from __future__ import annotations

import json
import socket
import ssl
import threading
import unittest
import warnings
from datetime import datetime, timezone
from typing import Callable, Dict, List, Optional, Tuple

from test_ssl_origin_scan import FIXTURES, _Listener, fixture_cert, run_main, sos

NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)
RSA_LEAF = 'bundle_leaf'        # RSA 2048: www.example.com, example.com
EC_LEAF = 'starttls_ec_leaf'    # EC P-256, self-signed: the same names (gen_starttls_fixtures.sh)


def _context(*fixtures: str, minimum: Optional[str] = None, maximum: Optional[str] = None,
             ciphers: Optional[str] = None) -> ssl.SSLContext:
    """A server context with one or several fixture certificates (one per key type)."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    for name in fixtures:
        context.load_cert_chain(str(FIXTURES / (name + '.pem')), str(FIXTURES / (name + '.key')))
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        if minimum:
            context.minimum_version = getattr(ssl.TLSVersion, minimum)
        if maximum:
            context.maximum_version = getattr(ssl.TLSVersion, maximum)
    for spec in ((ciphers or 'ALL') + ':@SECLEVEL=0', ciphers or 'ALL'):
        try:
            context.set_ciphers(spec)
            break
        except ssl.SSLError:
            continue
    return context


def _recv_line(conn: socket.socket) -> str:
    data = b''
    while not data.endswith(b'\n'):
        chunk = conn.recv(1)
        if not chunk:
            raise OSError('closed')
        data += chunk
    return data.decode('ascii').rstrip('\r\n')


class TlsResponder(_Listener):
    """TLS from the first byte with ``context``, or after the plain-text part of ``protocol``
    (smtp, imap, pop3); ``offer=False``: the server does not offer STARTTLS."""

    def __init__(self, context: ssl.SSLContext, protocol: str = 'tls', offer: bool = True) -> None:
        self.context = context
        self.protocol = protocol
        self.offer = offer
        self.commands = []  # type: List[str]
        super().__init__()

    def _plain(self, conn: socket.socket) -> bool:
        send = conn.sendall
        if self.protocol == 'smtp':
            send(b'220-mail.example.com ESMTP test\r\n220 ready\r\n')
            self.commands.append(_recv_line(conn))
            send(b'250-mail.example.com\r\n250-PIPELINING\r\n'
                 + (b'250-STARTTLS\r\n' if self.offer else b'') + b'250 8BITMIME\r\n')
            command = _recv_line(conn)
            self.commands.append(command)
            if command != 'STARTTLS':
                send(b'502 5.5.1 unknown command\r\n')
                return False
            send(b'220 2.0.0 Ready to start TLS\r\n')
        elif self.protocol == 'imap':
            send(b'* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n')
            command = _recv_line(conn)
            self.commands.append(command)
            tag = command.split(' ', 1)[0]
            if not self.offer:
                send(tag.encode('ascii') + b' BAD STARTTLS is not available\r\n')
                return False
            send(b'* CAPABILITY IMAP4rev1\r\n' + tag.encode('ascii') + b' OK Begin TLS now\r\n')
        elif self.protocol == 'pop3':
            send(b'+OK POP3 ready\r\n')
            self.commands.append(_recv_line(conn))
            if not self.offer:
                send(b'-ERR unknown command\r\n')
                return False
            send(b'+OK Begin TLS negotiation\r\n')
        return True

    def handle(self, conn: socket.socket) -> None:
        if self.protocol != 'tls' and not self._plain(conn):
            return
        tls = self.context.wrap_socket(conn, server_side=True)
        try:
            tls.recv(1)  # until the client hangs up
        finally:
            tls.close()


def _scan_json(*args: str) -> Tuple[int, dict, str]:
    code, out, err = run_main(*(args + ('--json', '-', '-q')))
    return code, json.loads(out) if out.strip() else {}, err


class ProtocolSyntaxTests(unittest.TestCase):
    def test_the_protocol_follows_the_port(self):
        self.assertEqual({port: sos.endpoint_protocol(port) for port in (25, 587, 143, 110, 21,
                                                                         389, 5222, 5432)},
                         {25: 'smtp', 587: 'smtp', 143: 'imap', 110: 'pop3', 21: 'ftp',
                          389: 'ldap', 5222: 'xmpp', 5432: 'postgres'})
        # implicit TLS: TLS from the first byte, like 443
        for port in (443, 465, 993, 995, 636, 990, 5223, 8443):
            self.assertEqual(sos.endpoint_protocol(port), 'tls', port)

    def test_ports_name_a_protocol_for_any_number(self):
        ports = sos.parse_ports('443,2525/smtp,5433-5434/postgresql,25/tls,993')
        self.assertEqual(ports, [443, 2525, 5433, 5434, 25, 993])
        self.assertEqual(sos.port_protocols(ports), {2525: 'smtp', 5433: 'postgres',
                                                     5434: 'postgres', 25: 'tls'})
        overrides = sos.port_protocols(ports)
        self.assertEqual([sos.endpoint_protocol(p, overrides) for p in (2525, 25, 587, 993)],
                         ['smtp', 'tls', 'smtp', 'tls'])
        # written twice: the protocol written wins, wherever it stands
        self.assertEqual(sos.port_protocols(sos.parse_ports('2525,2525/smtp')), {2525: 'smtp'})
        with self.assertRaisesRegex(sos.UsageError, "unknown protocol 'gopher'"):
            sos.parse_ports('70/gopher')
        with self.assertRaises(sos.UsageError):
            sos.parse_ports('smtp')

    def test_a_target_port_names_its_protocol(self):
        inventory = sos.parse_target_tokens(
            '203.0.113.10:2525/smtp web01=198.51.100.7:5433/pgsql [2001:db8::1]:1430/IMAP '
            'mail.example.net:2526/smtp 203.0.113.0/30 2001:db8::1/128')
        protocols = {}  # type: Dict[str, List[Tuple[int, str]]]
        for server in inventory.servers:
            for key, spec in server.ports.items():
                protocols[server.name + ' ' + key] = [
                    (int(port), sos.endpoint_protocol(port)) for port in spec if port is not None]
        self.assertEqual(protocols, {
            '203.0.113.10 203.0.113.10': [(2525, 'smtp')],
            'web01 198.51.100.7': [(5433, 'postgres')],
            '2001:db8::1 2001:db8::1': [(1430, 'imap')],
            'mail.example.net mail.example.net': [(2526, 'smtp')]})
        # the CIDRs keep their slash: 203.0.113.0/30 is two addresses, /128 one
        self.assertEqual(sorted(s.name for s in inventory.servers),
                         ['2001:db8::1', '203.0.113.1', '203.0.113.10', '203.0.113.2',
                          'mail.example.net', 'web01'])
        for bad, why in (('203.0.113.10:2525/gopher', 'unknown protocol'),
                         ('203.0.113.10:99999/smtp', 'outside 1-65535'),
                         ('=203.0.113.10:25/smtp', 'expected NAME=IP')):
            with self.assertRaisesRegex(sos.UsageError, why):
                sos.parse_target_tokens(bad)

    def test_inventory_ports_on_starttls_ports_are_no_plain_port_warning(self):
        inventory = sos.parse_inventory('mail01 10.0.0.25 ports=25,587,993,143\n'
                                        'web01 10.0.0.1 ports=80', 'x.txt')
        self.assertEqual([(w.line, w.reason) for w in inventory.warnings], [(2, 'plainPorts')])

    def test_compare_refuses_a_starttls_port(self):
        code, _out, err = run_main('--compare', '203.0.113.10', '203.0.113.11', '-n',
                                   'www.example.com', '-p', '2525/smtp')
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn('without a STARTTLS protocol', err)

    def test_run_scan_hands_the_protocol_to_the_prober(self):
        seen = []  # type: List[Tuple[int, str]]
        lock = threading.Lock()

        def tls_fn(ip: str, port: int, sni: Optional[str], timeout: float,
                   protocol: str = 'tls') -> sos.TlsResult:
            with lock:
                seen.append((port, protocol))
            return sos.TlsResult(der=fixture_cert(RSA_LEAF + '.pem').der, version='TLSv1.2')

        servers = sos.parse_target_tokens('203.0.113.25 203.0.113.26:2525/smtp').servers
        report = sos.run_scan(servers, sos.build_probe_names(['www.example.com']),
                              sos.parse_ports('25,465,5432,1430/imap'),
                              connect_fn=lambda ip, port, timeout: None, tls_fn=tls_fn)
        self.assertEqual(sorted(set(seen)), [(25, 'smtp'), (465, 'tls'), (1430, 'imap'),
                                             (2525, 'smtp'), (5432, 'postgres')])
        doc = sos.report_to_dict(report)
        self.assertEqual({(e['ip'], e['port']): e.get('protocol') for e in doc['endpoints']},
                         {('203.0.113.25', 25): 'smtp', ('203.0.113.25', 465): None,
                          ('203.0.113.25', 5432): 'postgres', ('203.0.113.25', 1430): 'imap',
                          ('203.0.113.26', 2525): 'smtp'})
        self.assertEqual(doc['options']['portProtocols'], {'1430': 'imap'})
        self.assertNotIn('tlsAudit', doc)
        text = sos.render_summary(report)
        self.assertIn('203.0.113.26:2525/smtp', text)
        self.assertIn('203.0.113.25:465\n', text)


class StartTlsNegotiationTests(unittest.TestCase):
    """The plain-text part of each protocol against a scripted server on a socket pair."""

    def converse(self, protocol: str, script: Callable[[socket.socket], None],
                 sni: Optional[str] = 'chat.example.com') -> Optional[Exception]:
        client, server = socket.socketpair()
        client.settimeout(5)
        server.settimeout(5)
        thread = threading.Thread(target=self._run_script, args=(script, server), daemon=True)
        thread.start()
        try:
            sos.starttls(client, protocol, sni)
            return None
        except (sos.StartTlsError, OSError) as exc:
            return exc
        finally:
            thread.join(5)
            client.close()
            server.close()

    @staticmethod
    def _run_script(script: Callable[[socket.socket], None], conn: socket.socket) -> None:
        try:
            script(conn)
        except OSError:
            pass

    def test_ftp_auth_tls(self):
        def ftp(conn: socket.socket) -> None:
            conn.sendall(b'220-Welcome\r\nthis line has no code\r\n220 FTP ready\r\n')
            self.assertEqual(_recv_line(conn), 'AUTH TLS')
            conn.sendall(b'234 AUTH TLS successful\r\n')
        self.assertIsNone(self.converse('ftp', ftp))

        def refused(conn: socket.socket) -> None:
            conn.sendall(b'220 FTP ready\r\n')
            _recv_line(conn)
            conn.sendall(b'500 AUTH not understood\r\n')
        self.assertRegex(str(self.converse('ftp', refused)), r'^FTP: AUTH TLS answered 500')

    def test_ldap_starttls_extended_operation(self):
        def ldap(code: int) -> Callable[[socket.socket], None]:
            def script(conn: socket.socket) -> None:
                request = conn.recv(64)
                self.assertEqual(request[:9], bytes.fromhex('301d02010177188016'))
                self.assertEqual(request[9:], b'1.3.6.1.4.1.1466.20037')
                text = b'' if code == 0 else b'unsupported extended operation'
                inner = (bytes([0x0A, 1, code]) + b'\x04\x00' + bytes([0x04, len(text)]) + text)
                response = b'\x78' + bytes([len(inner)]) + inner
                body = b'\x02\x01\x01' + response
                # OpenLDAP writes the outer length in four bytes
                conn.sendall(b'\x30\x84' + len(body).to_bytes(4, 'big') + body)
            return script
        self.assertIsNone(self.converse('ldap', ldap(0)))
        self.assertEqual(str(self.converse('ldap', ldap(2))),
                         'LDAP: StartTLS refused (result code 2: unsupported extended operation)')

    def test_xmpp_client_stream(self):
        def xmpp(offer: bool) -> Callable[[socket.socket], None]:
            def script(conn: socket.socket) -> None:
                header = conn.recv(4096).decode('ascii')
                self.assertIn("to='chat.example.com'", header)
                features = ("<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/>"
                            "</starttls>" if offer else "<mechanisms/>")
                conn.sendall(("<?xml version='1.0'?><stream:stream id='1' version='1.0'>"
                              "<stream:features>%s</stream:features>" % features).encode('ascii'))
                if offer:
                    self.assertIn(b'<starttls', conn.recv(4096))
                    conn.sendall(b"<proceed xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>")
            return script
        self.assertIsNone(self.converse('xmpp', xmpp(True)))
        self.assertEqual(str(self.converse('xmpp', xmpp(False))),
                         'XMPP: the server does not offer STARTTLS')

    def test_postgres_ssl_request(self):
        def postgres(answer: bytes) -> Callable[[socket.socket], None]:
            def script(conn: socket.socket) -> None:
                self.assertEqual(conn.recv(8), bytes.fromhex('0000000804d2162f'))
                conn.sendall(answer)
            return script
        self.assertIsNone(self.converse('postgres', postgres(b'S')))
        self.assertEqual(str(self.converse('postgres', postgres(b'N'))),
                         'PostgreSQL: the server does not accept SSL connections (ssl = off)')

    def test_data_after_the_go_ahead_and_endless_replies_fail(self):
        def eager(conn: socket.socket) -> None:
            conn.sendall(b'+OK ready\r\n')
            _recv_line(conn)
            conn.sendall(b'+OK go\r\nnot TLS\r\n')
        self.assertEqual(str(self.converse('pop3', eager)),
                         'POP3: data after the go-ahead for TLS')

        def chatty(conn: socket.socket) -> None:
            conn.sendall(b'* OK ready\r\n')
            _recv_line(conn)
            for _ in range(2000):
                conn.sendall(b'* CAPABILITY IMAP4rev1 IDLE NAMESPACE\r\n')
        self.assertRegex(str(self.converse('imap', chatty)), r'^IMAP: more than \d+ bytes')


class StartTlsScanTests(unittest.TestCase):
    """SMTP, IMAP and POP3 servers on 127.0.0.1: the renewal statuses apply unchanged."""

    @classmethod
    def setUpClass(cls) -> None:
        context = _context(RSA_LEAF)
        cls.servers = {protocol: TlsResponder(context, protocol)
                       for protocol in ('smtp', 'imap', 'pop3')}
        cls.no_starttls = TlsResponder(context, 'smtp', offer=False)

    @classmethod
    def tearDownClass(cls) -> None:
        for server in list(cls.servers.values()) + [cls.no_starttls]:
            server.close()

    def test_mail_servers_are_updated_through_starttls(self):
        targets = ['%s01=127.0.0.1:%d/%s' % (protocol, server.port, protocol)
                   for protocol, server in self.servers.items()]
        code, doc, _err = _scan_json('-t', *targets, '-n', 'www.example.com',
                                     '--cert', str(FIXTURES / (RSA_LEAF + '.pem')))
        self.assertEqual(code, 0)
        self.assertEqual({e['port']: e.get('protocol') for e in doc['endpoints']},
                         {server.port: protocol for protocol, server in self.servers.items()})
        named = [r for r in doc['results'] if r['name'] == 'www.example.com']
        self.assertEqual(sorted((r['port'], r['status']) for r in named),
                         sorted((server.port, 'UPDATED') for server in self.servers.values()))
        self.assertEqual(doc['summary']['serversUpdated'], 3)
        commands = self.servers['smtp'].commands
        self.assertIn('EHLO [127.0.0.1]', commands)  # an address literal (RFC 5321)
        self.assertIn('STARTTLS', commands)
        self.assertIn('STLS', self.servers['pop3'].commands)

    def test_ports_name_the_protocol_and_the_summary_shows_it(self):
        port = self.servers['imap'].port
        code, out, _err = run_main('-t', '127.0.0.1', '-p', '%d/imap' % port, '-n',
                                   'www.example.com', '--no-color')
        self.assertEqual(code, 0)
        self.assertIn('127.0.0.1:%d/imap' % port, out)

    def test_a_server_without_starttls_is_a_handshake_error(self):
        code, doc, _err = _scan_json('-t', '127.0.0.1:%d/smtp' % self.no_starttls.port,
                                     '-n', 'www.example.com')
        self.assertEqual(code, 0)
        row = next(r for r in doc['results'] if r['probe'] == 'sni')
        self.assertEqual((row['status'], row['error']),
                         ('TLS_ERROR', 'SMTP: the server does not offer STARTTLS'))
        self.assertEqual(doc['servers'][0]['status'], 'TLS_ERROR')

    def test_tls_spoken_to_a_starttls_server_fails_cleanly(self):
        # 2525/tls: the scan sends a ClientHello where the server greets in plain text
        code, doc, _err = _scan_json('-t', '127.0.0.1:%d/tls' % self.servers['smtp'].port,
                                     '-n', 'www.example.com', '--timeout', '2')
        self.assertEqual(code, 0)
        row = next(r for r in doc['results'] if r['probe'] == 'sni')
        self.assertIn(row['status'], ('TLS_ERROR', 'TIMEOUT'))


# --- the audit with a fake handshake ------------------------------------------------------------

def _fake_contexts(untestable_versions: Tuple[str, ...] = ('TLSv1.3',),
                   untestable_ciphers: Tuple[str, ...] = ('export', 'des')) -> sos.AuditContexts:
    contexts = sos.AuditContexts.__new__(sos.AuditContexts)
    contexts.library = 'TestSSL 1.0'
    contexts.versions = {v: (None, 'TestSSL 1.0 cannot offer %s' % v.replace('TLSv', 'TLS '))
                         if v in untestable_versions else ('v:' + v, None)
                         for v in sos.AUDIT_VERSIONS}
    contexts.ciphers = {g: (None, 'TestSSL 1.0 has no %s cipher suites' % g)
                        if g in untestable_ciphers else ('c:' + g, None)
                        for g, _spec in sos.WEAK_CIPHER_GROUPS}
    contexts.key_types = {k: ('k:' + k, None) for k, _spec in sos.AUDIT_KEY_TYPES}
    return contexts


def _fake_report(endpoints: List[Tuple[str, int, str, str]]) -> sos.ScanReport:
    """(server, ip, port, protocol) endpoints, each hosting www.example.com (UPDATED)."""
    cert = fixture_cert(RSA_LEAF + '.pem')
    eps, rows, servers = [], [], []
    for server, ip, port, protocol in endpoints:
        eps.append(sos.Endpoint(ip, port, sos.OPEN, protocol=protocol))
        rows.append(sos.ProbeResult(server, ip, port, sos.PROBE_DEFAULT, None, None,
                                    sos.UPDATED, cert=cert))
        rows.append(sos.ProbeResult(server, ip, port, sos.PROBE_SNI, 'www.example.com',
                                    'www.example.com', sos.UPDATED, cert=cert))
        servers.append(sos.Server(server, [ip]))
    eps.append(sos.Endpoint('203.0.113.99', 443, sos.CLOSED))
    rows.append(sos.ProbeResult('closed01', '203.0.113.99', 443, sos.PROBE_CONNECT, None, None,
                                sos.CLOSED))
    eps.append(sos.Endpoint('203.0.113.98', 443, sos.OPEN))
    rows.append(sos.ProbeResult('broken01', '203.0.113.98', 443, sos.PROBE_SNI,
                                'www.example.com', 'www.example.com', sos.TLS_ERROR))
    return sos.ScanReport(servers=servers, probes=sos.build_probe_names(['www.example.com']),
                          ports=[443], new_certs=[cert], endpoints=eps, results=rows,
                          certificates={cert.sha256: cert}, started_at=NOW, finished_at=NOW)


class FakeAuditTests(unittest.TestCase):
    # what each fake endpoint accepts: versions, weak families, key types; 'slow' times out
    PROFILES = {
        ('203.0.113.10', 443): ({'TLSv1.0', 'TLSv1.1', 'TLSv1.2'}, {'3des'}, {'RSA', 'ECDSA'}),
        ('203.0.113.11', 443): ({'TLSv1.2'}, set(), {'RSA'}),
        ('203.0.113.25', 25): ({'TLSv1.2'}, {'rc4'}, {'RSA', 'ECDSA'}),
        ('203.0.113.12', 443): (set(), set(), set()),   # TLS 1.3 only (untestable here)
        ('203.0.113.13', 443): 'slow',
    }

    def attempt(self, ip: str, port: int, protocol: str, sni: Optional[str], context: str,
                timeout: float) -> sos.AuditCheck:
        self.calls.append((ip, port, protocol, sni, context))
        profile = self.PROFILES[(ip, port)]
        if profile == 'slow':
            return sos.AuditCheck(sos.AUDIT_FAILED, error='timed out', timed_out=True)
        versions, weak, keys = profile
        kind, _, what = context.partition(':')
        accepted = what in (versions if kind == 'v' else weak if kind == 'c' else keys)
        if not accepted:
            return sos.AuditCheck(sos.AUDIT_REFUSED, error='handshake failure')
        return sos.AuditCheck(sos.AUDIT_ACCEPTED, version=what if kind == 'v' else 'TLSv1.2',
                              cipher={'3des': 'DES-CBC3-SHA', 'rc4': 'RC4-SHA'}.get(what),
                              key_algorithm={'RSA': 'RSA', 'ECDSA': 'EC'}.get(what))

    def setUp(self) -> None:
        self.calls = []  # type: List[Tuple[str, int, str, Optional[str], str]]
        self.report = _fake_report([('web01', '203.0.113.10', 443, 'tls'),
                                    ('web02', '203.0.113.11', 443, 'tls'),
                                    ('mail01', '203.0.113.25', 25, 'smtp'),
                                    ('web03', '203.0.113.12', 443, 'tls'),
                                    ('web04', '203.0.113.13', 443, 'tls')])
        lock = threading.Lock()

        def attempt(*args):  # type: ignore[no-untyped-def]
            with lock:
                return self.attempt(*args)

        self.report.audit = sos.run_tls_audit(self.report, timeout=1, workers=4,
                                              attempt=attempt, contexts=_fake_contexts())

    def test_each_check_and_its_outcome(self):
        audit = {e.label: e for e in self.report.audit.endpoints}
        self.assertEqual(sorted(audit), ['203.0.113.10:443', '203.0.113.11:443',
                                         '203.0.113.12:443', '203.0.113.13:443',
                                         '203.0.113.25:25/smtp', '203.0.113.98:443'])
        web01 = audit['203.0.113.10:443']
        self.assertEqual({v: c.outcome for v, c in web01.versions.items()},
                         {'TLSv1.0': 'accepted', 'TLSv1.1': 'accepted', 'TLSv1.2': 'accepted',
                          'TLSv1.3': 'untested'})
        self.assertEqual(web01.versions['TLSv1.3'].error, 'TestSSL 1.0 cannot offer TLS 1.3')
        self.assertEqual({g: c.outcome for g, c in web01.ciphers.items()},
                         {'null': 'refused', 'anon': 'refused', 'export': 'untested',
                          'rc4': 'refused', 'des': 'untested', '3des': 'accepted'})
        self.assertEqual((web01.legacy_versions, web01.weak_ciphers, web01.key_types_served),
                         (['TLSv1.0', 'TLSv1.1'], ['3des'], ['RSA', 'ECDSA']))
        self.assertEqual(web01.sni, 'www.example.com')
        # STARTTLS endpoints are audited through their protocol
        self.assertTrue(all(call[2] == 'smtp' for call in self.calls if call[1] == 25))
        # TLS 1.3 only: no weak suite, no key-type handshake; a timeout skips the rest
        web03 = audit['203.0.113.12:443']
        self.assertEqual({c.outcome for c in web03.ciphers.values()}, {'refused', 'untested'})
        self.assertEqual({c.outcome for c in web03.key_types.values()}, {'untested'})
        self.assertEqual(len([c for c in self.calls if c[0] == '203.0.113.12']), 3)
        web04 = audit['203.0.113.13:443']
        self.assertEqual(web04.status, 'timeout')
        self.assertEqual(len([c for c in self.calls if c[0] == '203.0.113.13']), 1)
        # no handshake completed in the scan: not audited, never connected to
        self.assertEqual(audit['203.0.113.98:443'].status, 'no-tls')
        self.assertFalse([c for c in self.calls if c[0] in ('203.0.113.98', '203.0.113.99')])

    def test_fleet_summary(self):
        summary = sos.audit_summary(self.report.audit)
        self.assertEqual({k: summary[k] for k in ('endpoints', 'audited', 'notAudited',
                                                  'timedOut', 'acceptingTls10',
                                                  'acceptingTls11')},
                         {'endpoints': 6, 'audited': 5, 'notAudited': 1, 'timedOut': 1,
                          'acceptingTls10': 1, 'acceptingTls11': 1})
        self.assertEqual([(e['servers'], e['versions']) for e in summary['legacyVersions']],
                         [(['web01'], ['TLSv1.0', 'TLSv1.1'])])
        self.assertEqual([(e['port'], e['protocol'], e['groups'], e['ciphers'])
                          for e in summary['weakCiphers']],
                         [(443, 'tls', ['3des'], ['DES-CBC3-SHA']),
                          (25, 'smtp', ['rc4'], ['RC4-SHA'])])
        # web01 and mail01 serve RSA + ECDSA for www.example.com: web02 serves half the pair
        self.assertEqual([(e['servers'], e['served'], e['missing'], e['sni'])
                          for e in summary['oneKeyType']],
                         [(['web02'], 'RSA', 'ECDSA', 'www.example.com')])

    def test_json_section_and_summary_text(self):
        doc = json.loads(sos.render_json(self.report))
        self.assertTrue(doc['options']['tlsAudit'])
        section = doc['tlsAudit']
        self.assertEqual(section['library'], 'TestSSL 1.0')
        self.assertEqual(section['untestable'],
                         {'versions': {'TLSv1.3': 'TestSSL 1.0 cannot offer TLS 1.3'},
                          'weakCiphers': {'export': 'TestSSL 1.0 has no export cipher suites',
                                          'des': 'TestSSL 1.0 has no des cipher suites'},
                          'keyTypes': {}})
        entry = next(e for e in section['endpoints'] if e['port'] == 25)
        self.assertEqual((entry['protocol'], entry['servers'], entry['status']),
                         ('smtp', ['mail01'], 'done'))
        self.assertEqual(entry['weakCiphers']['rc4'],
                         {'outcome': 'accepted', 'version': 'TLSv1.2', 'cipher': 'RC4-SHA',
                          'certSha256': None, 'keyAlgorithm': None, 'error': None})
        self.assertEqual(entry['keyTypesServed'], ['RSA', 'ECDSA'])
        # the readers of the web app still take the report (same major version)
        self.assertEqual(doc['version'].split('.')[0], '1')
        text = sos.render_tls_audit(self.report.audit)
        self.assertIn('TLS audit - 5 of 6 open endpoint(s) checked with TestSSL 1.0', text)
        self.assertIn('Still accepting TLS 1.0 / 1.1: 1 endpoint(s)', text)
        self.assertIn('203.0.113.10:443  web01  TLS 1.0, TLS 1.1', text)
        self.assertIn('203.0.113.25:25/smtp  mail01  RC4 (RC4-SHA)', text)
        self.assertIn('203.0.113.11:443  web02  RSA only, no ECDSA certificate for '
                      'www.example.com', text)
        self.assertIn('cannot offer: TLS 1.3 (versions); export grade, DES (cipher suites)', text)
        self.assertIn('1 endpoint(s) not audited', text)
        self.assertIn('1 endpoint(s) timed out', text)
        full = sos.render_tls_audit(self.report.audit, show_all=True)
        self.assertIn('203.0.113.10:443  web01  versions: TLS 1.0, TLS 1.1, TLS 1.2 | weak: 3des '
                      '| keys: RSA, ECDSA', full)

    def test_a_clean_fleet_says_so(self):
        self.PROFILES = {('203.0.113.10', 443): ({'TLSv1.2', 'TLSv1.3'}, set(), {'RSA'})}
        self.calls = []
        report = _fake_report([('web01', '203.0.113.10', 443, 'tls')])
        report.audit = sos.run_tls_audit(report, attempt=self.attempt,
                                         contexts=_fake_contexts(untestable_versions=()))
        text = sos.render_tls_audit(report.audit)
        self.assertIn('No endpoint accepts TLS 1.0 or TLS 1.1', text)
        self.assertIn('No endpoint accepts the weak cipher suites tried', text)
        self.assertIn('Every RSA + ECDSA pair is served whole', text)


# --- the audit against local servers -------------------------------------------------------------

def _loopback(server_context: ssl.SSLContext, client: sos.AuditContext) -> bool:
    """Can this Python complete a handshake with itself with these two contexts?"""
    context, _why = client
    if context is None:
        return False
    server = TlsResponder(server_context)
    try:
        check = sos.audit_handshake('127.0.0.1', server.port, 'tls', None, context, 5)
        return check.outcome == sos.AUDIT_ACCEPTED
    finally:
        server.close()


class LocalAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contexts = sos.AuditContexts()

    def audit(self, *targets: str, extra: Tuple[str, ...] = ()) -> dict:
        code, doc, err = _scan_json('-t', *targets, '-n', 'www.example.com', '--tls-audit',
                                    *extra)
        self.assertEqual(code, 0, err)
        return doc['tlsAudit']

    def test_tls12_only_server(self):
        server = TlsResponder(_context(RSA_LEAF, minimum='TLSv1_2', maximum='TLSv1_2'))
        try:
            section = self.audit('127.0.0.1:%d' % server.port)
        finally:
            server.close()
        versions = {v: c['outcome'] for v, c in section['endpoints'][0]['versions'].items()}
        self.assertEqual(versions['TLSv1.2'], 'accepted')
        for label in ('TLSv1.0', 'TLSv1.1', 'TLSv1.3'):
            expected = 'refused' if self.contexts.versions[label][0] is not None else 'untested'
            self.assertEqual(versions[label], expected, label)
            if expected == 'untested':  # said clearly, with the library's name
                self.assertIn(label, section['untestable']['versions'])
        self.assertEqual(section['summary']['legacyVersions'], [])
        self.assertEqual(section['endpoints'][0]['keyTypesServed'], ['RSA'])

    def test_tls10_server_is_listed(self):
        context = _context(RSA_LEAF, minimum='TLSv1', maximum='TLSv1_2')
        if not _loopback(_context(RSA_LEAF, minimum='TLSv1', maximum='TLSv1'),
                         self.contexts.versions['TLSv1.0']):
            self.skipTest('%s cannot complete a TLS 1.0 handshake with itself' % ssl.OPENSSL_VERSION)
        server = TlsResponder(context)
        try:
            section = self.audit('127.0.0.1:%d' % server.port)
        finally:
            server.close()
        self.assertEqual(section['summary']['acceptingTls10'], 1)
        self.assertEqual(section['endpoints'][0]['versions']['TLSv1.0']['version'], 'TLSv1.0')

    def test_tls13_is_tested_or_said_untestable(self):
        server = TlsResponder(_context(RSA_LEAF))
        try:
            section = self.audit('127.0.0.1:%d' % server.port)
        finally:
            server.close()
        check = section['endpoints'][0]['versions']['TLSv1.3']
        if getattr(ssl, 'HAS_TLSv1_3', False) and self.contexts.versions['TLSv1.3'][0] is not None:
            self.assertEqual(check['outcome'], 'accepted')
        else:
            self.assertEqual(check['outcome'], 'untested')
            self.assertIn('cannot offer TLS 1.3', check['error'])

    def test_anonymous_suites_are_weak(self):
        client = self.contexts.ciphers['anon']
        server_context = _context(RSA_LEAF, ciphers='ALL')  # ALL holds the anonymous suites
        if not _loopback(server_context, client):
            self.skipTest('%s cannot agree on an anonymous suite with itself' % ssl.OPENSSL_VERSION)
        server = TlsResponder(server_context)
        try:
            section = self.audit('127.0.0.1:%d' % server.port)
        finally:
            server.close()
        # LibreSSL's ALL holds RC4 and 3DES suites as well: listed with them
        self.assertIn('anon', section['summary']['weakCiphers'][0]['groups'])
        self.assertTrue(section['summary']['weakCiphers'][0]['ciphers'])

    def test_rsa_and_ecdsa_pair_served_by_halves(self):
        dual_context = _context(RSA_LEAF, EC_LEAF, maximum='TLSv1_2')
        if not (_loopback(dual_context, self.contexts.key_types['RSA'])
                and _loopback(dual_context, self.contexts.key_types['ECDSA'])):
            self.skipTest('%s cannot serve an RSA and an ECDSA certificate side by side'
                          % ssl.OPENSSL_VERSION)
        dual = TlsResponder(dual_context)
        single = TlsResponder(_context(RSA_LEAF, maximum='TLSv1_2'))
        mail = TlsResponder(dual_context, 'smtp')
        try:
            section = self.audit('dual=127.0.0.1:%d' % dual.port, 'single=127.0.0.1:%d' % single.port,
                                 'mail=127.0.0.1:%d/smtp' % mail.port)
        finally:
            for server in (dual, single, mail):
                server.close()
        served = {e['servers'][0]: e['keyTypesServed'] for e in section['endpoints']}
        self.assertEqual(served, {'dual': ['RSA', 'ECDSA'], 'single': ['RSA'],
                                  'mail': ['RSA', 'ECDSA']})
        halves = section['summary']['oneKeyType']
        self.assertEqual([(e['servers'], e['served'], e['missing']) for e in halves],
                         [(['single'], 'RSA', 'ECDSA')])
        keys = section['endpoints'][0]['keyTypes']
        self.assertEqual((keys['RSA']['keyAlgorithm'], keys['ECDSA']['keyAlgorithm']),
                         ('RSA', 'EC'))
        self.assertEqual(keys['ECDSA']['certSha256'], fixture_cert(EC_LEAF + '.pem').sha256)


if __name__ == '__main__':
    unittest.main()
