"""The --tls-audit follow-ups of cli/ssl_origin_scan.py (ROADMAP P1.10 / P1.11): RDP on 3389,
the --profile port presets, the certificate chain each endpoint sends (trusted for the name,
complete, in order) and the fleet check of one name served with different certificates of one
key type - the pool member a renewal missed.

The chain is read from the bundle-check PKI (tests/fixtures/bundle_*: root, intermediate, an RSA
leaf with an AIA URL) and the chainfix one (an intermediate that expires before its leaf); local
servers on 127.0.0.1 threads send it in every order, and a verifying client trusting the test root
stands in for this machine's store. Python 3.8 and 3.9 cannot read what a server sends: the
assertions that need it say so and the rest still run.

Run from the repository root:

    python3 -m unittest discover -s tests/python -p 'test_tls_audit_fleet.py' -v
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from typing import Dict, List, Optional, Sequence, Tuple
from unittest import mock

from test_ssl_origin_scan import FIXTURES, fixture_cert, run_main, sos
from test_starttls_audit import TlsResponder, _context, _fake_contexts, _scan_json

NOW = datetime(2026, 10, 8, 12, 0, 0, tzinfo=timezone.utc)


def _certs(name: str) -> List[sos.CertInfo]:
    certs, _warnings = sos.load_certificates((FIXTURES / name).read_bytes())
    return certs


LEAF = fixture_cert('bundle_leaf.pem')            # RSA, www.example.com, AIA caIssuers
INTER = _certs('bundle_inter.pem')[0]
ROOT = _certs('bundle_root.pem')[0]
OTHER = fixture_cert('bundle_ec_leaf.pem')        # api.example.net, the same intermediate
SELF_SIGNED = fixture_cert('starttls_ec_leaf.pem')


def ders(*certs: sos.CertInfo) -> List[bytes]:
    return [c.der for c in certs]


# --- RDP -----------------------------------------------------------------------------------------

RDP_CONFIRM = bytes.fromhex('030000130ed00000123400')   # TPKT (19 bytes), X.224 Connection Confirm


def rdp_reply(kind: Optional[int], value: int = 0) -> bytes:
    """An X.224 Connection Confirm with an RDP_NEG_RSP (kind 2) or RDP_NEG_FAILURE (kind 3); None:
    none at all (a server that knows only Standard RDP Security)."""
    if kind is None:
        return bytes.fromhex('0300000b06d00000123400')
    return RDP_CONFIRM + bytes([kind, 0]) + (8).to_bytes(2, 'little') + value.to_bytes(4, 'little')


class RdpResponder(TlsResponder):
    """An RDP server: the X.224 exchange, then TLS with ``context`` when ``reply`` selects it."""

    def __init__(self, context: ssl.SSLContext, reply: bytes) -> None:
        self.reply = reply
        self.requests = []  # type: List[bytes]
        super().__init__(context, 'rdp')

    def _plain(self, conn: socket.socket) -> bool:
        request = b''
        while len(request) < 19:
            chunk = conn.recv(19 - len(request))
            if not chunk:
                return False
            request += chunk
        self.requests.append(request)
        conn.sendall(self.reply)
        return self.reply[11:12] == b'\x02' and self.reply[15:19] != b'\x00' * 4


class RdpTests(unittest.TestCase):
    def test_3389_speaks_rdp_and_the_request_asks_for_tls_or_credssp(self):
        self.assertEqual(sos.endpoint_protocol(3389), 'rdp')
        self.assertEqual(sos.parse_protocol('ms-wbt-server', 'x'), 'rdp')
        self.assertEqual(sos.PROTOCOL_LABELS['rdp'], 'RDP')
        # TPKT (19 bytes), X.224 Connection Request, RDP_NEG_REQ with PROTOCOL_SSL | PROTOCOL_HYBRID
        self.assertEqual(sos._RDP_REQUEST.hex(), '030000130ee000000000000100080003000000')
        # an inventory's ports=3389 is no "carries no TLS" warning any more
        inventory = sos.parse_inventory('ts01 10.0.0.30 ports=3389\nweb01 10.0.0.1 ports=22', 'x.txt')
        self.assertEqual([(w.line, w.reason) for w in inventory.warnings], [(2, 'plainPorts')])

    def converse(self, reply: bytes) -> Optional[Exception]:
        client, server = socket.socketpair()
        client.settimeout(5)
        server.settimeout(5)

        def script() -> None:
            try:
                request = b''
                while len(request) < 19:
                    request += server.recv(19 - len(request))
                server.sendall(reply)
            except OSError:
                pass

        thread = threading.Thread(target=script, daemon=True)
        thread.start()
        try:
            sos.starttls(client, 'rdp', 'ts.example.com')
            return None
        except (sos.StartTlsError, OSError) as exc:
            return exc
        finally:
            thread.join(5)
            client.close()
            server.close()

    def test_the_negotiation(self):
        for selected in (1, 2, 8):
            self.assertIsNone(self.converse(rdp_reply(2, selected)), selected)
        self.assertEqual(str(self.converse(rdp_reply(2, 0))),
                         'RDP: the server chose Standard RDP Security (no TLS)')
        self.assertEqual(str(self.converse(rdp_reply(3, 2))),
                         'RDP: the server refused TLS (SSL_NOT_ALLOWED_BY_SERVER)')
        self.assertEqual(str(self.converse(rdp_reply(3, 77))),
                         'RDP: the server refused TLS (failure code 77)')
        self.assertEqual(str(self.converse(rdp_reply(None))),
                         'RDP: the server offers only Standard RDP Security (no TLS)')
        self.assertEqual(str(self.converse(b'HTTP/1.1 400 Bad Request\r\n\r\n')),
                         'RDP: not an RDP answer (no TPKT header)')
        self.assertEqual(str(self.converse(rdp_reply(2, 4))),
                         'RDP: the server chose an unknown security protocol (0x4)')

    def test_a_remote_desktop_server_is_scanned_through_its_negotiation(self):
        tls = RdpResponder(_context('bundle_leaf'), rdp_reply(2, 2))
        plain = RdpResponder(_context('bundle_leaf'), rdp_reply(3, 2))
        try:
            code, doc, _err = _scan_json('-t', 'ts01=127.0.0.1:%d/rdp' % tls.port,
                                         'ts02=127.0.0.1:%d/rdp' % plain.port, '-n',
                                         'www.example.com', '--cert',
                                         str(FIXTURES / 'bundle_leaf.pem'))
        finally:
            tls.close()
            plain.close()
        self.assertEqual(code, 0)
        rows = {r['server']: r for r in doc['results'] if r['probe'] == 'sni'}
        self.assertEqual(rows['ts01']['status'], 'UPDATED')
        self.assertEqual((rows['ts02']['status'], rows['ts02']['error']),
                         ('TLS_ERROR', 'RDP: the server refused TLS (SSL_NOT_ALLOWED_BY_SERVER)'))
        self.assertEqual({e.get('protocol') for e in doc['endpoints']}, {'rdp'})
        self.assertTrue(tls.requests and all(r == sos._RDP_REQUEST for r in tls.requests))


# --- --profile -----------------------------------------------------------------------------------

class ProfileTests(unittest.TestCase):
    def test_the_presets_and_how_they_join_p(self):
        self.assertEqual(sos.resolve_ports(None), [443])
        self.assertEqual(sos.resolve_ports(None, ['web']), [443, 8443])
        self.assertEqual(sos.resolve_ports(None, ['mail']), [25, 587, 465, 143, 993, 110, 995])
        everything = sos.resolve_ports(None, ['all'])
        self.assertEqual(everything[-8:], [21, 990, 389, 636, 5222, 5223, 5432, 3389])
        self.assertEqual({sos.endpoint_protocol(p) for p in everything},
                         {'tls', 'smtp', 'imap', 'pop3', 'ftp', 'ldap', 'xmpp', 'postgres', 'rdp'})
        # -p adds its own; a port named twice is scanned once, with the protocol -p writes
        ports = sos.resolve_ports('2525/smtp,25/tls', ['mail', 'web'])
        self.assertEqual(ports, [25, 587, 465, 143, 993, 110, 995, 443, 8443, 2525])
        self.assertEqual(sos.port_protocols(ports), {25: 'tls', 2525: 'smtp'})
        with self.assertRaisesRegex(sos.UsageError, "unknown --profile 'db'"):
            sos.resolve_ports(None, ['db'])

    def test_the_command_line(self):
        parser = sos.build_parser()
        args = parser.parse_args(['-t', '203.0.113.10', '--profile', 'mail', '--profile', 'web'])
        self.assertEqual((args.profile, args.ports), (['mail', 'web'], None))
        code, _out, err = run_main('-t', '203.0.113.10', '-n', 'www.example.com', '--profile', 'db')
        self.assertEqual(code, 2)
        self.assertIn("invalid choice: 'db'", err)
        code, _out, err = run_main('--compare', '203.0.113.10', '203.0.113.11', '-n',
                                   'www.example.com', '--profile', 'web')
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn('--compare does not take --profile', err)

    def test_a_scan_dials_the_profile_and_says_so(self):
        dialled = []  # type: List[int]
        lock = threading.Lock()

        def refuse(ip: str, port: int, timeout: float) -> None:
            with lock:
                dialled.append(port)
            raise ConnectionRefusedError()

        with mock.patch.object(sos, 'tcp_connect', side_effect=refuse):
            code, doc, _err = _scan_json('-t', '203.0.113.10', '-n', 'www.example.com',
                                         '--profile', 'mail', '--profile', 'mail', '-p', '8443')
        self.assertEqual(code, 0)
        self.assertEqual(sorted(dialled), sorted([25, 587, 465, 143, 993, 110, 995, 8443]))
        self.assertEqual(doc['options']['ports'], [25, 587, 465, 143, 993, 110, 995, 8443])
        self.assertEqual(doc['options']['profiles'], ['mail'])
        with mock.patch.object(sos, 'tcp_connect', side_effect=refuse):
            _code, plain, _err = _scan_json('-t', '203.0.113.10', '-n', 'www.example.com')
        self.assertNotIn('profiles', plain['options'])
        self.assertEqual(plain['options']['ports'], [443])


# --- the chain each endpoint sends ---------------------------------------------------------------

class AnalyzeChainTests(unittest.TestCase):
    def test_a_complete_trusted_chain_has_nothing_to_say(self):
        check = sos.analyze_chain(True, sent=ders(LEAF, INTER), built=ders(LEAF, INTER, ROOT),
                                  sni='www.example.com', now=NOW)
        self.assertEqual((check.status, check.problems), ('trusted', []))
        self.assertEqual([c.subject_cn for c in check.sent], ['www.example.com',
                                                             'Example Test Bundle Intermediate CA'])
        entry = check.to_dict()
        self.assertEqual(entry['sent'][1]['serialHex'], INTER.serial_hex)
        self.assertEqual((entry['status'], entry['problems'], entry['notes']), ('trusted', [], {}))

    def test_the_leaf_sent_alone_is_a_missing_intermediate_with_the_ca_url(self):
        check = sos.analyze_chain(False, 20, 'unable to get local issuer certificate',
                                  sent=ders(LEAF), sni='www.example.com', now=NOW)
        self.assertEqual((check.status, check.problems), ('untrusted', ['missing-intermediate']))
        self.assertEqual(check.notes['missing-intermediate'],
                         'the server does not send Example Test Bundle Intermediate CA (Example '
                         'Test PKI), the issuer of its certificate (the CA publishes it at '
                         'http://ca.example.com/bundle-inter.crt)')
        # trusted here because this machine had the intermediate: still missing for the others
        had = sos.analyze_chain(True, sent=ders(LEAF), built=ders(LEAF, INTER, ROOT), now=NOW)
        self.assertEqual((had.status, had.problems), ('trusted', ['missing-intermediate']))
        self.assertIn('this machine had it, a client without it fails',
                      had.notes['missing-intermediate'])
        # OpenSSL may build through a cross-signed copy of the CA sent (its subject and key):
        # that is no missing intermediate
        leaf, inter = fixture_cert('chainfix_leaf.pem'), _certs('chainfix_inter.pem')[0]
        cross, old_root = _certs('chainfix_inter_cross.pem')[0], _certs('chainfix_old_root.pem')[0]
        self.assertNotEqual(inter.sha256, cross.sha256)
        self.assertEqual(sos.analyze_chain(True, sent=ders(leaf, inter),
                                           built=ders(leaf, cross, old_root), now=NOW).problems, [])

    def test_a_complete_chain_to_a_root_this_machine_lacks(self):
        check = sos.analyze_chain(False, 20, 'unable to get local issuer certificate',
                                  sent=ders(LEAF, INTER), now=NOW)
        self.assertEqual(check.problems, ['untrusted-root'])
        self.assertIn('the chain ends at Example Test Bundle Intermediate CA (Example Test PKI), '
                      'issued by Example Test Bundle Root CA (Example Test PKI), which this '
                      'machine does not trust: a private CA (give it with --private-ca) or, on '
                      'Windows, a public root Windows has not fetched yet',
                      check.notes['untrusted-root'])
        sent_root = sos.analyze_chain(False, 19, 'self-signed certificate in certificate chain',
                                      sent=ders(LEAF, INTER, ROOT), now=NOW)
        self.assertEqual(sent_root.problems, ['untrusted-root', 'extra-root'])

    def test_order_an_extra_root_and_certificates_no_part_of_the_chain(self):
        check = sos.analyze_chain(True, sent=ders(LEAF, ROOT, INTER, OTHER), now=NOW)
        self.assertEqual(check.status, 'trusted')
        self.assertEqual(check.problems, ['wrong-order', 'extra-root', 'unrelated'])
        self.assertEqual(check.breaking, [])
        self.assertEqual(check.notes['unrelated'],
                         'api.example.net is sent but no part of the chain')
        self.assertEqual(sos.analyze_chain(True, sent=ders(INTER, LEAF), leaf=LEAF.der,
                                           now=NOW).problems,
                         ['wrong-order'], 'the leaf comes first')

    def test_dates_names_and_self_signed(self):
        late = datetime(2051, 1, 1, tzinfo=timezone.utc)
        expired = sos.analyze_chain(False, 10, 'certificate has expired', sent=ders(LEAF, INTER),
                                    now=late)
        self.assertEqual(expired.problems[:1], ['expired'])
        self.assertEqual(expired.notes['expired'], 'the certificate expired on 2050-01-01')
        early = sos.analyze_chain(False, 9, 'certificate is not yet valid', sent=ders(LEAF, INTER),
                                  now=datetime(2024, 6, 1, tzinfo=timezone.utc))
        self.assertEqual(early.problems, ['not-yet-valid'])
        # the chainfix intermediate expires half a year before its leaf
        leaf, inter = fixture_cert('chainfix_leaf.pem'), _certs('chainfix_inter.pem')[0]
        gap = sos.analyze_chain(False, 10, 'certificate has expired', sent=ders(leaf, inter),
                                now=datetime(2035, 9, 1, tzinfo=timezone.utc))
        self.assertEqual(gap.problems, ['expired-chain'])
        self.assertIn('DomainScope Test Issuing CA', gap.notes['expired-chain'])
        self.assertEqual(sos.analyze_chain(False, 62, 'Hostname mismatch', sent=ders(LEAF, INTER),
                                           sni='shop.example.com', now=NOW).notes,
                         {'name-mismatch': 'the certificate does not cover shop.example.com'})
        self.assertEqual(sos.analyze_chain(False, 18, 'self-signed certificate',
                                           sent=ders(SELF_SIGNED), now=NOW).problems,
                         ['self-signed'])
        odd = sos.analyze_chain(False, 66, 'EE certificate key too weak', sent=ders(LEAF, INTER),
                                now=NOW)
        self.assertEqual(odd.notes, {'untrusted': 'not trusted: EE certificate key too weak'})

    def test_before_python_3_10_the_leaf_alone_speaks(self):
        unknown = sos.analyze_chain(False, 20, 'unable to get local issuer certificate',
                                    sent=None, leaf=LEAF.der, now=NOW)
        self.assertEqual(unknown.problems, ['unknown-issuer'])
        self.assertIsNone(unknown.to_dict()['sent'])
        self.assertEqual(sos.analyze_chain(False, 21, 'unable to verify the first certificate',
                                           sent=None, leaf=LEAF.der, now=NOW).problems,
                         ['missing-intermediate'])
        self.assertEqual(sos.analyze_chain(True, sent=None, leaf=LEAF.der, now=NOW).problems, [])

    def test_a_private_ca_trusts_what_it_issued(self):
        leaf, ca = fixture_cert('cli_private_wild.pem'), fixture_cert('cli_private_ca.pem')
        check = sos.analyze_chain(False, 20, 'unable to get local issuer certificate',
                                  sent=ders(leaf), sni='a.wild.example.net', private_cas=[ca],
                                  now=NOW)
        self.assertEqual((check.status, check.problems, check.private_ca),
                         ('trusted', [], ca.subject_dn))
        # an intermediate given as --private-ca, sent by no server: still to be sent
        via_inter = sos.analyze_chain(False, 20, 'x', sent=ders(LEAF), private_cas=[INTER], now=NOW)
        self.assertEqual((via_inter.status, via_inter.problems), ('trusted', ['missing-intermediate']))
        # its dates still count
        late = sos.analyze_chain(False, 10, 'certificate has expired', sent=ders(leaf),
                                 private_cas=[ca], now=datetime(2051, 1, 1, tzinfo=timezone.utc))
        self.assertEqual(late.status, 'untrusted')
        # a self-signed server certificate given as --private-ca
        own = sos.analyze_chain(False, 18, 'self-signed certificate', sent=ders(SELF_SIGNED),
                                private_cas=[SELF_SIGNED], now=NOW)
        self.assertEqual((own.status, own.problems), ('trusted', []))

    def test_no_verifying_handshake_is_untested(self):
        check = sos.analyze_chain(None, now=NOW)
        self.assertEqual((check.status, check.problems), ('untested', []))


class FakeChainProbe:
    """Chain probes answered from a table: endpoint ip -> (verifying answer, plain answer)."""

    def __init__(self, table: Dict[str, Tuple[sos.ChainProbe, Optional[sos.ChainProbe]]]) -> None:
        self.table = table
        self.calls = []  # type: List[Tuple[str, Optional[str], object]]
        self.lock = threading.Lock()

    def __call__(self, ip: str, port: int, protocol: str, sni: Optional[str], context: object,
                 timeout: float) -> sos.ChainProbe:
        with self.lock:
            self.calls.append((ip, sni, context))
        verify, plain = self.table[ip]
        return plain if context == 'plain' else verify


def _audit_contexts() -> sos.AuditContexts:
    contexts = _fake_contexts(untestable_versions=(), untestable_ciphers=())
    contexts.verify = {True: 'verify:name', False: 'verify'}
    contexts.plain = 'plain'
    return contexts


def _report(rows: Sequence[Tuple[str, str, int, str, sos.CertInfo]],
            servers: Sequence[sos.Server] = ()) -> sos.ScanReport:
    """(server, ip, port, name, certificate served for the name) rows, every name hosted."""
    endpoints, results, by_name = [], [], {}  # type: List[sos.Endpoint], List[sos.ProbeResult], Dict[str, sos.Server]
    for server in servers:
        by_name[server.name] = server
    for server, ip, port, name, cert in rows:
        if (ip, port) not in [(e.ip, e.port) for e in endpoints]:
            endpoints.append(sos.Endpoint(ip, port, sos.OPEN))
        results.append(sos.ProbeResult(server, ip, port, sos.PROBE_SNI, name, name,
                                       sos.NEEDS_UPDATE, cert=cert))
        by_name.setdefault(server, sos.Server(server, [ip]))
    probes = sos.build_probe_names(sorted({r[3] for r in rows}))
    certs = {r[4].sha256: r[4] for r in rows}
    return sos.ScanReport(servers=list(by_name.values()), probes=probes, ports=[443], new_certs=[],
                          endpoints=endpoints, results=results, certificates=certs,
                          started_at=NOW, finished_at=NOW)


def _all_accepted(ip: str, port: int, protocol: str, sni: Optional[str], context: str,
                  timeout: float) -> sos.AuditCheck:
    kind, _, what = str(context).partition(':')
    if kind == 'v' and what in ('TLSv1.0', 'TLSv1.1'):
        return sos.AuditCheck(sos.AUDIT_REFUSED, error='protocol version')
    if kind == 'c':
        return sos.AuditCheck(sos.AUDIT_REFUSED, error='no shared cipher')
    if kind == 'k' and what == 'ECDSA':
        return sos.AuditCheck(sos.AUDIT_REFUSED, error='no shared cipher')
    return sos.AuditCheck(sos.AUDIT_ACCEPTED, version='TLSv1.2', key_algorithm='RSA')


class AuditChainTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = _report([('web01', '203.0.113.21', 443, 'www.example.com', LEAF),
                               ('web02', '203.0.113.22', 443, 'www.example.com', LEAF),
                               ('web03', '203.0.113.23', 443, 'www.example.com', LEAF),
                               ('web04', '203.0.113.24', 443, 'www.example.com', LEAF)])
        trusted = sos.ChainProbe(verified=True, chain=ders(LEAF, INTER), leaf=LEAF.der,
                                 built=ders(LEAF, INTER, ROOT))
        self.probe = FakeChainProbe({
            '203.0.113.21': (trusted, None),
            '203.0.113.22': (sos.ChainProbe(verified=False, verify_code=20,
                                            verify_message='unable to get local issuer certificate'),
                             sos.ChainProbe(chain=ders(LEAF), leaf=LEAF.der)),
            '203.0.113.23': (sos.ChainProbe(verified=True, chain=ders(LEAF, INTER, ROOT),
                                            leaf=LEAF.der, built=ders(LEAF, INTER, ROOT)), None),
            '203.0.113.24': (sos.ChainProbe(error='timed out', timed_out=True), None),
        })
        self.report.audit = sos.run_tls_audit(self.report, attempt=_all_accepted,
                                              contexts=_audit_contexts(),
                                              chain_attempt=self.probe, workers=4)

    def test_each_endpoint_once_more_for_its_name_then_for_what_it_sends(self):
        calls = sorted(self.probe.calls)
        self.assertEqual(calls, [('203.0.113.21', 'www.example.com', 'verify:name'),
                                 ('203.0.113.22', 'www.example.com', 'plain'),
                                 ('203.0.113.22', 'www.example.com', 'verify:name'),
                                 ('203.0.113.23', 'www.example.com', 'verify:name'),
                                 ('203.0.113.24', 'www.example.com', 'verify:name')])
        audit = {e.ip: e for e in self.report.audit.endpoints}
        self.assertEqual(audit['203.0.113.21'].chain.status, 'trusted')
        self.assertEqual(audit['203.0.113.22'].chain.problems, ['missing-intermediate'])
        self.assertEqual(audit['203.0.113.23'].chain.problems, ['extra-root'])
        self.assertEqual((audit['203.0.113.24'].chain.status, audit['203.0.113.24'].status),
                         ('untested', 'timeout'))

    def test_the_fleet_summary_json_and_text(self):
        summary = sos.audit_summary(self.report.audit)
        self.assertEqual((summary['chainsChecked'], summary['chainsBroken']), (3, 1))
        self.assertEqual([(e['servers'], e['status'], e['problems']) for e in summary['chainProblems']],
                         [(['web02'], 'untrusted', ['missing-intermediate']),
                          (['web03'], 'trusted', ['extra-root'])])
        doc = json.loads(sos.render_json(self.report))
        chain = next(e['chain'] for e in doc['tlsAudit']['endpoints'] if e['servers'] == ['web02'])
        self.assertEqual((chain['status'], chain['verifyCode'], chain['problems']),
                         ('untrusted', 20, ['missing-intermediate']))
        self.assertEqual([c['subjectCN'] for c in chain['sent']], ['www.example.com'])
        text = sos.render_tls_audit(self.report.audit)
        self.assertIn('Certificate chain not trusted or incomplete: 1 endpoint(s)', text)
        self.assertIn('203.0.113.22:443  web02  the server does not send Example Test Bundle '
                      'Intermediate CA (Example Test PKI), the issuer of its certificate', text)
        self.assertIn('Chain sent with extra or misordered certificates: 1 endpoint(s)', text)
        self.assertIn('203.0.113.23:443  web03  the root Example Test Bundle Root CA (Example Test '
                      'PKI) is sent too: clients use their own copy', text)
        self.assertIn('Every name is served with one certificate per key type across the endpoints',
                      text)
        full = sos.render_tls_audit(self.report.audit, show_all=True)
        self.assertIn('| chain: untrusted (missing-intermediate)', full)

    def test_a_fleet_whose_chains_cannot_be_checked_says_so(self):
        report = _report([('web01', '203.0.113.21', 443, 'www.example.com', LEAF)])
        report.audit = sos.run_tls_audit(report, attempt=_all_accepted,
                                         contexts=_fake_contexts())
        self.assertEqual(report.audit.endpoints[0].chain.error, 'no chain check with these contexts')
        text = sos.render_tls_audit(report.audit)
        self.assertIn('Certificate chains not checked: no verifying handshake completed', text)

    def test_a_python_that_cannot_read_chains_says_what_it_misses(self):
        contexts = _audit_contexts()
        contexts.chain_why = 'Python 3.8 cannot read the certificates a server sends'
        self.assertEqual(contexts.untestable()['chain'],
                         'Python 3.8 cannot read the certificates a server sends')
        report = _report([('web01', '203.0.113.21', 443, 'www.example.com', LEAF)])
        report.audit = sos.run_tls_audit(report, attempt=_all_accepted, contexts=contexts,
                                         chain_attempt=FakeChainProbe(
                                             {'203.0.113.21': (sos.ChainProbe(verified=True,
                                                                              leaf=LEAF.der), None)}))
        self.assertIn('Chains read in part - Python 3.8 cannot read the certificates a server sends',
                      sos.render_tls_audit(report.audit))


# --- one name, several certificates of one key type ----------------------------------------------

class SerialMismatchTests(unittest.TestCase):
    OLD = fixture_cert('ec_wildcard.pem')           # self-signed EC, *.wild.example.net, 2025
    NEW = fixture_cert('cli_renewed_wild.pem')      # self-signed EC, the same name, 2026

    def test_the_pool_member_left_behind_is_named_with_its_load_balancer(self):
        lb = sos.Server('lb01', ['203.0.113.2'], vips=['203.0.113.50'],
                        backends=['web01', 'web02', 'web03'])
        name = 'a.wild.example.net'
        report = _report([('web01', '10.0.0.21', 443, name, self.NEW),
                          ('web02', '10.0.0.22', 443, name, self.NEW),
                          ('web03', '10.0.0.23', 443, name, self.OLD),
                          ('lb01', '203.0.113.2', 443, name, self.NEW)],
                         servers=[lb])
        mismatches = sos.serial_mismatches(report)
        self.assertEqual(len(mismatches), 1)
        m = mismatches[0]
        self.assertEqual((m['name'], m['keyType'], m['kind']), (name, 'ECDSA', 'private'))
        self.assertEqual([(c['serialHex'], c['older']) for c in m['certificates']],
                         [(self.NEW.serial_hex, False), (self.OLD.serial_hex, True)])
        older = m['certificates'][1]['endpoints']
        self.assertEqual(older, [{'ip': '10.0.0.23', 'port': 443, 'protocol': 'tls',
                                  'servers': ['web03'], 'behind': ['lb01'], 'vips': []}])
        self.assertEqual([e['servers'] for e in m['certificates'][0]['endpoints']],
                         [['web01'], ['web02'], ['lb01']])
        self.assertEqual(m['certificates'][0]['endpoints'][2]['vips'], ['203.0.113.50'])
        lines = []  # type: List[str]
        sos.render_serial_mismatches(mismatches, lines, sos.Style(False))
        text = '\n'.join(lines)
        self.assertIn('One name served with different certificates of one key type: 1 name(s)', text)
        self.assertIn('    a.wild.example.net (ECDSA, private)', text)
        self.assertIn('      OLDER serial %s, issued 2025-01-01, expires 2051-01-01: 10.0.0.23:443 '
                      'web03 (behind lb01)' % self.OLD.serial_hex, text)
        self.assertIn('10.0.0.21:443 web01 (behind lb01); 10.0.0.22:443 web02 (behind lb01); '
                      '203.0.113.2:443 lb01 (VIP 203.0.113.50)', text)

    def test_a_pair_of_key_types_or_of_kinds_is_no_mismatch(self):
        rsa, ecdsa = fixture_cert('certdiff_renewed.pem'), fixture_cert('certdiff_new.pem')
        public, origin = fixture_cert('cli_public_wild.pem'), fixture_cert('cli_origin_wild.pem')
        report = _report([('web01', '203.0.113.21', 443, 'example.com', rsa),
                          ('web02', '203.0.113.22', 443, 'example.com', ecdsa),
                          ('web01', '203.0.113.21', 443, 'a.wild.example.net', public),
                          ('web03', '203.0.113.23', 443, 'a.wild.example.net', origin)])
        self.assertEqual(sos.serial_mismatches(report), [])
        lines = []  # type: List[str]
        sos.render_serial_mismatches([], lines, sos.Style(False))
        self.assertEqual(lines, ['  Every name is served with one certificate per key type across '
                                 'the endpoints'])

    def test_the_audit_adds_the_other_half_of_an_rsa_and_ecdsa_pair(self):
        # every endpoint serves the new ECDSA certificate to the scan; asked for RSA alone, web02
        # still serves last year's RSA certificate
        old_rsa, new_rsa = fixture_cert('certdiff_old.pem'), fixture_cert('certdiff_renewed.pem')
        ecdsa = fixture_cert('certdiff_new.pem')
        report = _report([('web01', '203.0.113.21', 443, 'example.com', ecdsa),
                          ('web02', '203.0.113.22', 443, 'example.com', ecdsa)])

        def attempt(ip: str, port: int, protocol: str, sni: Optional[str], context: str,
                    timeout: float) -> sos.AuditCheck:
            kind, _, what = str(context).partition(':')
            if kind != 'k':  # TLS 1.2 and 1.3 only, no weak suite
                accepted = kind == 'v' and what in ('TLSv1.2', 'TLSv1.3')
                return sos.AuditCheck(sos.AUDIT_ACCEPTED if accepted else sos.AUDIT_REFUSED,
                                      version=what if accepted else None)
            cert = ecdsa if what == 'ECDSA' else (old_rsa if ip == '203.0.113.22' else new_rsa)
            return sos.AuditCheck(sos.AUDIT_ACCEPTED, version='TLSv1.2', cert_sha256=cert.sha256,
                                  key_algorithm=cert.key_algorithm, cert=cert)

        report.audit = sos.run_tls_audit(report, attempt=attempt, contexts=_fake_contexts())
        summary = sos.audit_summary(report.audit)
        self.assertEqual([(m['name'], m['keyType']) for m in summary['serialMismatches']],
                         [('example.com', 'RSA')])
        certs = summary['serialMismatches'][0]['certificates']
        self.assertEqual([(c['serialHex'], c['older'], [e['servers'] for e in c['endpoints']])
                          for c in certs],
                         [(new_rsa.serial_hex, False, [['web01']]),
                          (old_rsa.serial_hex, True, [['web02']])])
        doc = json.loads(sos.render_json(report))
        self.assertEqual(doc['tlsAudit']['summary']['serialMismatches'][0]['name'], 'example.com')
        self.assertNotIn('cert', doc['tlsAudit']['endpoints'][0]['keyTypes']['RSA'])


# --- the chain check against local servers -------------------------------------------------------

def _trusting(*cas: sos.CertInfo):
    """sos.verify_context stand-in: a verifying client whose store is ``cas``."""
    def make(check_hostname: bool = True) -> ssl.SSLContext:
        context = ssl.create_default_context(cadata='\n'.join(
            ssl.DER_cert_to_PEM_cert(ca.der) for ca in cas))
        context.check_hostname = check_hostname
        strict = getattr(ssl, 'VERIFY_X509_STRICT', 0)
        if strict:
            context.verify_flags &= ~strict
        return context
    return make


class LocalChainTests(unittest.TestCase):
    """Real handshakes: a server sending the bundle chain in several shapes."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.servers = {}  # type: Dict[str, TlsResponder]
        for shape, certs in (('complete', [LEAF, INTER]), ('alone', [LEAF]),
                             ('reversed', [LEAF, ROOT, INTER])):
            path = os.path.join(cls.tmp.name, shape + '.pem')
            with open(path, 'w', encoding='ascii') as handle:
                handle.write(''.join(ssl.DER_cert_to_PEM_cert(c.der) for c in certs))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(path, str(FIXTURES / 'bundle_leaf.key'))
            cls.servers[shape] = TlsResponder(context)

    @classmethod
    def tearDownClass(cls) -> None:
        for server in cls.servers.values():
            server.close()
        cls.tmp.cleanup()

    def audit(self, *cas: sos.CertInfo) -> Dict[str, dict]:
        targets = ['%s=127.0.0.1:%d' % (shape, server.port) for shape, server in self.servers.items()]
        with mock.patch.object(sos, 'verify_context', side_effect=_trusting(*cas)):
            code, doc, err = _scan_json('-t', *targets, '-n', 'www.example.com', '--tls-audit')
        self.assertEqual(code, 0, err)
        return {e['servers'][0]: e['chain'] for e in doc['tlsAudit']['endpoints']}

    def test_against_a_store_with_the_root(self):
        chains = self.audit(ROOT)
        self.assertEqual((chains['complete']['status'], chains['complete']['problems']),
                         ('trusted', []))
        self.assertEqual(chains['alone']['status'], 'untrusted')
        self.assertEqual(chains['alone']['verifyCode'], 20)
        self.assertEqual(chains['reversed']['status'], 'trusted')
        if sos.CAN_READ_CHAIN:
            self.assertEqual(chains['alone']['problems'], ['missing-intermediate'])
            self.assertEqual(chains['reversed']['problems'], ['wrong-order', 'extra-root'])
            self.assertEqual([c['subjectCN'] for c in chains['complete']['sent']],
                             ['www.example.com', 'Example Test Bundle Intermediate CA'])
        else:
            self.assertEqual(chains['alone']['problems'], ['unknown-issuer'])
            self.assertEqual(chains['reversed']['problems'], [])
            self.assertIsNone(chains['complete']['sent'])

    def test_against_a_store_without_it_and_one_that_has_the_intermediate(self):
        chains = self.audit(fixture_cert('cli_private_ca.pem'))   # another root: not this chain's
        self.assertEqual(chains['complete']['status'], 'untrusted')
        self.assertEqual(chains['complete']['problems'],
                         ['untrusted-root'] if sos.CAN_READ_CHAIN else ['unknown-issuer'])
        if not sos.CAN_READ_CHAIN:
            self.skipTest('Python %d.%d cannot read the chain OpenSSL built' % tuple(
                __import__('sys').version_info[:2]))
        chains = self.audit(ROOT, INTER)
        self.assertEqual((chains['alone']['status'], chains['alone']['problems']),
                         ('trusted', ['missing-intermediate']))
        self.assertEqual(chains['complete']['problems'], [])


if __name__ == '__main__':
    unittest.main()
