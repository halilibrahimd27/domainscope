"""The CLI's sweep with the inventory topology (stdlib unittest; no network).

tests/fixtures/topology/inventory.txt describes two load balancers sharing a VIP (lb01 with its
own TLS ports), a plain-HTTP backend (web01, terminates_tls=no), a re-encrypting one (web02 on
8443 only), a server behind NAT (app01) and one with its own port (db01). The sweep scans each
server only on its own ports, leaves web01 out unless --include-backends, and the summary groups
the servers by load balancer; the JSON says where TLS terminates. Fake connect / TLS functions
stand in for the network.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

import base64
import contextlib
import importlib.util
import io
import os
import re
import sys
import tempfile
import threading
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'ssl_origin_scan.py'
FIXTURES = ROOT / 'tests' / 'fixtures'
TOPOLOGY = FIXTURES / 'topology'
CORE = ('lb01', 'lb02', 'web01', 'web02', 'app01', 'db01')
NAME = 'www.wild.example.net'   # tests/fixtures/cli_public_wild.pem covers *.wild.example.net


def _load_cli():
    if 'ssl_origin_scan' in sys.modules:
        return sys.modules['ssl_origin_scan']
    spec = importlib.util.spec_from_file_location('ssl_origin_scan', str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules['ssl_origin_scan'] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


sos = _load_cli()


def _pem_der(name):
    text = (FIXTURES / name).read_text(encoding='ascii')
    body = re.search(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----', text, re.S)
    return base64.b64decode(''.join(body.group(1).split()))


WILD_DER = _pem_der('cli_public_wild.pem')   # issued by a CA nobody lists, like a public one


def core_servers():
    """The fixture's six servers (the malformed lines are tests/python/test_inventory_targets.py's)."""
    inventory = sos.parse_inventory((TOPOLOGY / 'inventory.txt').read_text(encoding='utf-8'),
                                    'inventory.txt')
    return [server for server in inventory.servers if server.name in CORE]


class Network:
    """Every port open; every handshake answers with the *.wild.example.net certificate."""

    def __init__(self):
        self.calls = []
        self.lock = threading.Lock()

    def connect_fn(self, ip, port, timeout):
        with self.lock:
            self.calls.append((ip, port))

    def tls_fn(self, ip, port, sni, timeout):
        return sos.TlsResult(der=WILD_DER, version='TLSv1.3')


def scan(ports=(443,), **kwargs):
    network = Network()
    report = sos.run_scan(core_servers(), sos.build_probe_names([NAME]), list(ports), timeout=1,
                          workers=4, connect_fn=network.connect_fn, tls_fn=network.tls_fn,
                          **kwargs)
    return report, network


def run_main(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = sos.main(list(args))
    return code, out.getvalue(), err.getvalue()


class TopologySweep(unittest.TestCase):
    def test_each_server_is_scanned_only_on_its_own_ports(self):
        report, network = scan()
        self.assertEqual(sorted(set(network.calls)), [
            ('10.0.0.22', 8443),      # web02: ports=8443
            ('10.0.0.30', 443),       # app01: -p
            ('10.0.0.40', 5432),      # db01: 10.0.0.40:5432 keeps its own port over ports=443
            ('203.0.113.2', 443), ('203.0.113.2', 8443),   # lb01: ports=443,8443
            ('203.0.113.3', 443)])    # lb02: -p
        # -p applies only where the inventory gives no port
        report, network = scan(ports=(443, 10443))
        self.assertEqual(sorted({call for call in network.calls if call[0] == '203.0.113.3'}),
                         [('203.0.113.3', 443), ('203.0.113.3', 10443)])
        self.assertEqual(sorted({call for call in network.calls if call[0] == '203.0.113.2'}),
                         [('203.0.113.2', 443), ('203.0.113.2', 8443)])

    def test_a_plain_http_backend_is_not_scanned_unless_asked(self):
        report, network = scan()
        self.assertEqual([s.name for s in report.skipped_backends], ['web01'])
        self.assertNotIn('web01', [s.name for s in report.servers])
        self.assertFalse(any(ip == '10.0.0.21' for ip, _port in network.calls))
        report, network = scan(include_backends=True)
        self.assertEqual(report.skipped_backends, [])
        self.assertIn(('10.0.0.21', 443), network.calls)
        self.assertTrue(report.include_backends)

    def test_the_summary_groups_by_load_balancer(self):
        report, _network = scan()
        text = sos.render_summary(report, color=False, width=110)
        start = text.index('By load balancer: 2')
        self.assertEqual(text[start:].split('\n')[:7], [
            'By load balancer: 2',
            '  lb01  NEEDS_UPDATE  terminates TLS: install the certificate here; VIP 203.0.113.50',
            '    -> web01  not scanned  plain HTTP, no certificate needed (--include-backends scans it)',
            '    -> web02  NEEDS_UPDATE  re-encrypts: needs the certificate too',
            '  lb02  NEEDS_UPDATE  terminates TLS: install the certificate here; VIP 203.0.113.50',
            '    -> web01  not scanned  plain HTTP, no certificate needed (--include-backends scans it)',
            '    -> web02  NEEDS_UPDATE  re-encrypts: needs the certificate too'])
        self.assertIn('Shared address (VIP) 203.0.113.50: lb01, lb02 - install the certificate on both',
                      text)
        self.assertIn('NAT 203.0.113.10 -> app01 (10.0.0.30)', text)
        # every server line says where TLS terminates for it
        self.assertIn('  lb01  203.0.113.2  [LB: web01, web02; VIP 203.0.113.50 with lb02; '
                      'TLS ports 443,8443]', text)
        self.assertIn('  web02  10.0.0.22  [behind lb01, lb02, re-encrypts; TLS ports 8443]', text)
        self.assertIn('  app01  10.0.0.30  [NAT 203.0.113.10]', text)
        self.assertLess(start, text.index('Servers hosting the names'))

    def test_a_backend_dns_reaches_directly_is_scanned_from_the_web_apps_targets(self):
        # tests/fixtures/topology/targets-direct.txt is what SSL Targets writes when DNS points
        # at web01 directly although the inventory says terminates_tls=no (tests/js/topology.test.js):
        # the scan counts it as needing the certificate and writes no terminates_tls=no, so the CLI
        # scans it too, never leaving it out as a plain-HTTP backend.
        inventory = sos.parse_inventory((TOPOLOGY / 'targets-direct.txt').read_text(encoding='utf-8'),
                                        'targets-direct.txt')
        self.assertEqual(inventory.warnings, [])
        network = Network()
        report = sos.run_scan(inventory.servers, sos.build_probe_names([NAME]), [443], timeout=1,
                              workers=2, connect_fn=network.connect_fn, tls_fn=network.tls_fn)
        self.assertEqual(report.skipped_backends, [])
        self.assertIn(('203.0.113.12', 443), network.calls)
        self.assertEqual([(s.name, s.backends) for s in report.servers], [('lb01', ['web01']), ('web01', [])])

    def test_a_scan_without_topology_keys_reads_as_before(self):
        servers = [sos.Server('web01', ['10.0.0.21']), sos.Server('web02', ['10.0.0.22'])]
        network = Network()
        report = sos.run_scan(servers, sos.build_probe_names([NAME]), [443], timeout=1, workers=2,
                              connect_fn=network.connect_fn, tls_fn=network.tls_fn)
        text = sos.render_summary(report, color=False)
        self.assertNotIn('By load balancer', text)
        self.assertNotIn('[', text.split('\n')[3])
        doc = sos.report_to_dict(report)
        self.assertNotIn('skippedBackends', doc)
        self.assertNotIn('includeBackends', doc['options'])
        self.assertTrue(all('topology' not in server for server in doc['servers']))

    def test_the_json_report_says_where_tls_terminates(self):
        report, _network = scan()
        doc = sos.report_to_dict(report)
        servers = {server['name']: server for server in doc['servers']}
        self.assertEqual(servers['lb01']['topology'], {
            'terminatesTls': True, 'tlsPorts': [443, 8443], 'vips': ['203.0.113.50'], 'nats': [],
            'backends': ['web01', 'web02'], 'behind': []})
        self.assertEqual(servers['web02']['topology']['behind'], ['lb01', 'lb02'])
        self.assertEqual(servers['app01']['topology']['nats'], ['203.0.113.10'])
        self.assertEqual(servers['db01']['topology']['tlsPorts'], [443])
        self.assertEqual(servers['db01']['ports'], {'10.0.0.40': [5432]}, 'its own port, as before')
        self.assertEqual(doc['skippedBackends'], [{
            'name': 'web01', 'ips': ['10.0.0.21'],
            'topology': {'terminatesTls': False, 'tlsPorts': [], 'vips': [], 'nats': [],
                         'backends': [], 'behind': ['lb01', 'lb02']}}])
        self.assertEqual(doc['options']['includeBackends'], False)
        self.assertEqual(doc['summary']['servers'], 5)


class TopologyCommandLine(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix='ds-topology-')

    def tearDown(self):
        for name in os.listdir(self.dir):
            os.remove(os.path.join(self.dir, name))
        os.rmdir(self.dir)

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write(text)
        return path

    def test_only_plain_http_backends_is_a_usage_error_that_names_the_flag(self):
        path = self.write('backends.txt', 'web01 10.0.0.21 terminates_tls=no\n')
        code, _out, err = run_main('-t', path, '-n', NAME, '-q')
        self.assertEqual(code, sos.EXIT_USAGE)
        self.assertIn('terminates_tls=no', err)
        self.assertIn('--include-backends', err)

    def test_backends_may_name_a_server_of_another_file(self):
        lbs = self.write('lbs.txt', 'lb01 203.0.113.2 backends=web01\n')
        webs = self.write('webs.txt', 'web01 10.0.0.21 terminates_tls=no\n')
        servers, warnings = sos.load_targets([lbs, webs])
        self.assertEqual(warnings, [])
        self.assertEqual([(s.name, s.backends) for s in servers], [('lb01', ['web01']), ('web01', [])])
        servers, warnings = sos.load_targets([lbs])
        self.assertEqual([(w.code, w.reason) for w in warnings], [('TOPOLOGY', 'unknownBackend')])
        self.assertEqual(str(warnings[0]), '%s:1: TOPOLOGY backends=web01 on lb01: no server of that '
                         'name or address in the inventory' % lbs)

    def test_the_help_lists_the_flag_and_the_keys(self):
        text = sos.build_parser().format_help()
        self.assertIn('--include-backends', text)
        for key in ('ports=443,8443', 'terminates_tls=yes|no', 'vip=203.0.113.50',
                    'backends=web01,web02', 'nat=203.0.113.10'):
            self.assertIn(key, text)


if __name__ == '__main__':
    unittest.main()
