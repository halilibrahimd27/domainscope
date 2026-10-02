"""The web app's Servers › targets.txt read back by the CLI (stdlib unittest; no network).

tests/fixtures/inventory-targets.txt is exactly what views/inventory.js targetsText() writes for
server names with spaces, '#', '//', ';', '=' and control characters (tests/js/ui-dom.test.js
asserts that). The CLI must read one server per line, each with only its own addresses.

tests/fixtures/inventory-ports.txt holds addresses written with their own port: the CLI must read
the same servers, ip:port endpoints and warning lines as lib/inventory.js (tests/js/inventory.test.js),
and inventory-ports-targets.txt, the targets.txt the web app writes from it, back to the same
endpoints. Only a host name with a port on a line of its own differs: the CLI resolves it, the web
app (which matches servers by address) warns. JSON_CASES are the JSON values tests/js/inventory.test.js
reads too: a bad port there is a warning in both, never a dropped address or a name resolved instead.

tests/fixtures/topology/ holds one inventory with the topology keys (ports=, terminates_tls=, vip=,
backends=, nat=) in each format - lines with hosts-file and Ansible INI lines, CSV, Ansible YAML and
JSON: the CLI must read each to expected.json, as lib/inventory.js does (tests/js/inventory.test.js).

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'ssl_origin_scan.py'
TARGETS = ROOT / 'tests' / 'fixtures' / 'inventory-targets.txt'
PORTS = ROOT / 'tests' / 'fixtures' / 'inventory-ports.txt'
PORTS_TARGETS = ROOT / 'tests' / 'fixtures' / 'inventory-ports-targets.txt'
TOPOLOGY = ROOT / 'tests' / 'fixtures' / 'topology'

# What both parsers read from inventory-ports.txt: server -> its -t endpoints (a bare address is
# scanned on the -p ports). The web app writes its named servers first in targets.txt.
PORT_ENDPOINTS = {
    'web01': ['203.0.113.10:8443'],
    'web02': ['[2001:db8::2]:8443', '203.0.113.12'],
    'web03': ['203.0.113.13', '203.0.113.13:8443'],
    'web04': ['203.0.113.14'],
    'web05': ['203.0.113.15:9443'],
    'web06': ['[2001:db8::16]:443'],
    '203.0.113.17': ['203.0.113.17:8443'],
    'web11': ['203.0.113.22'],
    'web13': ['203.0.113.23'],
    'web16': ['203.0.113.10:9443'],
    'web14.example.com': ['203.0.113.24'],
    'web15': ['203.0.113.27:8443'],
    '203.0.113.25': ['203.0.113.25'],
    '2001:db8::26': ['2001:db8::26'],
}

# JSON values both parsers must warn about (tests/js/inventory.test.js has the same cases): codes
# here; the web app adds NO_IP for the host name with a port, which the CLI resolves instead.
JSON_CASES = [
    ('[{"name":"web01","ip":"203.0.113.10:99999"}]', ['INVALID_IP']),
    ('{"web01":"203.0.113.10:99999"}', ['INVALID_IP']),
    ('{"_meta":{"hostvars":{"web01":{"ansible_host":"203.0.113.10:99999"}}}}', ['INVALID_IP']),
    ('[{"ip":"[fe80::1%eth0]:8443"}]', ['INVALID_IP']),
    ('["web01 203.0.113.10:99999"]', ['INVALID_IP']),
    ('[{"name":"203.0.113.10:99999","ip":"203.0.113.11"}]', ['INVALID_IP']),
    ('[{"name":"cache01","image":"redis:7","ip":"203.0.113.12"}]', []),
]

# Host names with a port in vars and record attributes are no targets: silent in both parsers
# (tests/js/inventory.test.js reads the same documents), with each server's own address.
QUIET_HOST_PORTS = [
    ('x.json', '{"_meta":{"hostvars":{'
               '"web01":{"ansible_host":"203.0.113.10","consul_addr":"consul.example.com:8500",'
               '"db_url":"db.example.com:5432"},'
               '"web02":{"ansible_host":"203.0.113.11","consul_addr":"consul.example.com:8500",'
               '"db_url":"db.example.com:5432"}}},'
               '"all":{"children":["ungrouped","web"]},"web":{"hosts":["web01","web02"]}}',
     [('web01', ['203.0.113.10']), ('web02', ['203.0.113.11'])]),
    ('x.yaml', 'all:\n  vars:\n    consul_addr: consul.example.com:8500\n  hosts:\n    web01:\n'
               '      ansible_host: 203.0.113.10\n      db_url: db.example.com:5432\n',
     [('web01', ['203.0.113.10'])]),
    ('x.json', '[{"name":"web01","ip":"203.0.113.10","health_url":"web01.example.com:8080"}]',
     [('web01', ['203.0.113.10'])]),
]


def _load_cli():
    if 'ssl_origin_scan' in sys.modules:
        return sys.modules['ssl_origin_scan']
    spec = importlib.util.spec_from_file_location('ssl_origin_scan', str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules['ssl_origin_scan'] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


sos = _load_cli()


class InventoryTargetsRoundTrip(unittest.TestCase):
    def test_every_server_keeps_its_own_addresses(self):
        inventory = sos.parse_inventory(TARGETS.read_text(encoding='utf-8'), str(TARGETS))
        self.assertEqual(inventory.warnings, [])
        got = [(s.name, list(s.ips), list(s.hostnames)) for s in inventory.servers]
        self.assertEqual(got, [
            ('Web_Server_1', ['192.0.2.11'], []),
            ('Web_Server_2', ['192.0.2.12'], []),
            ('_bastion', ['192.0.2.13'], []),
            ('[prod]_api', ['192.0.2.14'], []),
            ('Web_2', ['198.51.100.2'], []),
            ('_legacy', ['198.51.100.3'], []),
            ('db_backup', ['198.51.100.4'], []),
            ('role_web', ['198.51.100.5'], []),
            ('db_primary', ['203.0.113.1', '2001:db8::1'], []),
            ('db_replica', ['203.0.113.2'], []),
            ('rack_web', ['203.0.113.3'], []),
            ('203.0.113.9', ['203.0.113.9'], []),
            ('192.0.2.15', ['192.0.2.15'], []),
            ('ansible_host_web', ['192.0.2.16'], []),
        ])



def endpoints(server):
    """The server's targets as lib/inventory.js serverTargets() writes them."""
    return [sos.format_endpoint(ip, port) for ip in server.ips for port in server.port_spec(ip)]


class InventoryPortsParity(unittest.TestCase):
    def test_the_same_endpoints_and_warnings_as_the_web_app(self):
        inventory = sos.parse_inventory(PORTS.read_text(encoding='utf-8'), str(PORTS))
        self.assertEqual({s.name: endpoints(s) for s in inventory.servers if s.ips}, PORT_ENDPOINTS)
        # line 15: the host name with a port the web app can only warn about is resolved here
        self.assertEqual([(s.name, s.hostnames, s.ports) for s in inventory.servers if not s.ips],
                         [('web12', ['web12.example.net'], {'web12.example.net': [8443]})])
        # the web app has these lines too, plus PARSE and NO_IP on line 15
        self.assertEqual([(w.line, w.code) for w in inventory.warnings],
                         [(10, 'INVALID_IP'), (11, 'INVALID_IP'), (12, 'INVALID_IP'), (13, 'INVALID_IP'),
                          (14, 'PARSE'), (24, 'PARSE'), (26, 'PARSE'), (27, 'PARSE')])
        self.assertIn('port 99999 is outside 1-65535', inventory.warnings[0].text)
        self.assertIn('db.example.net:5432: a host name with a port next to an address',
                      inventory.warnings[4].text)
        # an Ansible host's own port is its SSH port, never advice to move it onto the address
        self.assertEqual(inventory.warnings[5].text, 'web14.example.com:2222: port 2222 on an Ansible '
                         'host is its SSH port (ansible_port), not a TLS port - scanned on -p')
        self.assertTrue(all('ADDRESS:PORT' not in w.text for w in inventory.warnings[5:]))

    def test_the_web_apps_targets_txt_reads_back_to_the_same_endpoints(self):
        inventory = sos.parse_inventory(PORTS_TARGETS.read_text(encoding='utf-8'), str(PORTS_TARGETS))
        self.assertEqual(inventory.warnings, [])
        self.assertEqual({s.name: endpoints(s) for s in inventory.servers}, PORT_ENDPOINTS)
        self.assertEqual(len(inventory.servers), len(PORT_ENDPOINTS))

    def test_json_bad_ports_are_warnings_as_in_the_web_app(self):
        for text, codes in JSON_CASES:
            with self.subTest(text=text):
                inventory = sos.parse_inventory(text, 'x.json')
                self.assertEqual([w.code for w in inventory.warnings], codes)
                # never the address without its port, never the name "web01" resolved instead
                self.assertEqual([s.name for s in inventory.servers
                                  if '203.0.113.10' in s.ips or s.hostnames == ['web01']], [])
        inventory = sos.parse_inventory(JSON_CASES[0][0], 'x.json')
        self.assertIn('203.0.113.10:99999 (port 99999 is outside 1-65535)', inventory.warnings[0].text)
        inventory = sos.parse_inventory(JSON_CASES[5][0], 'x.json')
        self.assertEqual([(s.name, s.ips) for s in inventory.servers], [('203.0.113.11', ['203.0.113.11'])])
        # a host name with a port: resolved on that port, as NAME=HOST:PORT on a line (the web app warns)
        inventory = sos.parse_inventory('{"web01":"web01.example.net:8443"}', 'x.json')
        self.assertEqual([(s.name, s.hostnames, s.ports) for s in inventory.servers],
                         [('web01', ['web01.example.net'], {'web01.example.net': [8443]})])
        self.assertEqual(inventory.warnings, [])

    def test_host_names_with_a_port_in_vars_and_attributes_are_no_targets(self):
        for source, text, servers in QUIET_HOST_PORTS:
            with self.subTest(text=text):
                inventory = sos.parse_inventory(text, source)
                self.assertEqual(inventory.warnings, [])
                self.assertEqual([(s.name, list(s.ips)) for s in inventory.servers], servers)
                self.assertTrue(all(not s.hostnames for s in inventory.servers))

    def test_ansible_host_pattern_port_is_the_ssh_port(self):
        inventory = sos.parse_inventory('\n'.join([
            '[web]', '203.0.113.11:2222', 'web02 203.0.113.12:8443', '10:30 203.0.113.13',
            '[db]', '[2001:db8::5]:2222 ansible_user=admin', 'db02.example.com:5309',
            'db03:2222 ansible_host=203.0.113.14', '[db:vars]', 'ansible_port=2222']), 'hosts.ini')
        self.assertEqual({s.name: (endpoints(s), s.hostnames, s.groups) for s in inventory.servers}, {
            '203.0.113.11': (['203.0.113.11'], [], ['web']),
            'web02': (['203.0.113.12:8443'], [], ['web']),
            '203.0.113.13': (['203.0.113.13'], [], ['web']),
            '2001:db8::5': (['2001:db8::5'], [], ['db']),
            'db02.example.com': ([], ['db02.example.com'], ['db']),
            'db03': (['203.0.113.14'], [], ['db']),
        })
        self.assertEqual(inventory.servers[4].ports, {}, 'resolved on -p, not on the SSH port')
        self.assertEqual([(w.line, w.code) for w in inventory.warnings],
                         [(2, 'PARSE'), (6, 'PARSE'), (7, 'PARSE'), (8, 'PARSE')])
        # the same first token outside Ansible is a TLS target
        plain = sos.parse_inventory('203.0.113.11:2222\n[2001:db8::5]:8443 web05\n', 'list.txt')
        self.assertEqual({s.name: endpoints(s) for s in plain.servers},
                         {'203.0.113.11': ['203.0.113.11:2222'], 'web05': ['[2001:db8::5]:8443']})
        self.assertEqual(plain.warnings, [])
        bad = sos.parse_inventory('203.0.113.11:99999 ansible_user=admin\n', 'hosts.ini')
        self.assertEqual([(w.line, w.code) for w in bad.warnings], [(1, 'INVALID_IP')])
        self.assertEqual(bad.servers, [])

    def test_duplicates_are_per_endpoint(self):
        inventory = sos.parse_inventory('web01 203.0.113.10:8443\nweb02 203.0.113.10:9443\n'
                                        'web03 203.0.113.10:9443\nweb04 203.0.113.10\n'
                                        'web05 203.0.113.10 203.0.113.10:8443\n', 'x.txt')
        self.assertEqual([str(w) for w in inventory.warnings], [
            'x.txt:3: DUPLICATE_IP 203.0.113.10:9443 is listed for web02 and web03',
            'x.txt:5: DUPLICATE_IP 203.0.113.10 is listed for web04 and web05'])
        self.assertEqual(inventory.stats['ips'], 1)

    def test_a_bracketed_address_that_cannot_be_read_is_invalid(self):
        inventory = sos.parse_inventory('web01 [fe80::1%eth0]:8443\nweb02 [2001:db8::1]8443\n'
                                        'web03=[fe80::1%eth0]:8443\nweb04 [2001:db8::4]:8443\n', 'x.txt')
        self.assertEqual({s.name: endpoints(s) for s in inventory.servers}, {'web04': ['[2001:db8::4]:8443']})
        self.assertEqual([str(w) for w in inventory.warnings], [
            'x.txt:1: INVALID_IP [fe80::1%eth0]:8443 (an IPv6 zone id (%eth0) is not supported in a target)',
            'x.txt:2: INVALID_IP [2001:db8::1]8443 (expected [ADDRESS] or [ADDRESS]:PORT)',
            'x.txt:3: INVALID_IP [fe80::1%eth0]:8443 (an IPv6 zone id (%eth0) is not supported in a target)'])
        with self.assertRaises(sos.UsageError):
            sos.parse_target_tokens('[fe80::1%eth0]:8443')

    def test_a_time_of_day_is_no_name_and_target(self):
        inventory = sos.parse_inventory('time=10:30\nbackup=12:00:00\nweb01 203.0.113.10 10:30\n', 'x.txt')
        self.assertEqual([(s.name, endpoints(s)) for s in inventory.servers], [('web01', ['203.0.113.10'])])
        self.assertEqual(inventory.warnings, [])

    def test_name_equals_address_lines_as_the_web_app_reads_them(self):
        inventory = sos.parse_inventory('web01=203.0.113.10\nweb02=[2001:db8::2]:8443\n'
                                        'web03=203.0.113.300\nansible_user=root\ntimeout=30\n'
                                        'web04 ansible_host=203.0.113.14 ansible_port=2222\n', 'x.txt')
        self.assertEqual([(s.name, endpoints(s)) for s in inventory.servers], [
            ('web01', ['203.0.113.10']), ('web02', ['[2001:db8::2]:8443']), ('web04', ['203.0.113.14'])])
        self.assertEqual([(w.line, w.code) for w in inventory.warnings], [(3, 'INVALID_IP')])


def topology_endpoints(server):
    """The -t tokens lib/inventory.js serverTargets() writes: own ports, else ports=, else -p."""
    return [sos.format_endpoint(ip, port) for ip in server.ips for port in server.endpoint_spec(ip)]


def topology_model(inventory):
    """The model tests/js/inventory.test.js builds from lib/inventory.js (topologyModel)."""
    return {s.name: {'endpoints': topology_endpoints(s), 'tlsPorts': list(s.tls_ports),
                     'terminatesTls': s.terminates_tls, 'vips': list(s.vips), 'nats': list(s.nats),
                     'backends': list(s.backends)} for s in inventory.servers}


def topology_warnings(inventory, lines):
    """[line, code, reason] (line None when ``lines`` is false), sorted as expected.json has them."""
    rows = [[w.line if lines else None, w.code, w.reason or None] for w in inventory.warnings]
    return sorted(rows, key=lambda w: (-1 if w[0] is None else w[0], w[1], w[2] or ''))


class InventoryTopologyParity(unittest.TestCase):
    expected = json.loads((TOPOLOGY / 'expected.json').read_text(encoding='utf-8'))

    def test_every_format_reads_to_the_same_model_as_the_web_app(self):
        for name, want in self.expected['files'].items():
            with self.subTest(file=name):
                inventory = sos.parse_inventory((TOPOLOGY / name).read_text(encoding='utf-8'), name)
                model = dict(self.expected['servers'])
                model.update(want['extra'])
                self.assertEqual(topology_model(inventory), model)
                self.assertEqual(topology_warnings(inventory, want['lines']), want['warnings'])
                self.assertTrue(all(not s.hostnames for s in inventory.servers))

    def test_malformed_values_name_the_key_and_keep_the_server(self):
        inventory = sos.parse_inventory('\n'.join([
            'web01 10.0.0.1 ports=443,70000', 'web02 10.0.0.2 ports=',
            'web03 10.0.0.3 terminates_tls=yes,no', 'web04 10.0.0.4 vip=[2001:db8::1]:443',
            'web05 10.0.0.5 nat=10.0.0.0/24', 'web06 10.0.0.6 backends=10.0.0.300',
            'web07 10.0.0.7 backends=', 'nat=203.0.113.9 # a key without a server']), 'x.txt')
        self.assertEqual([(w.line, w.code, w.reason) for w in inventory.warnings], [
            (1, 'TOPOLOGY', 'ports'), (2, 'TOPOLOGY', 'ports'), (3, 'TOPOLOGY', 'terminatesTls'),
            (4, 'TOPOLOGY', 'vip'), (5, 'TOPOLOGY', 'nat'), (6, 'TOPOLOGY', 'backends'),
            (7, 'TOPOLOGY', 'backends'), (8, 'TOPOLOGY', 'noServer')])
        self.assertEqual(str(inventory.warnings[0]), 'x.txt:1: TOPOLOGY ports=443,70000: ports= '
                         'takes TLS ports 1-65535, comma separated (ports=443,8443)')
        self.assertEqual([s.name for s in inventory.servers],
                         ['web01', 'web02', 'web03', 'web04', 'web05', 'web06', 'web07'])
        self.assertTrue(all(not s.has_topology() for s in inventory.servers))

    def test_ports_precedence_as_the_web_app(self):
        inventory = sos.parse_inventory('\n'.join([
            'web01 203.0.113.10 203.0.113.12:9443 ports=443,8443',
            'web02 203.0.113.13 203.0.113.13:8443 ports=4443', 'web03 203.0.113.14',
            'web04 203.0.113.15 ports=8443', 'web04 203.0.113.15 ports=443']), 'x.txt')
        self.assertEqual({s.name: topology_endpoints(s) for s in inventory.servers}, {
            'web01': ['203.0.113.10:443', '203.0.113.10:8443', '203.0.113.12:9443'],
            'web02': ['203.0.113.13:4443', '203.0.113.13:8443'],
            'web03': ['203.0.113.14'],
            'web04': ['203.0.113.15:8443', '203.0.113.15:443']})
        self.assertEqual(inventory.warnings, [])
        # the scan: an address with its own port keeps it, ports= replaces -p, then -p
        web01, web02, web03 = inventory.servers[:3]
        self.assertEqual(web01.ports_for('203.0.113.10', [443]), [443, 8443])
        self.assertEqual(web01.ports_for('203.0.113.12', [443]), [9443])
        self.assertEqual(web02.ports_for('203.0.113.13', [443, 10443]), [4443, 8443])
        self.assertEqual(web03.ports_for('203.0.113.14', [443, 10443]), [443, 10443])
        nat = sos.parse_inventory('web01 203.0.113.10 ports=443\nweb02 203.0.113.10 ports=8443\n'
                                  'web03 203.0.113.10 ports=8443\n', 'x.txt')
        self.assertEqual([str(w) for w in nat.warnings],
                         ['x.txt:3: DUPLICATE_IP 203.0.113.10:8443 is listed for web02 and web03'])

    def test_an_inventory_without_topology_keys_is_read_as_before(self):
        for text in ('web01 10.0.0.1\nweb02 10.0.0.2 2001:db8::2', 'hostname,ip\nweb01,10.0.0.1',
                     '[{"name":"web01","ip":"10.0.0.1","natIP":"203.0.113.9"}]'):
            with self.subTest(text=text):
                inventory = sos.parse_inventory(text, 'x')
                self.assertTrue(all(not s.has_topology() for s in inventory.servers))
        gcp = sos.parse_inventory('[{"name":"web01","ip":"10.0.0.1","natIP":"203.0.113.9"}]', 'x.json')
        self.assertEqual(gcp.servers[0].ips, ['10.0.0.1', '203.0.113.9'])
        k8s = sos.parse_inventory(json.dumps([{'name': 'web01', 'ip': '10.0.0.1', 'ports': [
            {'containerPort': 80, 'protocol': 'TCP'}]}]), 'x.json')
        self.assertEqual((k8s.servers[0].tls_ports, k8s.warnings), ([], []))

    def test_terminates_tls_given_both_ways_keeps_yes_and_warns(self):
        for text in ('web01 10.0.0.1 terminates_tls=no\nweb01 10.0.0.1 terminates_tls=yes',
                     'web01 10.0.0.1 terminates_tls=yes\nweb01 10.0.0.1 terminates_tls=no',
                     'web01 10.0.0.1 terminates_tls=no terminates_tls=yes'):
            with self.subTest(text=text):
                inventory = sos.parse_inventory(text, 'x.txt')
                self.assertEqual([(s.name, s.terminates_tls) for s in inventory.servers], [('web01', True)])
                self.assertEqual([(w.code, w.reason) for w in inventory.warnings], [('TOPOLOGY', 'conflict')])
                self.assertIn('yes is kept', str(inventory.warnings[0]))
        self.assertEqual(sos.parse_inventory('web01 10.0.0.1 terminates_tls=no\nweb01 10.0.0.1 '
                                             'terminates_tls=off', 'x.txt').warnings, [])
        # two -t files: the same rule
        d = tempfile.mkdtemp(prefix='ds-conflict-')
        try:
            a, b = os.path.join(d, 'a.txt'), os.path.join(d, 'b.txt')
            Path(a).write_text('web01 10.0.0.1 terminates_tls=no\n', encoding='utf-8')
            Path(b).write_text('web01 10.0.0.1 terminates_tls=yes\n', encoding='utf-8')
            servers, warnings = sos.load_targets([a, b])
            self.assertEqual([(s.name, s.terminates_tls) for s in servers], [('web01', True)])
            self.assertEqual([(w.code, w.reason) for w in warnings], [('TOPOLOGY', 'conflict')])
        finally:
            for name in os.listdir(d):
                os.remove(os.path.join(d, name))
            os.rmdir(d)

    def test_backends_by_name_and_address_across_lines_and_files(self):
        inventory = sos.parse_inventory('\n'.join([
            'LB01 203.0.113.2 Backends=WEB01 terminatesTls=Yes', 'lb01 203.0.113.2 backends=10.0.0.22',
            'web01 10.0.0.21 terminates-tls=off', '10.0.0.22', 'web03 10.0.0.23 terminates_tls=0']),
            'x.txt')
        self.assertEqual([(s.name, s.backends, s.terminates_tls) for s in inventory.servers], [
            ('LB01', ['web01', '10.0.0.22'], True), ('web01', [], False), ('10.0.0.22', [], None),
            ('web03', [], False)])
        self.assertEqual(sos.TOPOLOGY_KEYS, ('ports', 'terminates_tls', 'vip', 'backends', 'nat'))

    def test_the_web_apps_targets_txt_reads_back_to_the_same_topology(self):
        # tests/fixtures/topology/targets.txt is what the web app writes for inventory.txt
        # (views/inventory.js targetsText, tests/js/topology.test.js): the ports= as ip:port
        # tokens, the other keys as they are. The CLI scans the same endpoints and skips and
        # groups the same servers.
        inventory = sos.parse_inventory((TOPOLOGY / 'targets.txt').read_text(encoding='utf-8'),
                                        'targets.txt')
        self.assertEqual(inventory.warnings, [])
        source = sos.parse_inventory((TOPOLOGY / 'inventory.txt').read_text(encoding='utf-8'),
                                     'inventory.txt')

        def scanned(inv):
            return {s.name: (topology_endpoints(s), s.gets_certificate, s.vips, s.nats, s.backends)
                    for s in inv.servers}
        self.assertEqual(scanned(inventory), scanned(source))


if __name__ == '__main__':
    unittest.main()
