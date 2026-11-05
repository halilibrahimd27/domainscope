"""Tests for cli/ip_scan.py (stdlib unittest; no Internet access needed).

Everything runs against 127.0.0.1 (a listening socket, a closed port, one ping when this
machine allows it) or through injected fakes for the ping, the ARP table, TCP, reverse DNS and
the web header, so nothing leaves the machine. Only loopback, documentation ranges
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), private ranges and example names appear.
Only 127.0.0.1 is ever bound or connected to: macOS has no other loopback address.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import socket
import subprocess
import struct
import sys
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'ip_scan.py'


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


ips = _load('ip_scan', CLI_PATH)

T0 = datetime(2026, 11, 5, 9, 0, 0, tzinfo=timezone.utc)


def clock(step_seconds: float = 3.0):
    """A fake `now` for run_scan: T0, then T0 + step on the next call."""
    calls = [0]

    def now() -> datetime:
        calls[0] += 1
        return T0 + timedelta(seconds=step_seconds * (calls[0] - 1))
    return now


@contextlib.contextmanager
def listening():
    """A TCP server on 127.0.0.1 -> (open port, a port nothing listens on)."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(('127.0.0.1', 0))
    srv.listen(16)
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(('127.0.0.1', 0))
    closed = probe.getsockname()[1]
    probe.close()
    try:
        yield srv.getsockname()[1], closed
    finally:
        srv.close()


class FakeSweeper:
    def __init__(self, replies: Optional[Dict[str, float]] = None, unreachable=(), method: str = 'dgram',
                 why: str = '') -> None:
        self.method = method
        self.why = why
        self._replies = replies or {}
        self._unreachable = set(unreachable)
        self.asked: List[str] = []
        self.closed = False

    def sweep(self, addresses, timeout, rounds=2, stop=None, workers=8):
        self.asked = list(addresses)
        return ({ip: rtt for ip, rtt in self._replies.items() if ip in addresses},
                {ip for ip in self._unreachable if ip in addresses})

    def close(self) -> None:
        self.closed = True


def fake_scan(blocks, ports=(22, 80, 443), replies=None, unreachable=(), table=None, tcp=None, ptr=None, web=None,
              method='dgram', arp_method='proc', **kw):
    """run_scan with every probe faked; returns (report, the TCP calls made, the sweeper)."""
    calls: List[Tuple[str, int]] = []
    lock = threading.Lock()
    tcp = tcp or {}

    def fake_tcp(ip, port, timeout):
        with lock:
            calls.append((ip, port))
        return tcp.get((ip, port), tcp.get(ip, ips.T_TIMEOUT))

    sweeper = FakeSweeper(replies, unreachable, method=method)
    report = ips.run_scan(
        blocks, list(ports), timeout=0.1, workers=4, tcp=fake_tcp,
        sweeper_factory=lambda: sweeper,
        arp_reader=lambda: (dict(table) if table is not None else None, arp_method if table is not None else 'unavailable'),
        ptr_lookup=lambda ip: list((ptr or {}).get(ip, [])),
        web_lookup=lambda ip, port, tls, timeout: (web or {}).get((ip, port)),
        now=clock(), **kw)
    return report, calls, sweeper


def by_ip(report) -> Dict[str, object]:
    return {r.ip: r for r in report.results}


class TargetsTests(unittest.TestCase):
    def blocks(self, *tokens, **kw):
        return ips.parse_targets(list(tokens), **kw)

    def test_a_network_marks_its_network_and_broadcast_addresses(self):
        blocks, addresses = self.blocks('192.0.2.0/29')
        self.assertEqual([b.text for b in blocks], ['192.0.2.0/29'])
        self.assertEqual(len(addresses), 8)
        self.assertEqual(ips.reserved_role('192.0.2.0', blocks), 'network')
        self.assertEqual(ips.reserved_role('192.0.2.7', blocks), 'broadcast')
        self.assertIsNone(ips.reserved_role('192.0.2.1', blocks))

    def test_host_bits_are_masked_and_31_32_have_no_reserved_address(self):
        blocks, addresses = self.blocks('192.0.2.77/24')
        self.assertEqual(blocks[0].text, '192.0.2.0/24')
        self.assertEqual(addresses[0], '192.0.2.0')
        blocks, addresses = self.blocks('198.51.100.4/31', '203.0.113.9/32')
        self.assertEqual(addresses, ['198.51.100.4', '198.51.100.5', '203.0.113.9'])
        self.assertEqual([b.kind for b in blocks], ['cidr', 'ip'])
        self.assertTrue(all(ips.reserved_role(a, blocks) is None for a in addresses))

    def test_ranges_long_short_spaced_and_en_dash(self):
        for text in ('192.0.2.10-192.0.2.13', '192.0.2.10-13', '192.0.2.10 - 192.0.2.13', '192.0.2.10 – 13'):
            blocks, addresses = self.blocks(text)
            self.assertEqual(addresses, ['192.0.2.10', '192.0.2.11', '192.0.2.12', '192.0.2.13'], text)
            self.assertEqual(blocks[0].text, '192.0.2.10-192.0.2.13')
            self.assertIsNone(ips.reserved_role('192.0.2.10', blocks))

    def test_overlaps_count_once_and_keep_order(self):
        blocks, addresses = self.blocks('192.0.2.4/30', '192.0.2.5', '192.0.2.6-8', '192.0.2.4/30')
        self.assertEqual(len(blocks), 3)
        self.assertEqual(addresses, ['192.0.2.4', '192.0.2.5', '192.0.2.6', '192.0.2.7', '192.0.2.8'])

    def test_what_is_not_a_target_is_a_usage_error(self):
        for bad, needle in (('2001:db8::1', 'IPv6'), ('2001:db8::/64', 'IPv6'), ('192.0.2.20-10', 'ends before'),
                            ('192.0.2.300', 'not an IPv4'), ('db.example.com', 'not an IPv4'),
                            ('192.0.2.0/33', 'not a network'), ('192.0.2.1-400', 'not an address range')):
            with self.assertRaises(ips.UsageError, msg=bad) as ctx:
                self.blocks(bad)
            self.assertIn(needle, str(ctx.exception), bad)

    def test_the_address_cap(self):
        with self.assertRaises(ips.UsageError) as ctx:
            self.blocks('10.0.0.0/16')
        self.assertIn('--max-addresses', str(ctx.exception))
        blocks, addresses = self.blocks('10.0.0.0/16', max_addresses=65536)
        self.assertEqual(len(addresses), 65536)

    def test_a_targets_file_with_comments_and_several_per_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ranges.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('# the office\n192.0.2.0/30, 198.51.100.7  # printer\n\n203.0.113.1-2\n')
            blocks, addresses = ips.parse_targets([], files=[path])
        self.assertEqual([b.text for b in blocks], ['192.0.2.0/30', '198.51.100.7', '203.0.113.1-203.0.113.2'])
        self.assertEqual(len(addresses), 7)
        with self.assertRaises(ips.UsageError):
            ips.parse_targets([], files=[os.path.join(ROOT, 'no-such-ranges.txt')])

    def test_ports(self):
        self.assertEqual(ips.parse_ports('default'), list(ips.DEFAULT_PORTS))
        self.assertEqual(ips.parse_ports('quick'), list(ips.QUICK_PORTS))
        self.assertEqual(ips.parse_ports('none'), [])
        self.assertEqual(ips.parse_ports('22, 80,443,8000-8002,80'), [22, 80, 443, 8000, 8001, 8002])
        for bad in ('0', '70000', 'http', '90-80', '1-100'):
            with self.assertRaises(ips.UsageError, msg=bad):
                ips.parse_ports(bad)


class VerdictTests(unittest.TestCase):
    def test_any_answer_is_used(self):
        for kw, reason in (({'rtt_ms': 0.4}, 'icmp'), ({'open_ports': [22]}, 'tcp-open'),
                           ({'refused_ports': [80]}, 'tcp-refused'), ({'mac': '00:11:22:33:44:55'}, 'arp')):
            state, reasons, confirmed = ips.verdict(ips.HostResult('192.0.2.5', **kw))
            self.assertEqual((state, reasons, confirmed), ('used', [reason], False))

    def test_a_dns_name_without_an_answer_is_claimed_unless_it_spells_the_address(self):
        r = ips.HostResult('10.0.5.7', ptr=['old-db.corp.example'])
        self.assertEqual(ips.verdict(r), ('claimed', ['ptr'], False))
        r = ips.HostResult('10.0.5.7', ptr=['10-0-5-7.dhcp.example'], arp_incomplete=True)
        self.assertEqual(ips.verdict(r), ('free', ['arp-incomplete'], True))
        r = ips.HostResult('10.0.5.7', ptr=['old-db.corp.example'], open_ports=[22])
        self.assertEqual(ips.verdict(r), ('used', ['tcp-open', 'ptr'], False))

    def test_free_is_confirmed_by_arp_or_a_router_only(self):
        self.assertEqual(ips.verdict(ips.HostResult('192.0.2.5')), ('free', [], False))
        self.assertEqual(ips.verdict(ips.HostResult('192.0.2.5', unreachable=True)), ('free', ['unreachable'], True))
        self.assertEqual(ips.verdict(ips.HostResult('192.0.2.5', reserved='network', rtt_ms=1.0)), ('reserved', [], False))

    def test_templated_ptr(self):
        for name, ip in (('10-0-5-7.dhcp.example', '10.0.5.7'), ('ip-203-0-113-5.provider.example', '203.0.113.5'),
                         ('7.5.0.10.static.example', '10.0.5.7'), ('host010000005007.example', '10.0.5.7'),
                         ('10_0_5_7.example', '10.0.5.7')):
            self.assertTrue(ips.templated_ptr(name, ip), name)
        for name, ip in (('db3.corp.example', '10.0.5.7'), ('110-0-5-7.example', '10.0.5.7'),
                         ('10-0-5-77.example', '10.0.5.7'), ('', '10.0.5.7')):
            self.assertFalse(ips.templated_ptr(name, ip), name)


class IcmpTests(unittest.TestCase):
    def test_checksum_and_echo_request(self):
        packet = ips.echo_request(0x1234, 7, b'abcdefgh')
        self.assertEqual(ips.icmp_checksum(packet), 0)
        self.assertEqual(packet[0], 8)
        self.assertEqual(struct.unpack('!HH', packet[4:8]), (0x1234, 7))
        self.assertEqual(ips.icmp_checksum(b'\x00\x01\xf2'), ips.icmp_checksum(b'\x00\x01\xf2\x00'))

    def test_parse_with_and_without_an_ip_header(self):
        reply = b'\x00\x00\x00\x00\x12\x34\x00\x07' + b'payload!'
        self.assertEqual(ips.parse_icmp(reply), (0, 0, b'payload!'))
        ip_header = bytes([0x45, 0, 0, 36, 0, 0, 0, 0, 64, 1, 0, 0]) + socket.inet_aton('192.0.2.9') + socket.inet_aton('198.51.100.1')
        self.assertEqual(ips.parse_icmp(ip_header + reply), (0, 0, b'payload!'))
        self.assertIsNone(ips.parse_icmp(b'\x00\x00'))
        self.assertIsNone(ips.parse_icmp(bytes([0x4f]) + b'\x00' * 22))

    def test_the_target_of_a_host_unreachable(self):
        quoted = bytes([0x45, 0, 0, 28, 0, 0, 0, 0, 64, 1, 0, 0]) + socket.inet_aton('198.51.100.1') + socket.inet_aton('192.0.2.44')
        self.assertEqual(ips.unreachable_target(quoted + b'\x08\x00\x00\x00\x00\x00\x00\x00'), '192.0.2.44')
        self.assertIsNone(ips.unreachable_target(b'\x60' + b'\x00' * 30))

    def test_ping_127_0_0_1_when_this_machine_allows_it(self):
        sweeper = ips.IcmpSweeper()
        try:
            if sweeper.method == ips.UNAVAILABLE:
                self.skipTest('no ping allowed here: %s' % sweeper.why)
            replies, gone = sweeper.sweep(['127.0.0.1'], 2.0, workers=2)
        finally:
            sweeper.close()
        self.assertIn('127.0.0.1', replies)
        self.assertGreaterEqual(replies['127.0.0.1'], 0.0)
        self.assertFalse(gone)


class ArpTests(unittest.TestCase):
    def test_normalize_mac(self):
        self.assertEqual(ips.normalize_mac('0:1b:2c:3:4:5'), '00:1b:2c:03:04:05')
        self.assertEqual(ips.normalize_mac('00-1B-2C-03-04-05'), '00:1b:2c:03:04:05')
        for bad in ('(incomplete)', '00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff', '01:00:5e:00:00:fb', '', '00:11:22:33:44'):
            self.assertIsNone(ips.normalize_mac(bad), bad)

    def test_proc_net_arp(self):
        text = ('IP address       HW type     Flags       HW address            Mask     Device\n'
                '10.0.5.1         0x1         0x2         00:11:22:33:44:55     *        eth0\n'
                '10.0.5.9         0x1         0x0         00:00:00:00:00:00     *        eth0\n'
                '10.0.5.10        0x1         0x6         00:11:22:33:44:66     *        eth0\n'
                'garbage line\n')
        self.assertEqual(ips.parse_proc_arp(text), {'10.0.5.1': '00:11:22:33:44:55', '10.0.5.9': None,
                                                    '10.0.5.10': '00:11:22:33:44:66'})

    def test_arp_command(self):
        text = ('? (10.0.5.1) at 0:11:22:33:44:55 on en0 ifscope [ethernet]\n'
                '? (10.0.5.9) at (incomplete) on en0 ifscope [ethernet]\n'
                '? (10.0.5.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]\n'
                'gw.example (10.0.5.254) at a:b:c:d:e:f on en0 permanent [ethernet]\n')
        self.assertEqual(ips.parse_arp_command(text), {'10.0.5.1': '00:11:22:33:44:55', '10.0.5.9': None,
                                                       '10.0.5.255': None, '10.0.5.254': '0a:0b:0c:0d:0e:0f'})

    def test_windows_ip_net_table(self):
        def row(ip, mac, kind):
            phys = bytes.fromhex(mac.replace(':', '')) if mac else b''
            addr = struct.unpack('<I', socket.inet_aton(ip))[0]
            return struct.pack('<II8sII', 11, len(phys), phys.ljust(8, b'\x00'), addr, kind)
        buf = struct.pack('<I', 3) + row('10.0.5.1', '00:11:22:33:44:55', 3) + row('10.0.5.9', '', 2) \
            + row('10.0.5.20', '00:11:22:33:44:77', 4)
        self.assertEqual(ips.parse_windows_ipnettable(buf), {'10.0.5.1': '00:11:22:33:44:55', '10.0.5.9': None,
                                                             '10.0.5.20': '00:11:22:33:44:77'})
        self.assertEqual(ips.parse_windows_ipnettable(b''), {})
        self.assertEqual(ips.parse_windows_ipnettable(struct.pack('<I', 5)), {})


class TcpTests(unittest.TestCase):
    def test_open_and_refused_on_127_0_0_1(self):
        with listening() as (open_port, closed_port):
            self.assertEqual(ips.tcp_probe('127.0.0.1', open_port, 5.0), ips.T_OPEN)
            # Windows retries a reset SYN for about a second before it calls the port refused
            self.assertEqual(ips.tcp_probe('127.0.0.1', closed_port, 5.0), ips.T_REFUSED)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.blocks, _ = ips.parse_targets(['10.0.5.0/29'])

    def test_every_kind_of_answer(self):
        report, calls, sweeper = fake_scan(
            self.blocks, replies={'10.0.5.1': 0.6},
            table={'10.0.5.1': '00:11:22:33:44:55', '10.0.5.2': None, '10.0.5.3': '00:11:22:33:44:66'},
            tcp={('10.0.5.1', 22): 'open', ('10.0.5.1', 80): 'open', ('10.0.5.4', 443): 'refused',
                 ('10.0.5.6', 22): 'unreachable'},
            ptr={'10.0.5.5': ['old-db.corp.example'], '10.0.5.6': ['10-0-5-6.dhcp.example']},
            web={('10.0.5.1', 80): 'nginx'})
        r = by_ip(report)
        self.assertEqual(r['10.0.5.0'].state, 'reserved')
        self.assertEqual(r['10.0.5.7'].state, 'reserved')
        self.assertEqual((r['10.0.5.1'].state, r['10.0.5.1'].reasons), ('used', ['icmp', 'tcp-open', 'arp']))
        self.assertEqual(r['10.0.5.1'].open_ports, [22, 80])
        self.assertEqual(r['10.0.5.1'].web, {80: 'nginx'})
        self.assertEqual((r['10.0.5.2'].state, r['10.0.5.2'].confirmed), ('free', True))
        self.assertTrue(r['10.0.5.2'].skipped_tcp)
        self.assertEqual(r['10.0.5.3'].reasons, ['arp'])
        self.assertEqual(r['10.0.5.4'].reasons, ['tcp-refused'])
        self.assertEqual(r['10.0.5.5'].state, 'claimed')
        self.assertEqual((r['10.0.5.6'].state, r['10.0.5.6'].reasons), ('free', ['unreachable']))
        # never probed: the reserved addresses; the address no device answered ARP for
        self.assertNotIn('10.0.5.0', sweeper.asked)
        self.assertFalse([c for c in calls if c[0] in ('10.0.5.0', '10.0.5.7', '10.0.5.2')])
        self.assertTrue(sweeper.closed)
        self.assertEqual(report.counts(), {'used': 3, 'claimed': 1, 'free': 2, 'reserved': 2,
                                           'freeConfirmed': 2, 'addresses': 8})
        self.assertEqual(report.free(), ['10.0.5.2', '10.0.5.6'])

    def test_without_ping_the_first_arp_table_is_not_used_to_skip(self):
        report, calls, _ = fake_scan(self.blocks, method='unavailable', table={'10.0.5.2': None})
        self.assertIn(('10.0.5.2', 22), calls)
        self.assertTrue(by_ip(report)['10.0.5.2'].confirmed)  # the table read after TCP counts
        self.assertTrue(any('no ping' in w for w in report.warnings))

    def test_no_arp_table_never_confirms_free(self):
        report, _calls, _ = fake_scan(self.blocks, table=None)
        self.assertEqual(report.counts()['freeConfirmed'], 0)
        self.assertEqual(report.methods['arp'], 'unavailable')
        self.assertTrue(any('ARP table' in w for w in report.warnings))

    def test_turned_off(self):
        report, calls, sweeper = fake_scan(self.blocks, ports=(), icmp=False, arp=False, ptr=False, web=False)
        self.assertEqual(calls, [])
        self.assertEqual(sweeper.asked, [])
        self.assertEqual(report.methods['icmp'], 'off')
        self.assertEqual(report.methods['arp'], 'off')
        self.assertEqual(report.counts()['free'], 6)

    def test_the_json_report(self):
        report, _calls, _ = fake_scan(self.blocks, replies={'10.0.5.1': 0.6}, table={'10.0.5.2': None},
                                      ptr={'10.0.5.1': ['gw.corp.example']})
        doc = report_doc = ips.report_to_dict(report)
        self.assertEqual(doc['schema'], 'domainscope.ip-scan/1')
        self.assertEqual(doc['tool'], 'ip_scan')
        self.assertEqual(doc['startedAt'], '2026-11-05T09:00:00Z')
        self.assertEqual(doc['targets'], ['10.0.5.0/29'])
        self.assertEqual(doc['summary'], {'addresses': 8, 'used': 1, 'claimed': 0, 'free': 5,
                                          'freeConfirmed': 1, 'reserved': 2})
        first = [r for r in report_doc['results'] if r['ip'] == '10.0.5.1'][0]
        self.assertEqual(first, {
            'ip': '10.0.5.1', 'state': 'used', 'confirmed': False, 'reasons': ['icmp', 'ptr'], 'reserved': None,
            'rttMs': 0.6, 'open': [], 'refused': [], 'mac': None, 'onLink': False, 'ptr': ['gw.corp.example'],
            'ptrTemplated': False, 'web': {}, 'errors': []})
        json.dumps(doc)

    def test_csv_is_spreadsheet_safe_and_text_has_a_summary(self):
        report, _calls, _ = fake_scan(self.blocks, ptr={'10.0.5.3': ['=cmd|calc!A1.example']},
                                      replies={'10.0.5.1': 0.6})
        text = ips.render_csv(report)
        self.assertTrue(text.startswith('ip,state,confirmed,reasons,ping_ms'))
        self.assertIn("'=cmd|calc!A1.example", text)
        out = ips.render_text(report)
        self.assertIn('Summary: 1 used · 1 silent with a DNS name · 4 free', out)
        self.assertIn('Free: 10.0.5.2, 10.0.5.4-10.0.5.6', out)
        self.assertIn('nothing confirmed "free"', out)
        self.assertNotIn('10.0.5.1 ', ips.render_text(report, show='free'))

    def test_free_ranges(self):
        self.assertEqual(ips.free_ranges(['10.0.5.4', '10.0.5.2', '10.0.5.3', '10.0.5.9', '10.0.6.0', '10.0.5.255']),
                         ['10.0.5.2-10.0.5.4', '10.0.5.9', '10.0.5.255-10.0.6.0'])
        self.assertEqual(ips.free_ranges([]), [])


def _node_major() -> int:
    node = shutil.which('node')
    if not node:
        return 0
    try:
        text = subprocess.run([node, '--version'], capture_output=True, text=True, timeout=20).stdout
    except (OSError, subprocess.SubprocessError):
        return 0
    match = re.match(r'v(\d+)', text.strip())
    return int(match.group(1)) if match else 0


class WebAppParityTests(unittest.TestCase):
    """The web app's IP Scan view (assets/js/lib/ipscan.js) reads what this CLI writes."""

    @unittest.skipUnless(_node_major() >= 22, 'needs Node 22+ to run assets/js/lib/ipscan.js')
    def test_the_web_app_reads_the_report_with_the_same_states(self):
        blocks, _ = ips.parse_targets(['10.0.5.0/29'])
        report, _calls, _ = fake_scan(
            blocks, replies={'10.0.5.1': 0.6}, table={'10.0.5.2': None, '10.0.5.3': '00:11:22:33:44:66'},
            tcp={('10.0.5.4', 443): 'refused'}, ptr={'10.0.5.5': ['old-db.corp.example'], '10.0.5.6': ['10-0-5-6.dhcp.example']},
            web={('10.0.5.1', 80): 'nginx'})
        doc = ips.report_to_dict(report)
        script = ('import { readScanReport, parseScanRange, addressMap } from %s;\n'
                  'const read = readScanReport(process.argv[1], { name: "scan.json" });\n'
                  'if (!read.ok) { console.log(JSON.stringify(read)); process.exit(0); }\n'
                  'const map = addressMap({ range: parseScanRange(read.report.targets.join(" ")), reports: [read.report] });\n'
                  'console.log(JSON.stringify({ ok: true, states: Object.fromEntries(map.rows.map((r) => [r.ip, [r.state, r.confirmed]])), '
                  'counts: map.counts }));\n'
                  % json.dumps((ROOT / 'assets' / 'js' / 'lib' / 'ipscan.js').as_uri()))
        proc = subprocess.run([shutil.which('node'), '--input-type=module', '-e', script, json.dumps(doc)],
                              capture_output=True, text=True, encoding='utf-8', timeout=60, cwd=str(ROOT))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertTrue(out['ok'], out)
        expected = {r['ip']: [r['state'], r['confirmed']] for r in doc['results']}
        self.assertEqual(out['states'], expected)
        self.assertEqual({k: out['counts'][k] for k in ('used', 'claimed', 'free', 'reserved', 'freeConfirmed')},
                         {k: doc['summary'][k] for k in ('used', 'claimed', 'free', 'reserved', 'freeConfirmed')})

    def test_the_fixtures_of_the_web_app_are_reports_of_this_version(self):
        for name in ('report-a.json', 'report-b.json'):
            with open(ROOT / 'tests' / 'fixtures' / 'ipscan' / name, encoding='utf-8') as handle:
                doc = json.load(handle)
            self.assertEqual(doc['schema'], ips.SCHEMA, name)
            self.assertEqual(sorted(doc['results'][0]), sorted(ips.result_to_dict(ips.HostResult('192.0.2.1'))), name)
            for row in doc['results']:
                result = ips.HostResult(row['ip'], reserved=row['reserved'], rtt_ms=row['rttMs'], open_ports=row['open'],
                                        refused_ports=row['refused'], mac=row['mac'], ptr=row['ptr'],
                                        arp_incomplete=ips.R_NO_ARP in row['reasons'],
                                        unreachable=ips.R_UNREACHABLE in row['reasons'])
                self.assertEqual([result.state, result.confirmed], [row['state'], row['confirmed']], '%s %s' % (name, row['ip']))


class MainTests(unittest.TestCase):
    def run_main(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = ips.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_a_used_address_a_report_and_expect_free(self):
        with listening() as (port, _closed), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'scan.json')
            base = ['127.0.0.1', '--ports', str(port), '--no-ping', '--no-arp', '--no-ptr', '--no-web',
                    '--timeout', '2', '--no-color']
            code, out, err = self.run_main(*base, '--json', path)
            self.assertEqual(code, 0, err)
            with open(path, encoding='utf-8') as handle:
                doc = json.load(handle)
            self.assertEqual(doc['results'][0]['state'], 'used')
            self.assertEqual(doc['results'][0]['open'], [port])
            self.assertIn('127.0.0.1', out)
            self.assertIn('scan only networks you run', err)
            code, out, err = self.run_main(*base, '--expect-free')
            self.assertEqual(code, 1)
            self.assertIn('taken: 127.0.0.1 (used)', err)
            code, out, _err = self.run_main(*base, '--free', '-q')
            self.assertEqual((code, out), (0, ''))

    def test_usage_errors(self):
        for argv, needle in ((['192.0.2.1', '--json', '-', '--free'], 'cannot share stdout'),
                             (['192.0.2.1', '--timeout', '0'], '--timeout'),
                             (['192.0.2.1', '--workers', '0'], '--workers'),
                             (['192.0.2.1', '--ports', 'http'], '--ports'),
                             ([], 'no targets'),
                             (['example.com'], 'not an IPv4')):
            code, _out, err = self.run_main(*argv)
            self.assertEqual(code, 2, argv)
            self.assertIn(needle, err, argv)
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'same')
            code, _out, err = self.run_main('192.0.2.1', '--json', path, '--csv', path)
            self.assertEqual(code, 2)
            self.assertIn('same file', err)

    def test_a_report_not_written_is_exit_3_and_a_crash_exit_70(self):
        with listening() as (port, _closed):
            base = ['127.0.0.1', '--ports', str(port), '--no-ping', '--no-arp', '--no-ptr', '--no-web', '-q']
            code, _out, err = self.run_main(*base, '--json', os.path.join(str(ROOT), 'no-such-dir', 'x', 'scan.json'))
            self.assertEqual(code, 3)
            self.assertIn('cannot write', err)
        with mock.patch.object(ips, 'run_scan', side_effect=RuntimeError('boom')):
            code, _out, err = self.run_main('192.0.2.1', '-q')
        self.assertEqual(code, 70)
        self.assertIn('internal error: RuntimeError: boom', err)


if __name__ == '__main__':
    unittest.main()
