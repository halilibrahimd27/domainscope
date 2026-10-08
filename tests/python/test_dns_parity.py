"""Tests for cli/dns_parity.py (stdlib unittest; no Internet access needed).

The integration tests start tiny authoritative DNS servers on 127.0.0.1 (UDP and TCP on the
same ephemeral port) that answer from a table, with their own message encoder: names
compressed against the question, referrals for a delegation, truncation over UDP, REFUSED,
answers without the authoritative flag, and one that never answers.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'dns_parity.py'


def _load_cli():
    spec = importlib.util.spec_from_file_location('dns_parity', str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules['dns_parity'] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


dp = _load_cli()

CODES = {'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33, 'CAA': 257,
         'LOC': 29, 'NAPTR': 35, 'OPENPGPKEY': 61, 'SVCB': 64, 'HTTPS': 65, 'URI': 256, 'TYPE65534': 65534}


# ============================================================================ a test server

def enc_name(name: str) -> bytes:
    out = b''
    for label in [l for l in name.rstrip('.').split('.') if l]:
        out += bytes([len(label)]) + label.encode('ascii')
    return out + b'\x00'


def rdata(rtype: str, value) -> bytes:
    """Wire rdata from a test value (its own encoder: never the CLI's); bytes are the rdata."""
    if isinstance(value, bytes):
        return value
    if rtype == 'A':
        return socket.inet_aton(value)
    if rtype == 'AAAA':
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype in ('NS', 'CNAME'):
        return enc_name(value)
    if rtype == 'MX':
        return struct.pack('!H', value[0]) + enc_name(value[1])
    if rtype == 'SRV':
        return struct.pack('!HHH', *value[:3]) + enc_name(value[3])
    if rtype == 'TXT':
        return b''.join(bytes([len(s)]) + s for s in (v if isinstance(v, bytes) else v.encode() for v in value))
    if rtype == 'CAA':
        flags, tag, val = value
        return bytes([flags, len(tag)]) + tag.encode() + val.encode()
    if rtype == 'SOA':
        mname, rname, serial = value
        return enc_name(mname) + enc_name(rname) + struct.pack('!IIIII', serial, 7200, 900, 1209600, 300)
    raise ValueError(rtype)


class FakeAuthority:
    """An authoritative server for ``origin`` answering from ``records``:
    {(name, TYPE): [(ttl, value), ...]}; ``cuts``: {child: ([ns targets], {glue name: ip})}."""

    def __init__(self, origin: str, records: Dict[Tuple[str, str], List], serial: int = 7,
                 cuts: Optional[Dict[str, Tuple[List[str], Dict[str, str]]]] = None,
                 refuse: bool = False, authoritative: bool = True, silent: bool = False,
                 truncate: Tuple[str, ...] = (), servfail: Tuple[str, ...] = ()) -> None:
        self.origin = origin
        self.records = dict(records)
        self.records.setdefault((origin, 'SOA'), [(3600, ('ns1.example.net', 'hostmaster.example.com', serial))])
        self.cuts = cuts or {}
        self.refuse = refuse
        self.authoritative = authoritative
        self.silent = silent
        self.truncate = set(truncate)
        self.servfail = set(servfail)  # record types answered with SERVFAIL
        self.asked = []  # type: List[Tuple[str, str, str]]
        # TCP first: its ephemeral port is never in a range Windows reserves for TCP (Hyper-V,
        # Docker), which a UDP ephemeral port can be in. Windows hands TCP ports out in sequence,
        # so a run of them can sit inside one 100-port block reserved for UDP: after a few tries,
        # ports below every system's ephemeral range are tried instead.
        for want in [0] * 8 + random.sample(range(20000, 32000), 200):
            tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                tcp.bind(('127.0.0.1', want))
                udp.bind(('127.0.0.1', tcp.getsockname()[1]))
            except OSError:
                tcp.close()
                udp.close()
                continue
            self.tcp, self.udp, self.port = tcp, udp, tcp.getsockname()[1]
            break
        else:
            raise OSError('no local port free for both UDP and TCP')
        self.tcp.listen(16)
        self.alive = True
        threading.Thread(target=self._serve_udp, daemon=True).start()
        threading.Thread(target=self._serve_tcp, daemon=True).start()

    def close(self) -> None:
        self.alive = False
        for sock in (self.udp, self.tcp):
            try:
                sock.close()
            except OSError:
                pass

    # --- answering ---------------------------------------------------------------------
    def owners(self):
        return {name for name, _ in self.records}

    def answer(self, query: bytes, over: str) -> Optional[bytes]:
        msg_id, _flags, qd = struct.unpack('!HHH', query[:6])
        pos, labels = 12, []
        while query[pos]:
            labels.append(query[pos + 1:pos + 1 + query[pos]].decode('ascii').lower())
            pos += 1 + query[pos]
        qname = '.'.join(labels)
        qtype = struct.unpack('!H', query[pos + 1:pos + 3])[0]
        rtype = {v: k for k, v in CODES.items()}.get(qtype, 'TYPE%d' % qtype)
        self.asked.append((qname, rtype, over))
        question = query[12:pos + 5]
        aa, rcode = self.authoritative, 0
        answers, authority, additional = [], [], []

        def rr(name, t, ttl, value, pointer=False):
            owner = b'\xc0\x0c' if pointer else enc_name(name)
            data = rdata(t, value)
            return owner + struct.pack('!HHIH', CODES[t], 1, ttl, len(data)) + data

        if self.refuse:
            rcode, aa = 5, False
        elif rtype in self.servfail:
            rcode = 2
        else:
            cut = next((c for c in self.cuts if qname == c or qname.endswith('.' + c)), None)
            if cut and not (qname == cut and rtype == 'DS'):
                aa = False
                targets, glue = self.cuts[cut]
                authority = [rr(cut, 'NS', 3600, t) for t in targets]
                additional = [rr(n, 'A', 3600, ip) for n, ip in glue.items()]
            elif (qname, rtype) in self.records:
                answers = [rr(qname, rtype, ttl, v, pointer=True) for ttl, v in self.records[(qname, rtype)]]
            elif rtype != 'CNAME' and (qname, 'CNAME') in self.records:
                ttl, target = self.records[(qname, 'CNAME')][0]
                answers = [rr(qname, 'CNAME', ttl, target, pointer=True)]
                for ttl2, v in self.records.get((target, rtype), []):
                    answers.append(rr(target, rtype, ttl2, v))
            elif qname not in self.owners() and not any(o.endswith('.' + qname) for o in self.owners()):
                rcode = 3
        tc = over == 'udp' and qname in self.truncate
        if tc:
            answers, authority, additional = [], [], []
        flags = 0x8000 | (0x0400 if aa else 0) | (0x0200 if tc else 0) | rcode
        header = struct.pack('!HHHHHH', msg_id, flags, 1, len(answers), len(authority), len(additional))
        return header + question + b''.join(answers + authority + additional)

    def _serve_udp(self) -> None:
        while self.alive:
            try:
                data, addr = self.udp.recvfrom(4096)
            except OSError:
                return
            if self.silent:
                continue
            reply = self.answer(data, 'udp')
            try:
                self.udp.sendto(reply, addr)
            except OSError:
                return

    def _serve_tcp(self) -> None:
        while self.alive:
            try:
                conn, _ = self.tcp.accept()
            except OSError:
                return
            with conn:
                try:
                    size = struct.unpack('!H', conn.recv(2))[0]
                    data = b''
                    while len(data) < size:
                        data += conn.recv(size - len(data))
                    reply = self.answer(data, 'tcp')
                    conn.sendall(struct.pack('!H', len(reply)) + reply)
                except (OSError, struct.error):
                    pass

    def ns(self, name: str = 'ns1.example.net') -> str:
        return '%s=127.0.0.1:%d' % (name, self.port)


def run_main(*args: str) -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = dp.main(list(args))
    return code, out.getvalue(), err.getvalue()


ZONE_TEXT = """\
$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.org. hostmaster.example.com. ( 2026092801 ; serial
                7200 900 1209600 300 )
@       86400 IN NS ns1.example.org.
@       86400 IN NS ns2.example.org.
@       300 IN A 192.0.2.10
@       IN MX 10 mail
@       IN TXT "v=spf1 mx -all"
@       IN CAA 0 issue "letsencrypt.org"
mail    600 IN A 198.51.100.25
www     IN CNAME @
old     IN A 198.51.100.30
long    IN TXT "part one " "part two"
_sip._tcp IN SRV 10 5 5060 sip.example.com.
dev     IN NS ns1.dev.example.com.
ns1.dev IN A 192.0.2.53
x.dev   IN A 192.0.2.54
@       IN DNSKEY 257 3 13 AAAA
"""

# A second $ORIGIN part way (RFC 1035 5.1): relative names in the data follow it.
SUB_ORIGIN_TEXT = """\
$ORIGIN example.com.
$TTL 3600
@       IN SOA ns1.example.org. hostmaster.example.com. 2026092801 7200 900 1209600 300
@       IN NS ns1.example.org.
@       IN MX 10 mail
mail    IN A 198.51.100.25
dev     IN NS ns1.dev
$ORIGIN dev.example.com.
ns1     IN A 192.0.2.53
x       IN A 192.0.2.54
$ORIGIN sub.example.com.
@       IN MX 10 mail
www     IN CNAME host
_sip._tcp IN SRV 10 5 5060 sip
host    IN A 192.0.2.20
mail    IN A 192.0.2.21
"""

GOOD = {
    ('example.com', 'NS'): [(86400, 'ns1.example.net'), (86400, 'ns2.example.net')],
    ('example.com', 'A'): [(300, '192.0.2.10')],
    ('example.com', 'MX'): [(3600, (10, 'mail.example.com'))],
    ('example.com', 'TXT'): [(3600, ['v=spf1 mx -all'])],
    ('example.com', 'CAA'): [(3600, (0, 'issue', 'letsencrypt.org'))],
    ('mail.example.com', 'A'): [(3600, '198.51.100.25')],
    ('www.example.com', 'CNAME'): [(3600, 'example.com')],
    ('long.example.com', 'TXT'): [(3600, ['part one part two'])],
    ('_sip._tcp.example.com', 'SRV'): [(3600, (10, 5, 5060, 'sip.example.com'))],
}
DEV_CUT = {'dev.example.com': (['ns1.dev.example.com'], {'ns1.dev.example.com': '192.0.2.53'})}


# ============================================================================ the zone file

class ZoneFileTests(unittest.TestCase):

    def test_bind_syntax(self):
        zone = dp.parse_zone(ZONE_TEXT, source='example.com.zone')
        self.assertEqual(zone.origin, 'example.com')
        by = {(r.name, r.rtype): r for r in zone.records}
        self.assertEqual(by[('example.com', 'SOA')].ttl, 3600)
        self.assertEqual(by[('example.com', 'NS')].ttl, 86400)
        self.assertEqual(by[('mail.example.com', 'A')].ttl, 600)
        self.assertEqual(by[('www.example.com', 'CNAME')].tokens[0].text, '@')
        self.assertEqual(dp.file_value(by[('www.example.com', 'CNAME')], 'example.com'), ('example.com', 'example.com.'))
        self.assertEqual(dp.file_value(by[('example.com', 'MX')], 'example.com'), ((10, 'mail.example.com'), '10 mail.example.com.'))
        self.assertEqual(dp.file_value(by[('long.example.com', 'TXT')], 'example.com')[0], (b'part one ', b'part two'))
        self.assertEqual(dp.file_value(by[('example.com', 'CAA')], 'example.com'),
                         ((0, 'issue', b'letsencrypt.org'), '0 issue "letsencrypt.org"'))
        self.assertEqual(dp.file_value(by[('_sip._tcp.example.com', 'SRV')], 'example.com')[0], (10, 5, 5060, 'sip.example.com'))
        self.assertEqual(zone.warnings, [])

    def test_blank_owners_ttl_units_class_order_escapes_and_cloudflare_tags(self):
        text = ('$ORIGIN example.net.\n@ 1h IN SOA ns1 h 1 2 3 4 5\n'
                'a IN 2d A 192.0.2.1\n  AAAA 2001:DB8::1\n'
                'txt TXT "semi;colon \\"q\\" \\065" plain\n'
                'p 1 IN A 192.0.2.2 ; cf_tags=team:x,cf-proxied:true\n'
                'f 1 IN CNAME t.example.org. ; cf_tags=cf-flatten-cname,cf-proxied:false\n'
                'r 60 IN A 192.0.2.3 ; AWS routing="WEIGHTED" weight=90\n'
                'al AWS ALIAS A d1.example.org. Z1 false\n')
        zone = dp.parse_zone(text)
        by = {(r.name, r.rtype): r for r in zone.records}
        self.assertEqual(by[('a.example.net', 'A')].ttl, 172800)
        self.assertEqual(dp.file_value(by[('a.example.net', 'AAAA')], 'example.net')[0], '2001:db8::1')
        self.assertEqual(dp.file_value(by[('txt.example.net', 'TXT')], 'example.net')[0], (b'semi;colon "q" A', b'plain'))
        self.assertEqual([by[('p.example.net', 'A')].proxied, by[('f.example.net', 'CNAME')].flatten,
                          by[('r.example.net', 'A')].routing, by[('al.example.net', 'ALIAS')].alias], [True, True, True, 'A'])
        self.assertTrue(zone.cloudflare)

    def test_directives_and_problems_are_warnings(self):
        zone = dp.parse_zone('$ORIGIN example.com.\n$INCLUDE part.zone\n$GENERATE 1-3 h$ A 192.0.2.$\n'
                             '@ SOA ns1 h 1 2 3 4 5\nbad "unterminated\nx IN BOGUS 1\nother.example.org. A 192.0.2.1\n'
                             'y IN A 192.0.2.9 (\n')
        text = '\n'.join(zone.warnings)
        for part in ('$INCLUDE part.zone is not followed', '$GENERATE is not expanded', 'never closed',
                     'unknown record type BOGUS', 'other.example.org is outside example.com'):
            self.assertIn(part, text)

    def test_origin_from_the_soa_or_the_command_line(self):
        self.assertEqual(dp.parse_zone('example.org. 300 IN SOA ns1.example.org. h. 1 2 3 4 5\n').origin, 'example.org')
        self.assertEqual(dp.parse_zone('@ 300 IN A 192.0.2.1\n', origin='Example.NET.').origin, 'example.net')
        with self.assertRaises(dp.UsageError):
            dp.parse_zone('www 300 IN A 192.0.2.1\n')

    def test_the_soa_owner_completes_the_relative_owners_after_it(self):
        zone = dp.parse_zone('example.org. 300 IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                             'example.org. 300 IN MX 10 mail\nmail 300 IN A 192.0.2.25\n')
        by = {(r.name, r.rtype): r for r in zone.records}
        self.assertEqual(sorted(by), [('example.org', 'MX'), ('example.org', 'SOA'), ('mail.example.org', 'A')])
        self.assertEqual(dp.file_value(by[('example.org', 'MX')], zone.origin)[0], (10, 'mail.example.org'))
        self.assertEqual(zone.warnings, [])
        path = ROOT / 'tests' / 'fixtures' / 'zones' / 'cpanel-example.com.db.txt'
        cpanel = dp.parse_zone(path.read_text(encoding='utf-8'), source=path.name)
        names = {(r.name, r.rtype) for r in cpanel.records}
        self.assertEqual(cpanel.origin, 'example.com')
        self.assertEqual(len(cpanel.records), 34, 'every record of the cPanel export, as zoneparse.js reads it')
        self.assertTrue({('mail.example.com', 'CNAME'), ('www.example.com', 'CNAME'), ('ftp.example.com', 'A')} <= names)
        self.assertEqual([w for w in cpanel.warnings if 'without an origin' in w], [])

    def test_a_second_origin_completes_the_relative_names_of_its_records(self):
        zone = dp.parse_zone(SUB_ORIGIN_TEXT)
        by = {(r.name, r.rtype): r for r in zone.records}
        value = lambda name, rtype: dp.file_value(by[(name, rtype)], zone.origin)
        self.assertEqual(zone.origin, 'example.com')
        self.assertEqual(value('www.sub.example.com', 'CNAME')[0], 'host.sub.example.com')
        self.assertEqual(value('sub.example.com', 'MX')[0], (10, 'mail.sub.example.com'))
        self.assertEqual(value('_sip._tcp.sub.example.com', 'SRV')[0], (10, 5, 5060, 'sip.sub.example.com'))
        self.assertEqual(value('example.com', 'MX')[0], (10, 'mail.example.com'), 'the first $ORIGIN still applies above')
        self.assertEqual(value('dev.example.com', 'NS')[0], 'ns1.dev.example.com')
        asked, skipped = dp.plan_rrsets(zone)
        self.assertIn(('ns1.dev.example.com', 'A'), {(r.name, r.rtype) for r in asked}, 'glue named relative to its own $ORIGIN')
        self.assertEqual([(r.name, reason) for r, reason in skipped], [('x.dev.example.com', 'delegated')])

    def test_rfc3597_types_and_svcparams_read_as_the_wire_says(self):
        zone = dp.parse_zone('$ORIGIN example.com.\n@ IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                             'mx IN TYPE15 \\# 20 000a 046d61696c 076578616d706c65 03636f6d 00\n'
                             'big IN TYPE65536 \\# 1 00\n'
                             'a IN HTTPS 1 . mandatory=port,alpn alpn=h2 port=8443 no-default-alpn '
                             'ech="AQID" key65000="x\\,y"\n'
                             'b IN HTTPS 1 . alpn="f\\\\\\\\oo\\\\,bar,h2"\n'
                             'c IN HTTPS 1 . alpn\n')
        by = {r.name: r for r in zone.records}
        self.assertEqual(dp.file_value(by['mx.example.com'], zone.origin), ((10, 'mail.example.com'), '10 mail.example.com.'))
        self.assertEqual(by['mx.example.com'].rtype, 'MX', 'a known type by its name, as answers say it')
        self.assertNotIn('big.example.com', by)
        self.assertIn('line 4: unknown record type TYPE65536', zone.warnings)
        wire = (b'\x00\x01\x00' + b'\x00\x00\x00\x04\x00\x01\x00\x03' + b'\x00\x01\x00\x03\x02h2' + b'\x00\x02\x00\x00'
                + b'\x00\x03\x00\x02\x20\xfb' + b'\x00\x05\x00\x03\x01\x02\x03' + b'\xfd\xe8\x00\x03x,y')
        self.assertEqual(dp.file_value(by['a.example.com'], zone.origin), dp._rdata(wire, 'HTTPS', 0, len(wire)))
        self.assertEqual(dp.file_value(by['a.example.com'], zone.origin)[1],
                         '1 . mandatory=alpn,port alpn="h2" no-default-alpn port=8443 ech=AQID key65000="x,y"')
        self.assertEqual(dp.file_value(by['b.example.com'], zone.origin)[0][2], ((1, b'\x08f\\oo,bar\x02h2'),),
                         'RFC 9460 A.1: "f\\oo,bar" and "h2"')
        with self.assertRaises(ValueError):
            dp.file_value(by['c.example.com'], zone.origin)

    def test_a_long_digit_run_is_no_ttl_at_once(self):
        # a hex digest wrapped onto a blank-owner line: the TTL test ran in 2^n steps
        start = time.monotonic()
        zone = dp.parse_zone('$ORIGIN example.com.\n@ IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                             '   %sf\n' % ('1' * 26))
        self.assertLess(time.monotonic() - start, 0.5)
        self.assertIsNone(dp.parse_ttl('1' * 26 + 'f'))
        self.assertEqual([dp.parse_ttl(t) for t in ('3600', '1h30m', '2D', '1w2d3h4m5s', '1hh', 'h1')],
                         [3600, 5400, 172800, 788645, None, None])
        self.assertEqual(len(zone.records), 1)

    def test_names(self):
        self.assertEqual(dp.canonical_name('A\\046b.Example.COM.'), 'a\\046b.example.com')
        self.assertEqual(dp.text_to_labels('*.example.com'), [b'*', b'example', b'com'])
        for bad in ('a..b', 'x' * 64 + '.example.com', '\\999.example.com'):
            with self.assertRaises(ValueError):
                dp.text_to_labels(bad)


# ============================================================================ messages

class MessageTests(unittest.TestCase):

    def test_query_layout(self):
        q = dp.build_query('_dmarc.example.com', 'TXT', 0x1234)
        self.assertEqual(q[:12], struct.pack('!HHHHHH', 0x1234, 0, 1, 0, 0, 1), 'RD off, one OPT record')
        self.assertIn(enc_name('_dmarc.example.com') + struct.pack('!HH', 16, 1), q)
        self.assertTrue(q.endswith(b'\x00' + struct.pack('!HHIH', 41, dp.UDP_PAYLOAD, 0, 0)))

    def test_a_server_reply_decodes_with_compression(self):
        server = FakeAuthority('example.com', GOOD)
        try:
            reply = server.answer(dp.build_query('www.example.com', 'A', 7), 'udp')
        finally:
            server.close()
        msg = dp.parse_message(reply)
        self.assertEqual([msg.id, msg.rcode, msg.aa, msg.tc], [7, 'NOERROR', True, False])
        self.assertEqual([(rr.name, rr.rtype, rr.key) for rr in msg.answers], [('www.example.com', 'CNAME', 'example.com'),
                                                                                ('example.com', 'A', '192.0.2.10')])

    def test_malformed_replies(self):
        for bad in (b'\x00' * 5, struct.pack('!HHHHHH', 1, 0x8000, 1, 0, 0, 0) + b'\x03abc',
                    struct.pack('!HHHHHH', 1, 0x8000, 1, 0, 0, 0) + b'\xc0\x0c\x00\x01\x00\x01'):
            with self.assertRaises(dp.DnsError):
                dp.parse_message(bad)


class NameServerArgTests(unittest.TestCase):

    def test_forms(self):
        fake = lambda name: '192.0.2.53'
        self.assertEqual(dp.parse_nameserver('NS1.Example.NET.', resolve=fake).__dict__,
                         {'label': 'ns1.example.net', 'host': 'ns1.example.net', 'address': '192.0.2.53', 'port': 53,
                          'state': '', 'serial': None, 'detail': ''})
        ns = dp.parse_nameserver('ns1.example.net=192.0.2.54:5353', resolve=fake)
        self.assertEqual([ns.label, ns.host, ns.address, ns.port], ['ns1.example.net', 'ns1.example.net', '192.0.2.54', 5353])
        ns = dp.parse_nameserver('[2001:db8::53]:5353')
        self.assertEqual([ns.label, ns.host, ns.address, ns.port], ['2001:db8::53', None, '2001:db8::53', 5353])
        self.assertEqual(dp.parse_nameserver('192.0.2.55').port, 53)
        for bad in ('ns1..example.net', 'x=notanip', '192.0.2.1:99999', 'host:port', 'single'):
            with self.assertRaises(dp.UsageError, msg=bad):
                dp.parse_nameserver(bad, resolve=fake)


# ============================================================================ runs

class ParityRunTests(unittest.TestCase):

    def run_zone(self, *servers: FakeAuthority, text: str = ZONE_TEXT, names=None, **kwargs):
        zone = dp.parse_zone(text)
        nss = [dp.parse_nameserver(s.ns(n)) for s, n in zip(servers, names or ['ns1.example.net', 'ns2.example.net'])]
        report = dp.run_parity(zone, nss, timeout=kwargs.pop('timeout', 1.0), **kwargs)
        return report, {(r.ns, r.name, r.rtype, 'extra' in r.notes): r for r in report.rows}

    def status(self, rows, name, rtype, ns='ns1.example.net', extra=False):
        row = rows.get((ns, name, rtype, extra))
        return (row.status, row.notes) if row else None

    def test_a_faithful_copy_with_a_delegation_and_glue(self):
        a = FakeAuthority('example.com', GOOD, cuts=DEV_CUT)
        b = FakeAuthority('example.com', GOOD, cuts=DEV_CUT)
        try:
            report, rows = self.run_zone(a, b)
        finally:
            a.close()
            b.close()
        s = lambda *k, **kw: self.status(rows, *k, **kw)
        self.assertEqual([ns.state for ns in report.nameservers], ['OK', 'OK'])
        self.assertEqual(s('example.com', 'A'), ('SAME', []))
        self.assertEqual(s('example.com', 'NS'), ('SAME', ['ns-new']))
        self.assertEqual(s('example.com', 'MX'), ('SAME', []))
        self.assertEqual(s('example.com', 'CAA'), ('SAME', []))
        self.assertEqual(s('long.example.com', 'TXT'), ('SAME', ['txt-chunking']))
        self.assertEqual(s('mail.example.com', 'A'), ('SAME', ['ttl']))
        self.assertEqual(s('old.example.com', 'A'), ('MISSING', ['nxdomain']))
        self.assertEqual(s('dev.example.com', 'NS'), ('SAME', ['referral']))
        self.assertEqual(s('ns1.dev.example.com', 'A'), ('SAME', ['referral']))
        self.assertEqual(s('x.dev.example.com', 'A'), ('SKIPPED', ['delegated']))
        self.assertEqual(s('example.com', 'DNSKEY'), ('SKIPPED', ['dnssec']))
        self.assertEqual(s('_sip._tcp.example.com', 'SRV'), ('SAME', []))
        self.assertEqual(s('www.example.com', 'CNAME'), ('SAME', []))
        self.assertEqual(report.verdict(), 'fix', 'old.example.com is missing')
        asked = {q[:2] for q in a.asked}
        self.assertNotIn(('x.dev.example.com', 'A'), asked, 'a record below the delegation is never asked')
        self.assertIn(('example.com', 'AAAA'), asked, 'an extra question at the apex')
        text = dp.render_summary(report)
        self.assertIn('old.example.com A', text)
        self.assertIn('ns2.example.net: ', text)
        self.assertIn('the same answers as the first server', text)
        self.assertIn('keep the old zone answering for at least 48 hours', text)

    def test_differences_extras_and_truncation(self):
        records = dict(GOOD)
        records[('example.com', 'MX')] = [(3600, (10, 'mx.example.net'))]
        records[('mail.example.com', 'CNAME')] = [(600, 'mail.example.net')]
        del records[('mail.example.com', 'A')]
        records[('example.com', 'AAAA')] = [(300, '2001:db8::99')]
        records[('www.example.com', 'CNAME')] = [(3600, 'example.com')]
        records[('example.com', 'NS')] = [(86400, 'ns1.example.net'), (86400, 'ns9.example.net')]
        records[('old.example.com', 'A')] = [(3600, '198.51.100.30')]
        records[('old.example.com', 'TXT')] = [(3600, ['parking'])]
        server = FakeAuthority('example.com', records, cuts=DEV_CUT, truncate=('long.example.com',))
        try:
            report, rows = self.run_zone(server)
        finally:
            server.close()
        s = lambda *k, **kw: self.status(rows, *k, **kw)
        mx = rows[('ns1.example.net', 'example.com', 'MX', False)]
        self.assertEqual([mx.status, mx.added, mx.removed], ['DIFFERENT', ['10 mx.example.net.'], ['10 mail.example.com.']])
        self.assertEqual(s('mail.example.com', 'A'), ('DIFFERENT', ['cname']))
        ns = rows[('ns1.example.net', 'example.com', 'NS', False)]
        self.assertEqual([ns.status, ns.notes, ns.added, ns.removed], ['DIFFERENT', ['ns-mismatch'], ['ns9.example.net.'], []])
        self.assertEqual(s('example.com', 'AAAA', extra=True), ('EXTRA', ['extra']))
        self.assertEqual(s('old.example.com', 'TXT', extra=True), ('EXTRA', ['extra']))
        self.assertEqual(s('long.example.com', 'TXT'), ('SAME', ['txt-chunking']), 'truncated over UDP, read over TCP')
        self.assertIn(('long.example.com', 'TXT', 'tcp'), server.asked)
        self.assertEqual(report.verdict(), 'fix')

    def test_cloudflare_proxied_records(self):
        text = ('$ORIGIN example.com.\n@ 3600 IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                '@ 1 IN A 192.0.2.10 ; cf_tags=cf-proxied:true\n'
                'api 1 IN A 192.0.2.14 ; cf_tags=cf-proxied:true\n'
                'app 1 IN CNAME lb.example.net. ; cf_tags=cf-proxied:true\n'
                'shop 1 IN CNAME shops.example.org. ; cf_tags=cf-proxied:true\n'
                'other 1 IN A 192.0.2.15 ; cf_tags=cf-proxied:true\n')
        records = {
            ('example.com', 'A'): [(300, '104.16.0.1')],
            ('api.example.com', 'A'): [(300, '192.0.2.14')],
            ('app.example.com', 'A'): [(300, '104.16.0.2')],
            ('shop.example.com', 'CNAME'): [(300, 'shops.example.org')],
            ('other.example.com', 'A'): [(300, '198.51.100.9')],
        }
        server = FakeAuthority('example.com', records)
        try:
            report, rows = self.run_zone(server, text=text)
        finally:
            server.close()
        s = lambda *k, **kw: self.status(rows, *k, **kw)
        self.assertEqual(s('example.com', 'A'), ('SAME', ['proxied']))
        self.assertEqual(s('api.example.com', 'A'), ('UNPROXIED', ['proxy-off']))
        self.assertEqual(s('app.example.com', 'CNAME'), ('SAME', ['proxied']))
        self.assertEqual(s('shop.example.com', 'CNAME'), ('UNPROXIED', ['proxy-off']))
        self.assertEqual(s('other.example.com', 'A'), ('DIFFERENT', ['not-cloudflare']))
        self.assertIsNone(s('example.com', 'AAAA', extra=True), 'never asked at a proxied name')
        self.assertIsNone(rows.get(('ns1.example.net', 'example.com', 'A', False)).file_ttl, 'TTL 1 is automatic')

    def test_relative_names_under_a_second_origin_are_the_same_at_the_new_server(self):
        records = {
            ('example.com', 'NS'): [(3600, 'ns1.example.net')],
            ('example.com', 'MX'): [(3600, (10, 'mail.example.com'))],
            ('mail.example.com', 'A'): [(3600, '198.51.100.25')],
            ('sub.example.com', 'MX'): [(3600, (10, 'mail.sub.example.com'))],
            ('www.sub.example.com', 'CNAME'): [(3600, 'host.sub.example.com')],
            ('_sip._tcp.sub.example.com', 'SRV'): [(3600, (10, 5, 5060, 'sip.sub.example.com'))],
            ('host.sub.example.com', 'A'): [(3600, '192.0.2.20')],
            ('mail.sub.example.com', 'A'): [(3600, '192.0.2.21')],
        }
        server = FakeAuthority('example.com', records, cuts={'dev.example.com': (['ns1.dev.example.com'], {'ns1.dev.example.com': '192.0.2.53'})})
        try:
            report, rows = self.run_zone(server, text=SUB_ORIGIN_TEXT, extras=False)
        finally:
            server.close()
        s = lambda *k, **kw: self.status(rows, *k, **kw)
        self.assertEqual(s('www.sub.example.com', 'CNAME'), ('SAME', []))
        self.assertEqual(s('sub.example.com', 'MX'), ('SAME', []))
        self.assertEqual(s('_sip._tcp.sub.example.com', 'SRV'), ('SAME', []))
        self.assertEqual(s('example.com', 'MX'), ('SAME', []))
        self.assertEqual(s('dev.example.com', 'NS'), ('SAME', ['referral']))
        self.assertEqual(s('ns1.dev.example.com', 'A'), ('SAME', ['referral']))
        self.assertEqual(report.verdict(), 'ready')

    def test_every_type_of_the_file_is_asked_and_its_values_compared(self):
        text = ('$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                '@ IN NS ns1.example.net.\n'
                '@ IN HTTPS 1 . alpn="h3,h2" ipv4hint=192.0.2.2,192.0.2.1 port=443\n'
                'svc IN SVCB 0 svc.example.net.\n'
                'sip IN NAPTR 10 100 "S" "SIP+D2U" "" _sip._udp\n'
                'key IN OPENPGPKEY AQID\n'
                'geo IN LOC 52 22 23.000 N 4 53 32.000 E -2.00m\n'
                '_ftp._tcp IN URI 10 1 "ftp://ftp.example.com/public"\n'
                'gen IN TYPE65534 \\# 3 0a0b0c\n'
                'raw IN A \\# 4 c0000221\n')
        # the wire forms, encoded here: SvcParams in key order, LOC per RFC 1876 (1m, 10000m, 10m)
        https = (b'\x00\x01\x00' + b'\x00\x01\x00\x06\x02h3\x02h2' + b'\x00\x03\x00\x02\x01\xbb'
                 + b'\x00\x04\x00\x08' + socket.inet_aton('192.0.2.1') + socket.inet_aton('192.0.2.2'))
        loc = struct.pack('!BBBBIII', 0, 0x12, 0x16, 0x13, 2 ** 31 + 188543000, 2 ** 31 + 17612000,
                          10000000 - 200)
        served = {
            ('example.com', 'NS'): [(3600, 'ns1.example.net')],
            ('example.com', 'HTTPS'): [(3600, https)],
            ('svc.example.com', 'SVCB'): [(3600, b'\x00\x00' + enc_name('svc.example.net'))],
            ('sip.example.com', 'NAPTR'): [(3600, struct.pack('!HH', 10, 100) + b'\x01S\x07SIP+D2U\x00'
                                            + enc_name('_sip._udp.example.com'))],
            ('key.example.com', 'OPENPGPKEY'): [(3600, b'\x01\x02\x03')],
            ('geo.example.com', 'LOC'): [(3600, loc)],
            ('_ftp._tcp.example.com', 'URI'): [(3600, struct.pack('!HH', 10, 1) + b'ftp://ftp.example.com/public')],
            ('gen.example.com', 'TYPE65534'): [(3600, b'\x0a\x0b\x0c')],
            ('raw.example.com', 'A'): [(3600, '192.0.2.33')],
        }
        same = FakeAuthority('example.com', served)
        lacking = dict(served)
        del lacking[('sip.example.com', 'NAPTR')], lacking[('example.com', 'HTTPS')]
        lacking[('geo.example.com', 'LOC')] = [(3600, loc[:-4] + struct.pack('!I', 10000000 + 500))]
        other = FakeAuthority('example.com', lacking)
        try:
            report, rows = self.run_zone(same, text=text, names=['ns1.example.net'])
            other_report, other_rows = self.run_zone(other, text=text, names=['ns1.example.net'])
        finally:
            same.close()
            other.close()
        kinds = [('example.com', 'HTTPS'), ('svc.example.com', 'SVCB'), ('sip.example.com', 'NAPTR'),
                 ('key.example.com', 'OPENPGPKEY'), ('geo.example.com', 'LOC'),
                 ('_ftp._tcp.example.com', 'URI'), ('gen.example.com', 'TYPE65534'), ('raw.example.com', 'A')]
        for name, rtype in kinds:
            self.assertEqual(self.status(rows, name, rtype), ('SAME', []), (name, rtype))
        self.assertEqual(report.verdict(), 'ready')
        self.assertEqual(self.status(other_rows, 'sip.example.com', 'NAPTR'), ('MISSING', ['nxdomain']))
        self.assertEqual(self.status(other_rows, 'example.com', 'HTTPS'), ('MISSING', ['nodata']))
        self.assertEqual(self.status(other_rows, 'geo.example.com', 'LOC'), ('DIFFERENT', ['values']))
        geo = other_rows[('ns1.example.net', 'geo.example.com', 'LOC', False)]
        self.assertEqual((geo.removed, geo.added), (['52 22 23.000 N 4 53 32.000 E -2.00m 1m 10000m 10m'],
                                                    ['52 22 23.000 N 4 53 32.000 E 5.00m 1m 10000m 10m']))
        self.assertEqual(other_report.verdict(), 'fix')
        https_row = rows[('ns1.example.net', 'example.com', 'HTTPS', False)]
        self.assertEqual(https_row.file, ['1 . alpn="h3,h2" port=443 ipv4hint=192.0.2.1,192.0.2.2'])

    def test_a_cname_at_the_new_provider_is_one_row(self):
        # a CNAME answers every type asked at its name: one EXTRA row (www, asked A and AAAA), none
        # where a compared record set says it already (shop, asked AAAA, MX, TXT and CAA as well)
        text = ('$ORIGIN example.com.\n$TTL 3600\n@ IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                '@ IN NS ns1.example.net.\nshop IN A 192.0.2.20\n')
        server = FakeAuthority('example.com', {('example.com', 'NS'): [(3600, 'ns1.example.net')],
                                               ('shop.example.com', 'CNAME'): [(3600, 'stores.example.org')],
                                               ('www.example.com', 'CNAME'): [(3600, 'example.org')]})
        try:
            report, rows = self.run_zone(server, text=text, names=['ns1.example.net'])
        finally:
            server.close()
        self.assertEqual(self.status(rows, 'shop.example.com', 'A'), ('DIFFERENT', ['cname']))
        self.assertEqual([(r.name, r.rtype, r.new) for r in report.rows if r.status == 'EXTRA'],
                         [('www.example.com', 'CNAME', ['example.org.'])])

    def test_servers_that_do_not_serve_the_zone(self):
        refusing = FakeAuthority('example.com', GOOD, refuse=True)
        cache = FakeAuthority('example.com', GOOD, authoritative=False)
        silent = FakeAuthority('example.com', GOOD, silent=True)
        try:
            report, rows = self.run_zone(refusing, cache, silent, names=['ns1.example.net', 'ns2.example.net', 'ns3.example.net'], timeout=0.3)
        finally:
            for server in (refusing, cache, silent):
                server.close()
        self.assertEqual([ns.state for ns in report.nameservers], ['REFUSED', 'NOT_AUTHORITATIVE', 'UNREACHABLE'])
        self.assertEqual(report.rows, [])
        self.assertEqual(len(refusing.asked), 1, 'the SOA only')
        self.assertEqual(report.verdict(), 'blocked')
        self.assertIn('No name server serves example.com yet', dp.render_summary(report))


class CommandLineTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.zone = os.path.join(cls.tmp.name, 'example.com.parity.zone')
        with open(cls.zone, 'w', encoding='utf-8') as handle:
            handle.write(ZONE_TEXT)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_reports_and_exit_codes(self):
        server = FakeAuthority('example.com', GOOD, cuts=DEV_CUT)
        out_json = os.path.join(self.tmp.name, 'parity.json')
        out_csv = os.path.join(self.tmp.name, 'parity.csv')
        try:
            code, out, err = run_main(self.zone, '--ns', server.ns(), '--json', out_json, '--csv', out_csv, '-q')
            self.assertEqual(code, 0)
            code2, _, _ = run_main(self.zone, '--ns', server.ns(), '--fail-on-diff', '-q', '--no-extras')
            self.assertEqual(code2, 1, 'old.example.com is missing')
            code3, out3, _ = run_main(self.zone, '--ns', server.ns(), '--json', '-', '-q', '--no-extras')
        finally:
            server.close()
        self.assertIn('DNS parity: example.com', out)
        self.assertEqual(err, '')
        doc = json.loads(Path(out_json).read_text(encoding='utf-8'))
        self.assertEqual(doc['schema'], 'domainscope.dns-parity/1')
        self.assertEqual(doc['nameservers'][0]['state'], 'OK')
        self.assertEqual(doc['summary']['verdict'], 'fix')
        self.assertTrue(any(r['status'] == 'MISSING' and r['name'] == 'old.example.com' for r in doc['rows']))
        with open(out_csv, encoding='utf-8-sig') as handle:
            head = handle.readline().strip()
        self.assertEqual(head, ','.join(dp.CSV_COLUMNS))
        self.assertEqual(code3, 0)
        self.assertEqual(json.loads(out3)['zone'], 'example.com', 'only the JSON on stdout')

    def test_host_names_that_share_one_address_are_asked_once_and_both_expected_at_the_apex(self):
        server = FakeAuthority('example.com', GOOD, cuts=DEV_CUT)
        try:
            code, out, _ = run_main(self.zone, '--ns', server.ns('ns1.example.net'), server.ns('ns2.example.net'),
                                    '--json', '-', '-q', '--no-extras')
        finally:
            server.close()
        doc = json.loads(out)
        self.assertEqual([ns['name'] for ns in doc['nameservers']], ['ns1.example.net'], 'one server, asked once')
        apex = [(r['status'], r['notes']) for r in doc['rows'] if (r['name'], r['type']) == ('example.com', 'NS')]
        self.assertEqual(apex, [('SAME', ['ns-new'])])
        self.assertEqual(code, 0)

    def test_unproxied_and_extra_are_check_as_in_the_web_app_and_still_fail_the_check(self):
        # A proxied record answered with its origin and a parking address at the apex: nothing
        # missing or different, so the verdict is 'check' (the web app's); --fail-on-diff fails.
        path = os.path.join(self.tmp.name, 'check.zone')
        with open(path, 'w', encoding='utf-8') as handle:
            handle.write('$ORIGIN example.com.\n@ 3600 IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                         '@ 3600 IN NS ns1.example.net.\n'
                         'api 1 IN A 192.0.2.14 ; cf_tags=cf-proxied:true\n')
        records = {('example.com', 'NS'): [(3600, 'ns1.example.net')], ('api.example.com', 'A'): [(300, '192.0.2.14')],
                   ('example.com', 'A'): [(300, '198.51.100.80')]}
        server = FakeAuthority('example.com', records)
        out_json = os.path.join(self.tmp.name, 'check.json')
        try:
            code, out, _ = run_main(path, '--ns', server.ns(), '--json', out_json, '-q')
            failed, _, _ = run_main(path, '--ns', server.ns(), '--fail-on-diff', '-q')
        finally:
            server.close()
        doc = json.loads(Path(out_json).read_text(encoding='utf-8'))
        self.assertEqual(sorted(r['status'] for r in doc['rows']), ['EXTRA', 'SAME', 'UNPROXIED'])
        self.assertEqual([code, doc['summary']['verdict']], [0, 'check'])
        self.assertIn('Nothing is missing or different. Check the rest before you switch: 1 extra, 1 unproxied', out)
        self.assertEqual(failed, dp.EXIT_DIFFERENCES, 'stricter than the verdict: unproxied and extra fail it')

    def test_a_dns_only_record_answered_with_cloudflare_addresses_says_the_proxy_is_on(self):
        text = ('$ORIGIN example.com.\n@ 3600 IN SOA ns1.example.org. h. 1 2 3 4 5\n'
                'direct 300 IN A 192.0.2.16 ; cf_tags=cf-proxied:false\n'
                'plain 300 IN A 192.0.2.17\n')
        server = FakeAuthority('example.com', {('direct.example.com', 'A'): [(300, '104.16.0.3')],
                                               ('plain.example.com', 'A'): [(300, '104.16.0.4')]})
        try:
            zone = dp.parse_zone(text)
            report = dp.run_parity(zone, [dp.parse_nameserver(server.ns())], timeout=1.0, extras=False)
        finally:
            server.close()
        rows = {r.name: r for r in report.rows}
        self.assertEqual([rows['direct.example.com'].status, rows['direct.example.com'].notes], ['DIFFERENT', ['proxy-on']])
        self.assertEqual(rows['plain.example.com'].notes, ['values'], 'no proxy flag in the file: other values')
        self.assertIn('the proxy is on at the new provider', dp.render_summary(report))

    def test_record_sets_without_an_answer_are_partial_and_fail_the_check(self):
        # The server serves the zone (SOA, NS) but SERVFAILs every MX and TXT question: the
        # comparison did not finish, as the web app's 'partial' says, never "nothing is missing".
        records = dict(GOOD)
        records[('old.example.com', 'A')] = [(3600, '198.51.100.30')]
        records[('example.com', 'NS')] = [(86400, 'ns1.example.net')]
        server = FakeAuthority('example.com', records, cuts=DEV_CUT, servfail=('MX', 'TXT'))
        out_json = os.path.join(self.tmp.name, 'partial.json')
        try:
            code, out, _ = run_main(self.zone, '--ns', server.ns(), '--no-extras', '--json', out_json, '-q')
            failed, _, _ = run_main(self.zone, '--ns', server.ns(), '--no-extras', '--fail-on-diff', '-q')
        finally:
            server.close()
        doc = json.loads(Path(out_json).read_text(encoding='utf-8'))
        self.assertEqual(sorted((r['name'], r['type']) for r in doc['rows'] if r['status'] == 'ERROR'),
                         [('example.com', 'MX'), ('example.com', 'TXT'), ('long.example.com', 'TXT')])
        self.assertFalse([r for r in doc['rows'] if r['status'] in ('MISSING', 'DIFFERENT', 'EXTRA', 'UNPROXIED')])
        self.assertEqual([code, doc['summary']['verdict']], [0, 'partial'])
        self.assertIn('3 record sets got no answer: run this again before you switch', out)
        self.assertNotIn('Nothing is missing or different. Check the rest', out)
        self.assertEqual(failed, dp.EXIT_DIFFERENCES, 'an unfinished comparison fails the check')

    def test_usage_errors(self):
        for args in ([self.zone], [self.zone, '--ns', 'bad..name'], [os.path.join(self.tmp.name, 'none.zone'), '--ns', '192.0.2.1'],
                     [self.zone, '--ns', '192.0.2.1', '--timeout', '0'], [self.zone, '--ns', '192.0.2.1', '--json', '-', '--csv', '-'],
                     [self.zone, '--ns'] + ['192.0.2.%d' % i for i in range(1, 10)]):
            code, _, err = run_main(*args)
            self.assertEqual(code, 2, args)
        no_origin = os.path.join(self.tmp.name, 'no-origin.zone')
        with open(no_origin, 'w', encoding='utf-8') as handle:
            handle.write('www 300 IN A 192.0.2.1\n')
        code, _, err = run_main(no_origin, '--ns', '192.0.2.1')
        self.assertEqual(code, 2)
        self.assertIn('--origin', err)

    def test_a_name_server_whose_name_does_not_resolve_is_unreachable_and_the_others_are_asked(self):
        def resolve(host):
            raise dp.DnsError('resolve', 'its name does not resolve: Name or service not known')
        server = FakeAuthority('example.com', GOOD, cuts=DEV_CUT)
        out_json = os.path.join(self.tmp.name, 'unresolved.json')
        try:
            with mock.patch.object(dp, '_resolve', resolve):
                code, out, err = run_main(self.zone, '--ns', server.ns(), 'ns2.example.net', '--json', out_json, '--no-extras')
        finally:
            server.close()
        self.assertEqual(code, 0)
        self.assertIn('ns2.example.net (no address)  UNREACHABLE: its name does not resolve', out)
        self.assertIn('warning: name server ns2.example.net: its name does not resolve', err)
        doc = json.loads(Path(out_json).read_text(encoding='utf-8'))
        self.assertEqual([(n['name'], n['address'], n['state']) for n in doc['nameservers']],
                         [('ns1.example.net', '127.0.0.1', 'OK'), ('ns2.example.net', None, 'UNREACHABLE')])
        self.assertEqual(doc['summary']['verdict'], 'fix', 'a server that cannot be asked is a server to fix')

    def test_the_file_is_read_before_any_name_is_resolved(self):
        def resolve(host):
            raise dp.DnsError('resolve', 'its name does not resolve: Name or service not known')
        with mock.patch.object(dp, '_resolve', resolve):
            code, _, err = run_main(os.path.join(self.tmp.name, 'none.zone'), '--ns', 'ns1.example.net')
            self.assertEqual(code, 2)
            self.assertIn('cannot read', err)
            code, _, err = run_main(self.zone, '--ns', 'ns1.example.net', 'ns2.example.net')
        self.assertEqual(code, 2, 'no server can be asked')
        self.assertIn('no name server can be asked: ns1.example.net: its name does not resolve', err)

    def test_help_and_version(self):
        code, out, _ = run_main('--help')
        self.assertEqual(code, 0)
        self.assertIn('UNPROXIED', out)
        self.assertIn('Türkçe', out)
        code, out, _ = run_main('--version')
        self.assertEqual((code, out.strip()), (0, 'dns_parity.py 1.0.0'))


if __name__ == '__main__':
    unittest.main()
