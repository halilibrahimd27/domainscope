#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ip_scan.py - which addresses of an IPv4 range are in use, and which are free.

Companion CLI of the "DomainScope - SSL & DNS Toolkit" web app
(https://github.com/halilibrahimd27/domainscope). Before you give a new server an address,
ask the network which addresses already answer: a ping, a TCP port (open, or closed with a
reset - both mean a machine is there), the machine's own ARP table and reverse DNS. A browser
page cannot do this - it cannot ping, and it cannot reach your internal network - so it lives in
the CLI, run from a machine on that network. The web app's IP Scan view reads its --json report
and draws the range as a map, with your server inventory on top.

Scan only networks you run or are authorised to scan. What it sends, per address:
  * ICMP echo requests (two rounds), when this machine allows them: an unprivileged ICMP socket
    (macOS; Linux when net.ipv4.ping_group_range includes your group), a raw socket as root, or
    the Windows ICMP API. Otherwise it says so and relies on the rest;
  * TCP connections to a short list of common ports (--ports), closed again at once: a SYN-ACK
    or a reset proves a machine. Nothing is sent over a connection, except
  * one HEAD / request to the web ports that are open, for the Server header (--no-web: none);
  * a reverse DNS (PTR) question to this machine's resolver, which also sees internal zones.
And it reads, without sending anything: this machine's ARP table (/proc/net/arp on Linux, the
Windows IP Helper API, or `arp -an` on macOS / BSD - the only program it runs; --no-arp: none).

Verdicts, per address:
  used      something answered: a ping, a TCP port, or the ARP table holds its MAC address;
  claimed   nothing answered, but the address has a reverse DNS name: a machine that is off or
            drops everything, or a record left behind - check before you use it;
  free      nothing answered and no DNS name. "confirmed" when no device answered ARP for it
            (it is on this machine's own network) or a router said the host is unreachable;
            otherwise a machine that drops every packet would look the same;
  reserved  the network or broadcast address of a CIDR block (/30 and wider): never probed.

JSON (`--json`) and CSV (`--csv`) reports carry every address; `--free` prints only the free
addresses, one a line, for a script. Exit code 0; 1 with `--expect-free` when an address you
expected to be free is used or claimed; 2 for a usage error, 3 when a report file could not be
written, 70 for an internal error, 130 when interrupted.

Python 3.8+, standard library only, single file - copy it anywhere.

The module is importable: parse_targets(), Block, HostResult, verdict(), tcp_probe(),
IcmpSweeper, parse_proc_arp(), parse_arp_command(), read_arp_table(), ptr_names(),
web_server(), run_scan(), ScanReport, render_text(), report_to_dict(), render_csv(),
free_ranges() and main() are the public API.
"""

from __future__ import annotations

import argparse
import csv
import errno
import io
import ipaddress
import json
import os
import re
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, wait as wait_futures, FIRST_COMPLETED
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

__version__ = '1.0.0'
PROG = 'ip_scan.py'
SCHEMA = 'domainscope.ip-scan/1'
TOOL = 'ip_scan'
USER_AGENT = 'ip_scan/%s (+https://github.com/halilibrahimd27/domainscope)' % __version__

# --- verdicts ---------------------------------------------------------------------------
USED = 'used'
CLAIMED = 'claimed'
FREE = 'free'
RESERVED = 'reserved'
STATES = (USED, CLAIMED, FREE, RESERVED)

# --- the evidence behind a verdict (HostResult.reasons) ---------------------------------
R_ICMP = 'icmp'                 # answered a ping
R_TCP_OPEN = 'tcp-open'         # a port accepted the connection
R_TCP_REFUSED = 'tcp-refused'   # a port answered with a reset: a machine is there
R_ARP = 'arp'                   # the ARP table holds its MAC address
R_PTR = 'ptr'                   # a reverse DNS name (claimed when nothing else answered)
R_NO_ARP = 'arp-incomplete'     # on this machine's network, and no device answered ARP
R_UNREACHABLE = 'unreachable'   # a router (or this machine) said the host is unreachable
REASONS = (R_ICMP, R_TCP_OPEN, R_TCP_REFUSED, R_ARP, R_PTR, R_NO_ARP, R_UNREACHABLE)

# --- the outcome of one TCP connection --------------------------------------------------
T_OPEN = 'open'
T_REFUSED = 'refused'
T_TIMEOUT = 'timeout'
T_UNREACHABLE = 'unreachable'
T_ERROR = 'error'

# --- how the machine could ping / read ARP ----------------------------------------------
ICMP_DGRAM = 'dgram'          # an unprivileged ICMP socket (macOS, Linux ping_group_range)
ICMP_RAW = 'raw'              # a raw socket (root / administrator)
ICMP_WINDOWS = 'windows'      # IcmpSendEcho of the Windows IP Helper API
ARP_PROC = 'proc'             # /proc/net/arp (Linux)
ARP_COMMAND = 'arp-command'   # `arp -an` (macOS, BSD)
ARP_WINDOWS = 'windows'       # GetIpNetTable (Windows)
OFF = 'off'                   # turned off on the command line
UNAVAILABLE = 'unavailable'   # this machine does not allow it

# Common service ports: SSH, the web, Windows (RPC, SMB, RDP, WinRM), mail, DNS, databases,
# printers. Any port works as a probe on a host that answers closed ports with a reset; the
# list is short so a /24 stays quick, and open ones fill the PORTS column.
DEFAULT_PORTS = (21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 5985,
                 8080, 8443, 9100)
QUICK_PORTS = (22, 80, 443, 445, 3389)
WEB_PORTS = {80: False, 8080: False, 443: True, 8443: True}  # port -> TLS
DEFAULT_TIMEOUT = 1.0
MAX_TIMEOUT = 10.0
DEFAULT_WORKERS = 128
MAX_WORKERS = 512
DEFAULT_MAX_ADDRESSES = 4096        # a /20
MAX_ADDRESSES = 65536               # a /16
MAX_PORTS = 64
ICMP_ROUNDS = 2
MAX_SERVER_HEADER = 120

EXIT_OK = 0
EXIT_IN_USE = 1             # only with --expect-free
EXIT_USAGE = 2
EXIT_OUTPUT_ERROR = 3       # a --json / --csv file could not be written after the scan
EXIT_INTERNAL_ERROR = 70
EXIT_INTERRUPTED = 130

# errno values that mean "no machine there" (a failed ARP, or a router's host unreachable),
# on Linux, macOS / BSD and Windows (WSA*)
_UNREACHABLE_ERRNOS = {getattr(errno, name) for name in ('EHOSTUNREACH', 'EHOSTDOWN') if hasattr(errno, name)}
_UNREACHABLE_ERRNOS |= {10064, 10065}
_TRANSIENT_ERRNOS = {getattr(errno, name) for name in ('ENOBUFS', 'EAGAIN', 'EWOULDBLOCK') if hasattr(errno, name)}


class UsageError(Exception):
    """Bad command line or input; reported as ``error: ...`` with exit code 2."""


# ---------------------------------------------------------------------------------------
# Text safety: names and Server headers come from the network
# ---------------------------------------------------------------------------------------

def _plain(text: str) -> str:
    """Printable ASCII for the terminal: anything else ``\\xNN`` / ``\\uNNNN``."""
    return ''.join(c if 0x20 <= ord(c) < 0x7f else '\\x%02x' % ord(c) if ord(c) < 0x100
                   else '\\u%04x' % ord(c) for c in text)


_CSV_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')
_CSV_ESCAPE_RE = re.compile(r'[\x00-\x1f\x7f-\x9f‪-‮⁦-⁩]')


def csv_cell(value: Any) -> Any:
    """A spreadsheet-safe cell: text starting with ``= + - @`` TAB or CR gets a leading
    apostrophe, control and bidi characters become ``\\xNN`` / ``\\uNNNN``; numbers stay."""
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if not isinstance(value, str):
        return value
    if value.startswith(_CSV_FORMULA_START):
        value = "'" + value
    return _CSV_ESCAPE_RE.sub(lambda m: '\\x%02x' % ord(m.group()) if ord(m.group()) < 0x100
                              else '\\u%04x' % ord(m.group()), value)


# ---------------------------------------------------------------------------------------
# Targets: networks, ranges and addresses (IPv4)
# ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Block:
    """One target as typed: a network, a range or an address."""
    text: str           # canonical: 192.0.2.0/24, 192.0.2.10-192.0.2.50 or 192.0.2.7
    kind: str           # 'cidr' | 'range' | 'ip'
    first: int
    last: int
    network: Optional[int] = None    # a CIDR block of /30 or wider: its network address
    broadcast: Optional[int] = None  # ... and its broadcast address

    @property
    def size(self) -> int:
        return self.last - self.first + 1


_RANGE_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s*[-–]\s*(\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$')
_TOKEN_SPLIT_RE = re.compile(r'[\s,;]+')


def _v4(text: str) -> Optional[ipaddress.IPv4Address]:
    try:
        addr = ipaddress.ip_address(text.strip())
    except ValueError:
        return None
    return addr if isinstance(addr, ipaddress.IPv4Address) else None


def parse_block(token: str) -> Tuple[Optional[Block], Optional[str]]:
    """One token -> (Block, None), or (None, why it is not a target)."""
    text = token.strip()
    if not text:
        return None, 'empty'
    if ':' in text:
        return None, '%s: IPv6 is not scanned (a /64 alone holds 2^64 addresses); give IPv4' % _plain(text)
    if '/' in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return None, '%s: not a network (write 192.0.2.0/24)' % _plain(text)
        if not isinstance(net, ipaddress.IPv4Network):
            return None, '%s: IPv6 is not scanned; give IPv4' % _plain(text)
        first, last = int(net.network_address), int(net.broadcast_address)
        if net.prefixlen <= 30:
            return Block(str(net), 'cidr', first, last, first, last), None
        return Block(str(net) if net.prefixlen < 32 else str(net.network_address),
                     'cidr' if net.prefixlen < 32 else 'ip', first, last), None
    m = _RANGE_RE.match(text)
    if m:
        start = _v4(m.group(1))
        if start is None:
            return None, '%s: not an address range' % _plain(text)
        tail = m.group(2)
        if '.' in tail:
            end = _v4(tail)
        else:
            octet = int(tail)
            end = ipaddress.IPv4Address((int(start) & ~0xff) | octet) if octet <= 255 else None
        if end is None:
            return None, '%s: not an address range' % _plain(text)
        if int(end) < int(start):
            return None, '%s: the range ends before it starts' % _plain(text)
        if int(end) == int(start):
            return Block(str(start), 'ip', int(start), int(start)), None
        return Block('%s-%s' % (start, end), 'range', int(start), int(end)), None
    addr = _v4(text)
    if addr is None:
        return None, '%s: not an IPv4 address, range or network' % _plain(text)
    return Block(str(addr), 'ip', int(addr), int(addr)), None


def _read_lines(path: str, stdin: Optional[Any] = None) -> List[str]:
    try:
        if path == '-':
            text = (stdin or sys.stdin).read()
        else:
            with open(path, 'r', encoding='utf-8-sig', errors='replace') as handle:
                text = handle.read()
    except OSError as exc:
        raise UsageError('cannot read %s: %s' % (_plain(path), exc.strerror or exc))
    out = []
    for line in text.splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            out.append(line)
    return out


def _join_spaced_ranges(text: str) -> str:
    """`192.0.2.10 - 192.0.2.20` (a range typed with spaces or an en dash) -> one token."""
    return re.sub(r'(\d)\s*[-–]\s*(\d)', r'\1-\2', text)


def parse_targets(values: Sequence[str], files: Sequence[str] = (),
                  max_addresses: int = DEFAULT_MAX_ADDRESSES,
                  stdin: Optional[Any] = None) -> Tuple[List[Block], List[str]]:
    """The command line's targets -> (blocks, addresses in order, de-duplicated).
    Raises UsageError for anything that is not a target, and when the distinct addresses
    exceed `max_addresses`."""
    tokens: List[str] = []
    for value in values:
        tokens.extend(t for t in _TOKEN_SPLIT_RE.split(_join_spaced_ranges(value)) if t)
    for path in files:
        for line in _read_lines(path, stdin):
            tokens.extend(t for t in _TOKEN_SPLIT_RE.split(_join_spaced_ranges(line)) if t)
    blocks: List[Block] = []
    problems: List[str] = []
    for token in tokens:
        block, why = parse_block(token)
        if block is None:
            problems.append(why or token)
        elif block not in blocks:
            blocks.append(block)
    if problems:
        shown = problems[:5]
        more = '' if len(problems) <= 5 else ' (and %d more)' % (len(problems) - 5)
        raise UsageError('; '.join(shown) + more)
    total = _distinct_count(blocks)
    if total > max_addresses:
        raise UsageError('%d addresses is more than --max-addresses %d (at most %d): scan a '
                         'smaller part, or raise the limit' % (total, max_addresses, MAX_ADDRESSES))
    return blocks, addresses_of(blocks)


def _distinct_count(blocks: Sequence[Block]) -> int:
    spans = sorted((b.first, b.last) for b in blocks)
    count, end = 0, -1
    for first, last in spans:
        if last <= end:
            continue
        count += last - max(first, end + 1) + 1
        end = last
    return count


def addresses_of(blocks: Sequence[Block]) -> List[str]:
    """Every address of the blocks, in block order, each once."""
    seen: Set[int] = set()
    out: List[str] = []
    for block in blocks:
        for value in range(block.first, block.last + 1):
            if value not in seen:
                seen.add(value)
                out.append(str(ipaddress.IPv4Address(value)))
    return out


def reserved_role(ip: str, blocks: Sequence[Block]) -> Optional[str]:
    """'network' / 'broadcast' when the address is that of a CIDR block (/30 or wider)."""
    value = int(ipaddress.IPv4Address(ip))
    for block in blocks:
        if block.network is not None and value == block.network:
            return 'network'
        if block.broadcast is not None and value == block.broadcast:
            return 'broadcast'
    return None


def parse_ports(text: str) -> List[int]:
    """`22,80,443`, `1-1024` or `quick` / `default` -> the ports (at most MAX_PORTS)."""
    text = (text or '').strip().lower()
    if text in ('', 'default'):
        return list(DEFAULT_PORTS)
    if text == 'quick':
        return list(QUICK_PORTS)
    if text == 'none':
        return []
    out: List[int] = []
    for part in re.split(r'[\s,]+', text):
        if not part:
            continue
        m = re.match(r'^(\d{1,5})(?:-(\d{1,5}))?$', part)
        if not m:
            raise UsageError('--ports: %s is not a port or a range of ports' % _plain(part))
        lo = int(m.group(1))
        hi = int(m.group(2) or lo)
        if not (1 <= lo <= 65535 and 1 <= hi <= 65535 and lo <= hi):
            raise UsageError('--ports: %s is not between 1 and 65535' % _plain(part))
        for port in range(lo, hi + 1):
            if port not in out:
                out.append(port)
        if len(out) > MAX_PORTS:
            raise UsageError('--ports: at most %d ports (this is not a port scanner)' % MAX_PORTS)
    return out


# ---------------------------------------------------------------------------------------
# One address: what answered, and the verdict
# ---------------------------------------------------------------------------------------

@dataclass
class HostResult:
    ip: str
    reserved: Optional[str] = None          # 'network' | 'broadcast'
    rtt_ms: Optional[float] = None          # answered a ping
    open_ports: List[int] = field(default_factory=list)
    refused_ports: List[int] = field(default_factory=list)
    unreachable: bool = False               # a router / this machine said: no such host
    mac: Optional[str] = None               # from the ARP table
    on_link: Optional[bool] = None          # in the ARP table at all (None: no table read)
    arp_incomplete: bool = False            # in the table, no device answered
    ptr: List[str] = field(default_factory=list)
    web: Dict[int, str] = field(default_factory=dict)   # port -> Server header
    errors: List[str] = field(default_factory=list)
    skipped_tcp: bool = False               # no device on the link: TCP was not asked

    @property
    def state(self) -> str:
        return verdict(self)[0]

    @property
    def reasons(self) -> List[str]:
        return verdict(self)[1]

    @property
    def confirmed(self) -> bool:
        return verdict(self)[2]


def verdict(result: HostResult) -> Tuple[str, List[str], bool]:
    """-> (state, reasons, confirmed). `confirmed` is only true for a free address that no
    device answered ARP for, or that a router called unreachable."""
    if result.reserved:
        return RESERVED, [], False
    reasons = []
    if result.rtt_ms is not None:
        reasons.append(R_ICMP)
    if result.open_ports:
        reasons.append(R_TCP_OPEN)
    if result.refused_ports:
        reasons.append(R_TCP_REFUSED)
    if result.mac:
        reasons.append(R_ARP)
    if reasons:
        if result.ptr:
            reasons.append(R_PTR)
        return USED, reasons, False
    if any(not templated_ptr(name, result.ip) for name in result.ptr):
        return CLAIMED, [R_PTR], False
    if result.arp_incomplete:
        reasons.append(R_NO_ARP)
    if result.unreachable:
        reasons.append(R_UNREACHABLE)
    return FREE, reasons, bool(reasons)


# ---------------------------------------------------------------------------------------
# TCP: one connection, closed at once
# ---------------------------------------------------------------------------------------

def tcp_probe(ip: str, port: int, timeout: float) -> str:
    """-> T_OPEN, T_REFUSED (a reset: a machine is there), T_TIMEOUT, T_UNREACHABLE (no such
    host: a failed ARP or a router's answer) or T_ERROR (no route from this machine, ...)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        code = sock.connect_ex((ip, port))
    except socket.timeout:
        return T_TIMEOUT
    except OSError as exc:
        code = exc.errno or -1
    finally:
        try:
            sock.close()
        except OSError:
            pass
    if code == 0:
        return T_OPEN
    if code in (errno.ECONNREFUSED, 10061):
        return T_REFUSED
    if code in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, errno.EINPROGRESS, 10060, 10035):
        return T_TIMEOUT
    if code in _UNREACHABLE_ERRNOS:
        return T_UNREACHABLE
    return T_ERROR


# ---------------------------------------------------------------------------------------
# ICMP echo
# ---------------------------------------------------------------------------------------

def icmp_checksum(data: bytes) -> int:
    """The Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b'\x00'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xffff) + (total >> 16)
    return ~total & 0xffff


def echo_request(ident: int, seq: int, payload: bytes) -> bytes:
    """An ICMP echo request (type 8) with its checksum."""
    header = struct.pack('!BBHHH', 8, 0, 0, ident & 0xffff, seq & 0xffff)
    checksum = icmp_checksum(header + payload)
    return struct.pack('!BBHHH', 8, 0, checksum, ident & 0xffff, seq & 0xffff) + payload


def parse_icmp(data: bytes) -> Optional[Tuple[int, int, bytes]]:
    """A received packet -> (type, code, the rest after the 8-byte header), the IP header
    stripped when there is one (raw sockets and macOS datagram sockets include it)."""
    if len(data) >= 20 and data[0] >> 4 == 4:
        ihl = (data[0] & 0x0f) * 4
        if ihl < 20 or len(data) < ihl + 8:
            return None
        data = data[ihl:]
    if len(data) < 8:
        return None
    return data[0], data[1], data[8:]


def unreachable_target(rest: bytes) -> Optional[str]:
    """The destination of the packet a "destination unreachable" message quotes."""
    if len(rest) < 20 or rest[0] >> 4 != 4:
        return None
    return socket.inet_ntoa(rest[16:20])


class IcmpSweeper:
    """Ping many addresses from one socket (or, on Windows, one API call per address).

    `method` is ICMP_DGRAM, ICMP_RAW, ICMP_WINDOWS or UNAVAILABLE (with `why`)."""

    def __init__(self) -> None:
        self.sock: Optional[socket.socket] = None
        self.method = UNAVAILABLE
        self.why = ''
        self.token = secrets.token_bytes(8)
        self.ident = os.getpid() & 0xffff
        if sys.platform == 'win32':
            if _windows_icmp_api() is not None:
                self.method = ICMP_WINDOWS
            else:
                self.why = 'the Windows ICMP API could not be loaded'
            return
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP)
            self.method = ICMP_DGRAM
            return
        except OSError as exc:
            first = exc
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.method = ICMP_RAW
        except OSError:
            self.why = ('this machine allows no unprivileged ping (%s); run as root, or on Linux '
                        'allow your group in net.ipv4.ping_group_range'
                        % (first.strerror or first))

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None

    def sweep(self, addresses: Sequence[str], timeout: float, rounds: int = ICMP_ROUNDS,
              stop: Optional[threading.Event] = None,
              workers: int = DEFAULT_WORKERS) -> Tuple[Dict[str, float], Set[str]]:
        """-> ({address: round-trip ms}, {addresses a router called unreachable})."""
        if self.method == ICMP_WINDOWS:
            return _windows_sweep(addresses, timeout, rounds, stop, workers)
        if self.sock is None:
            return {}, set()
        replies: Dict[str, float] = {}
        unreachable: Set[str] = set()
        index = {ip: i for i, ip in enumerate(addresses)}
        wanted = set(addresses)
        sock = self.sock
        sock.setblocking(False)
        for _round in range(max(1, rounds)):
            pending = [ip for ip in addresses if ip not in replies and ip not in unreachable]
            if not pending or (stop is not None and stop.is_set()):
                break
            sent: Dict[str, float] = {}
            for n, ip in enumerate(pending):
                if stop is not None and stop.is_set():
                    break
                payload = self.token + struct.pack('!I', index[ip]) + b'domainscope'
                packet = echo_request(self.ident, index[ip], payload)
                for _try in range(4):
                    try:
                        sock.sendto(packet, (ip, 0))
                        sent[ip] = time.monotonic()
                        break
                    except OSError as exc:
                        if exc.errno in _TRANSIENT_ERRNOS:
                            self._drain(sock, addresses, wanted, sent, replies, unreachable, 0.005)
                            continue
                        if exc.errno in _UNREACHABLE_ERRNOS:
                            unreachable.add(ip)
                        break
                if n % 32 == 31:
                    self._drain(sock, addresses, wanted, sent, replies, unreachable, 0.0)
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and len(replies) + len(unreachable) < len(addresses):
                if stop is not None and stop.is_set():
                    break
                self._drain(sock, addresses, wanted, sent, replies, unreachable,
                            min(0.05, max(0.0, deadline - time.monotonic())))
        return replies, unreachable - set(replies)

    def _drain(self, sock: socket.socket, addresses: Sequence[str], wanted: Set[str],
               sent: Mapping[str, float], replies: Dict[str, float], unreachable: Set[str],
               wait: float) -> None:
        try:
            ready, _, _ = select.select([sock], [], [], wait)
        except (OSError, ValueError):
            return
        while ready:
            try:
                data, peer = sock.recvfrom(2048)
            except (BlockingIOError, InterruptedError):
                return
            except OSError:
                return
            now = time.monotonic()
            parsed = parse_icmp(data)
            if parsed is not None:
                kind, code, rest = parsed
                if kind == 0 and rest[:8] == self.token and len(rest) >= 12:
                    i = struct.unpack('!I', rest[8:12])[0]
                    ip = addresses[i] if i < len(addresses) else None
                    # the answer must come from the address asked (never a broadcast reply)
                    if ip is not None and peer and peer[0] == ip and ip in sent and ip not in replies:
                        replies[ip] = round((now - sent[ip]) * 1000.0, 1)
                elif kind == 3 and code == 1:
                    target = unreachable_target(rest)
                    if target in wanted:
                        unreachable.add(target)
            try:
                ready, _, _ = select.select([sock], [], [], 0)
            except (OSError, ValueError):
                return


_WIN_ICMP: Dict[str, Any] = {}


def _windows_icmp_api() -> Optional[Any]:
    """iphlpapi's IcmpCreateFile / IcmpSendEcho / IcmpCloseHandle, or None."""
    if sys.platform != 'win32':
        return None
    if 'api' in _WIN_ICMP:
        return _WIN_ICMP['api']
    try:
        import ctypes
        from ctypes import wintypes
        lib = ctypes.WinDLL('iphlpapi', use_last_error=True)
        lib.IcmpCreateFile.restype = wintypes.HANDLE
        lib.IcmpCreateFile.argtypes = []
        lib.IcmpSendEcho.restype = wintypes.DWORD
        lib.IcmpSendEcho.argtypes = [wintypes.HANDLE, ctypes.c_ulong, ctypes.c_void_p, wintypes.WORD,
                                     ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        lib.IcmpCloseHandle.restype = wintypes.BOOL
        lib.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
        _WIN_ICMP['api'] = lib
    except (OSError, AttributeError, ImportError):
        _WIN_ICMP['api'] = None
    return _WIN_ICMP['api']


IP_SUCCESS = 0
IP_DEST_HOST_UNREACHABLE = 11003


def _windows_ping(ip: str, timeout: float) -> Tuple[Optional[float], bool]:
    """One echo through IcmpSendEcho -> (round-trip ms or None, host unreachable)."""
    import ctypes
    lib = _windows_icmp_api()
    if lib is None:
        return None, False
    handle = lib.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return None, False
    try:
        payload = b'domainscope-ip-scan'
        data = ctypes.create_string_buffer(payload, len(payload))
        reply = ctypes.create_string_buffer(256 + len(payload))
        dest = struct.unpack('<I', socket.inet_aton(ip))[0]
        count = lib.IcmpSendEcho(handle, dest, data, len(payload), None, reply, len(reply),
                                 max(1, int(timeout * 1000)))
        if count:
            status, rtt = struct.unpack_from('<II', reply.raw, 4)
            if status == IP_SUCCESS:
                return float(rtt), False
            return None, status == IP_DEST_HOST_UNREACHABLE
        return None, ctypes.get_last_error() == IP_DEST_HOST_UNREACHABLE
    finally:
        lib.IcmpCloseHandle(handle)


def _windows_sweep(addresses: Sequence[str], timeout: float, rounds: int,
                   stop: Optional[threading.Event], workers: int) -> Tuple[Dict[str, float], Set[str]]:
    replies: Dict[str, float] = {}
    unreachable: Set[str] = set()
    lock = threading.Lock()

    def one(ip: str) -> None:
        if stop is not None and stop.is_set():
            return
        rtt, gone = _windows_ping(ip, timeout)
        with lock:
            if rtt is not None:
                replies[ip] = rtt
            elif gone:
                unreachable.add(ip)

    for _round in range(max(1, rounds)):
        pending = [ip for ip in addresses if ip not in replies and ip not in unreachable]
        if not pending:
            break
        _run_all(one, pending, workers, stop)
    return replies, unreachable - set(replies)


# ---------------------------------------------------------------------------------------
# The ARP table (read only: nothing is sent)
# ---------------------------------------------------------------------------------------

_BAD_MACS = {'00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'}


def normalize_mac(text: str) -> Optional[str]:
    """`0:1b:2c:3:4:5` / `00-1B-2C-03-04-05` -> `00:1b:2c:03:04:05`; None for anything else
    (incomplete, all zeros, broadcast, multicast)."""
    parts = re.split(r'[:-]', (text or '').strip().lower())
    if len(parts) != 6 or not all(re.match(r'^[0-9a-f]{1,2}$', p) for p in parts):
        return None
    mac = ':'.join(p.zfill(2) for p in parts)
    if mac in _BAD_MACS or int(parts[0], 16) & 1:
        return None
    return mac


def parse_proc_arp(text: str) -> Dict[str, Optional[str]]:
    """/proc/net/arp -> {address: MAC, or None when the entry is incomplete / failed}."""
    out: Dict[str, Optional[str]] = {}
    for line in text.splitlines()[1:]:
        cols = line.split()
        if len(cols) < 4 or _v4(cols[0]) is None:
            continue
        try:
            flags = int(cols[2], 16)
        except ValueError:
            continue
        mac = normalize_mac(cols[3]) if flags & 0x2 else None
        if cols[0] not in out or mac:
            out[cols[0]] = mac
    return out


_ARP_LINE_RE = re.compile(r'\((\d{1,3}(?:\.\d{1,3}){3})\)\s+at\s+(\S+)')


def parse_arp_command(text: str) -> Dict[str, Optional[str]]:
    """`arp -an` (macOS, BSD) -> {address: MAC, or None for "(incomplete)"}."""
    out: Dict[str, Optional[str]] = {}
    for line in text.splitlines():
        m = _ARP_LINE_RE.search(line)
        if not m or _v4(m.group(1)) is None:
            continue
        mac = normalize_mac(m.group(2))
        if m.group(1) not in out or mac:
            out[m.group(1)] = mac
    return out


def parse_windows_ipnettable(buf: bytes) -> Dict[str, Optional[str]]:
    """A MIB_IPNETTABLE (GetIpNetTable) -> {address: MAC, or None when invalid}."""
    out: Dict[str, Optional[str]] = {}
    if len(buf) < 4:
        return out
    count = struct.unpack_from('<I', buf, 0)[0]
    for i in range(count):
        off = 4 + i * 24
        if off + 24 > len(buf):
            break
        _index, length = struct.unpack_from('<II', buf, off)
        phys = buf[off + 8:off + 16][:min(length, 8)]
        addr, kind = struct.unpack_from('<II', buf, off + 16)
        ip = socket.inet_ntoa(struct.pack('<I', addr))
        mac = None
        if kind in (3, 4) and length == 6:
            mac = normalize_mac(':'.join('%02x' % b for b in phys))
        if ip not in out or mac:
            out[ip] = mac
    return out


def _windows_arp() -> Optional[Dict[str, Optional[str]]]:
    try:
        import ctypes
        from ctypes import wintypes
        lib = ctypes.WinDLL('iphlpapi')
        size = wintypes.ULONG(0)
        lib.GetIpNetTable(None, ctypes.byref(size), False)
        if not size.value:
            return {}
        buf = ctypes.create_string_buffer(size.value)
        if lib.GetIpNetTable(buf, ctypes.byref(size), False) != 0:
            return None
        return parse_windows_ipnettable(buf.raw[:size.value])
    except (OSError, AttributeError, ImportError):
        return None


def read_arp_table() -> Tuple[Optional[Dict[str, Optional[str]]], str]:
    """-> (the table or None, the method: ARP_PROC, ARP_WINDOWS, ARP_COMMAND or UNAVAILABLE)."""
    if sys.platform.startswith('linux'):
        try:
            with open('/proc/net/arp', 'r', encoding='ascii', errors='replace') as handle:
                return parse_proc_arp(handle.read()), ARP_PROC
        except OSError:
            return None, UNAVAILABLE
    if sys.platform == 'win32':
        table = _windows_arp()
        return (table, ARP_WINDOWS) if table is not None else (None, UNAVAILABLE)
    try:
        done = subprocess.run(['arp', '-an'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=15, check=False)
    except (OSError, subprocess.SubprocessError):
        return None, UNAVAILABLE
    if done.returncode != 0:
        return None, UNAVAILABLE
    return parse_arp_command(done.stdout.decode('ascii', 'replace')), ARP_COMMAND


# ---------------------------------------------------------------------------------------
# Reverse DNS and the web Server header
# ---------------------------------------------------------------------------------------

def templated_ptr(name: str, ip: str) -> bool:
    """A provider-generated reverse name that spells the address out (`10-0-5-7.dhcp.example`,
    `ip-203-0-113-5.provider.net`, `7.5.0.10.static.example`): it exists for every address of
    the block, so it says nothing about a machine."""
    octets = ip.split('.')
    name = (name or '').lower()
    candidates = []
    for order in (octets, list(reversed(octets))):
        for sep in ('-', '.', '_', ''):
            candidates.append(sep.join(order))
            candidates.append(sep.join(o.zfill(3) for o in order))
    for text in candidates:
        if len(text) < 7:
            continue
        for m in re.finditer(re.escape(text), name):
            before = name[m.start() - 1] if m.start() else ''
            after = name[m.end()] if m.end() < len(name) else ''
            if not before.isdigit() and not after.isdigit():
                return True
    return False


def ptr_names(ip: str) -> List[str]:
    """The reverse DNS names of an address, through this machine's resolver ([] without)."""
    try:
        name, aliases, _addrs = socket.gethostbyaddr(ip)
    except (socket.herror, socket.gaierror, OSError, UnicodeError):
        return []
    out = []
    for item in [name] + list(aliases or []):
        item = (item or '').rstrip('.').lower()
        if item and item != ip and item not in out and not item.endswith('.in-addr.arpa'):
            out.append(item)
    return out[:4]


def web_server(ip: str, port: int, tls: bool, timeout: float) -> Optional[str]:
    """The Server header of `HEAD /` on an open web port (TLS not verified: only the header is
    read), or None."""
    import http.client
    conn: Any = None
    try:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(ip, port, timeout=timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(ip, port, timeout=timeout)
        conn.request('HEAD', '/', headers={'User-Agent': USER_AGENT, 'Connection': 'close'})
        response = conn.getresponse()
        server = response.getheader('Server') or ''
        server = ' '.join(server.split())[:MAX_SERVER_HEADER]
        return server or None
    except (http.client.HTTPException, OSError, ssl.SSLError, ValueError, UnicodeError):
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except OSError:
                pass


# ---------------------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------------------

def _run_all(fn: Callable[..., None], items: Iterable[Any], workers: int,
             stop: Optional[threading.Event]) -> None:
    """fn(item) for every item on a thread pool; Ctrl-C (KeyboardInterrupt in the main thread)
    stops the rest and is raised again."""
    items = list(items)
    if not items:
        return
    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(items))))
    futures = set()
    try:
        for item in items:
            futures.add(pool.submit(fn, item))
        pending = futures
        while pending:
            done, pending = wait_futures(pending, timeout=0.2, return_when=FIRST_COMPLETED)
            for future in done:
                exc = future.exception()
                if exc is not None:
                    raise exc
    except BaseException:
        if stop is not None:
            stop.set()
        for future in futures:
            future.cancel()
        pool.shutdown(wait=False)
        raise
    pool.shutdown(wait=True)


def safe_workers(requested: int) -> int:
    """Fewer threads than open files allowed: each TCP probe holds one socket (macOS starts
    with 256)."""
    try:
        import resource
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft and soft != resource.RLIM_INFINITY:
            return max(8, min(requested, soft // 2 - 16))
    except (ImportError, ValueError, OSError):
        pass
    return requested


@dataclass
class ScanReport:
    blocks: List[Block]
    results: List[HostResult]
    started_at: datetime
    finished_at: datetime
    methods: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)

    def counts(self) -> Dict[str, int]:
        out = {state: 0 for state in STATES}
        confirmed = 0
        for result in self.results:
            state, _reasons, sure = verdict(result)
            out[state] += 1
            if state == FREE and sure:
                confirmed += 1
        out['freeConfirmed'] = confirmed
        out['addresses'] = len(self.results)
        return out

    def free(self) -> List[str]:
        return [r.ip for r in self.results if r.state == FREE]

    def taken(self) -> List[HostResult]:
        return [r for r in self.results if r.state in (USED, CLAIMED)]


def run_scan(blocks: Sequence[Block], ports: Sequence[int], timeout: float = DEFAULT_TIMEOUT,
             workers: int = DEFAULT_WORKERS, icmp: bool = True, arp: bool = True, ptr: bool = True,
             web: bool = True, progress: Optional[Callable[[str, int, int], None]] = None,
             tcp: Callable[[str, int, float], str] = tcp_probe,
             sweeper_factory: Callable[[], Any] = IcmpSweeper,
             arp_reader: Callable[[], Tuple[Optional[Dict[str, Optional[str]]], str]] = read_arp_table,
             ptr_lookup: Callable[[str], List[str]] = ptr_names,
             web_lookup: Callable[[str, int, bool, float], Optional[str]] = web_server,
             now: Callable[[], datetime] = lambda: datetime.now(timezone.utc)) -> ScanReport:
    """Probe every address of the blocks (see the module docstring for what is sent)."""
    started = now()
    stop = threading.Event()
    addresses = addresses_of(blocks)
    results = {ip: HostResult(ip, reserved=reserved_role(ip, blocks)) for ip in addresses}
    live = [ip for ip in addresses if not results[ip].reserved]
    methods: Dict[str, Any] = {'icmp': OFF, 'arp': OFF, 'tcpPorts': list(ports), 'ptr': ptr,
                               'web': web, 'timeout': timeout}
    warnings: List[str] = []
    lock = threading.Lock()
    workers = safe_workers(workers)

    # 1. ping: one socket, two rounds
    if icmp and live:
        sweeper = sweeper_factory()
        methods['icmp'] = sweeper.method
        if sweeper.method == UNAVAILABLE:
            warnings.append('no ping: %s' % sweeper.why)
        else:
            if progress:
                progress('ping', 0, len(live))
            try:
                replies, gone = sweeper.sweep(live, timeout, stop=stop, workers=workers)
            finally:
                sweeper.close()
            for ip, rtt in replies.items():
                results[ip].rtt_ms = rtt
            for ip in gone:
                results[ip].unreachable = True
            if progress:
                progress('ping', len(live), len(live))

    def apply_arp(table: Optional[Dict[str, Optional[str]]]) -> None:
        if table is None:
            return
        for ip in live:
            if ip in table:
                results[ip].on_link = True
                mac = table[ip]
                if mac:
                    results[ip].mac = mac
                    results[ip].arp_incomplete = False
                elif not results[ip].mac:
                    results[ip].arp_incomplete = True
            elif results[ip].on_link is None:
                results[ip].on_link = False

    # 2. the ARP table after the pings: an address on this network that no device answered
    #    ARP for has nothing behind it, and its TCP probes are skipped
    arp_method = OFF
    if arp and live:
        table, arp_method = arp_reader()
        methods['arp'] = arp_method
        if table is None:
            warnings.append('the ARP table could not be read: "free" is never confirmed')
        elif methods['icmp'] not in (OFF, UNAVAILABLE):
            apply_arp(table)

    # 3. TCP, port by port across the addresses (an address proven absent is skipped), with
    #    the reverse DNS questions on the same pool
    tasks: List[Tuple[str, Any]] = []
    for port in ports:
        for ip in live:
            tasks.append(('tcp', (ip, port)))
    if ptr:
        tasks.extend(('ptr', ip) for ip in live)
    done = [0]
    total = len(tasks)

    def one(task: Tuple[str, Any]) -> None:
        if stop.is_set():
            return
        kind, arg = task
        if kind == 'ptr':
            names = ptr_lookup(arg)
            with lock:
                results[arg].ptr = names
        else:
            ip, port = arg
            result = results[ip]
            if (result.arp_incomplete and not result.mac and result.rtt_ms is None) or result.unreachable:
                with lock:
                    result.skipped_tcp = True
            else:
                outcome = tcp(ip, port, timeout)
                with lock:
                    if outcome == T_OPEN:
                        result.open_ports.append(port)
                    elif outcome == T_REFUSED:
                        result.refused_ports.append(port)
                    elif outcome == T_UNREACHABLE and not result.open_ports and not result.refused_ports:
                        result.unreachable = True
                    elif outcome == T_ERROR and len(result.errors) < 3:
                        result.errors.append('tcp/%d: no route from this machine' % port)
        with lock:
            done[0] += 1
            if progress and (done[0] % 50 == 0 or done[0] == total):
                progress('tcp', done[0], total)

    if progress and total:
        progress('tcp', 0, total)
    _run_all(one, tasks, workers, stop)

    # 4. the ARP table again: the TCP connections made this machine ask for every address on
    #    its own network (the only signal when ping is not allowed)
    if arp and live and arp_method != UNAVAILABLE:
        table, _method = arp_reader()
        apply_arp(table)

    # 5. the Server header of the open web ports
    if web:
        web_tasks = [(r.ip, port) for r in results.values() for port in sorted(r.open_ports) if port in WEB_PORTS]

        def web_one(task: Tuple[str, int]) -> None:
            ip, port = task
            server = web_lookup(ip, port, WEB_PORTS[port], timeout)
            if server:
                with lock:
                    results[ip].web[port] = server

        _run_all(web_one, web_tasks, workers, stop)

    for result in results.values():
        result.open_ports.sort()
        result.refused_ports.sort()
    return ScanReport(list(blocks), [results[ip] for ip in addresses], started, now(), methods, warnings)


# ---------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------

class _Color:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, code: str, text: str) -> str:
        return '\x1b[%sm%s\x1b[0m' % (code, text) if self.enabled else text

    red = lambda self, t: self.paint('31', t)
    yellow = lambda self, t: self.paint('33', t)
    green = lambda self, t: self.paint('32', t)
    dim = lambda self, t: self.paint('2', t)
    bold = lambda self, t: self.paint('1', t)


_STATE_COLOR = {USED: 'red', CLAIMED: 'yellow', FREE: 'green', RESERVED: 'dim'}
_ICMP_TEXT = {ICMP_DGRAM: 'ping', ICMP_RAW: 'ping (raw socket)', ICMP_WINDOWS: 'ping (Windows API)',
              OFF: 'no ping (--no-ping)', UNAVAILABLE: 'no ping (not allowed here)'}
_ARP_TEXT = {ARP_PROC: 'ARP table', ARP_COMMAND: 'ARP table (arp -an)', ARP_WINDOWS: 'ARP table',
             OFF: 'no ARP (--no-arp)', UNAVAILABLE: 'no ARP table'}


def free_ranges(ips: Sequence[str]) -> List[str]:
    """Consecutive addresses folded: [.2, .3, .4, .9] -> ['x.2-x.4', 'x.9']."""
    values = sorted(int(ipaddress.IPv4Address(ip)) for ip in ips)
    out: List[str] = []
    i = 0
    while i < len(values):
        j = i
        while j + 1 < len(values) and values[j + 1] == values[j] + 1:
            j += 1
        a, b = ipaddress.IPv4Address(values[i]), ipaddress.IPv4Address(values[j])
        out.append(str(a) if i == j else '%s-%s' % (a, b))
        i = j + 1
    return out


def _plural(count: int, word: str, plural: Optional[str] = None) -> str:
    return '%d %s' % (count, word if count == 1 else (plural or word + 's'))


def _note(result: HostResult) -> str:
    state, reasons, confirmed = verdict(result)
    bits: List[str] = []
    if result.reserved:
        return '%s address' % result.reserved
    if result.ptr:
        bits.append(', '.join(result.ptr))
    for port in sorted(result.web):
        bits.append(result.web[port] if len(result.web) == 1 else '%d: %s' % (port, result.web[port]))
    if state == CLAIMED:
        bits.append('(a DNS name, nothing answered)')
    elif state == FREE and R_NO_ARP in reasons:
        bits.append('no device answered ARP')
    elif state == FREE and R_UNREACHABLE in reasons:
        bits.append('host unreachable')
    if result.errors and state != USED:
        bits.append(result.errors[0])
    return ' · '.join(_plain(b) for b in bits)


def render_text(report: ScanReport, color: Optional[_Color] = None, show: str = 'all') -> str:
    """The table (all addresses, or only `used` / `free` ones) and the summary."""
    color = color or _Color(False)
    out = io.StringIO()
    counts = report.counts()
    seconds = (report.finished_at - report.started_at).total_seconds()
    methods = report.methods
    out.write('%s %s · %s · %s · %s · %s · %s · %.1f s\n\n' % (
        PROG, __version__, ', '.join(b.text for b in report.blocks), _plural(counts['addresses'], 'address', 'addresses'),
        _ICMP_TEXT.get(methods.get('icmp'), str(methods.get('icmp'))),
        _ARP_TEXT.get(methods.get('arp'), str(methods.get('arp'))),
        _plural(len(methods.get('tcpPorts') or []), 'TCP port'), seconds))
    rows = report.results
    if show == 'used':
        rows = [r for r in rows if r.state in (USED, CLAIMED)]
    elif show == 'free':
        rows = [r for r in rows if r.state == FREE]
    if rows:
        out.write('%-15s  %-8s  %-8s  %-22s  %-17s  %s\n' % ('IP', 'STATE', 'PING', 'PORTS', 'MAC', 'NAME / WEB'))
        for r in rows:
            state = r.state
            label = state + ('*' if state == FREE and r.confirmed else '')
            ping = '%.1f ms' % r.rtt_ms if r.rtt_ms is not None else ''
            ports = ','.join(str(p) for p in r.open_ports)
            if not ports and r.refused_ports:
                ports = '(closed: %s)' % ','.join(str(p) for p in r.refused_ports[:3])
            if len(ports) > 22:
                ports = ports[:21] + '…'
            paint = getattr(color, _STATE_COLOR[state])
            out.write('%-15s  %s  %-8s  %-22s  %-17s  %s\n' % (
                r.ip, paint('%-8s' % label), ping, ports, r.mac or '', _note(r)))
        out.write('\n')
    summary = [color.red(_plural(counts[USED], 'used', 'used'))]
    if counts[CLAIMED]:
        summary.append(color.yellow('%d silent with a DNS name' % counts[CLAIMED]))
    free_text = _plural(counts[FREE], 'free', 'free')
    if counts['freeConfirmed']:
        free_text += ' (%d confirmed*: no device answered ARP, or unreachable)' % counts['freeConfirmed']
    summary.append(color.green(free_text))
    if counts[RESERVED]:
        summary.append(color.dim('%d reserved' % counts[RESERVED]))
    out.write('Summary: %s\n' % ' · '.join(summary))
    free = report.free()
    if free:
        folded = free_ranges(free)
        shown = folded[:12]
        out.write('Free: %s%s\n' % (', '.join(shown), ' … (+%d)' % (len(folded) - 12) if len(folded) > 12 else ''))
    if counts[FREE] and not counts['freeConfirmed']:
        out.write(color.dim('Note: nothing confirmed "free" - a machine that drops every packet looks free. '
                            'Run it from a machine on the same network (ARP), or check your inventory.\n'))
    for warning in report.warnings:
        out.write(color.dim('Note: %s\n' % warning))
    return out.getvalue()


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def result_to_dict(result: HostResult) -> Dict[str, Any]:
    state, reasons, confirmed = verdict(result)
    return {
        'ip': result.ip,
        'state': state,
        'confirmed': confirmed,
        'reasons': reasons,
        'reserved': result.reserved,
        'rttMs': result.rtt_ms,
        'open': list(result.open_ports),
        'refused': list(result.refused_ports),
        'mac': result.mac,
        'onLink': result.on_link,
        'ptr': list(result.ptr),
        'ptrTemplated': bool(result.ptr) and all(templated_ptr(n, result.ip) for n in result.ptr),
        'web':{str(port): server for port, server in sorted(result.web.items())},
        'errors': list(result.errors),
    }


def report_to_dict(report: ScanReport) -> Dict[str, Any]:
    counts = report.counts()
    return {
        'schema': SCHEMA,
        'tool': TOOL,
        'version': __version__,
        'startedAt': _iso(report.started_at),
        'finishedAt': _iso(report.finished_at),
        'targets': [b.text for b in report.blocks],
        'methods': dict(report.methods),
        'summary': {'addresses': counts['addresses'], 'used': counts[USED], 'claimed': counts[CLAIMED],
                    'free': counts[FREE], 'freeConfirmed': counts['freeConfirmed'],
                    'reserved': counts[RESERVED]},
        'warnings': list(report.warnings),
        'results': [result_to_dict(r) for r in report.results],
    }


CSV_COLUMNS = ('ip', 'state', 'confirmed', 'reasons', 'ping_ms', 'open_ports', 'refused_ports', 'mac',
               'ptr', 'web', 'reserved')


def render_csv(report: ScanReport, lineterminator: str = '\r\n') -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator=lineterminator)
    writer.writerow(CSV_COLUMNS)
    for r in report.results:
        state, reasons, confirmed = verdict(r)
        writer.writerow([csv_cell(v) for v in (
            r.ip, state, confirmed, ' '.join(reasons), r.rtt_ms if r.rtt_ms is not None else '',
            ' '.join(str(p) for p in r.open_ports), ' '.join(str(p) for p in r.refused_ports), r.mac or '',
            ' '.join(r.ptr), ' '.join('%d=%s' % (p, s) for p, s in sorted(r.web.items())), r.reserved or '')])
    return out.getvalue()


# ---------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------

EPILOG = """examples:
  %(prog)s 10.0.5.0/24                      the whole /24: used, claimed, free
  %(prog)s 10.0.5.20-60 --free              only the free addresses, one a line
  %(prog)s 10.0.5.37 --expect-free          exit 1 when 10.0.5.37 is taken (before you assign it)
  %(prog)s 10.0.5.0/24 --json scan.json     a report for the web app's IP Scan view
  %(prog)s -t ranges.txt --ports quick      the ranges of a file, five ports per address

Scan only networks you run or are authorised to scan. Run it from a machine on that network:
the ARP table only knows the addresses of the machine's own network, and only those can be
confirmed free."""


def build_parser() -> argparse.ArgumentParser:
    description = ('Which addresses of an IPv4 range are in use, and which are free: ping, a few '
                   'TCP ports, the ARP table and reverse DNS, per address. Python 3.8+, stdlib only.')
    parser = argparse.ArgumentParser(prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=description, epilog=EPILOG)
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('targets', nargs='*', metavar='TARGET',
                        help='a network (10.0.5.0/24), a range (10.0.5.10-10.0.5.50 or 10.0.5.10-50) '
                             'or an address')
    src = parser.add_argument_group('targets')
    src.add_argument('-t', '--targets-file', action='append', default=[], metavar='FILE',
                     help='a file of targets, one or more a line ("-" = stdin, # starts a comment); repeatable')
    src.add_argument('--max-addresses', type=int, default=DEFAULT_MAX_ADDRESSES, metavar='N',
                     help='refuse more than N addresses (default: %(default)s, a /20; at most '
                          + str(MAX_ADDRESSES) + ')')
    how = parser.add_argument_group('what is asked')
    how.add_argument('-p', '--ports', default='default', metavar='LIST',
                     help='TCP ports per address: "default" (%s), "quick" (%s), "none", or a list '
                          'such as 22,80,443,8000-8010 (at most %d)'
                          % (','.join(str(p) for p in DEFAULT_PORTS), ','.join(str(p) for p in QUICK_PORTS), MAX_PORTS))
    how.add_argument('--no-ping', action='store_true', help='send no ICMP echo requests')
    how.add_argument('--no-arp', action='store_true', help='do not read the ARP table')
    how.add_argument('--no-ptr', action='store_true', help='ask no reverse DNS names')
    how.add_argument('--no-web', action='store_true', help='do not ask the open web ports for their Server header')
    how.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                     help='per ping round and per TCP connection (default: %(default)s)')
    how.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                     help='probes in parallel (default: %(default)s; fewer when the open-file limit is low)')
    out = parser.add_argument_group('output')
    out.add_argument('--json', metavar='FILE', help='write a JSON report ("-" = stdout); the web app opens it')
    out.add_argument('--csv', metavar='FILE', help='write a CSV report ("-" = stdout)')
    out.add_argument('--show', choices=('all', 'used', 'free'), default='all',
                     help='which addresses the table lists (default: all)')
    out.add_argument('--free', action='store_true',
                     help='print only the free addresses, one a line (nothing else on stdout)')
    out.add_argument('--expect-free', action='store_true',
                     help='exit with code 1 when any address scanned is used or claimed')
    out.add_argument('--no-color', action='store_true', help='no ANSI colors')
    out.add_argument('-q', '--quiet', action='store_true', help='no progress or notes on stderr')
    return parser


def _same_path(a: str, b: str) -> bool:
    try:
        return os.path.samefile(a, b)
    except OSError:
        return os.path.abspath(a) == os.path.abspath(b)


def _write(path: str, text: str, encoding: str = 'utf-8') -> None:
    """stdout for "-", else a temporary file in the same directory renamed over the target, so
    a report is never left half written."""
    if path == '-':
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.ip_scan-', suffix='.tmp', dir=directory)
    try:
        with os.fdopen(fd, 'w', encoding=encoding, newline='') as handle:
            handle.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _run(args: argparse.Namespace) -> int:
    err = sys.stderr
    if not 0 < args.timeout <= MAX_TIMEOUT:
        raise UsageError('--timeout must be > 0 and <= %g seconds' % MAX_TIMEOUT)
    if not 1 <= args.workers <= MAX_WORKERS:
        raise UsageError('--workers must be between 1 and %d' % MAX_WORKERS)
    if not 1 <= args.max_addresses <= MAX_ADDRESSES:
        raise UsageError('--max-addresses must be between 1 and %d' % MAX_ADDRESSES)
    stdout_users = [name for name, used in (('--json -', args.json == '-'), ('--csv -', args.csv == '-'),
                                            ('--free', args.free)) if used]
    if len(stdout_users) > 1:
        raise UsageError('%s cannot share stdout' % ' and '.join(stdout_users))
    if args.json and args.csv and args.json != '-' and _same_path(args.json, args.csv):
        raise UsageError('--json and --csv name the same file')
    ports = parse_ports(args.ports)
    blocks, addresses = parse_targets(args.targets, files=args.targets_file, max_addresses=args.max_addresses)
    if not blocks:
        raise UsageError('no targets: give a network (10.0.5.0/24), a range (10.0.5.10-50), an address or -t FILE')

    if not args.quiet:
        print('note: scanning %s on %s (%s); scan only networks you run or are authorised to scan'
              % (_plural(len(addresses), 'address', 'addresses'), ', '.join(b.text for b in blocks[:4])
                 + (' …' if len(blocks) > 4 else ''), _plural(len(ports), 'TCP port')), file=err)
    tty = not args.quiet and hasattr(err, 'isatty') and err.isatty()

    def progress(phase: str, done: int, total: int) -> None:
        if tty:
            err.write('\r%-4s %d / %d   ' % (phase, done, total))
            if phase == 'tcp' and done == total:
                err.write('\r' + ' ' * 30 + '\r')
            err.flush()

    report = run_scan(blocks, ports, timeout=args.timeout, workers=args.workers, icmp=not args.no_ping,
                      arp=not args.no_arp, ptr=not args.no_ptr, web=not args.no_web, progress=progress)

    failed = False
    for path, kind in ((args.json, 'json'), (args.csv, 'csv')):
        if not path:
            continue
        text = (json.dumps(report_to_dict(report), indent=2) + '\n' if kind == 'json'
                else render_csv(report, '\n' if path == '-' else '\r\n'))
        try:
            _write(path, text, 'utf-8' if kind == 'json' or path == '-' else 'utf-8-sig')
        except OSError as exc:
            print('%s: error: cannot write %s: %s' % (PROG, _plain(path), exc.strerror or exc), file=err)
            failed = True

    if args.free:
        sys.stdout.write(''.join(ip + '\n' for ip in report.free()))
        sys.stdout.flush()
    elif args.json != '-' and args.csv != '-':
        use_color = not args.no_color and not os.environ.get('NO_COLOR') \
            and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        sys.stdout.write(render_text(report, _Color(use_color), show=args.show))
        sys.stdout.flush()
    elif not args.quiet:
        counts = report.counts()
        print('%d used · %d claimed · %d free · %d reserved' % (counts[USED], counts[CLAIMED], counts[FREE],
                                                               counts[RESERVED]), file=err)

    if failed:
        return EXIT_OUTPUT_ERROR
    if args.expect_free and report.taken():
        if not args.quiet:
            print('%s: taken: %s' % (PROG, ', '.join('%s (%s)' % (r.ip, r.state) for r in report.taken()[:10])), file=err)
        return EXIT_IN_USE
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point; returns the exit code (0, 1, 2, 3, 70 or 130)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')
        except (AttributeError, ValueError, io.UnsupportedOperation):
            pass
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else EXIT_USAGE
    try:
        return _run(args)
    except UsageError as exc:
        print('%s: error: %s' % (PROG, exc), file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print('\ninterrupted', file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # noqa: BLE001 - an internal error must not look like a result
        print('%s: internal error: %s: %s' % (PROG, type(exc).__name__, _plain(str(exc))), file=sys.stderr)
        traceback.print_exc()
        return EXIT_INTERNAL_ERROR


if __name__ == '__main__':
    sys.exit(main())
