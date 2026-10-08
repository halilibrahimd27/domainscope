#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dns_parity.py - before you move a zone to a new DNS provider, check that the new name servers
serve what the zone file says.

Companion CLI of the "DomainScope - SSL & DNS Toolkit" web app
(https://github.com/halilibrahimd27/domainscope). The web app's Zone File view compares a zone
with the NEW name servers through Globalping probes, up to 100 probes a run; this script does
the same from your own machine, for zones of any size and for free: it reads a BIND zone file
and asks each new name server directly (UDP port 53, TCP when an answer is truncated) for every
record set of the file, before the registrar's NS records change.

It reports, per name server: record sets that are MISSING there, DIFFERENT, or served
without the proxy (UNPROXIED: a Cloudflare-proxied record answered with its origin), records
at a name of the file that the file does not have (EXTRA: a provider's parking address, a
default MX), TTL differences, whether the server is authoritative for the zone and its SOA
serial, and the order of the move.

Python 3.8+, standard library only, single file - copy it anywhere.

The module is importable: parse_zone(), build_query(), parse_message(), query_dns(),
parse_nameserver(), check_nameserver(), run_parity(), render_summary(), report_to_dict(),
render_csv() and main() are the public API.
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import ipaddress
import json
import os
import random
import re
import socket
import struct
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

__version__ = '1.0.0'
PROG = 'dns_parity.py'

# --- row statuses ------------------------------------------------------------------------
SAME = 'SAME'            # the new server serves what the file says
DIFFERENT = 'DIFFERENT'  # it serves other values (or a CNAME instead)
MISSING = 'MISSING'      # it does not serve the record set (NXDOMAIN / no data)
UNPROXIED = 'UNPROXIED'  # a Cloudflare-proxied record answered with its origin
EXTRA = 'EXTRA'          # a record at a name of the file that the file does not have
SKIPPED = 'SKIPPED'      # not compared (a DNSSEC type, an alias, below a delegation ...)
ERROR = 'ERROR'          # no usable answer (timeout, SERVFAIL, REFUSED ...)
STATUSES = (SAME, DIFFERENT, MISSING, UNPROXIED, EXTRA, SKIPPED, ERROR)
# What --fail-on-diff exits 1 for (with a server that does not serve the zone).
PROBLEMS = (DIFFERENT, MISSING, UNPROXIED, EXTRA)
# What must be fixed at the new provider before the switch (the verdict 'fix', as in the web app);
# UNPROXIED and EXTRA rows are 'check': a decision to make, not a copy error.
TO_FIX = (DIFFERENT, MISSING)

# --- name server states (its SOA answer) ---------------------------------------------------
NS_OK = 'OK'
NS_REFUSED = 'REFUSED'
NS_NOT_AUTHORITATIVE = 'NOT_AUTHORITATIVE'
NS_NO_ZONE = 'NO_ZONE'
NS_SERVFAIL = 'SERVFAIL'
NS_UNREACHABLE = 'UNREACHABLE'

EXIT_OK = 0
EXIT_DIFFERENCES = 1   # only with --fail-on-diff
EXIT_USAGE = 2
EXIT_OUTPUT_ERROR = 3  # a --json / --csv file could not be written after the run
EXIT_INTERRUPTED = 130

DEFAULT_PORT = 53
DEFAULT_TIMEOUT = 3.0
DEFAULT_WORKERS = 8
MAX_WORKERS = 64
UDP_PAYLOAD = 1232           # EDNS(0) buffer size (DNS flag day 2020)
TRIES = 2                    # UDP attempts per question (like dig +tries=2)
MAX_NAMESERVERS = 8
MAX_ZONE_BYTES = 20 * 1024 * 1024
TTL_AUTO = 1                 # a Cloudflare export writes TTL 1 for "automatic"

TYPE_CODES = {
    'A': 1, 'NS': 2, 'CNAME': 5, 'SOA': 6, 'PTR': 12, 'MX': 15, 'TXT': 16, 'AAAA': 28, 'SRV': 33,
    'NAPTR': 35, 'DS': 43, 'SSHFP': 44, 'RRSIG': 46, 'NSEC': 47, 'DNSKEY': 48, 'NSEC3': 50,
    'NSEC3PARAM': 51, 'TLSA': 52, 'SMIMEA': 53, 'CDS': 59, 'CDNSKEY': 60, 'OPENPGPKEY': 61,
    'SVCB': 64, 'HTTPS': 65, 'SPF': 99, 'CAA': 257, 'DNAME': 39, 'OPT': 41, 'LOC': 29, 'URI': 256,
}
TYPE_NAMES = {code: name for name, code in TYPE_CODES.items()}
# SvcParamKeys by number (RFC 9460, 9461, 9540 and tls-supported-groups, as lib/dnswire.js);
# any other key is keyN.
SVC_KEYS = ('mandatory', 'alpn', 'no-default-alpn', 'port', 'ipv4hint', 'ech', 'ipv6hint', 'dohpath',
            'ohttp', 'tls-supported-groups')
# LOC's size and precisions when the file leaves them out: 1m, 10000m, 10m (RFC 1876).
LOC_DEFAULTS = (0x12, 0x16, 0x13)
# Signed live by the provider: never compared with an export.
DNSSEC_TYPES = ('RRSIG', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'DNSKEY', 'CDNSKEY')
# Asked at every name of the file that has none of them, to find EXTRA records.
EXTRA_TYPES = ('A', 'AAAA', 'MX', 'TXT', 'CAA')
RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'}
CLASSES = ('IN', 'CH', 'HS', 'CS')

# Cloudflare's published ranges (https://www.cloudflare.com/ips/, 2026-09-23): a proxied
# record answered from these is still proxied at the new provider.
CLOUDFLARE_RANGES = tuple(ipaddress.ip_network(n) for n in (
    '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
    '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22',
    '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13',
    '131.0.72.0/22', '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32',
    '2405:8100::/32', '2a06:98c0::/29', '2c0f:f248::/32'))


class UsageError(Exception):
    """Bad command line or input; reported as ``error: ...`` with exit code 2."""


class DnsError(Exception):
    """A question that got no usable DNS answer (timeout, a malformed or foreign reply)."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind  # 'timeout' | 'network' | 'format' | 'resolve' (a name server's own name)


# ---------------------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------------------

_PLAIN_LABEL = re.compile(r'^[a-z0-9_*-]+$')


def text_to_labels(name: str) -> List[bytes]:
    """A presentation name (absolute, no trailing dot needed; ``\\DDD`` and ``\\X`` escapes)
    as wire labels. Raises ValueError for an empty label, a label over 63 or a name over 255
    octets."""
    labels = []  # type: List[bytes]
    cur = bytearray()
    i = 0
    text = name[:-1] if name.endswith('.') and not name.endswith('\\.') else name
    if text in ('', '.'):
        return []
    while i < len(text):
        char = text[i]
        if char == '\\' and i + 1 < len(text):
            nxt = text[i + 1:i + 4]
            if len(nxt) == 3 and nxt.isdigit():
                value = int(nxt)
                if value > 255:
                    raise ValueError('bad escape in %r' % name)
                cur.append(value)
                i += 4
                continue
            cur.extend(text[i + 1].encode('utf-8'))
            i += 2
            continue
        if char == '.':
            if not cur:
                raise ValueError('empty label in %r' % name)
            labels.append(bytes(cur))
            cur = bytearray()
            i += 1
            continue
        cur.extend(char.encode('utf-8'))
        i += 1
    if not cur:
        raise ValueError('empty label in %r' % name)
    labels.append(bytes(cur))
    if any(len(label) > 63 for label in labels) or sum(len(label) + 1 for label in labels) + 1 > 255:
        raise ValueError('name too long: %r' % name)
    return labels


def labels_to_text(labels: Sequence[bytes]) -> str:
    """Wire labels as the canonical presentation name: lowercase, no trailing dot, anything
    outside letters, digits, '-', '_' and a lone '*' written ``\\DDD`` (the root is '')."""
    out = []
    for label in labels:
        low = label.lower()
        if low == b'*' or all(chr(b) in 'abcdefghijklmnopqrstuvwxyz0123456789-_' for b in low):
            out.append(low.decode('ascii'))
        else:
            out.append(''.join(chr(b) if chr(b) in 'abcdefghijklmnopqrstuvwxyz0123456789-_' else '\\%03d' % b
                               for b in low))
    return '.'.join(out)


def canonical_name(name: str) -> str:
    """A presentation name in the canonical form of :func:`labels_to_text`."""
    return labels_to_text(text_to_labels(name))


def absolute_name(token: str, origin: Optional[str]) -> str:
    """A zone-file name (``@``, relative or absolute) as a canonical absolute name."""
    if token == '@':
        if origin is None:
            raise ValueError('"@" without an origin')
        return origin
    if token.endswith('.') and not token.endswith('\\.'):
        return canonical_name(token)
    if origin is None:
        raise ValueError('relative name %r without an origin ($ORIGIN or --origin)' % token)
    return canonical_name(token + ('.' + origin if origin else ''))


def in_zone(name: str, origin: str) -> bool:
    return name == origin or name.endswith('.' + origin)


def record_origin(record: 'Record', zone_origin: str) -> str:
    """The origin that completes the relative names in a record's data: the $ORIGIN in force
    at that line of the file, else the zone's."""
    return record.origin if record.origin is not None else zone_origin


# ---------------------------------------------------------------------------------------
# Zone file (BIND / RFC 1035 master format)
# ---------------------------------------------------------------------------------------

@dataclass
class Token:
    text: str
    quoted: bool = False


@dataclass
class Entry:
    line: int
    blank_owner: bool
    tokens: List[Token]
    comment: str


@dataclass
class Record:
    """One resource record of the zone file."""
    name: str
    rtype: str
    ttl: Optional[int]
    tokens: List[Token]
    line: int
    comment: str = ''
    proxied: Optional[bool] = None   # Cloudflare cf_tags=cf-proxied:true|false
    flatten: bool = False            # Cloudflare cf_tags=cf-flatten-cname
    routing: bool = False            # a cli53 "; AWS routing=" variant
    alias: Optional[str] = None      # a cli53 "AWS ALIAS <type> <target>" record
    origin: Optional[str] = None     # the $ORIGIN in force at this record (relative names in its data)


@dataclass
class Zone:
    origin: str
    records: List[Record]
    warnings: List[str] = field(default_factory=list)
    cloudflare: bool = False


def split_entries(text: str) -> Tuple[List[Entry], List[str]]:
    """Master-file entries: parentheses join lines, ``;`` starts a comment outside quotes,
    quoted strings keep their escapes; an entry whose line starts with a blank has no owner."""
    entries = []  # type: List[Entry]
    warnings = []  # type: List[str]
    tokens = []  # type: List[Token]
    comments = []  # type: List[str]
    depth = 0
    line = 1
    entry_line = 1
    blank = False
    line_start = True
    i = 0
    n = len(text)

    def finish() -> None:
        nonlocal tokens, comments
        if tokens:
            entries.append(Entry(entry_line, blank, tokens, ' '.join(comments).strip()))
        tokens = []
        comments = []

    while i < n:
        char = text[i]
        if line_start:
            line_start = False
            if depth == 0 and not tokens:
                blank = char in ' \t'
                entry_line = line
        if char == '\n':
            line += 1
            line_start = True
            if depth == 0:
                finish()
            i += 1
            continue
        if char in ' \t\r':
            i += 1
            continue
        if char == ';':
            end = text.find('\n', i)
            end = n if end < 0 else end
            comments.append(text[i + 1:end])
            i = end
            continue
        if char == '(':
            depth += 1
            i += 1
            continue
        if char == ')':
            if depth:
                depth -= 1
            i += 1
            continue
        if char == '"':
            j = i + 1
            buf = []
            while j < n and text[j] != '"' and text[j] != '\n':
                if text[j] == '\\' and j + 1 < n:
                    buf.append(text[j:j + 2])
                    j += 2
                    continue
                buf.append(text[j])
                j += 1
            if j >= n or text[j] != '"':
                warnings.append('line %d: a quote is never closed; entry skipped' % line)
                tokens = []
                i = j
                continue
            tokens.append(Token(''.join(buf), True))
            i = j + 1
            continue
        j = i
        buf = []
        while j < n and text[j] not in ' \t\r\n;()"':
            if text[j] == '\\' and j + 1 < n:
                buf.append(text[j:j + 2])
                j += 2
                continue
            buf.append(text[j])
            j += 1
        tokens.append(Token(''.join(buf)))
        i = j
    if depth:
        warnings.append('line %d: a parenthesis is never closed' % entry_line)
    finish()
    return entries, warnings


_TTL_RE = re.compile(r'^(?:\d+[smhdw]?)+$', re.I)
_TTL_UNITS = {'s': 1, 'm': 60, 'h': 3600, 'd': 86400, 'w': 604800}


def parse_ttl(text: str) -> Optional[int]:
    """``3600``, ``1h``, ``1h30m``, ``2d`` -> seconds; None when it is not a TTL."""
    if not _TTL_RE.match(text):
        return None
    if text.isdigit():
        return int(text)
    total = 0
    for number, unit in re.findall(r'(\d+)([smhdw]?)', text.lower()):
        total += int(number) * _TTL_UNITS.get(unit or 's', 1)
    return total


def _cf_tags(comment: str) -> Tuple[Optional[bool], bool]:
    match = re.search(r'cf_tags=(\S+)', comment)
    if not match:
        return None, False
    tags = match.group(1).split(',')
    proxied = None  # type: Optional[bool]
    if 'cf-proxied:true' in tags:
        proxied = True
    elif 'cf-proxied:false' in tags:
        proxied = False
    return proxied, 'cf-flatten-cname' in tags


def parse_zone(text: str, origin: Optional[str] = None, source: str = '') -> Zone:
    """Parse a BIND zone file (Cloudflare, cPanel, DirectAdmin, GoDaddy, cli53, ``dig AXFR``
    and the web app's "Download the zone as BIND" all fit). ``origin`` is used when the file
    names none ($ORIGIN before the first record, else the SOA owner). ``$INCLUDE`` is not
    followed and ``$GENERATE`` is not expanded (both are warnings). Raises UsageError when no
    zone name can be found."""
    entries, warnings = split_entries(text)
    current = canonical_name(origin) if origin else None
    user_origin = current
    default_ttl = None  # type: Optional[int]
    last_ttl = None  # type: Optional[int]
    last_owner = None  # type: Optional[str]
    records = []  # type: List[Record]
    zone_origin = user_origin
    cloudflare = 'cf_tags=' in text or ';; Domain:' in text
    for entry in entries:
        head = entry.tokens[0]
        if not head.quoted and head.text.startswith('$'):
            directive = head.text.upper()
            arg = entry.tokens[1].text if len(entry.tokens) > 1 else ''
            if directive == '$ORIGIN' and arg:
                try:
                    current = absolute_name(arg, current)
                except ValueError as exc:
                    warnings.append('line %d: %s' % (entry.line, exc))
                if zone_origin is None and not records:
                    zone_origin = current
            elif directive == '$TTL':
                default_ttl = parse_ttl(arg)
                if default_ttl is None:
                    warnings.append('line %d: $TTL %s is not a TTL' % (entry.line, arg))
            elif directive == '$INCLUDE':
                warnings.append('line %d: $INCLUDE %s is not followed: pass that file\'s records '
                                'in one file' % (entry.line, arg))
            elif directive == '$GENERATE':
                warnings.append('line %d: $GENERATE is not expanded; those records are not '
                                'checked' % entry.line)
            else:
                warnings.append('line %d: unknown directive %s' % (entry.line, head.text))
            continue
        toks = list(entry.tokens)
        try:
            if entry.blank_owner:
                if last_owner is None:
                    raise ValueError('a record without an owner')
                owner = last_owner
            else:
                owner = absolute_name(toks.pop(0).text, current)
        except ValueError as exc:
            warnings.append('line %d: %s' % (entry.line, exc))
            continue
        ttl = None  # type: Optional[int]
        while toks and not toks[0].quoted:
            value = parse_ttl(toks[0].text)
            if value is not None and ttl is None:
                ttl = value
                toks.pop(0)
            elif toks[0].text.upper() in CLASSES:
                toks.pop(0)
            else:
                break
        if not toks:
            warnings.append('line %d: no record type' % entry.line)
            continue
        rtype = toks.pop(0).text.upper()
        last_owner = owner
        alias = None  # type: Optional[str]
        if rtype == 'AWS' and toks and toks[0].text.upper() == 'ALIAS':
            alias = toks[1].text.upper() if len(toks) > 1 else 'A'
            rtype = 'ALIAS'
        elif rtype not in TYPE_CODES:
            code = int(rtype[4:]) if re.match(r'^TYPE\d{1,5}$', rtype) else 0
            if not 0 < code < 65536:
                warnings.append('line %d: unknown record type %s' % (entry.line, rtype))
                continue
            # RFC 3597's TYPEnnn: a known type by its name, as the servers' answers say it.
            rtype = TYPE_NAMES.get(code, 'TYPE%d' % code)
        if ttl is None:
            ttl = default_ttl if default_ttl is not None else last_ttl
        if rtype == 'SOA' and zone_origin is None:
            zone_origin = owner
            if current is None:
                # cPanel and others write an absolute SOA owner and no $ORIGIN: the relative
                # owners after it are under the zone, as in zoneparse.js.
                current = owner
        if rtype == 'SOA' and ttl is None and len(toks) >= 7:
            ttl = parse_ttl(toks[6].text)
        last_ttl = ttl if ttl is not None else last_ttl
        proxied, flatten = _cf_tags(entry.comment)
        records.append(Record(owner, rtype, ttl, toks, entry.line, entry.comment, proxied, flatten,
                              'AWS routing=' in entry.comment, alias, current))
    if zone_origin is None:
        raise UsageError('%s names no zone: give --origin example.com' % (source or 'the zone file'))
    kept = []
    for record in records:
        if in_zone(record.name, zone_origin):
            kept.append(record)
        else:
            warnings.append('line %d: %s is outside %s; not checked' % (record.line, record.name,
                                                                         zone_origin))
    return Zone(zone_origin, kept, warnings, cloudflare)


# ---------------------------------------------------------------------------------------
# Record values: the comparison keys (the same for the file and the wire)
# ---------------------------------------------------------------------------------------

def _unescape(text: str) -> bytes:
    """A character-string with ``\\DDD`` / ``\\X`` escapes as bytes."""
    out = bytearray()
    i = 0
    while i < len(text):
        if text[i] == '\\' and i + 1 < len(text):
            digits = text[i + 1:i + 4]
            if len(digits) == 3 and digits.isdigit() and int(digits) < 256:
                out.append(int(digits))
                i += 4
                continue
            out.extend(text[i + 1].encode('utf-8'))
            i += 2
            continue
        out.extend(text[i].encode('utf-8'))
        i += 1
    return bytes(out)


def _present_string(data: bytes) -> str:
    """A character-string as dig prints it: quoted, printable ASCII kept, the rest ``\\DDD``."""
    out = []
    for byte in data:
        char = chr(byte)
        if char in '"\\':
            out.append('\\' + char)
        elif 0x20 <= byte < 0x7f:
            out.append(char)
        else:
            out.append('\\%03d' % byte)
    return '"%s"' % ''.join(out)


def _hex(tokens: Sequence[Token]) -> str:
    text = ''.join(t.text for t in tokens).lower()
    if not re.match(r'^[0-9a-f]*$', text):
        raise ValueError('not hexadecimal: %s' % text)
    return text


def _generic(tokens: Sequence[Token]) -> bytes:
    """RFC 3597's ``\\# length hex`` as the rdata bytes."""
    data = bytes.fromhex(_hex(tokens[2:]))
    if len(data) != int(tokens[1].text):
        raise ValueError('\\# %s: not the length of the data' % tokens[1].text)
    return data


def _u16(text: str) -> int:
    value = int(text)
    if not 0 <= value < 65536:
        raise ValueError('not a 16-bit number: %s' % text)
    return value


def _value_list(data: bytes) -> List[bytes]:
    """An RFC 9460 value-list, its character-string escapes undone: the items between commas,
    a backslash keeping the byte after it (``\\,`` a comma in an item)."""
    items, item, i = [], bytearray(), 0  # type: List[bytes], bytearray, int
    while i < len(data):
        if data[i] == 0x5c and i + 1 < len(data):
            item.append(data[i + 1])
            i += 2
            continue
        if data[i] == 0x2c:
            items.append(bytes(item))
            item = bytearray()
        else:
            item.append(data[i])
        i += 1
    return items + [bytes(item)]


def _svc_code(name: str) -> int:
    if name in SVC_KEYS:
        return SVC_KEYS.index(name)
    match = re.match(r'^key(\d{1,5})$', name)
    if not match or int(match.group(1)) > 65535:
        raise ValueError('unknown SvcParamKey %s' % name)
    return int(match.group(1))


def _svc_name(code: int) -> str:
    return SVC_KEYS[code] if code < len(SVC_KEYS) else 'key%d' % code


def _svc_wire(code: int, value: Optional[bytes]) -> bytes:
    """A SvcParam's presentation value (``None`` for a key written alone) as its wire bytes."""
    if code in (2, 7, 8) or code >= len(SVC_KEYS):
        if code in (2, 8) and value:
            raise ValueError('%s takes no value' % SVC_KEYS[code])
        return value or b''
    if value is None:
        raise ValueError('%s needs a value' % SVC_KEYS[code])
    if code == 1:
        alpn = _value_list(value)
        if not all(0 < len(item) < 256 for item in alpn):
            raise ValueError('an empty or too long alpn')
        return b''.join(bytes([len(item)]) + item for item in alpn)
    if code == 5:
        return base64.b64decode(value, validate=True)
    items = [item.decode('ascii') for item in _value_list(value)]
    if code == 0:
        return b''.join(struct.pack('!H', _svc_code(item)) for item in items)
    if code == 4:
        return b''.join(ipaddress.IPv4Address(item).packed for item in items)
    if code == 6:
        return b''.join(ipaddress.IPv6Address(item).packed for item in items)
    if code == 3 and len(items) != 1:
        raise ValueError('one port')
    return b''.join(struct.pack('!H', _u16(item)) for item in items)


def _svc_canon(code: int, data: bytes) -> bytes:
    """A SvcParam value as both sides compare it: the IP hints and mandatory keys sorted."""
    size = {0: 2, 4: 4, 6: 16}.get(code)
    if not size or len(data) % size:
        return data
    return b''.join(sorted(data[i:i + size] for i in range(0, len(data), size)))


def _svc_text(key: Tuple[Any, ...]) -> str:
    """SVCB / HTTPS as dig prints it: priority, target, the SvcParams in key order."""
    parts = ['%d %s.' % (key[0], key[1])]
    for code, data in key[2]:
        size = {0: 2, 3: 2, 4: 4, 6: 16, 9: 2}.get(code, 0)
        chunks = [data[i:i + size] for i in range(0, len(data), size)] if size and not len(data) % size else []
        if code == 1:
            alpn, pos = [], 0  # type: List[bytes], int
            while pos < len(data):
                alpn.append(data[pos + 1:pos + 1 + data[pos]].replace(b'\\', b'\\\\').replace(b',', b'\\,'))
                pos += 1 + data[pos]
            value = '=' + _present_string(b','.join(alpn))
        elif chunks and code in (4, 6):
            version = ipaddress.IPv4Address if code == 4 else ipaddress.IPv6Address
            value = '=' + ','.join(str(version(chunk)) for chunk in chunks)
        elif chunks and (code != 3 or len(chunks) == 1):
            numbers = [struct.unpack('!H', chunk)[0] for chunk in chunks]
            value = '=' + ','.join(_svc_name(n) if code == 0 else '%d' % n for n in numbers)
        elif code == 5:
            value = '=' + base64.b64encode(data).decode('ascii')
        else:
            value = '=' + _present_string(data) if data else ''
        parts.append(_svc_name(code) + value)
    return ' '.join(parts)


def _naptr_text(key: Tuple[Any, ...]) -> str:
    return '%d %d %s %s %s %s.' % (key[0], key[1], _present_string(key[2]), _present_string(key[3]),
                                  _present_string(key[4]), key[5])


def _uri_text(key: Tuple[Any, ...]) -> str:
    return '%d %d %s' % (key[0], key[1], _present_string(key[2]))


def _precsize(cm: int) -> int:
    """A LOC size or precision in centimetres as its byte (a digit and a power of ten, as BIND)."""
    exponent = 0
    while exponent < 9 and cm >= 10 ** (exponent + 1):
        exponent += 1
    return (min(cm // 10 ** exponent, 9) << 4) | exponent


def _loc_key(t: List[str]) -> Tuple[int, ...]:
    """A LOC value (``d [m [s]] N|S d [m [s]] E|W alt[m] [size[m] [hp[m] [vp[m]]]]``) as its wire
    fields: version, size, both precisions, latitude, longitude, altitude."""
    pos, fields = 0, [0]  # type: int, List[int]
    coords = []  # type: List[int]
    for hemispheres, limit in ((('N', 'S'), 90), (('E', 'W'), 180)):
        start = pos
        while t[pos].upper() not in hemispheres:
            pos += 1
        degrees, minutes, seconds = (t[start:pos] + ['0', '0'])[:3]
        whole, _, fraction = seconds.partition('.')
        if not (pos - start <= 3 and degrees.isdigit() and minutes.isdigit() and whole.isdigit()
                and re.match(r'^\d{0,3}$', fraction) and int(minutes) < 60 and int(whole) < 60):
            raise ValueError('LOC: not a coordinate')
        value = ((int(degrees) * 60 + int(minutes)) * 60 + int(whole)) * 1000 + int(fraction.ljust(3, '0'))
        if value > limit * 3600000:
            raise ValueError('LOC: not a coordinate')
        coords.append(2 ** 31 + (value if t[pos].upper() == hemispheres[0] else -value))
        pos += 1
    lengths = []  # type: List[int]
    for text in t[pos:]:
        match = re.match(r'^(-?)(\d+)(?:\.(\d{1,2}))?m?$', text, re.I)
        if not match or (match.group(1) and lengths):
            raise ValueError('LOC: not a length: %s' % text)
        cm = int(match.group(2)) * 100 + int((match.group(3) or '').ljust(2, '0'))
        lengths.append(-cm if match.group(1) else cm)
    if not 1 <= len(lengths) <= 4:
        raise ValueError('LOC: an altitude and at most three sizes')
    fields += [_precsize(cm) for cm in lengths[1:]] + list(LOC_DEFAULTS[len(lengths) - 1:])
    return tuple(fields + coords + [lengths[0] + 10000000])


def _loc_text(key: Tuple[int, ...]) -> str:
    """LOC as dig prints it: latitude and longitude in degrees, minutes and seconds, then the
    altitude, the size and both precisions in metres."""
    parts = []  # type: List[str]
    for value, hemispheres in ((key[4], 'NS'), (key[5], 'EW')):
        value -= 2 ** 31
        hemisphere = hemispheres[value < 0]
        value = abs(value)
        parts.append('%d %d %d.%03d %s' % (value // 3600000, value // 60000 % 60, value // 1000 % 60,
                                           value % 1000, hemisphere))
    altitude = key[6] - 10000000
    parts.append('%s%d.%02dm' % ('-' if altitude < 0 else '', abs(altitude) // 100, abs(altitude) % 100))
    for byte in key[1:4]:
        cm = (byte >> 4) * 10 ** (byte & 0xf)
        parts.append('%d%sm' % (cm // 100, '.%02d' % (cm % 100) if cm % 100 else ''))
    return ' '.join(parts)


def file_value(record: Record, origin: str) -> Tuple[Any, str]:
    """``(key, text)`` of a file record: the comparison key and the value as printed. A relative
    name in the data is completed with the $ORIGIN in force at the record (``origin`` when the
    file set none there). Raises ValueError for a value this script cannot read."""
    rtype = record.rtype
    t = [tok.text for tok in record.tokens]
    origin = record_origin(record, origin)
    if t and t[0] == '\\#':
        # Any type in RFC 3597's form: its bytes, read as an answer's rdata.
        data = _generic(record.tokens)
        try:
            return _rdata(data, rtype, 0, len(data))
        except (DnsError, struct.error) as exc:
            raise ValueError('%s: %s' % (rtype, exc))
    if rtype == 'A':
        ip = str(ipaddress.IPv4Address(t[0]))
        return ip, ip
    if rtype == 'AAAA':
        ip = str(ipaddress.IPv6Address(t[0]))
        return ip, ip
    if rtype in ('NS', 'CNAME', 'PTR', 'DNAME'):
        name = absolute_name(t[0], origin)
        return name, name + '.'
    if rtype == 'MX':
        name = absolute_name(t[1], origin)
        return (int(t[0]), name), '%d %s.' % (int(t[0]), name)
    if rtype == 'SRV':
        name = absolute_name(t[3], origin) if t[3] != '.' else ''
        key = (int(t[0]), int(t[1]), int(t[2]), name)
        return key, '%d %d %d %s.' % key
    if rtype in ('TXT', 'SPF'):
        strings = tuple(_unescape(tok.text) for tok in record.tokens)
        return strings, ' '.join(_present_string(s) for s in strings)
    if rtype == 'CAA':
        value = _unescape(t[2]) if len(t) > 2 else b''
        key = (int(t[0]), t[1].lower(), value)
        return key, '%d %s %s' % (key[0], key[1], _present_string(value))
    if rtype in ('TLSA', 'SMIMEA'):
        key = (int(t[0]), int(t[1]), int(t[2]), _hex(record.tokens[3:]))
        return key, '%d %d %d %s' % key
    if rtype == 'SSHFP':
        key = (int(t[0]), int(t[1]), _hex(record.tokens[2:]))
        return key, '%d %d %s' % key
    if rtype in ('DS', 'CDS'):
        key = (int(t[0]), int(t[1]), int(t[2]), _hex(record.tokens[3:]))
        return key, '%d %d %d %s' % key
    if rtype == 'NAPTR':
        name = absolute_name(t[5], origin) if t[5] != '.' else ''
        key = (int(t[0]), int(t[1])) + tuple(_unescape(tok.text) for tok in record.tokens[2:5]) + (name,)
        return key, _naptr_text(key)
    if rtype in ('SVCB', 'HTTPS'):
        target = absolute_name(t[1], origin) if t[1] != '.' else ''
        params = {}  # type: Dict[int, bytes]
        tokens = record.tokens[2:]
        while tokens:
            token = tokens.pop(0)
            if token.quoted:
                raise ValueError('a quoted SvcParam without its key')
            name, eq, value = token.text.partition('=')
            if eq and not value and tokens and tokens[0].quoted:
                value = tokens.pop(0).text  # key="value": the quote ends the token
            code = _svc_code(name.lower())
            if code in params:
                raise ValueError('%s twice' % name)
            params[code] = _svc_canon(code, _svc_wire(code, _unescape(value) if eq else None))
        key = (int(t[0]), target, tuple(sorted(params.items())))
        return key, _svc_text(key)
    if rtype == 'LOC':
        key = _loc_key(t)
        return key, _loc_text(key)
    if rtype == 'OPENPGPKEY':
        data = base64.b64decode(''.join(t), validate=True)
        return data, base64.b64encode(data).decode('ascii')
    if rtype == 'URI':
        key = (int(t[0]), int(t[1]), _unescape(t[2]))
        return key, _uri_text(key)
    if rtype == 'SOA':
        return (int(t[2]),), ' '.join(t)
    raise ValueError('a %s value is read only as \\# length hex' % rtype)


# ---------------------------------------------------------------------------------------
# DNS messages
# ---------------------------------------------------------------------------------------

@dataclass
class RR:
    name: str
    rtype: str
    ttl: int
    key: Any
    text: str


@dataclass
class Message:
    id: int
    rcode: str
    aa: bool
    tc: bool
    qr: bool
    question: Optional[Tuple[str, int]]
    answers: List[RR]
    authority: List[RR]
    additional: List[RR]


def _encode_name(name: str) -> bytes:
    out = b''
    for label in text_to_labels(name):
        out += bytes([len(label)]) + label
    return out + b'\x00'


def build_query(name: str, rtype: str, msg_id: int, edns: bool = True) -> bytes:
    """A query for ``name`` / ``rtype`` with RD off (an authoritative server's own data is
    wanted) and, by default, an EDNS(0) OPT record offering :data:`UDP_PAYLOAD` bytes."""
    code = TYPE_CODES.get(rtype) or int(rtype[4:])
    header = struct.pack('!HHHHHH', msg_id & 0xffff, 0, 1, 0, 0, 1 if edns else 0)
    question = _encode_name(name) + struct.pack('!HH', code, 1)
    opt = b'\x00' + struct.pack('!HHIH', 41, UDP_PAYLOAD, 0, 0) if edns else b''
    return header + question + opt


def _read_name(msg: bytes, pos: int) -> Tuple[str, int]:
    labels = []  # type: List[bytes]
    jumps = 0
    end = None  # type: Optional[int]
    while True:
        if pos >= len(msg):
            raise DnsError('format', 'truncated name')
        length = msg[pos]
        if length & 0xc0 == 0xc0:
            if pos + 1 >= len(msg):
                raise DnsError('format', 'truncated pointer')
            if end is None:
                end = pos + 2
            pos = ((length & 0x3f) << 8) | msg[pos + 1]
            jumps += 1
            if jumps > 64:
                raise DnsError('format', 'compression loop')
            continue
        if length & 0xc0:
            raise DnsError('format', 'bad label type')
        pos += 1
        if length == 0:
            break
        if pos + length > len(msg):
            raise DnsError('format', 'truncated label')
        labels.append(msg[pos:pos + length])
        pos += length
    return labels_to_text(labels), end if end is not None else pos


def _rdata(msg: bytes, rtype: str, start: int, length: int) -> Tuple[Any, str]:
    data = msg[start:start + length]
    if rtype == 'A' and length == 4:
        ip = str(ipaddress.IPv4Address(data))
        return ip, ip
    if rtype == 'AAAA' and length == 16:
        ip = str(ipaddress.IPv6Address(data))
        return ip, ip
    if rtype in ('NS', 'CNAME', 'PTR', 'DNAME'):
        name, _ = _read_name(msg, start)
        return name, name + '.'
    if rtype == 'MX' and length >= 3:
        pref = struct.unpack('!H', data[:2])[0]
        name, _ = _read_name(msg, start + 2)
        return (pref, name), '%d %s.' % (pref, name)
    if rtype == 'SRV' and length >= 7:
        prio, weight, port = struct.unpack('!HHH', data[:6])
        name, _ = _read_name(msg, start + 6)
        return (prio, weight, port, name), '%d %d %d %s.' % (prio, weight, port, name)
    if rtype in ('TXT', 'SPF'):
        strings = []
        pos = 0
        while pos < len(data):
            size = data[pos]
            strings.append(bytes(data[pos + 1:pos + 1 + size]))
            pos += 1 + size
        return tuple(strings), ' '.join(_present_string(s) for s in strings)
    if rtype == 'CAA' and length >= 2:
        flags, tag_len = data[0], data[1]
        tag = data[2:2 + tag_len].decode('ascii', 'replace').lower()
        value = bytes(data[2 + tag_len:])
        return (flags, tag, value), '%d %s %s' % (flags, tag, _present_string(value))
    if rtype in ('TLSA', 'SMIMEA') and length >= 3:
        key = (data[0], data[1], data[2], data[3:].hex())
        return key, '%d %d %d %s' % key
    if rtype == 'SSHFP' and length >= 2:
        key = (data[0], data[1], data[2:].hex())
        return key, '%d %d %s' % key
    if rtype in ('DS', 'CDS') and length >= 4:
        key = (struct.unpack('!H', data[:2])[0], data[2], data[3], data[4:].hex())
        return key, '%d %d %d %s' % key
    if rtype == 'NAPTR' and length >= 7:
        pos, strings = 4, []  # type: int, List[bytes]
        for _ in range(3):
            end = pos + 1 + data[pos]
            if end > length:
                raise DnsError('format', 'truncated NAPTR')
            strings.append(bytes(data[pos + 1:end]))
            pos = end
        name, _ = _read_name(msg, start + pos)
        key = struct.unpack('!HH', data[:4]) + tuple(strings) + (name,)
        return key, _naptr_text(key)
    if rtype in ('SVCB', 'HTTPS') and length >= 3:
        target, pos = _read_name(msg, start + 2)
        params = []  # type: List[Tuple[int, bytes]]
        while pos < start + length:
            code, size = struct.unpack('!HH', msg[pos:pos + 4])
            if pos + 4 + size > start + length:
                raise DnsError('format', 'truncated SvcParam')
            params.append((code, _svc_canon(code, bytes(msg[pos + 4:pos + 4 + size]))))
            pos += 4 + size
        key = (struct.unpack('!H', data[:2])[0], target, tuple(sorted(params)))
        return key, _svc_text(key)
    if rtype == 'LOC' and length == 16 and data[0] == 0:
        key = struct.unpack('!BBBBIII', data)
        return key, _loc_text(key)
    if rtype == 'OPENPGPKEY':
        return bytes(data), base64.b64encode(data).decode('ascii')
    if rtype == 'URI' and length >= 4:
        key = struct.unpack('!HH', data[:4]) + (bytes(data[4:]),)
        return key, _uri_text(key)
    if rtype == 'SOA':
        mname, pos = _read_name(msg, start)
        rname, pos = _read_name(msg, pos)
        serial, refresh, retry, expire, minimum = struct.unpack('!IIIII', msg[pos:pos + 20])
        return (serial,), '%s. %s. %d %d %d %d %d' % (mname, rname, serial, refresh, retry, expire, minimum)
    return ('#', data.hex()), '\\# %d %s' % (length, data.hex())


def parse_message(msg: bytes) -> Message:
    """Decode a DNS response (names decompressed, the compared types' values as keys)."""
    if len(msg) < 12:
        raise DnsError('format', 'short message')
    msg_id, flags, qd, an, ns, ar = struct.unpack('!HHHHHH', msg[:12])
    pos = 12
    question = None
    for _ in range(qd):
        qname, pos = _read_name(msg, pos)
        if pos + 4 > len(msg):
            raise DnsError('format', 'truncated question')
        question = (qname, struct.unpack('!H', msg[pos:pos + 2])[0])
        pos += 4
    sections = []  # type: List[List[RR]]
    for count in (an, ns, ar):
        rrs = []
        for _ in range(count):
            name, pos = _read_name(msg, pos)
            if pos + 10 > len(msg):
                raise DnsError('format', 'truncated record')
            code, _cls, ttl, length = struct.unpack('!HHIH', msg[pos:pos + 10])
            pos += 10
            if pos + length > len(msg):
                raise DnsError('format', 'truncated rdata')
            rtype = TYPE_NAMES.get(code, 'TYPE%d' % code)
            if rtype != 'OPT':
                try:
                    key, text = _rdata(msg, rtype, pos, length)
                except (DnsError, ValueError, struct.error, IndexError):
                    key, text = ('#', msg[pos:pos + length].hex()), '\\# %d' % length
                rrs.append(RR(name, rtype, ttl, key, text))
            pos += length
        sections.append(rrs)
    rcode = RCODES.get(flags & 0xf, 'RCODE%d' % (flags & 0xf))
    return Message(msg_id, rcode, bool(flags & 0x0400), bool(flags & 0x0200), bool(flags & 0x8000),
                   question, sections[0], sections[1], sections[2])


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise DnsError('network', 'connection closed')
        data += chunk
    return data


def query_dns(server: str, port: int, name: str, rtype: str, timeout: float = DEFAULT_TIMEOUT,
              tcp: bool = False) -> Message:
    """Ask ``server`` (an IP address) for ``name`` / ``rtype``: over UDP (:data:`TRIES`
    attempts), then over TCP when the answer is truncated (or only TCP with ``tcp``).
    Raises DnsError."""
    msg_id = random.randint(0, 0xffff)
    query = build_query(name, rtype, msg_id)
    family = socket.AF_INET6 if ':' in server else socket.AF_INET
    want = (canonical_name(name), TYPE_CODES.get(rtype) or int(rtype[4:]))
    if not tcp:
        for _attempt in range(TRIES):
            sock = socket.socket(family, socket.SOCK_DGRAM)
            try:
                sock.settimeout(timeout)
                sock.sendto(query, (server, port))
                while True:
                    data, _ = sock.recvfrom(65535)
                    try:
                        reply = parse_message(data)
                    except DnsError:
                        continue
                    if reply.id == msg_id and reply.qr and (reply.question is None or reply.question == want):
                        break
            except socket.timeout:
                continue
            except OSError as exc:
                raise DnsError('network', exc.strerror or str(exc))
            finally:
                sock.close()
            if not reply.tc:
                return reply
            break
        else:
            raise DnsError('timeout', 'no answer from %s in %gs (%d tries)' % (server, timeout, TRIES))
    try:
        sock = socket.create_connection((server, port), timeout=timeout)
    except socket.timeout:
        raise DnsError('timeout', 'no TCP connection to %s in %gs' % (server, timeout))
    except OSError as exc:
        raise DnsError('network', exc.strerror or str(exc))
    try:
        sock.settimeout(timeout)
        sock.sendall(struct.pack('!H', len(query)) + query)
        size = struct.unpack('!H', _recv_exact(sock, 2))[0]
        reply = parse_message(_recv_exact(sock, size))
    except socket.timeout:
        raise DnsError('timeout', 'no TCP answer from %s in %gs' % (server, timeout))
    except OSError as exc:
        raise DnsError('network', exc.strerror or str(exc))
    finally:
        sock.close()
    if reply.id != msg_id:
        raise DnsError('format', 'answer to another question')
    return reply


# ---------------------------------------------------------------------------------------
# Name servers
# ---------------------------------------------------------------------------------------

@dataclass
class NameServer:
    label: str                 # what was given: a host name, or an address
    host: Optional[str]        # its host name, when one was given
    address: str               # the address asked ('' when the host name does not resolve)
    port: int
    state: str = ''
    serial: Optional[int] = None
    detail: str = ''


def _resolve(host: str) -> str:
    """The first address of a host name (IPv4 first). Raises DnsError('resolve', ...)."""
    try:
        infos = socket.getaddrinfo(host, None, 0, socket.SOCK_DGRAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise DnsError('resolve', 'its name does not resolve: %s' % (getattr(exc, 'strerror', None) or exc))
    v4 = [i[4][0] for i in infos if i[0] == socket.AF_INET]
    v6 = [i[4][0] for i in infos if i[0] == socket.AF_INET6]
    if not v4 and not v6:
        raise DnsError('resolve', 'its name has no address')
    return (v4 or v6)[0]


def parse_nameserver(value: str, default_port: int = DEFAULT_PORT, resolve: Any = None) -> NameServer:
    """``ns1.example.net``, ``ns1.example.net=192.0.2.53`` (a host name asked at an address:
    before its name resolves), ``192.0.2.53``, ``192.0.2.53:5353``, ``[2001:db8::53]:5353``.
    A host name that does not resolve is no usage error: the server comes back without an
    address, already :data:`NS_UNREACHABLE` (the report says so, and the others are asked).
    Raises UsageError for a value that is not a name server."""
    text = value.strip().rstrip('.') if '=' not in value else value.strip()
    host = None  # type: Optional[str]
    if '=' in text:
        host_part, text = text.split('=', 1)
        host = canonical_name(host_part.strip().rstrip('.').lower())
    port = default_port
    match = re.match(r'^\[([0-9a-fA-F:.]+)\](?::(\d+))?$', text)
    if match:
        text, port = match.group(1), int(match.group(2) or default_port)
    elif text.count(':') == 1:
        text, port_text = text.split(':')
        if not port_text.isdigit():
            raise UsageError('bad name server %r' % value)
        port = int(port_text)
    if not 1 <= port <= 65535:
        raise UsageError('bad port in name server %r' % value)
    try:
        address = str(ipaddress.ip_address(text))
        return NameServer(host or address, host, address, port)
    except ValueError:
        pass
    if host is not None:
        raise UsageError('bad address in name server %r' % value)
    try:
        name = canonical_name(text.lower())
    except ValueError:
        raise UsageError('bad name server %r' % value)
    if not re.match(r'^[a-z0-9-]+(\.[a-z0-9-]+)+$', name):
        raise UsageError('bad name server %r' % value)
    try:
        address = (resolve or _resolve)(name)
    except DnsError as exc:
        return NameServer(name, name, '', port, NS_UNREACHABLE, None, str(exc))
    return NameServer(name, name, address, port)


# ---------------------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------------------

@dataclass
class Row:
    ns: str
    name: str
    rtype: str
    status: str
    notes: List[str] = field(default_factory=list)
    file: List[str] = field(default_factory=list)
    new: List[str] = field(default_factory=list)
    added: List[str] = field(default_factory=list)
    removed: List[str] = field(default_factory=list)
    file_ttl: Optional[int] = None
    new_ttl: Optional[int] = None


@dataclass
class ParityReport:
    zone: Zone
    source: str
    nameservers: List[NameServer]
    rows: List[Row]
    generated: datetime
    rrsets: int = 0

    def problems(self) -> List[Row]:
        """The rows --fail-on-diff exits 1 for: missing, different, unproxied, extra."""
        return [row for row in self.rows if row.status in PROBLEMS]

    def ttl_rows(self) -> List[Row]:
        return [row for row in self.rows if 'ttl' in row.notes]

    def serials_differ(self) -> bool:
        return len({ns.serial for ns in self.nameservers if ns.state == NS_OK}) > 1

    def unanswered(self) -> int:
        """The record sets a server gave no usable answer for (ERROR rows), each counted once."""
        return len({(row.name, row.rtype) for row in self.rows if row.status == ERROR})

    def verdict(self) -> str:
        """The web app's verdicts (lib/nsparity.js paritySummary): 'blocked' (no server could
        be compared), 'fix' (something missing or different, or a server that does not serve the
        zone), 'partial' (nothing to fix so far, but record sets got no answer: what they hold is
        not known, as the web app counts them not compared), 'check' (only unproxied or extra
        records, TTL differences or serials out of step) or 'ready'. The web app's other
        reasons for 'partial' (a stop, the probe cap, types a probe cannot ask) do not occur
        here: this script asks every record set."""
        if not any(ns.state == NS_OK for ns in self.nameservers):
            return 'blocked'
        if any(row.status in TO_FIX for row in self.rows) or any(ns.state != NS_OK for ns in self.nameservers):
            return 'fix'
        if self.unanswered():
            return 'partial'
        if any(row.status in (UNPROXIED, EXTRA) for row in self.rows) or self.ttl_rows() or self.serials_differ():
            return 'check'
        return 'ready'


def is_cloudflare(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr.version == net.version and addr in net for net in CLOUDFLARE_RANGES)


@dataclass
class RRset:
    name: str
    rtype: str
    records: List[Record]


def plan_rrsets(zone: Zone) -> Tuple[List[RRset], List[Tuple[RRset, str]]]:
    """The record sets to ask about, and the ones left out with the reason: SOA (asked
    first, apart), DNSSEC types (signed live), aliases, records below a delegation (the child
    zone's servers answer them) and data the file shadows at a cut."""
    groups = {}  # type: Dict[Tuple[str, str], RRset]
    for record in zone.records:
        key = (record.name, record.rtype)
        if key not in groups:
            groups[key] = RRset(record.name, record.rtype, [])
        groups[key].records.append(record)
    cuts = {name for (name, rtype) in groups if rtype == 'NS' and name != zone.origin}
    # Glue: the addresses of a delegation's own name servers, which the parent serves in its referral.
    glue = set()
    for cut in cuts:
        for record in groups[(cut, 'NS')].records:
            try:
                target = absolute_name(record.tokens[0].text, record_origin(record, zone.origin))
            except (ValueError, IndexError):
                continue
            if target == cut or target.endswith('.' + cut):
                glue.add(target)
    asked, skipped = [], []  # type: List[RRset], List[Tuple[RRset, str]]
    for rrset in groups.values():
        below = next((c for c in cuts if rrset.name.endswith('.' + c)), None)
        if rrset.rtype == 'SOA':
            continue
        if rrset.rtype in DNSSEC_TYPES:
            skipped.append((rrset, 'dnssec'))
        elif rrset.rtype == 'ALIAS':
            skipped.append((rrset, 'alias'))
        elif below and not (rrset.rtype in ('A', 'AAAA') and rrset.name in glue):
            skipped.append((rrset, 'delegated'))
        elif rrset.name in cuts and rrset.rtype not in ('NS', 'DS'):
            skipped.append((rrset, 'delegated'))
        else:
            asked.append(rrset)
    return asked, skipped


def _own(rrs: Sequence[RR], name: str, rtype: str) -> List[RR]:
    return [rr for rr in rrs if rr.name == name and rr.rtype == rtype]


def _referral(reply: Message, name: str) -> bool:
    return (not reply.aa and reply.rcode == 'NOERROR'
            and any(rr.rtype == 'NS' and (name == rr.name or name.endswith('.' + rr.name))
                    for rr in reply.authority))


def _min_ttl(rrs: Sequence[RR]) -> Optional[int]:
    return min(rr.ttl for rr in rrs) if rrs else None


class Asker:
    """Asks one name server, each (name, type) once (thread-safe memo)."""

    def __init__(self, ns: NameServer, timeout: float, tcp: bool, query: Any = query_dns) -> None:
        self.ns = ns
        self.timeout = timeout
        self.tcp = tcp
        self.query = query
        self.lock = threading.Lock()
        self.memo = {}  # type: Dict[Tuple[str, str], Any]

    def ask(self, name: str, rtype: str) -> Any:
        key = (name, rtype)
        with self.lock:
            if key in self.memo:
                return self.memo[key]
        try:
            result = self.query(self.ns.address, self.ns.port, name, rtype, self.timeout, self.tcp)
        except DnsError as exc:
            result = exc
        with self.lock:
            self.memo[key] = result
        return result


def check_nameserver(asker: Asker, origin: str) -> None:
    """Ask the SOA of the zone and set the server's state and serial (a server without an
    address, whose name did not resolve, stays :data:`NS_UNREACHABLE` and is not asked)."""
    ns = asker.ns
    if not ns.address:
        ns.state = NS_UNREACHABLE
        ns.detail = ns.detail or 'its name does not resolve'
        return
    reply = asker.ask(origin, 'SOA')
    if isinstance(reply, DnsError):
        ns.state, ns.detail = NS_UNREACHABLE, str(reply)
        return
    if reply.rcode == 'REFUSED':
        ns.state, ns.detail = NS_REFUSED, 'refuses questions about %s: it does not serve this zone (yet)' % origin
        return
    if reply.rcode == 'SERVFAIL':
        ns.state, ns.detail = NS_SERVFAIL, 'answers SERVFAIL for %s' % origin
        return
    soa = _own(reply.answers, origin, 'SOA')
    if reply.rcode != 'NOERROR' or not soa:
        ns.state, ns.detail = NS_NO_ZONE, 'has no SOA for %s (%s)' % (origin, reply.rcode)
        return
    ns.serial = soa[0].key[0]
    if not reply.aa:
        ns.state, ns.detail = NS_NOT_AUTHORITATIVE, 'answers for %s without the authoritative flag' % origin
        return
    ns.state, ns.detail = NS_OK, ''


def _error_row(ns: str, rrset: RRset, reply: Any, file_texts: List[str], file_ttl: Optional[int]) -> Row:
    note = reply.kind if isinstance(reply, DnsError) else reply.rcode.lower()
    return Row(ns, rrset.name, rrset.rtype, ERROR, [note], file_texts, file_ttl=file_ttl)


def compare_rrset(asker: Asker, rrset: RRset, zone: Zone, ns_names: Sequence[str]) -> Row:
    """One record set of the file against one name server."""
    ns = asker.ns.label
    origin = zone.origin
    values = []  # type: List[Tuple[Any, str]]
    for record in rrset.records:
        try:
            values.append(file_value(record, origin))
        except (ValueError, IndexError):
            return Row(ns, rrset.name, rrset.rtype, SKIPPED, ['unreadable'], [' '.join(t.text for t in record.tokens)])
    file_keys = {key: text for key, text in values}
    file_texts = list(file_keys.values())
    ttls = [r.ttl for r in rrset.records if r.ttl is not None]
    auto = any(r.ttl == TTL_AUTO for r in rrset.records) and zone.cloudflare
    file_ttl = None if auto or not ttls else min(ttls)
    proxied = any(r.proxied for r in rrset.records)
    row = Row(ns, rrset.name, rrset.rtype, SAME, [], file_texts, file_ttl=file_ttl)
    qname = rrset.name
    reply = asker.ask(qname, rrset.rtype)
    if isinstance(reply, DnsError) or reply.rcode not in ('NOERROR', 'NXDOMAIN'):
        return _error_row(ns, rrset, reply, file_texts, file_ttl)
    own = _own(reply.answers, qname, rrset.rtype)
    if not own and _referral(reply, qname):
        # A delegation: the parent's servers answer its NS (and glue) as a referral.
        pool = reply.authority if rrset.rtype == 'NS' else reply.additional
        own = _own(pool, qname, rrset.rtype)
        if own:
            row.notes.append('referral')
    cnames = _own(reply.answers, qname, 'CNAME') if rrset.rtype != 'CNAME' else []
    row.new = [rr.text for rr in own] or [rr.text for rr in cnames]
    row.new_ttl = _min_ttl(own or cnames)

    if rrset.rtype == 'CNAME' and (proxied or any(r.flatten for r in rrset.records)
                                   or (rrset.name == origin and zone.cloudflare)):
        # A proxied or flattened CNAME: Cloudflare answers the name with addresses.
        target = next(iter(file_keys))
        if own and all(rr.key == target for rr in own):
            if proxied:
                row.status, row.notes = UNPROXIED, ['proxy-off']
            return row
        if own:
            row.status, row.notes = DIFFERENT, ['values']
            row.added, row.removed = [rr.text for rr in own], file_texts
            return row
        addr = asker.ask(qname, 'A')
        if isinstance(addr, DnsError) or addr.rcode not in ('NOERROR', 'NXDOMAIN'):
            return _error_row(ns, rrset, addr, file_texts, file_ttl)
        ips = [rr.key for rr in _own(addr.answers, qname, 'A')]
        row.new, row.new_ttl = ips, _min_ttl(_own(addr.answers, qname, 'A'))
        if addr.rcode == 'NXDOMAIN' or not ips:
            row.status, row.notes = MISSING, ['nxdomain' if addr.rcode == 'NXDOMAIN' else 'nodata']
        elif proxied and not all(is_cloudflare(ip) for ip in ips):
            row.status, row.notes = DIFFERENT, ['not-cloudflare']
            row.added = [ip for ip in ips if not is_cloudflare(ip)]
        else:
            row.notes = ['proxied' if proxied else 'flattened']
        return row

    if reply.rcode == 'NXDOMAIN':
        row.status, row.notes = MISSING, ['nxdomain']
        return row
    if not own and cnames:
        row.status, row.notes = DIFFERENT, ['cname']
        return row
    if not own:
        row.status, row.notes = MISSING, ['nodata']
        return row
    live = {rr.key: rr.text for rr in own}
    if rrset.rtype in ('A', 'AAAA') and proxied:
        ips = list(live)
        origins = set(file_keys)
        if any(ip in origins and not is_cloudflare(ip) for ip in ips):
            row.status, row.notes = UNPROXIED, ['proxy-off']
        elif all(is_cloudflare(ip) for ip in ips):
            row.notes = ['proxied']
        else:
            row.status, row.notes = DIFFERENT, ['not-cloudflare']
            row.added = [ip for ip in ips if not is_cloudflare(ip)]
        return row
    if rrset.name == origin and rrset.rtype == 'NS' and ns_names:
        got = sorted(set(live))
        want = sorted(set(ns_names))
        if got == want:
            row.notes = ['ns-new']
        else:
            row.status, row.notes = DIFFERENT, ['ns-mismatch']
            row.added = [n + '.' for n in got if n not in want]
            row.removed = [n + '.' for n in want if n not in got]
        return row
    if rrset.name == origin and rrset.rtype == 'NS':
        row.status, row.notes = SKIPPED, ['ns-by-address']
        return row
    added = [text for key, text in live.items() if key not in file_keys]
    removed = [text for key, text in file_keys.items() if key not in live]
    routing = any(r.routing for r in rrset.records)
    if not added and not removed:
        pass
    elif routing and not added:
        row.notes.append('routing')
    elif rrset.rtype in ('TXT', 'SPF') and sorted(b''.join(k) for k in live) == sorted(b''.join(k) for k in file_keys):
        row.notes.append('txt-chunking')
    elif (rrset.rtype in ('A', 'AAAA') and all(r.proxied is False for r in rrset.records)
          and all(is_cloudflare(ip) for ip in live)):
        # DNS-only in a Cloudflare export, Cloudflare's addresses there: the proxy is on at the new provider.
        row.status, row.added, row.removed = DIFFERENT, added, removed
        row.notes.append('proxy-on')
    else:
        row.status, row.added, row.removed = DIFFERENT, added, removed
        row.notes.append('values')
    if (row.file_ttl is not None and row.new_ttl is not None and row.file_ttl != row.new_ttl
            and not proxied):
        row.notes.append('ttl')
    return row


def extra_questions(zone: Zone) -> List[Tuple[str, str]]:
    """(name, type) pairs asked to find EXTRA records: every :data:`EXTRA_TYPES` type a name of
    the file does not have (none at a CNAME, a wildcard or a delegation; no A / AAAA at a
    proxied name, where Cloudflare adds AAAA itself), and A / AAAA at ``www`` when the file has
    no ``www`` and no wildcard that covers it."""
    have = {}  # type: Dict[str, set]
    proxied = set()
    for record in zone.records:
        have.setdefault(record.name, set()).add(record.rtype)
        if record.proxied:
            proxied.add(record.name)
    cuts = {n for n, types in have.items() if 'NS' in types and n != zone.origin}
    out = []  # type: List[Tuple[str, str]]
    for name in sorted(have):
        types = have[name]
        if 'CNAME' in types or 'ALIAS' in types or name.startswith('*') or name in cuts \
                or any(name.endswith('.' + c) for c in cuts):
            continue
        for rtype in EXTRA_TYPES:
            if rtype in types or (rtype in ('A', 'AAAA') and name in proxied):
                continue
            out.append((name, rtype))
    www = 'www.' + zone.origin
    if www not in have and ('*.' + zone.origin) not in have:
        out.extend([(www, 'A'), (www, 'AAAA')])
    return out


def extra_row(asker: Asker, name: str, rtype: str) -> Optional[Row]:
    reply = asker.ask(name, rtype)
    ns = asker.ns.label
    if isinstance(reply, DnsError):
        return Row(ns, name, rtype, ERROR, ['extra', reply.kind])
    if reply.rcode not in ('NOERROR', 'NXDOMAIN'):
        return Row(ns, name, rtype, ERROR, ['extra', reply.rcode.lower()])
    own = _own(reply.answers, name, rtype)
    if not own:
        own = _own(reply.answers, name, 'CNAME')
        rtype = 'CNAME'
    if not own:
        return None
    texts = [rr.text for rr in own]
    return Row(ns, name, rtype, EXTRA, ['extra'], [], texts, texts, [], None, _min_ttl(own))


def run_parity(zone: Zone, nameservers: Sequence[NameServer], timeout: float = DEFAULT_TIMEOUT,
               workers: int = DEFAULT_WORKERS, tcp: bool = False, extras: bool = True,
               source: str = '', query: Any = query_dns, progress: Any = None,
               given: Optional[Sequence[NameServer]] = None) -> ParityReport:
    """Compare every record set of ``zone`` with every name server (each asked for its SOA
    first; a server that does not serve the zone is not asked anything else). ``given``: the
    servers as given, when host names that share one address were merged into one server: the
    apex NS set should still hold each of those names."""
    asked, skipped = plan_rrsets(zone)
    given = list(given or nameservers)
    ns_names = [ns.host for ns in given if ns.host]
    if len(ns_names) != len(given):
        ns_names = []   # a server given by address: which names the set should hold is not known
    rows = []  # type: List[Row]
    extra_q = extra_questions(zone) if extras else []
    total = len(nameservers) * (1 + len(asked) + len(extra_q))
    done = [0]
    lock = threading.Lock()

    def step(value: Any) -> Any:
        with lock:
            done[0] += 1
            if progress:
                progress(done[0], total)
        return value

    for ns in nameservers:
        asker = Asker(ns, timeout, tcp, query)
        step(check_nameserver(asker, zone.origin))
        if ns.state != NS_OK:
            continue
        for rrset, reason in skipped:
            texts = []
            for record in rrset.records:
                try:
                    texts.append(file_value(record, zone.origin)[1])
                except (ValueError, IndexError):
                    texts.append(' '.join(t.text for t in record.tokens))
            rows.append(Row(ns.label, rrset.name, rrset.rtype, SKIPPED, [reason], texts))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            results = list(pool.map(lambda r: step(compare_rrset(asker, r, zone, ns_names)), asked))
            found = list(pool.map(lambda q: step(extra_row(asker, q[0], q[1])), extra_q))
        rows.extend(results)
        rows.extend(r for r in found if r is not None)
    return ParityReport(zone, source, list(nameservers), rows, datetime.now(timezone.utc),
                        len(asked) + len(skipped))


# ---------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------

NOTE_TEXT = {
    'nxdomain': 'the name does not exist there',
    'nodata': 'the name exists there without this type',
    'cname': 'a CNAME is served instead',
    'values': 'other values',
    'proxy-off': 'served without the proxy: the origin address becomes public at the switch',
    'proxy-on': 'DNS-only in the file, Cloudflare addresses there: the proxy is on at the new provider',
    'not-cloudflare': 'proxied in the file, other addresses there',
    'proxied': 'proxied (Cloudflare addresses)',
    'flattened': 'flattened (addresses; the target is not compared)',
    'routing': 'one routing variant',
    'txt-chunking': 'the same text, split differently',
    'ttl': 'TTL differs',
    'referral': 'a referral (delegation)',
    'ns-new': 'the new servers name themselves',
    'ns-mismatch': 'other name servers than the ones given',
    'ns-by-address': 'servers given by address: the NS set is not compared',
    'dnssec': 'DNSSEC: signed by the provider, not compared',
    'alias': 'an alias record: resolved by the provider, not compared',
    'delegated': 'below a delegation: the child zone\'s servers answer it',
    'unreadable': 'the file\'s value could not be read',
    'extra': 'not in the file',
    'timeout': 'no answer in time',
    'network': 'network error',
    'format': 'a malformed answer',
    'servfail': 'SERVFAIL',
    'refused': 'REFUSED',
    'formerr': 'FORMERR',
    'notimp': 'NOTIMP',
}


def _plain(text: str) -> str:
    """Printable ASCII for the terminal: anything else ``\\xNN`` (values come from servers)."""
    return ''.join(c if 0x20 <= ord(c) < 0x7f else '\\x%02x' % ord(c) if ord(c) < 0x100 else '\\u%04x' % ord(c)
                   for c in text)


def _row_line(row: Row, width: int, ttl_only: bool = False) -> str:
    label = '%s %s' % (row.name, row.rtype)
    notes = '; '.join(NOTE_TEXT.get(n, n) for n in row.notes if not ttl_only or n == 'ttl')
    parts = []
    if ttl_only:
        parts.append('file %s s, new %s s' % (row.file_ttl, row.new_ttl))
    elif 'ns-mismatch' in row.notes:
        given = sorted(set(n for n in row.removed) | set(n for n in row.new if n not in row.added))
        parts.append('given: %s' % ', '.join(given))
        parts.append('served: %s' % ', '.join(row.new))
    elif row.status in (DIFFERENT, UNPROXIED):
        if row.removed or row.added:
            parts.append('file: %s' % ', '.join(row.removed or row.file))
            parts.append('new: %s' % ', '.join(row.added or row.new))
        else:
            parts.append('file: %s' % ', '.join(row.file))
            parts.append('new: %s' % ', '.join(row.new))
    elif row.status == MISSING:
        parts.append('file: %s' % ', '.join(row.file))
    elif row.status == EXTRA:
        parts.append('new: %s' % ', '.join(row.new))
    elif 'ttl' in row.notes:
        parts.append('file %s s, new %s s' % (row.file_ttl, row.new_ttl))
    text = '  %s  %s' % (label.ljust(width), ' | '.join(parts))
    if notes:
        text += '  (%s)' % notes
    return _plain(text)


def _rest_text(report: ParityReport, always: bool = False) -> str:
    """What the 'check' verdict asks to look at: '1 extra, 2 unproxied, 0 TTL differences'
    ('' when there is nothing, unless ``always``)."""
    extra = sum(1 for r in report.rows if r.status == EXTRA)
    unproxied = sum(1 for r in report.rows if r.status == UNPROXIED)
    ttl = len(report.ttl_rows())
    if not (always or extra or unproxied or ttl):
        return ''
    return '%d extra, %d unproxied, %d TTL difference%s' % (extra, unproxied, ttl, '' if ttl == 1 else 's')


def render_summary(report: ParityReport, show_all: bool = False) -> str:
    """The text report: the servers, then per server the problems, TTL differences and what
    was not compared, then the order of the move."""
    zone = report.zone
    lines = ['DNS parity: %s (%d record sets in %s) against %d name server(s)' % (
        zone.origin, report.rrsets, report.source or 'the zone file', len(report.nameservers))]
    for ns in report.nameservers:
        address = ns.address or 'no address'
        where = address if ns.port == DEFAULT_PORT else '%s port %d' % (address, ns.port)
        if ns.state == NS_OK:
            state = 'authoritative, serial %s' % ns.serial
        else:
            state = '%s: %s' % (ns.state, ns.detail)
        lines.append('  %s (%s)  %s' % (_plain(ns.label), where, _plain(state)))
    if report.serials_differ():
        lines.append('  The servers serve different serials: they are not in sync yet.')
    width = min(48, max([len('%s %s' % (r.name, r.rtype)) for r in report.rows] or [10]))
    first_sig = None
    for ns in report.nameservers:
        if ns.state != NS_OK:
            continue
        rows = [r for r in report.rows if r.ns == ns.label]
        sig = [(r.name, r.rtype, r.status, tuple(r.new), tuple(r.notes)) for r in rows]
        counts = {s: sum(1 for r in rows if r.status == s) for s in STATUSES}
        lines.append('')
        lines.append('%s: %s' % (_plain(ns.label), ', '.join('%d %s' % (counts[s], s.lower())
                                                            for s in STATUSES if counts[s])))
        if first_sig is not None and sig == first_sig:
            lines.append('  the same answers as the first server')
            continue
        if first_sig is None:
            first_sig = sig
        for status, title in ((MISSING, 'MISSING at the new name server'), (DIFFERENT, 'DIFFERENT'),
                              (UNPROXIED, 'UNPROXIED (the proxy ends at the switch)'),
                              (EXTRA, 'EXTRA (not in the file)'), (ERROR, 'NOT ANSWERED')):
            group = [r for r in rows if r.status == status]
            if group:
                lines.append(' %s' % title)
                lines.extend(_row_line(r, width) for r in group)
        ttl = [r for r in rows if 'ttl' in r.notes]
        if ttl:
            lines.append(' TTL differences')
            lines.extend(_row_line(r, width, ttl_only=True) for r in ttl)
        skipped = [r for r in rows if r.status == SKIPPED]
        if skipped and show_all:
            lines.append(' NOT COMPARED')
            lines.extend(_row_line(r, width) for r in skipped)
        elif skipped:
            reasons = sorted({n for r in skipped for n in r.notes})
            lines.append(' Not compared: %d (%s); --show-all lists them' % (
                len(skipped), ', '.join(reasons)))
        if show_all:
            same = [r for r in rows if r.status == SAME and 'ttl' not in r.notes]
            if same:
                lines.append(' SAME')
                lines.extend(_row_line(r, width) for r in same)
    lines.append('')
    verdict = report.verdict()
    if verdict == 'blocked':
        lines.append('No name server serves %s yet: create the zone at the new provider (or check '
                     'the names you gave), then run this again.' % zone.origin)
    elif verdict == 'fix':
        lines.append('Fix the new provider\'s zone (what is missing or different above, and every server '
                     'that does not serve it), then run this again before you switch.')
    elif verdict == 'partial':
        count = report.unanswered()
        rest = _rest_text(report)
        lines.append('%d record set%s got no answer: run this again before you switch (a server that does '
                     'not answer them now may not serve them). Nothing is missing or different among the '
                     'others so far%s.' % (count, '' if count == 1 else 's',
                                           '; check the rest too: ' + rest if rest else ''))
    elif verdict == 'check':
        lines.append('Nothing is missing or different. Check the rest before you switch: %s.'
                     % _rest_text(report, always=True))
    else:
        lines.append('The new name servers serve every compared record set of the file.')
    lines.append('The move: lower the TTLs at the current provider (the NS records at the apex too) '
                 'and wait out the old ones; compare again; DNSSEC first (remove the DS at the '
                 'registrar and wait for its TTL, or pre-publish the new provider\'s DNSKEY and DS '
                 'when both providers support multi-signer); then switch the NS at the registrar and '
                 'keep the old zone answering for at least 48 hours.')
    return '\n'.join(lines) + '\n'


def report_to_dict(report: ParityReport) -> Dict[str, Any]:
    """The JSON report (schema ``domainscope.dns-parity/1``)."""
    counts = {s: sum(1 for r in report.rows if r.status == s) for s in STATUSES}
    return {
        'schema': 'domainscope.dns-parity/1',
        'tool': {'name': PROG, 'version': __version__},
        'generatedAt': report.generated.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'zone': report.zone.origin,
        'file': report.source,
        'recordSets': report.rrsets,
        'nameservers': [{'name': ns.label, 'address': ns.address or None, 'port': ns.port, 'state': ns.state,
                         'serial': ns.serial, 'detail': ns.detail} for ns in report.nameservers],
        'rows': [{'ns': r.ns, 'name': r.name, 'type': r.rtype, 'status': r.status, 'notes': r.notes,
                  'file': r.file, 'new': r.new, 'added': r.added, 'removed': r.removed,
                  'fileTtl': r.file_ttl, 'newTtl': r.new_ttl} for r in report.rows],
        'summary': {'counts': counts, 'ttlDifferences': len(report.ttl_rows()), 'verdict': report.verdict()},
        'warnings': report.zone.warnings,
    }


CSV_COLUMNS = ('ns', 'name', 'type', 'status', 'notes', 'file_values', 'new_values', 'file_ttl', 'new_ttl')


def render_csv(report: ParityReport, lineterminator: str = '\r\n') -> str:
    """One row per name server and record set; a value starting with = + - @ gets a leading
    apostrophe (a spreadsheet would run it as a formula)."""
    def cell(value: Any) -> Any:
        if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
            return "'" + value
        return '' if value is None else value
    out = io.StringIO()
    writer = csv.writer(out, lineterminator=lineterminator)
    writer.writerow(CSV_COLUMNS)
    for r in report.rows:
        writer.writerow([cell(v) for v in (r.ns, r.name, r.rtype, r.status, ' '.join(r.notes),
                                           ' | '.join(r.file), ' | '.join(r.new), r.file_ttl, r.new_ttl)])
    return out.getvalue()


# ---------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------

EPILOG = """\
examples:
  The zone as the web app downloads it (Zone File > New name servers), two new servers:
    python3 dns_parity.py example.com.parity.zone --ns ns1.example.net ns2.example.net

  A cPanel / BIND file without $ORIGIN, and a server whose name does not resolve yet:
    python3 dns_parity.py db.example.com --origin example.com --ns ns1.example.net=192.0.2.53

  Reports for scripts, and exit code 1 while anything is missing or different:
    python3 dns_parity.py example.com.zone --ns ns1.example.net --json parity.json --fail-on-diff

statuses (per name server and record set):
  SAME       the new server serves what the file says
  DIFFERENT  other values, or a CNAME instead
  MISSING    the new server does not serve it (NXDOMAIN, or the name without this type)
  UNPROXIED  a Cloudflare-proxied record answered with its origin address
  EXTRA      at a name of the file (and www), a record the file does not have
  SKIPPED    not compared: DNSSEC records, aliases, records below a delegation, other types
  ERROR      no usable answer (timeout, SERVFAIL, REFUSED)
  The apex NS set is compared with the --ns host names: the new provider names itself there.
  A TTL that differs from the file's is listed apart.

verdict (the web app's): FIX while something is MISSING or DIFFERENT or a server does not
  serve the zone; PARTIAL while record sets got no answer (ERROR: run it again before you
  switch, what they hold is not known); CHECK for UNPROXIED or EXTRA records, TTL
  differences or serials out of step; READY otherwise. The web app's other reasons for
  PARTIAL (a stopped run, its probe cap, types a probe cannot ask) do not occur here: this
  script asks every record set.

exit codes: 0 done, 1 something missing, different, extra or unproxied, a record set without
  an answer, or a server that does not serve the zone (only with --fail-on-diff: stricter
  than the verdict, UNPROXIED and EXTRA fail it too), 2 usage error, 3 a report file could
  not be written, 130 interrupted.

Türkçe: DNS sağlayıcısını değiştirmeden önce yeni ad sunucularının zone dosyasındaki her
  kaydı sunup sunmadığını kontrol eder (eksik, farklı, fazladan kayıtlar, TTL farkları).
  Web uygulamasının Zone File > Yeni ad sunucuları sekmesi indirdiği dosyayla, örnek:
    python3 dns_parity.py example.com.parity.zone --ns ns1.example.net ns2.example.net
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG,
        description='Before a DNS provider move: ask the NEW name servers for every record set of a '
                    'BIND zone file and list what is missing, different or extra there. Python 3.8+, '
                    'standard library only.')
    parser.add_argument('zonefile', help='the zone file (BIND / RFC 1035 master format; "-" for stdin)')
    parser.add_argument('--ns', metavar='SERVER', action='extend', nargs='+', required=True,
                        help='the new name servers: host names, addresses, NAME=ADDRESS or ADDRESS:PORT '
                             '(repeatable, at most %d)' % MAX_NAMESERVERS)
    parser.add_argument('--origin', metavar='ZONE', help='the zone name, when the file names none')
    parser.add_argument('--port', type=int, default=DEFAULT_PORT, help='DNS port (default: 53)')
    parser.add_argument('--tcp', action='store_true', help='ask over TCP only')
    parser.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                        help='per question (default: %(default)s)')
    parser.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                        help='questions in flight per server (default: %(default)s)')
    parser.add_argument('--no-extras', action='store_true',
                        help='do not look for records the file does not have')
    parser.add_argument('--json', metavar='FILE', help='write a JSON report ("-" = stdout)')
    parser.add_argument('--csv', metavar='FILE', help='write a CSV report ("-" = stdout)')
    parser.add_argument('--show-all', action='store_true', help='also list what is the same and what was not compared')
    parser.add_argument('--fail-on-diff', action='store_true',
                        help='exit with code 1 when anything is missing, different, extra or unproxied, '
                             'or got no answer')
    parser.add_argument('-q', '--quiet', action='store_true', help='no progress and no warnings on stderr')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    return parser


def _read_zone_text(path: str) -> str:
    if path == '-':
        return sys.stdin.read()
    try:
        size = os.path.getsize(path)
        if size > MAX_ZONE_BYTES:
            raise UsageError('%s is larger than %d MB' % (path, MAX_ZONE_BYTES // (1024 * 1024)))
        with open(path, 'rb') as handle:
            raw = handle.read()
    except OSError as exc:
        raise UsageError('cannot read %s: %s' % (path, exc.strerror or exc))
    for encoding in ('utf-8-sig', 'cp1252'):
        try:
            return raw.decode(encoding)
        except UnicodeDecodeError:
            continue
    return raw.decode('latin-1')


def _write(path: str, text: str, encoding: str = 'utf-8') -> None:
    if path == '-':
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    with open(path, 'w', encoding=encoding, newline='') as handle:
        handle.write(text)


def _run(args: argparse.Namespace) -> int:
    err = sys.stderr
    if not 0 < args.timeout <= 60:
        raise UsageError('--timeout must be > 0 and <= 60 seconds')
    if not 1 <= args.workers <= MAX_WORKERS:
        raise UsageError('--workers must be between 1 and %d' % MAX_WORKERS)
    if not 1 <= args.port <= 65535:
        raise UsageError('--port must be 1-65535')
    if args.json == '-' and args.csv == '-':
        raise UsageError('--json - and --csv - cannot both write to stdout')
    values = [v for item in args.ns for v in re.split(r'[\s,]+', item) if v]
    if len(values) > MAX_NAMESERVERS:
        raise UsageError('at most %d name servers' % MAX_NAMESERVERS)
    # The file first: a file that cannot be read is reported as such, before any name is resolved.
    try:
        zone = parse_zone(_read_zone_text(args.zonefile), args.origin, args.zonefile)
    except ValueError as exc:
        raise UsageError(str(exc))
    if not args.quiet:
        for warning in zone.warnings[:25]:
            print('warning: %s' % _plain(warning), file=err)
        if len(zone.warnings) > 25:
            print('warning: ... and %d more' % (len(zone.warnings) - 25), file=err)
    if not zone.records:
        raise UsageError('no records of %s in %s' % (zone.origin, args.zonefile))
    nameservers, given = [], []  # type: List[NameServer], List[NameServer]
    for value in values:
        ns = parse_nameserver(value, args.port)
        given.append(ns)
        if all((n.address or n.label, n.port) != (ns.address or ns.label, ns.port) for n in nameservers):
            nameservers.append(ns)
    unresolved = [ns for ns in nameservers if not ns.address]
    if len(unresolved) == len(nameservers):
        raise UsageError('no name server can be asked: %s' % '; '.join(
            '%s: %s' % (ns.label, ns.detail) for ns in unresolved))
    if not args.quiet:
        for ns in unresolved:
            print('warning: name server %s: %s; reported UNREACHABLE' % (ns.label, _plain(ns.detail)), file=err)

    tty = not args.quiet and hasattr(err, 'isatty') and err.isatty()

    def progress(done: int, total: int) -> None:
        if tty and (done == total or done % 10 == 0):
            err.write('\r%d / %d questions' % (done, total))
            if done == total:
                err.write('\n')
            err.flush()

    report = run_parity(zone, nameservers, timeout=args.timeout, workers=args.workers, tcp=args.tcp,
                        extras=not args.no_extras, source=args.zonefile, progress=progress, given=given)
    failed = False
    for path, text, encoding in ((args.json, json.dumps(report_to_dict(report), indent=2) + '\n', 'utf-8'),
                                 (args.csv, None, 'utf-8-sig')):
        if not path:
            continue
        if text is None:
            text = render_csv(report, '\n' if path == '-' else '\r\n')
        try:
            _write(path, text, 'utf-8' if path == '-' else encoding)
        except OSError as exc:
            print('%s: error: cannot write %s: %s' % (PROG, path, exc.strerror or exc), file=err)
            failed = True
    if args.json != '-' and args.csv != '-':
        sys.stdout.write(render_summary(report, show_all=args.show_all))
        sys.stdout.flush()
    if failed:
        return EXIT_OUTPUT_ERROR
    if args.fail_on_diff and (report.verdict() in ('fix', 'blocked', 'partial') or report.problems()):
        return EXIT_DIFFERENCES
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point; returns the exit code (0, 1, 2, 3 or 130)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors='replace')  # the Turkish help on a console that lacks a letter
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


if __name__ == '__main__':
    sys.exit(main())
