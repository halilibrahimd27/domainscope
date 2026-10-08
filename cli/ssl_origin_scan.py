#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ssl_origin_scan.py - find which of your servers serve (and still need) a TLS certificate.

Companion CLI of the "DomainScope - SSL & DNS Toolkit" web app (https://github.com/halilibrahimd27/domainscope).

DNS cannot tell you which of *your* servers host a name when the name sits behind
Cloudflare (orange cloud) or another CDN: the public IPs belong to the proxy. This
tool connects to every server IP from your inventory directly and performs a TLS
handshake with SNI = each hostname. The certificate a server returns for a name
tells you whether it hosts that name and whether it already serves the renewed
certificate.

Run it from a machine inside your network (a jump host). Python 3.8+, stdlib only,
single file - copy it anywhere.

Pipeline:
  1. targets  -> inventory files / IPs / CIDRs / hostnames, resolved to IPs
  2. exclude  -> --exclude IPs / CIDRs removed from the target set (never probed)
  3. names    -> -n names/files and the SAN names of --cert (wildcards expanded)
  4. phase 1  -> TCP connect to every ip:port (thread pool), closed ports skipped
  5. phase 2  -> TLS handshake per open ip:port x name (SNI) + one probe without SNI
  6. verdict  -> UPDATED / NEEDS_UPDATE / ORIGIN_CERT / PRIVATE_CERT / NOT_HOSTED /
                 TLS_ERROR / TIMEOUT / CLOSED
  7. status   -> --ari / --revocation: each served certificate's ARI window and CRL entry
  8. monitor  -> changes since a --baseline report, --warn-days expiry, --notify webhook

--compare OLD_IP NEW_IP -n NAME runs instead of a scan: one GET over TLS (SNI and Host =
NAME) against each address, the two answers side by side (before DNS moves the name).

The module is importable: parse_certificate(), load_certificates(),
parse_inventory(), load_targets(), load_excludes(), apply_excludes(),
is_numeric_host(), build_probe_names(), run_scan(), report_to_dict(), render_csv(),
render_summary(), load_baseline(), compare_reports(), expiring_certificates(),
build_monitor(), build_notification(), notify_request(), pagerduty_plan(),
pagerduty_open_after(), pagerduty_events(), send_notification(), fetch_side(), compare_sides(),
render_compare() and main() are the public API.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bisect
import codecs
import csv
import email.utils
import hashlib
import hmac
import http.client
import io
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import ssl
import stat
import sys
import textwrap
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import warnings
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
from encodings import idna as _idna_codec
from typing import (Any, Callable, Dict, Iterable, List, Optional, Sequence,
                    Set, TextIO, Tuple, Union)

__version__ = '1.0.0'
PROG = 'ssl_origin_scan.py'

# --- statuses (per server, port and name) ------------------------------------------
UPDATED = 'UPDATED'            # serves the new certificate (--cert) for the name
NEEDS_UPDATE = 'NEEDS_UPDATE'  # serves a cert covering the name, but not the new one
ORIGIN_CERT = 'ORIGIN_CERT'    # ... a Cloudflare Origin CA cert (trusted by Cloudflare only)
PRIVATE_CERT = 'PRIVATE_CERT'  # ... a self-signed cert or one issued by a --private-ca
NOT_HOSTED = 'NOT_HOSTED'      # served cert does not cover the name (default cert)
TLS_ERROR = 'TLS_ERROR'        # handshake failed (or refused after the port check)
TIMEOUT = 'TIMEOUT'            # no answer within --timeout
CLOSED = 'CLOSED'              # port closed / host unreachable (phase-1 port check)
STATUSES = (UPDATED, NEEDS_UPDATE, ORIGIN_CERT, PRIVATE_CERT, NOT_HOSTED, TLS_ERROR, TIMEOUT,
            CLOSED)
# The server hosts the name with a certificate that is not the new one. ORIGIN_CERT and
# PRIVATE_CERT come from another kind of CA than the new certificate: not counted as
# needing it, unless --strict-public (then they are NEEDS_UPDATE).
HOSTED_STATUSES = (NEEDS_UPDATE, ORIGIN_CERT, PRIVATE_CERT)

OPEN = 'OPEN'  # endpoint state after a successful TCP connect (phase 1)
# Not a scan status: a target address removed by --exclude (CSV rows only, never probed).
EXCLUDED = 'EXCLUDED'
# Not a scan status either: a server with terminates_tls=no left out of the scan (no
# --include-backends); a --baseline change to it is listed as SKIPPED, never counted.
SKIPPED = 'SKIPPED'

# Kinds of result rows.
PROBE_SNI = 'sni'            # handshake with SNI = the name
PROBE_WILDCARD = 'wildcard'  # handshake with a synthetic name under a wildcard
PROBE_DEFAULT = 'default'    # handshake without SNI (the server's default cert)
PROBE_CONNECT = 'connect'    # the port was not open; one row per endpoint
PROBE_EXCLUDED = 'excluded'  # CSV only: a target address --exclude removed before the scan

EXIT_OK = 0
EXIT_NEEDS_UPDATE = 1
EXIT_USAGE = 2
EXIT_OUTPUT_ERROR = 3   # the scan ran, but a --json / --csv file could not be written
EXIT_CHANGED = 4        # something changed since --baseline (only with --fail-on-change)
EXIT_NOTIFY_ERROR = 5   # the --notify message was not delivered (--fail-on-notify-error)
EXIT_INTERRUPTED = 130

DEFAULT_PORTS = '443'
DEFAULT_WORKERS = 64
DEFAULT_TIMEOUT = 5.0
MAX_WORKERS = 1024
MAX_PER_ENDPOINT = 4        # TLS handshakes in flight to one ip:port (per-client limits)
MAX_TIMEOUT = 300.0
CIDR_LIMIT = 1 << 16        # addresses per CIDR/range without --allow-large (a /16)
CIDR_HARD_LIMIT = 1 << 20   # absolute cap even with --allow-large (a /12)
WILDCARD_PROBE_LABEL = 'ssl-origin-scan-wildcard-probe'
MAX_PRINTED_WARNINGS = 25
MAX_WARN_DAYS = 3650        # --warn-days ceiling (ten years)
NOTIFY_ENV = 'DOMAINSCOPE_NOTIFY_URL'   # --notify URL, kept out of the shell history
NOTIFY_TIMEOUT = 10.0       # seconds per webhook POST
NOTIFY_RETRY_DELAY = 2.0    # seconds before the one retry
NOTIFY_SECRET_ENV = 'DOMAINSCOPE_NOTIFY_SECRET'   # signs the json format (HMAC-SHA256)
NTFY_TOKEN_ENV = 'DOMAINSCOPE_NTFY_TOKEN'         # an ntfy access token (Authorization: Bearer)

# What an endpoint speaks before TLS starts. The protocol follows the port (PORT_PROTOCOLS);
# every other port speaks TLS from the first byte, the implicit-TLS ports of mail, directory,
# file transfer and chat (465, 993, 995, 636, 990, 5223) included. A protocol written with a
# port names it for any number: -p 2525/smtp, a target 203.0.113.10:2525/smtp, 25/tls.
PROTO_TLS = 'tls'
PROTO_SMTP, PROTO_IMAP, PROTO_POP3, PROTO_FTP = 'smtp', 'imap', 'pop3', 'ftp'
PROTO_LDAP, PROTO_XMPP, PROTO_POSTGRES, PROTO_RDP = 'ldap', 'xmpp', 'postgres', 'rdp'
STARTTLS_PROTOCOLS = (PROTO_SMTP, PROTO_IMAP, PROTO_POP3, PROTO_FTP, PROTO_LDAP, PROTO_XMPP,
                      PROTO_POSTGRES, PROTO_RDP)
PROTOCOLS = (PROTO_TLS,) + STARTTLS_PROTOCOLS
PORT_PROTOCOLS = {25: PROTO_SMTP, 587: PROTO_SMTP, 143: PROTO_IMAP, 110: PROTO_POP3,
                  21: PROTO_FTP, 389: PROTO_LDAP, 5222: PROTO_XMPP, 5432: PROTO_POSTGRES,
                  3389: PROTO_RDP}
_PROTOCOL_ALIASES = {'submission': PROTO_SMTP, 'pop': PROTO_POP3, 'postgresql': PROTO_POSTGRES,
                     'pgsql': PROTO_POSTGRES, 'xmpp-client': PROTO_XMPP,
                     'ms-wbt-server': PROTO_RDP}
PROTOCOL_LABELS = {PROTO_TLS: 'TLS', PROTO_SMTP: 'SMTP', PROTO_IMAP: 'IMAP', PROTO_POP3: 'POP3',
                   PROTO_FTP: 'FTP', PROTO_LDAP: 'LDAP', PROTO_XMPP: 'XMPP',
                   PROTO_POSTGRES: 'PostgreSQL', PROTO_RDP: 'RDP'}
# --profile: the ports of a kind of server, in place of -p's default (443); -p adds its own.
# all: every port whose protocol the scan supports by default (web, mail, file transfer,
# directory, chat, database, remote desktop).
PORT_PROFILES = {
    'web': (443, 8443),
    'mail': (25, 587, 465, 143, 993, 110, 995),
    'all': (443, 8443, 25, 587, 465, 143, 993, 110, 995, 21, 990, 389, 636, 5222, 5223, 5432,
            3389),
}
PROFILE_NAMES = ('web', 'mail', 'all')


class UsageError(Exception):
    """Bad command line or input files; reported as ``error: ...`` with exit code 2."""


class ProtocolPort(int):
    """A port number written with its protocol (``2525/smtp``, ``25/tls``).

    It compares, hashes, sorts and prints as the number, so it travels wherever ports do (the
    -p list, the ports a target is written with) and :func:`endpoint_protocol` reads the
    protocol back where the endpoint is dialled.
    """

    protocol = PROTO_TLS  # type: str

    def __new__(cls, port: int, protocol: str = PROTO_TLS) -> 'ProtocolPort':
        value = super().__new__(cls, port)
        value.protocol = protocol
        return value


def parse_protocol(word: str, token: str) -> str:
    """The protocol ``word`` names (``smtp``, ``postgresql`` -> ``postgres``); UsageError,
    naming ``token``, for any other word."""
    key = word.strip().lower()
    key = _PROTOCOL_ALIASES.get(key, key)
    if key not in PROTOCOLS:
        raise UsageError('unknown protocol %r in %r (one of %s)'
                         % (word, token, ', '.join(PROTOCOLS)))
    return key


def endpoint_protocol(port: int, overrides: Optional[Dict[int, str]] = None) -> str:
    """The protocol spoken on ``port``: the one written with it (:class:`ProtocolPort`), else
    the one -p names for that number (``overrides``), else :data:`PORT_PROTOCOLS`, else TLS."""
    named = port.protocol if isinstance(port, ProtocolPort) else None
    if named:
        return named
    number = int(port)
    if overrides and number in overrides:
        return overrides[number]
    return PORT_PROTOCOLS.get(number, PROTO_TLS)


def port_label(port: int, protocol: str) -> str:
    """``443``, ``25/smtp``: a port as -p takes it, with the protocol unless it is TLS."""
    return '%d' % port if protocol == PROTO_TLS else '%d/%s' % (port, protocol)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: Optional[datetime]) -> Optional[str]:
    """Format an aware datetime like JavaScript's ``Date#toISOString`` (``...T..:..:...000Z``)."""
    if value is None:
        return None
    value = value.astimezone(timezone.utc)
    return '%04d-%02d-%02dT%02d:%02d:%02d.%03dZ' % (
        value.year, value.month, value.day, value.hour, value.minute, value.second,
        value.microsecond // 1000)


def days_until(when: datetime, now: datetime) -> int:
    """Whole days from ``now`` until ``when`` (negative once ``when`` has passed)."""
    return int(math.floor((when - now).total_seconds() / 86400.0))


# =====================================================================================
# Minimal DER / X.509 parser (no third-party crypto library, no private ssl APIs)
# =====================================================================================

class DerError(ValueError):
    """Raised when DER/ASN.1 input is malformed or not a supported structure."""


# What callers of parse_certificate() catch for certificates from a server or a file:
# DerError (a ValueError), plus a last line of defence against parser bugs on hostile
# input, so one bad certificate becomes a row or a warning, never a lost scan.
_CERT_PARSE_ERRORS = (ValueError, OverflowError, IndexError)


# A decoded TLV: (tag byte, header start, content start, content end) - offsets into
# the buffer so exact sub-structures (e.g. a whole certificate) can be sliced out.
Tlv = Tuple[int, int, int, int]


def _read_tlv(buf: bytes, pos: int, end: int) -> Tlv:
    """Decode one DER TLV starting at ``pos`` without reading past ``end``."""
    start = pos
    if pos >= end:
        raise DerError('unexpected end of data')
    tag = buf[pos]
    pos += 1
    if tag & 0x1F == 0x1F:
        # High-tag-number form (never used by X.509, but skip it safely).
        for _ in range(4):
            if pos >= end:
                raise DerError('truncated tag')
            octet = buf[pos]
            pos += 1
            if not octet & 0x80:
                break
        else:
            raise DerError('tag number too large')
    if pos >= end:
        raise DerError('truncated length')
    first = buf[pos]
    pos += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError('indefinite length is not allowed in DER')
    else:
        count = first & 0x7F
        if count > 4:
            raise DerError('length field too long')
        if pos + count > end:
            raise DerError('truncated length')
        length = int.from_bytes(buf[pos:pos + count], 'big')
        pos += count
    if length > end - pos:
        raise DerError('length exceeds available data')
    return tag, start, pos, pos + length


def _children(buf: bytes, start: int, end: int) -> List[Tlv]:
    """Decode all consecutive TLVs in ``buf[start:end]`` (the content of a constructed value)."""
    out = []
    pos = start
    while pos < end:
        tlv = _read_tlv(buf, pos, end)
        out.append(tlv)
        pos = tlv[3]
    return out


def _expect(tlv: Tlv, tag: int, what: str) -> Tlv:
    if tlv[0] != tag:
        raise DerError('expected %s (tag 0x%02x), got tag 0x%02x' % (what, tag, tlv[0]))
    return tlv


def _content(buf: bytes, tlv: Tlv) -> bytes:
    return buf[tlv[2]:tlv[3]]


# Octets per OID arc: 20 x 7 bits holds a 2.25 UUID arc (128 bits); a longer arc would only
# make str() hit Python's int-to-str digit limit (ValueError, not DerError).
_MAX_OID_ARC_OCTETS = 20


def _decode_oid(data: bytes) -> str:
    if not data:
        raise DerError('empty OBJECT IDENTIFIER')
    if data[-1] & 0x80:
        raise DerError('truncated OBJECT IDENTIFIER')
    arcs = []
    value = 0
    octets = 0
    for octet in data:
        octets += 1
        if octets > _MAX_OID_ARC_OCTETS:
            raise DerError('OBJECT IDENTIFIER arc too large')
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            arcs.append(value)
            value = 0
            octets = 0
    first = arcs[0]
    if first < 40:
        head = [0, first]
    elif first < 80:
        head = [1, first - 40]
    else:
        head = [2, first - 80]
    return '.'.join(str(arc) for arc in head + arcs[1:])


def _oid(buf: bytes, tlv: Tlv) -> str:
    return _decode_oid(_content(buf, _expect(tlv, 0x06, 'OBJECT IDENTIFIER')))


def _decode_string(tag: int, data: bytes) -> Optional[str]:
    """Decode an ASN.1 character string; ``None`` for non-string types."""
    if tag == 0x0C:                          # UTF8String
        return data.decode('utf-8', 'replace')
    if tag in (0x12, 0x13, 0x16, 0x1A):      # Numeric, Printable, IA5, Visible (ASCII)
        return data.decode('latin-1')
    if tag == 0x14:                          # TeletexString: latin-1 is the usual reality
        return data.decode('latin-1')
    if tag == 0x1E:                          # BMPString
        return data.decode('utf-16-be', 'replace')
    if tag == 0x1C:                          # UniversalString
        return data.decode('utf-32-be', 'replace')
    return None


# Attribute short names as printed by `openssl x509 -nameopt RFC2253`.
_DN_ATTRS = {
    '2.5.4.3': 'CN', '2.5.4.4': 'SN', '2.5.4.5': 'serialNumber', '2.5.4.6': 'C',
    '2.5.4.7': 'L', '2.5.4.8': 'ST', '2.5.4.9': 'street', '2.5.4.10': 'O',
    '2.5.4.11': 'OU', '2.5.4.12': 'title', '2.5.4.15': 'businessCategory',
    '2.5.4.17': 'postalCode', '2.5.4.41': 'name', '2.5.4.42': 'GN', '2.5.4.43': 'initials',
    '2.5.4.44': 'generationQualifier', '2.5.4.46': 'dnQualifier', '2.5.4.65': 'pseudonym',
    '2.5.4.97': 'organizationIdentifier',
    '0.9.2342.19200300.100.1.1': 'UID', '0.9.2342.19200300.100.1.25': 'DC',
    '1.2.840.113549.1.9.1': 'emailAddress',
    '1.3.6.1.4.1.311.60.2.1.1': 'jurisdictionL', '1.3.6.1.4.1.311.60.2.1.2': 'jurisdictionST',
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
}

_SIGNATURE_ALGORITHMS = {
    '1.2.840.113549.1.1.2': 'md2WithRSAEncryption',
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
    '1.3.14.3.2.29': 'sha1WithRSA',
    '1.2.840.10040.4.3': 'dsaWithSHA1',
    '1.2.840.113549.1.1.10': 'rsassaPss',
    '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
    '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
    '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
    '1.2.840.10045.4.1': 'ecdsa-with-SHA1',
    '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
    '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
    '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
    '1.3.101.112': 'Ed25519',
    '1.3.101.113': 'Ed448',
}

_CURVES = {
    '1.2.840.10045.3.1.7': ('P-256', 256),
    '1.3.132.0.34': ('P-384', 384),
    '1.3.132.0.35': ('P-521', 521),
    '1.3.132.0.10': ('secp256k1', 256),
    '1.3.36.3.3.2.8.1.1.7': ('brainpoolP256r1', 256),
    '1.3.36.3.3.2.8.1.1.11': ('brainpoolP384r1', 384),
    '1.3.36.3.3.2.8.1.1.13': ('brainpoolP512r1', 512),
}

_OID_RSA = '1.2.840.113549.1.1.1'
_OID_RSA_PSS = '1.2.840.113549.1.1.10'
_OID_EC = '1.2.840.10045.2.1'
_OID_DSA = '1.2.840.10040.4.1'
_OID_ED25519 = '1.3.101.112'
_OID_ED448 = '1.3.101.113'
_OID_SAN = '2.5.29.17'
_OID_BASIC_CONSTRAINTS = '2.5.29.19'
_OID_KEY_USAGE = '2.5.29.15'
_OID_SKI = '2.5.29.14'
_OID_AKI = '2.5.29.35'
_OID_AIA = '1.3.6.1.5.5.7.1.1'
_OID_CA_ISSUERS = '1.3.6.1.5.5.7.48.2'
_OID_CRL_DP = '2.5.29.31'
_OID_CT_POISON = '1.3.6.1.4.1.11129.2.4.3'   # RFC 6962: a precertificate
_OID_PKCS7_DATA = '1.2.840.113549.1.7.1'
_OID_PKCS7_SIGNED = '1.2.840.113549.1.7.2'

# Name = RDNs; RDN = [(attribute short name or dotted OID, text or None, raw TLV bytes)]
Rdn = List[Tuple[str, Optional[str], bytes]]


def _parse_name(buf: bytes, tlv: Tlv) -> List[Rdn]:
    rdns = []
    for rdn in _children(buf, tlv[2], tlv[3]):
        _expect(rdn, 0x31, 'RelativeDistinguishedName SET')
        atvs = []
        for atv in _children(buf, rdn[2], rdn[3]):
            _expect(atv, 0x30, 'AttributeTypeAndValue')
            parts = _children(buf, atv[2], atv[3])
            if len(parts) != 2:
                raise DerError('malformed AttributeTypeAndValue')
            oid = _oid(buf, parts[0])
            value = parts[1]
            text = _decode_string(value[0], _content(buf, value))
            atvs.append((_DN_ATTRS.get(oid, oid), text, buf[value[1]:value[3]]))
        rdns.append(atvs)
    return rdns


def _escape_dn_value(value: str) -> str:
    """Escape an attribute value per RFC 4514 section 2.4 (UTF-8 kept as-is)."""
    out = []
    last = len(value) - 1
    for i, ch in enumerate(value):
        if ch in ',+"\\<>;':
            out.append('\\' + ch)
        elif ch == '\x00':
            out.append('\\00')
        elif (i == 0 and ch in '# ') or (i == last and ch == ' '):
            out.append('\\' + ch)
        else:
            out.append(ch)
    return ''.join(out)


def _dn_string(rdns: List[Rdn]) -> str:
    """Render a Name like ``openssl -nameopt RFC2253`` (most specific RDN first)."""
    parts = []
    for rdn in reversed(rdns):
        items = []
        for name, text, raw in rdn:
            if text is None:
                items.append('%s=#%s' % (name, raw.hex()))
            else:
                items.append('%s=%s' % (name, _escape_dn_value(text)))
        parts.append('+'.join(items))
    return ','.join(parts)


def _dn_attrs(rdns: List[Rdn]) -> Dict[str, str]:
    """First value of every attribute, in certificate order (``{'CN': ..., 'O': ...}``)."""
    attrs = {}  # type: Dict[str, str]
    for rdn in rdns:
        for name, text, _raw in rdn:
            if text is not None and name not in attrs:
                attrs[name] = text
    return attrs


_UTCTIME_RE = re.compile(r'^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z|[+-]\d{4})?$')
_GENTIME_RE = re.compile(
    r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})?(\d{2})?(?:[.,](\d{1,9}))?(Z|[+-]\d{4})?$')


def _parse_time(tag: int, data: bytes) -> datetime:
    """Decode UTCTime (0x17, RFC 5280 50-year pivot) or GeneralizedTime (0x18) to aware UTC."""
    try:
        text = data.decode('ascii')
    except UnicodeDecodeError:
        raise DerError('non-ASCII time value')
    micro = 0
    if tag == 0x17:
        match = _UTCTIME_RE.match(text)
        if not match:
            raise DerError('invalid UTCTime %r' % text)
        yy = int(match.group(1))
        year = 1900 + yy if yy >= 50 else 2000 + yy
        month, day, hour, minute = (int(match.group(i)) for i in range(2, 6))
        second = int(match.group(6) or 0)
        zone = match.group(7)
    elif tag == 0x18:
        match = _GENTIME_RE.match(text)
        if not match:
            raise DerError('invalid GeneralizedTime %r' % text)
        year, month, day, hour = (int(match.group(i)) for i in range(1, 5))
        minute = int(match.group(5) or 0)
        second = int(match.group(6) or 0)
        if match.group(7):
            micro = int((match.group(7) + '000000')[:6])
        zone = match.group(8)
    else:
        raise DerError('unsupported time type 0x%02x' % tag)
    try:
        value = datetime(year, month, day, hour, minute, second, micro, tzinfo=timezone.utc)
    except ValueError:
        raise DerError('invalid time %r' % text)
    if zone and zone != 'Z':
        hours, minutes = int(zone[1:3]), int(zone[3:5])
        if hours > 23 or minutes > 59:
            raise DerError('invalid time zone offset %r' % text)
        offset = timedelta(hours=hours, minutes=minutes)
        try:
            value = value - offset if zone[0] == '+' else value + offset
        except OverflowError:  # 9999-12-31T23:00-0100, 0001-01-01T00:00+0100
            raise DerError('time out of range %r' % text)
    return value


def _format_ip_bytes(data: bytes) -> str:
    if len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if len(data) == 16:
        return _format_ipv6(ipaddress.IPv6Address(data))
    return data.hex()  # malformed (e.g. name-constraint style address/mask)


def _format_ipv6(addr: ipaddress.IPv6Address) -> str:
    """RFC 5952 text; IPv4-mapped addresses keep dotted form (``::ffff:1.2.3.4``)."""
    if addr.ipv4_mapped is not None:
        return '::ffff:%s' % addr.ipv4_mapped
    return addr.compressed


def _parse_spki(buf: bytes, spki: Tlv) -> Tuple[str, Optional[int], Optional[str]]:
    """Return (key algorithm, key bits, curve) from SubjectPublicKeyInfo."""
    parts = _children(buf, spki[2], spki[3])
    if len(parts) != 2:
        raise DerError('malformed SubjectPublicKeyInfo')
    alg_parts = _children(buf, *_expect(parts[0], 0x30, 'AlgorithmIdentifier')[2:4])
    if not alg_parts:
        raise DerError('empty AlgorithmIdentifier')
    oid = _oid(buf, alg_parts[0])
    bits_tlv = _expect(parts[1], 0x03, 'subjectPublicKey BIT STRING')
    if oid in (_OID_RSA, _OID_RSA_PSS):
        # BIT STRING content: 1 byte "unused bits" + RSAPublicKey SEQUENCE { n, e }.
        inner = _expect(_read_tlv(buf, bits_tlv[2] + 1, bits_tlv[3]), 0x30, 'RSAPublicKey')
        fields = _children(buf, inner[2], inner[3])
        if not fields:
            raise DerError('malformed RSAPublicKey')
        modulus = int.from_bytes(_content(buf, _expect(fields[0], 0x02, 'modulus')), 'big')
        return 'RSA', modulus.bit_length(), None
    if oid == _OID_EC:
        if len(alg_parts) > 1 and alg_parts[1][0] == 0x06:
            curve_oid = _oid(buf, alg_parts[1])
            name, bits = _CURVES.get(curve_oid, (curve_oid, None))
            return 'EC', bits, name
        return 'EC', None, None
    if oid == _OID_ED25519:
        return 'Ed25519', 256, None
    if oid == _OID_ED448:
        return 'Ed448', 456, None
    if oid == _OID_DSA:
        if len(alg_parts) > 1 and alg_parts[1][0] == 0x30:
            params = _children(buf, alg_parts[1][2], alg_parts[1][3])
            if params and params[0][0] == 0x02:
                return 'DSA', int.from_bytes(_content(buf, params[0]), 'big').bit_length(), None
        return 'DSA', None, None
    return 'unknown', None, None


_KEY_FAMILIES = {_OID_RSA: 'RSA', _OID_RSA_PSS: 'RSA', _OID_EC: 'EC', _OID_ED25519: 'Ed25519',
                 _OID_ED448: 'Ed448', _OID_DSA: 'DSA'}


@dataclass(frozen=True)
class PublicKey:
    """A public key reduced to what identifies it: bundle-check compares these.

    ``ident`` is what every encoding of one key has in common - an RSA key's modulus and
    exponent, an EC key's curve, x coordinate and the parity of y (a compressed and an
    uncompressed point are the same key), the raw key bytes of any other algorithm - so two
    files hold the same key exactly when their ``ident`` is equal. It is public data.
    """

    algorithm: str                 # RSA | EC | Ed25519 | Ed448 | DSA | unknown
    bits: Optional[int]
    curve: Optional[str]           # P-256 ... for EC; the dotted OID of an unknown curve
    ident: Tuple[Any, ...] = field(repr=False)

    def label(self) -> str:
        """``RSA 2048``, ``EC P-256``, ``Ed25519``."""
        if self.algorithm == 'EC':
            return 'EC %s' % (self.curve or '(curve not named)')
        if self.algorithm in ('RSA', 'DSA') and self.bits:
            return '%s %d' % (self.algorithm, self.bits)
        return self.algorithm


def _ec_point_ident(curve: Optional[str], point: bytes) -> Tuple[Any, ...]:
    """(EC, curve, x, parity of y) of an uncompressed (04), hybrid (06 / 07) or compressed
    (02 / 03) point; the raw bytes when it is none of these."""
    if len(point) > 1 and len(point) % 2 == 1 and point[0] in (4, 6, 7):
        size = (len(point) - 1) // 2
        return ('EC', curve, int.from_bytes(point[1:1 + size], 'big'), point[-1] & 1)
    if len(point) > 1 and point[0] in (2, 3):
        return ('EC', curve, int.from_bytes(point[1:], 'big'), point[0] & 1)
    return ('EC', curve, point)


def _ec_point_bits(point: bytes) -> Optional[int]:
    if len(point) > 1 and point[0] in (4, 6, 7):
        return (len(point) - 1) // 2 * 8
    if len(point) > 1 and point[0] in (2, 3):
        return (len(point) - 1) * 8
    return None


def _curve_of(oid: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """(curve name, bits) of a named-curve OID (the OID itself when it is not known)."""
    if not oid:
        return None, None
    return _CURVES.get(oid, (oid, None))


def rsa_public_key(modulus: int, exponent: int) -> PublicKey:
    """The :class:`PublicKey` of an RSA modulus and public exponent."""
    return PublicKey('RSA', modulus.bit_length(), None, ('RSA', modulus, exponent))


def ec_public_key(curve_oid: Optional[str], point: bytes) -> PublicKey:
    """The :class:`PublicKey` of an EC point on the named curve ``curve_oid``."""
    curve, bits = _curve_of(curve_oid)
    return PublicKey('EC', bits or _ec_point_bits(point), curve, _ec_point_ident(curve, point))


def public_key_from_spki(der: Union[bytes, bytearray, memoryview]) -> PublicKey:
    """The :class:`PublicKey` of a DER SubjectPublicKeyInfo (a certificate's, a CSR's or a
    ``PUBLIC KEY`` PEM's). Raises :class:`DerError` on malformed input."""
    buf = bytes(der)
    spki = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'SubjectPublicKeyInfo')
    parts = _children(buf, spki[2], spki[3])
    if len(parts) != 2:
        raise DerError('malformed SubjectPublicKeyInfo')
    alg_parts = _children(buf, *_expect(parts[0], 0x30, 'AlgorithmIdentifier')[2:4])
    if not alg_parts:
        raise DerError('empty AlgorithmIdentifier')
    oid = _oid(buf, alg_parts[0])
    bits_tlv = _expect(parts[1], 0x03, 'subjectPublicKey BIT STRING')
    key = buf[bits_tlv[2] + 1:bits_tlv[3]]  # after the "unused bits" byte
    family = _KEY_FAMILIES.get(oid, 'unknown')
    if family == 'RSA':
        inner = _expect(_read_tlv(key, 0, len(key)), 0x30, 'RSAPublicKey')
        fields = _children(key, inner[2], inner[3])
        if len(fields) < 2:
            raise DerError('malformed RSAPublicKey')
        return rsa_public_key(int.from_bytes(_content(key, _expect(fields[0], 0x02, 'modulus')), 'big'),
                              int.from_bytes(_content(key, _expect(fields[1], 0x02, 'exponent')),
                                             'big'))
    if family == 'EC':
        curve_oid = _oid(buf, alg_parts[1]) if len(alg_parts) > 1 and alg_parts[1][0] == 0x06 \
            else None
        return ec_public_key(curve_oid, key)
    _algorithm, bits, curve = _parse_spki(buf, spki)
    return PublicKey(family, bits, curve, (oid, key))


_HOSTNAME_LIKE_RE = re.compile(r'^(\*\.)?[a-z0-9_-]+(\.[a-z0-9_-]+)+$')


@dataclass
class CertInfo:
    """The parts of an X.509 certificate this tool needs (field names mirror lib/x509.js)."""

    der: bytes = field(repr=False)
    version: int
    serial_hex: str
    signature_algorithm: str
    subject: Dict[str, str]
    subject_dn: str
    subject_cn: Optional[str]
    issuer: Dict[str, str]
    issuer_dn: str
    issuer_cn: Optional[str]
    not_before: datetime
    not_after: datetime
    dns_names: List[str]
    ip_addresses: List[str]
    emails: List[str]
    uris: List[str]
    key_algorithm: str
    key_bits: Optional[int]
    curve: Optional[str]
    is_ca: bool
    self_signed: bool
    sha256: str
    sha1: str
    subject_key_id: Optional[str] = None     # lowercase hex (SubjectKeyIdentifier)
    authority_key_id: Optional[str] = None   # lowercase hex (AKI keyIdentifier only)
    spki_der: bytes = field(default=b'', repr=False)  # SubjectPublicKeyInfo DER
    spki_sha256: Optional[str] = None        # lowercase hex SHA-256 of spki_der (key pinning)
    ca_issuers: List[str] = field(default_factory=list)  # AIA "CA Issuers" URLs
    key_cert_sign: Optional[bool] = None     # keyUsage keyCertSign (None: no keyUsage extension)
    precert: bool = False                    # the CT poison extension: a precertificate, never served
    crl_urls: List[str] = field(default_factory=list)  # CRL distribution point URIs (--revocation)

    def public_key(self) -> Optional[PublicKey]:
        """The certificate's :class:`PublicKey`, or None when its key cannot be read."""
        try:
            return public_key_from_spki(self.spki_der) if self.spki_der else None
        except _CERT_PARSE_ERRORS:
            return None

    @property
    def issuer_o(self) -> Optional[str]:
        """Issuer organisation (``O``), e.g. "Let's Encrypt"."""
        return self.issuer.get('O')

    @property
    def hostnames(self) -> List[str]:
        """SAN DNS names (lowercase); legacy fallback to the CN when there is no SAN DNS name."""
        names = []  # type: List[str]
        for name in self.dns_names:
            name = name.strip().lower().rstrip('.')
            if name and name not in names:
                names.append(name)
        if not names and self.subject_cn:
            cn = self.subject_cn.strip().lower().rstrip('.')
            if _HOSTNAME_LIKE_RE.match(cn):
                names.append(cn)
        return names

    def days_left(self, now: Optional[datetime] = None) -> int:
        """Whole days until notAfter (negative when expired)."""
        return days_until(self.not_after, now or _utcnow())

    def covers(self, host: str) -> Tuple[bool, Optional[str]]:
        """RFC 6125 name check against :attr:`hostnames` -> ``(covered, matching SAN)``."""
        return cert_covers(self.hostnames, host)

    def short_label(self) -> str:
        """Subject CN, or the full subject DN when the certificate has no CN."""
        return self.subject_cn or self.subject_dn or '(empty subject)'

    def issuer_label(self) -> str:
        """Issuer CN plus organisation when it adds information."""
        cn, org = self.issuer_cn, self.issuer_o
        if cn and org and org not in cn:
            return '%s (%s)' % (cn, org)
        return cn or org or self.issuer_dn or '(unknown issuer)'

    def to_dict(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """JSON-friendly summary (camelCase keys, ISO dates, no DER)."""
        return {
            'subjectCN': self.subject_cn,
            'subjectDN': self.subject_dn,
            'issuerCN': self.issuer_cn,
            'issuerO': self.issuer_o,
            'issuerDN': self.issuer_dn,
            'serialHex': self.serial_hex,
            'notBefore': iso_utc(self.not_before),
            'notAfter': iso_utc(self.not_after),
            'daysLeft': self.days_left(now),
            'dnsNames': list(self.dns_names),
            'ipAddresses': list(self.ip_addresses),
            'emails': list(self.emails),
            'hostnames': self.hostnames,
            'keyAlgorithm': self.key_algorithm,
            'keyBits': self.key_bits,
            'curve': self.curve,
            'signatureAlgorithm': self.signature_algorithm,
            'isCA': self.is_ca,
            'selfSigned': self.self_signed,
            'subjectKeyId': self.subject_key_id,
            'authorityKeyId': self.authority_key_id,
            'sha256': self.sha256,
            'sha1': self.sha1,
            'spkiSha256': self.spki_sha256,
        }


def parse_certificate(der: Union[bytes, bytearray, memoryview]) -> CertInfo:
    """Parse one DER-encoded X.509 certificate.

    Trailing bytes after the certificate SEQUENCE are ignored; fingerprints are computed
    over the exact certificate encoding. Raises :class:`DerError` on malformed input.
    """
    buf = bytes(der)
    if not buf:
        raise DerError('empty input')
    cert = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'Certificate SEQUENCE')
    cert_der = buf[cert[1]:cert[3]]
    top = _children(buf, cert[2], cert[3])
    if len(top) < 3:
        raise DerError('a Certificate has 3 elements, found %d' % len(top))
    tbs = _expect(top[0], 0x30, 'TBSCertificate')
    sig_parts = _children(buf, *_expect(top[1], 0x30, 'signatureAlgorithm')[2:4])
    if not sig_parts:
        raise DerError('empty signatureAlgorithm')
    sig_oid = _oid(buf, sig_parts[0])
    fields = _children(buf, tbs[2], tbs[3])

    index = 0
    version = 1
    if fields and fields[0][0] == 0xA0:
        inner = _children(buf, fields[0][2], fields[0][3])
        if len(inner) != 1 or inner[0][0] != 0x02:
            raise DerError('malformed version')
        version = int.from_bytes(_content(buf, inner[0]), 'big', signed=True) + 1
        index = 1
    if len(fields) < index + 6:
        raise DerError('TBSCertificate is missing fields')
    serial, _tbs_sig, issuer_tlv, validity, subject_tlv, spki = fields[index:index + 6]
    _expect(serial, 0x02, 'serialNumber')
    _expect(_tbs_sig, 0x30, 'signature AlgorithmIdentifier')
    _expect(issuer_tlv, 0x30, 'issuer Name')
    _expect(validity, 0x30, 'Validity')
    _expect(subject_tlv, 0x30, 'subject Name')
    _expect(spki, 0x30, 'SubjectPublicKeyInfo')

    raw_serial = _content(buf, serial)
    if not raw_serial:
        raise DerError('empty serialNumber')
    serial_hex = raw_serial.hex()
    while len(serial_hex) > 2 and serial_hex.startswith('00'):
        serial_hex = serial_hex[2:]  # drop the DER sign byte

    times = _children(buf, validity[2], validity[3])
    if len(times) != 2:
        raise DerError('Validity must hold notBefore and notAfter')
    not_before = _parse_time(times[0][0], _content(buf, times[0]))
    not_after = _parse_time(times[1][0], _content(buf, times[1]))

    issuer_rdns = _parse_name(buf, issuer_tlv)
    subject_rdns = _parse_name(buf, subject_tlv)
    issuer = _dn_attrs(issuer_rdns)
    subject = _dn_attrs(subject_rdns)
    key_algorithm, key_bits, curve = _parse_spki(buf, spki)

    dns_names = []  # type: List[str]
    ip_addresses = []  # type: List[str]
    emails = []  # type: List[str]
    uris = []  # type: List[str]
    is_ca = False
    subject_key_id = None  # type: Optional[str]
    authority_key_id = None  # type: Optional[str]
    ca_issuers = []  # type: List[str]
    crl_urls = []  # type: List[str]
    key_cert_sign = None  # type: Optional[bool]
    precert = False
    for extra in fields[index + 6:]:
        if extra[0] != 0xA3:
            continue  # issuerUniqueID [1] / subjectUniqueID [2]
        wrapper = _children(buf, extra[2], extra[3])
        if len(wrapper) != 1:
            raise DerError('malformed extensions')
        for ext in _children(buf, *_expect(wrapper[0], 0x30, 'Extensions')[2:4]):
            parts = _children(buf, *_expect(ext, 0x30, 'Extension')[2:4])
            if len(parts) < 2:
                raise DerError('malformed Extension')
            ext_oid = _oid(buf, parts[0])
            value = _expect(parts[-1], 0x04, 'extnValue OCTET STRING')
            if ext_oid == _OID_SAN:
                names = _expect(_read_tlv(buf, value[2], value[3]), 0x30, 'GeneralNames')
                for general in _children(buf, names[2], names[3]):
                    data = _content(buf, general)
                    if general[0] == 0x82:       # [2] dNSName
                        dns_names.append(data.decode('ascii', 'replace'))
                    elif general[0] == 0x87:     # [7] iPAddress
                        ip_addresses.append(_format_ip_bytes(data))
                    elif general[0] == 0x81:     # [1] rfc822Name
                        emails.append(data.decode('ascii', 'replace'))
                    elif general[0] == 0x86:     # [6] uniformResourceIdentifier
                        uris.append(data.decode('ascii', 'replace'))
            elif ext_oid == _OID_BASIC_CONSTRAINTS:
                constraints = _expect(_read_tlv(buf, value[2], value[3]), 0x30,
                                      'BasicConstraints')
                items = _children(buf, constraints[2], constraints[3])
                if items and items[0][0] == 0x01:
                    is_ca = any(_content(buf, items[0]))
            elif ext_oid == _OID_KEY_USAGE:
                # KeyUsage BIT STRING: keyCertSign is bit 5 (0x04 of the first byte after the
                # unused-bits count). `openssl req -x509` leaves the extension out by default.
                bits = _content(buf, _expect(_read_tlv(buf, value[2], value[3]), 0x03, 'KeyUsage'))
                key_cert_sign = len(bits) > 1 and bool(bits[1] & 0x04)
            elif ext_oid == _OID_CT_POISON:
                precert = True
            elif ext_oid == _OID_SKI:
                key_id = _expect(_read_tlv(buf, value[2], value[3]), 0x04, 'SubjectKeyIdentifier')
                subject_key_id = _content(buf, key_id).hex()
            elif ext_oid == _OID_AKI:
                aki = _expect(_read_tlv(buf, value[2], value[3]), 0x30, 'AuthorityKeyIdentifier')
                for item in _children(buf, aki[2], aki[3]):
                    if item[0] == 0x80:  # [0] keyIdentifier
                        authority_key_id = _content(buf, item).hex()
            elif ext_oid == _OID_AIA:
                # AuthorityInfoAccessSyntax: where to download the issuer (bundle-check names it
                # for a missing intermediate). A malformed entry is skipped, never fatal.
                try:
                    aia = _expect(_read_tlv(buf, value[2], value[3]), 0x30, 'AuthorityInfoAccess')
                    for access in _children(buf, aia[2], aia[3]):
                        method, location = _children(buf, access[2], access[3])[:2]
                        if _oid(buf, method) == _OID_CA_ISSUERS and location[0] == 0x86:
                            ca_issuers.append(_content(buf, location).decode('ascii', 'replace'))
                except (DerError, ValueError):
                    pass
            elif ext_oid == _OID_CRL_DP:
                # CRLDistributionPoints: the URIs of each distributionPoint's fullName (what
                # --revocation reads). A malformed entry is skipped, never fatal.
                try:
                    points = _expect(_read_tlv(buf, value[2], value[3]), 0x30,
                                     'CRLDistributionPoints')
                    for point in _children(buf, points[2], points[3]):
                        for part in _children(buf, *_expect(point, 0x30, 'DistributionPoint')[2:4]):
                            if part[0] != 0xA0:  # distributionPoint [0]
                                continue
                            for name in _children(buf, part[2], part[3]):
                                if name[0] != 0xA0:  # fullName [0] GeneralNames
                                    continue
                                for general in _children(buf, name[2], name[3]):
                                    if general[0] == 0x86:  # uniformResourceIdentifier
                                        crl_urls.append(_content(buf, general).decode('ascii',
                                                                                      'replace'))
                except (DerError, ValueError):
                    pass

    spki_der = buf[spki[1]:spki[3]]
    return CertInfo(
        der=cert_der,
        version=version,
        serial_hex=serial_hex,
        signature_algorithm=_SIGNATURE_ALGORITHMS.get(sig_oid, sig_oid),
        subject=subject,
        subject_dn=_dn_string(subject_rdns),
        subject_cn=subject.get('CN'),
        issuer=issuer,
        issuer_dn=_dn_string(issuer_rdns),
        issuer_cn=issuer.get('CN'),
        not_before=not_before,
        not_after=not_after,
        dns_names=dns_names,
        ip_addresses=ip_addresses,
        emails=emails,
        uris=uris,
        key_algorithm=key_algorithm,
        key_bits=key_bits,
        curve=curve,
        is_ca=is_ca,
        # Self-issued: identical encoded subject and issuer Names, and - as lib/x509.js -
        # the same key identifier on both sides when the certificate carries both.
        self_signed=(buf[issuer_tlv[1]:issuer_tlv[3]] == buf[subject_tlv[1]:subject_tlv[3]]
                     and (not subject_key_id or not authority_key_id
                          or subject_key_id == authority_key_id)),
        sha256=hashlib.sha256(cert_der).hexdigest(),
        sha1=hashlib.sha1(cert_der).hexdigest(),
        subject_key_id=subject_key_id,
        authority_key_id=authority_key_id,
        spki_der=spki_der,
        spki_sha256=hashlib.sha256(spki_der).hexdigest(),
        ca_issuers=ca_issuers,
        key_cert_sign=key_cert_sign,
        precert=precert,
        crl_urls=crl_urls,
    )


# ------------------------------------------------------------ certificate containers

_PEM_RE = re.compile(r'-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----', re.S)
_CERT_LABELS = ('CERTIFICATE', 'X509 CERTIFICATE', 'TRUSTED CERTIFICATE')
_BASE64_RE = re.compile(r'^[A-Za-z0-9+/=_-]+$')
PKCS12_HINT = 'openssl pkcs12 -in FILE.pfx -nokeys -clcerts -out new-cert.pem'

# Warning codes mirror lib/x509.js: PRIVATE_KEY_PRESENT, NO_CERTIFICATE,
# PKCS12_UNSUPPORTED, CSR_NOT_CERT, PARSE_ERROR.
CertWarning = Tuple[str, str]


def _b64decode(body: str) -> bytes:
    lines = [line for line in body.splitlines() if ':' not in line]  # drop RFC 1421 headers
    compact = re.sub(r'\s+', '', ''.join(lines))
    return base64.b64decode(compact, validate=True)


def _pkcs7_certificates(buf: bytes) -> Optional[List[bytes]]:
    """Certificates (DER) inside a PKCS#7 SignedData (.p7b); ``None`` if not PKCS#7."""
    try:
        outer = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'ContentInfo')
        parts = _children(buf, outer[2], outer[3])
        if len(parts) < 2 or _oid(buf, parts[0]) != _OID_PKCS7_SIGNED or parts[1][0] != 0xA0:
            return None
        signed = _expect(_read_tlv(buf, parts[1][2], parts[1][3]), 0x30, 'SignedData')
        found = []
        for item in _children(buf, signed[2], signed[3]):
            if item[0] == 0xA0:  # certificates [0] IMPLICIT SET OF Certificate
                for cert in _children(buf, item[2], item[3]):
                    if cert[0] == 0x30:
                        found.append(buf[cert[1]:cert[3]])
        return found
    except DerError:
        return None


def _looks_like_pkcs12(buf: bytes) -> bool:
    """PFX ::= SEQUENCE { version INTEGER (3), authSafe ContentInfo, macData OPTIONAL }."""
    try:
        outer = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'PFX')
        parts = _children(buf, outer[2], outer[3])
        if len(parts) < 2 or parts[0][0] != 0x02 or _content(buf, parts[0]) != b'\x03':
            return False
        auth = _children(buf, *_expect(parts[1], 0x30, 'ContentInfo')[2:4])
        return bool(auth) and _oid(buf, auth[0]) in (_OID_PKCS7_DATA, _OID_PKCS7_SIGNED)
    except DerError:
        return False


def _load_der(buf: bytes, certs: List[CertInfo], warnings: List[CertWarning]) -> None:
    pkcs7 = _pkcs7_certificates(buf)
    if pkcs7 is not None:
        for der in pkcs7:
            try:
                certs.append(parse_certificate(der))
            except _CERT_PARSE_ERRORS as exc:
                warnings.append(('PARSE_ERROR', str(exc)))
        return
    if _looks_like_pkcs12(buf):
        warnings.append(('PKCS12_UNSUPPORTED', PKCS12_HINT))
        return
    try:
        certs.append(parse_certificate(buf))
    except _CERT_PARSE_ERRORS as exc:
        warnings.append(('PARSE_ERROR', str(exc)))


def _text_bytes(raw: bytes) -> bytes:
    """UTF-16 text -> latin-1 bytes, and a UTF-8 BOM dropped, like lib/x509.js decodeText:
    a BOM, or ASCII with NUL high bytes (UTF-16LE without BOM). PowerShell 5.1's ``>`` and
    ``Out-File`` write UTF-16LE. Raw DER (``30 82 ...``) never looks like either."""
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        return raw.decode('utf-16', 'replace').encode('latin-1', 'replace')
    if len(raw) >= 4 and raw[0] and not raw[1] and raw[2] and not raw[3]:
        return raw.decode('utf-16-le', 'replace').encode('latin-1', 'replace')
    if raw.startswith(b'\xef\xbb\xbf'):
        return raw[3:]
    return raw


def load_certificates(data: Union[bytes, str]) -> Tuple[List[CertInfo], List[CertWarning]]:
    """Parse every certificate in ``data``; never raises for bad input.

    Accepts PEM (one or many blocks, CRLF, surrounding text such as an e-mail), raw DER,
    bare base64 DER and PKCS#7 (.p7b, PEM or DER), as UTF-8 or UTF-16 text. Detects
    PKCS#12 and CSRs. Private keys are never decoded - their presence only produces a
    PRIVATE_KEY_PRESENT warning.
    Returns ``(certificates in input order, [(code, detail), ...])``.
    """
    certs = []  # type: List[CertInfo]
    warnings = []  # type: List[CertWarning]
    raw = (data.lstrip('\ufeff').encode('latin-1', 'replace') if isinstance(data, str)
           else _text_bytes(bytes(data)))
    text = raw.decode('latin-1')
    if '-----BEGIN ' in text:
        for match in _PEM_RE.finditer(text):
            label, body = match.group(1), match.group(2)
            if 'PRIVATE KEY' in label:
                warnings.append(('PRIVATE_KEY_PRESENT', label))
                continue
            if 'CERTIFICATE REQUEST' in label:
                warnings.append(('CSR_NOT_CERT', label))
                continue
            if label not in _CERT_LABELS and label not in ('PKCS7', 'CMS'):
                continue
            try:
                der = _b64decode(body)
            except (binascii.Error, ValueError) as exc:
                warnings.append(('PARSE_ERROR', '%s: bad base64 (%s)' % (label, exc)))
                continue
            _load_der(der, certs, warnings)
    elif raw[:1] == b'\x30':
        _load_der(raw, certs, warnings)
    else:
        compact = re.sub(r'\s+', '', text)
        if compact and _BASE64_RE.match(compact):
            try:
                der = base64.b64decode(compact + '=' * (-len(compact) % 4),
                                       altchars=b'-_' if ('-' in compact or '_' in compact)
                                       else None)
            except (binascii.Error, ValueError):
                der = b''
            if der[:1] == b'\x30':
                _load_der(der, certs, warnings)
            else:
                warnings.append(('PARSE_ERROR', 'not PEM, DER or base64 DER'))
        elif compact:
            warnings.append(('PARSE_ERROR', 'not PEM, DER or base64 DER'))
    if not certs and not any(code != 'PRIVATE_KEY_PRESENT' for code, _ in warnings):
        warnings.append(('NO_CERTIFICATE', 'no certificate found'))
    return certs, warnings


def select_leaf(certs: Sequence[CertInfo]) -> Optional[CertInfo]:
    """The end-entity certificate of a (possibly unordered) chain; first cert as fallback."""
    for cert in certs:
        if cert.is_ca:
            continue
        issues_other = any(other is not cert and other.issuer_dn == cert.subject_dn
                           for other in certs)
        if not issues_other:
            return cert
    return certs[0] if certs else None


# =====================================================================================
# Hostnames, IPs and RFC 6125 coverage
# =====================================================================================

_LABEL_RE = re.compile(r'^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$')
_SCHEME_RE = re.compile(r'^[a-zA-Z][a-zA-Z0-9+.-]*://')
# An IPv4 part with a leading zero ("010"): octal for inet_aton (glibc, Windows), decimal
# for Python < 3.8.12 / 3.9.5 - ambiguous, so never accepted as an address.
_IPV4_LEADING_ZERO_RE = re.compile(r'(?:^|\.)0[0-9]')


def _has_ambiguous_ipv4_part(text: str) -> bool:
    """True when the IPv4 part of ``text`` (dotted tail of an IPv6 too) has a leading zero."""
    tail = text.rsplit(':', 1)[-1].split('/', 1)[0]
    return '.' in tail and bool(_IPV4_LEADING_ZERO_RE.search(tail))


def normalize_ip(value: str) -> Optional[str]:
    """Canonical IP text (IPv6: RFC 5952, lowercase), or ``None`` if invalid.

    Strips surrounding ``[]`` and a ``%zone`` suffix. IPv4 parts with a leading zero
    (``010.0.0.1``: octal for the system resolver) are rejected on every Python version.
    """
    text = value.strip()
    if text.startswith('[') and text.endswith(']'):
        text = text[1:-1]
    if '%' in text:
        text = text.split('%', 1)[0]
    if _has_ambiguous_ipv4_part(text):
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address):
        return _format_ipv6(addr)
    return str(addr)


def _parse_network(token: str) -> Optional[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]]:
    """``addr/prefix`` -> network (host bits tolerated), or ``None`` if not a CIDR."""
    if _has_ambiguous_ipv4_part(token):
        return None
    try:
        return ipaddress.ip_network(token, strict=False)
    except ValueError:
        return None


def _unscannable_reason(ip: str) -> Optional[str]:
    """Why ``ip`` must never be dialled (``None`` when it is a scannable unicast address)."""
    addr = ipaddress.ip_address(ip)  # type: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # dialled as IPv4 (see _connect_address)
    if addr.is_unspecified:
        return 'unspecified address'
    if addr.version == 4 and int(addr) >> 24 == 0:
        return '0.0.0.0/8 "this network" - some systems dial it as the local host'
    if addr.is_multicast:
        return 'multicast address'
    if addr.version == 4 and int(addr) == 0xFFFFFFFF:
        return 'broadcast address'
    return None


def is_scannable_ip(ip: str) -> bool:
    """False for unspecified, 0.0.0.0/8, multicast and limited-broadcast addresses.

    IPv4-mapped IPv6 addresses (``::ffff:a.b.c.d``) are judged by their IPv4 address,
    because that is what gets dialled.
    """
    return _unscannable_reason(ip) is None


def _host_text(value: str) -> Optional[str]:
    """Strip scheme, userinfo, path/query/fragment, port and one trailing dot; lowercase.

    ``None`` for bracketed or IPv6-looking input and for a non-numeric port.
    """
    text = value.strip()
    if not text:
        return None
    text = _SCHEME_RE.sub('', text)
    for sep in ('/', '?', '#'):
        text = text.split(sep, 1)[0]
    if '@' in text:
        text = text.rsplit('@', 1)[1]
    if text.startswith('['):
        return None
    if text.count(':') == 1:
        host, port = text.split(':')
        if port and not port.isdigit():
            return None
        text = host
    elif ':' in text:
        return None
    if text.endswith('.'):
        text = text[:-1]
    return text.lower()


# UTS #46 deviation characters: IDNA 2003 (Python's 'idna' codec) maps them away - ß to
# ss, ς to σ, ZWJ / ZWNJ dropped - while browsers (non-transitional processing) keep them.
_IDN_DEVIATION_RE = re.compile('([\u00df\u03c2\u200c\u200d])')
_JOINERS = ('\u200c', '\u200d')  # ZWNJ, ZWJ
# UTS #46 maps small Cherokee letters to capital ones (Python's lower() goes the other way,
# and IDNA 2003 knows no small Cherokee letter), so both spellings give the web app's name.
_CHEROKEE_CAPITAL = dict([(0xAB70 + i, 0x13A0 + i) for i in range(0x50)]
                         + [(0x13F8 + i, 0x13F0 + i) for i in range(6)])
_CHEROKEE_RE = re.compile('[\u13a0-\u13f5]')
_VIRAMA = 9  # canonical combining class of a virama (RFC 5892 CONTEXTJ for ZWJ / ZWNJ)


def _idna_label(label: str) -> Optional[str]:
    """One non-ASCII label -> ``xn--`` form, as the web app (``new URL``, UTS #46
    non-transitional) computes it; ``None`` if invalid.

    Python's ``idna`` codec is IDNA 2003: ``straße`` would become ``strasse``, another
    registrable name. A deviation character is kept as it is (ZWJ / ZWNJ only right after
    a virama, so a Persian ZWNJ name needs its ``xn--`` form); the text around it gets the
    codec's nameprep mapping, and the whole label its bidi rule (``ς`` next to a Hebrew
    letter mixes directions). A label may not start with a combining mark either: the web
    app rejects both. Cherokee letters stay capital, as UTS #46 maps them (nameprep lowers
    them with today's Unicode data, so such a label is prepared here, not by the codec).
    """
    label = label.replace('\u1e9e', '\u00df')  # capital sharp s
    label = label.translate(_CHEROKEE_CAPITAL)
    if not label or unicodedata.category(label[0]).startswith('M'):
        return None
    if label.startswith('xn--'):
        return None  # an ACE prefix on a non-ASCII label: refused by the codec and the web app
    try:
        if not _IDN_DEVIATION_RE.search(label) and not _CHEROKEE_RE.search(label):
            return label.encode('idna').decode('ascii').lower()
        out = ''
        for part in _IDN_DEVIATION_RE.split(label):
            if part in _JOINERS:
                if not out or unicodedata.combining(out[-1]) != _VIRAMA:
                    return None
                out += part
            elif part in ('\u00df', '\u03c2'):
                out += part
            elif part:
                out += _idna_codec.nameprep(part).translate(_CHEROKEE_CAPITAL)
        # RFC 3454 section 6, as nameprep checks a label: right-to-left letters rule out
        # left-to-right ones (ß, ς are) and must start and end the label.
        bidi = [unicodedata.bidirectional(char) for char in out]
        if ({'R', 'AL'} & set(bidi)
                and ('L' in bidi or not {bidi[0], bidi[-1]} <= {'R', 'AL'})):
            return None
        return 'xn--' + out.encode('punycode').decode('ascii')
    except UnicodeError:
        return None


def normalize_hostname(value: str, allow_wildcard: bool = False) -> Optional[str]:
    """Lowercase ASCII (punycode) hostname without trailing dot, or ``None`` if invalid.

    Strips scheme, userinfo, path/query/fragment and port. IDN labels are converted like
    the web app does (UTS #46 non-transitional: ``straße`` -> ``xn--strae-oqa``, never
    ``strasse``; see :func:`_idna_label`). ``_`` is allowed in labels. IP literals are
    rejected (``None``), and so are numeric names the system resolver would read as an IPv4 address
    (``2026092401``, ``127.1``, ``0x7f.0x1`` - see :func:`is_numeric_host`).
    ``allow_wildcard`` permits a single leading ``*.`` label.
    """
    text = _host_text(value)
    if not text:
        return None
    wildcard = False
    if text.startswith('*.'):
        if not allow_wildcard:
            return None
        wildcard = True
        text = text[2:]
    # Label separators in UTS #46, mapped as the web app does: after lowercasing (a final
    # sigma before one stays final) and after the wildcard test (``*。`` is no wildcard).
    for dot in _IDEOGRAPHIC_DOTS:
        text = text.replace(dot, '.')
    if text.endswith('.'):
        text = text[:-1]
    if not text or normalize_ip(text) is not None:
        return None
    labels = []
    for label in text.split('.'):
        if not label:
            return None
        if not label.isascii():
            label = _idna_label(label)
            if label is None:
                return None
        if not _LABEL_RE.match(label):
            return None
        labels.append(label)
    host = '.'.join(labels)
    if len(host) > 253 or (wildcard and len(host) > 251):
        return None
    if _numeric_labels(labels):
        return None
    return '*.' + host if wildcard else host


# A label inet_aton-style parsers read as a number: decimal, octal (leading 0) or 0x-hex.
_NUMERIC_LABEL_RE = re.compile(r'^(?:0x[0-9a-f]*|[0-9]+)$')
_IDEOGRAPHIC_DOTS = ('\u3002', '\uff0e', '\uff61')


def _numeric_labels(labels: Sequence[str]) -> bool:
    """Every label is a number (``127.1``, ``0x7f.0x1``), or the last one is all digits.

    RFC 1123 section 2.1: the top-level label of a host name is never numeric.
    """
    if not labels:
        return False
    if all(_NUMERIC_LABEL_RE.match(label) for label in labels):
        return True
    return labels[-1].isascii() and labels[-1].isdigit()


def _legacy_ipv4(text: str) -> Optional[str]:
    """The IPv4 address inet_aton (glibc, Windows) reads ``text`` as, or ``None``.

    1 to 4 parts, each decimal, octal (leading ``0``) or hex (``0x``); the last part
    fills the remaining bytes: ``2130706433`` -> ``127.0.0.1``, ``127.1`` ->
    ``127.0.0.1``, ``0x7f.0x1`` -> ``127.0.0.1``, ``0177.0.0.1`` -> ``127.0.0.1`` (and a
    zone serial such as ``2026092401`` -> a public address in 120.0.0.0/8).
    """
    parts = text.lower().split('.')
    if not 1 <= len(parts) <= 4:
        return None
    values = []
    for part in parts:
        if re.match(r'^0x[0-9a-f]*$', part):
            values.append(int(part[2:] or '0', 16))
        elif re.match(r'^0[0-7]*$', part):
            values.append(int(part, 8))
        elif re.match(r'^[1-9][0-9]*$', part):
            values.append(int(part))
        else:
            return None
    last_bits = 8 * (5 - len(values))
    if any(value > 0xFF for value in values[:-1]) or values[-1] >= 1 << last_bits:
        return None
    number = 0
    for value in values[:-1]:
        number = (number << 8) | value
    number = (number << last_bits) | values[-1]
    return str(ipaddress.IPv4Address(number))


def _numeric_candidate(value: str) -> Optional[str]:
    """``value`` as host text for the numeric test (NFKC, ideographic dots, no wildcard)."""
    text = unicodedata.normalize('NFKC', value)
    for dot in _IDEOGRAPHIC_DOTS:
        text = text.replace(dot, '.')
    host = _host_text(text)
    if host and host.startswith('*.'):
        host = host[2:]
    return host or None


def is_numeric_host(value: str) -> bool:
    """True when ``value`` looks like a hostname but is a number / numeric IPv4 form.

    The system resolver (glibc and Windows ``getaddrinfo``, inet_aton rules) turns
    ``2026092401``, ``127.1``, ``0x7f.0x1`` or ``0177.0.0.1`` into an IPv4 address without
    any DNS lookup - e.g. a zone file's SOA serial would make the scan dial an unrelated
    public address. Such names are never resolved nor used as SNI names. Detected: every
    label is a decimal, octal or ``0x`` hex number, or the last label is all digits
    (RFC 1123 section 2.1). Canonical IP literals (:func:`normalize_ip`) are addresses,
    not hostnames: they return False.
    """
    host = _numeric_candidate(value)
    if not host or normalize_ip(host) is not None:
        return False
    return _numeric_labels(host.split('.'))


def numeric_host_note(value: str) -> str:
    """Why a numeric "hostname" is refused (names the address the resolver would dial)."""
    host = _numeric_candidate(value) or value.strip()
    address = _legacy_ipv4(host)
    if address:
        return ('%s is not a hostname - the system resolver reads it as the IPv4 address %s'
                % (value.strip(), address))
    return '%s is not a hostname - a host name never ends in a numeric label' % value.strip()


def wildcard_matches(pattern: str, host: str) -> bool:
    """RFC 6125 section 6.4.3: ``*`` only as the whole left-most label, matching exactly one label.

    ``*.a.com`` matches ``x.a.com`` but not ``a.com`` or ``x.y.a.com``; partial wildcards
    (``w*.a.com``) and wildcards directly under a single label (``*.com``) never match.
    """
    pattern = pattern.strip().lower().rstrip('.')
    host = host.strip().lower().rstrip('.')
    if not pattern.startswith('*.'):
        return False
    base = pattern[2:]
    if not base or '*' in base or '.' not in base:
        return False
    if '.' not in host:
        return False
    first, rest = host.split('.', 1)
    return bool(first) and '*' not in first and rest == base


def cert_covers(cert_hostnames: Iterable[str], host: str) -> Tuple[bool, Optional[str]]:
    """Whether a certificate with these names is valid for ``host`` -> ``(covered, by)``."""
    host = host.strip().lower().rstrip('.')
    names = [name.strip().lower().rstrip('.') for name in cert_hostnames]
    for name in names:
        if name == host:
            return True, name
    for name in names:
        if wildcard_matches(name, host):
            return True, name
    return False, None


# =====================================================================================
# Inventory parsing (mirrors lib/inventory.js) + CIDR / range expansion + resolution
# =====================================================================================

@dataclass
class Server:
    """One inventory entry: a named machine with one or more IPs."""

    name: str
    ips: List[str] = field(default_factory=list)
    groups: List[str] = field(default_factory=list)
    line: int = 0
    source: str = ''
    hostnames: List[str] = field(default_factory=list)  # to resolve when no IP was given
    # Ports written with an address or host name (203.0.113.10:8443, [2001:db8::1]:8443,
    # web01.example.net:8443): that target is scanned on these ports instead of -p. None
    # stands for the -p ports (the target was also given without a port). A target that is
    # not a key here is scanned on the -p ports only.
    ports: Dict[str, List[Optional[int]]] = field(default_factory=dict)
    # Topology (lib/inventory.js reads the same keys): ports=443,8443 - the TLS ports of the
    # targets written without a port, in place of -p; terminates_tls=no - never gets the
    # certificate, not scanned without --include-backends (None: not given, i.e. yes); vip= -
    # shared addresses (an HA pair); nat= - public addresses it is reachable at; backends= -
    # the servers this one (a load balancer) forwards to, by name.
    tls_ports: List[int] = field(default_factory=list)
    terminates_tls: Optional[bool] = None
    vips: List[str] = field(default_factory=list)
    nats: List[str] = field(default_factory=list)
    backends: List[str] = field(default_factory=list)
    # backends= as written, (name or address, line, source), until link_backends() resolves them
    backend_refs: List[Tuple[str, int, str]] = field(default_factory=list, repr=False,
                                                     compare=False)

    @property
    def id(self) -> str:
        """Stable identifier: the name, else the first IP."""
        return self.name or (self.ips[0] if self.ips else '')

    @property
    def gets_certificate(self) -> bool:
        """False for ``terminates_tls=no``: a backend that never gets the certificate."""
        return self.terminates_tls is not False

    def has_topology(self) -> bool:
        """Whether the inventory gave this server any topology key."""
        return bool(self.tls_ports or self.terminates_tls is not None or self.vips or self.nats
                    or self.backends or self.backend_refs)

    def add_ip(self, ip: str, port: Optional[int] = None) -> None:
        """Add address ``ip``: on ``port``, or on the -p ports when ``port`` is None."""
        self._add_target(self.ips, ip, port)

    def add_hostname(self, host: str, port: Optional[int] = None) -> None:
        """Add a host name to resolve: its addresses get ``port`` (None: the -p ports)."""
        self._add_target(self.hostnames, host, port)

    def _add_target(self, items: List[str], key: str, port: Optional[int]) -> None:
        if key not in items:
            items.append(key)
            if port is not None:
                self.ports[key] = [port]
            return
        spec = self.ports.get(key)
        if spec is None:  # so far on the -p ports only
            if port is not None:
                self.ports[key] = [None, port]
        elif port not in spec:
            spec.append(port)
        elif isinstance(port, ProtocolPort):  # 2525/smtp after 2525: keep what it names
            spec[spec.index(port)] = port

    def port_spec(self, key: str) -> List[Optional[int]]:
        """The ports of address or host name ``key`` (None = the -p ports)."""
        return list(self.ports.get(key, [None]))

    def endpoint_spec(self, key: str) -> List[Optional[int]]:
        """:meth:`port_spec` with the server's own TLS ports (``ports=``) in place of None:
        the ports lib/inventory.js addressTargets() writes ``key`` with (None = -p)."""
        out = []  # type: List[Optional[int]]
        for port in self.ports.get(key, [None]):
            for value in (self.tls_ports if port is None and self.tls_ports else [port]):
                if value not in out:
                    out.append(value)
        return out

    def ports_for(self, ip: str, default: Sequence[int]) -> List[int]:
        """The ports address ``ip`` is scanned on: a port written with the address keeps
        exactly that port; one written without is scanned on the server's ``ports=``, else on
        ``default`` (the -p ports)."""
        default = self.tls_ports or default
        out = []  # type: List[int]
        for port in self.ports.get(ip, [None]):
            for value in (default if port is None else [port]):
                if value not in out:
                    out.append(value)
        return out


@dataclass
class InventoryWarning:
    """A skipped or suspicious inventory line (codes mirror lib/inventory.js, plus RESOLVE)."""

    line: int
    code: str  # NO_IP | INVALID_IP | DUPLICATE_IP | PARSE | TOPOLOGY | RESOLVE
    text: str
    source: str = ''
    # TOPOLOGY: the cause, as lib/inventory.js names it (TOPOLOGY_REASONS): ports,
    # terminatesTls, vip, nat, backends (a malformed value), plainPorts, unknownBackend,
    # selfBackend, conflict, noServer, groupVars, noTermination, vipMixed, cycle,
    # ownedAddress, nearMiss
    reason: str = ''

    def __str__(self) -> str:
        where = self.source or 'targets'
        if self.line:
            where += ':%d' % self.line
        return '%s: %s %s' % (where, self.code, self.text)


@dataclass
class Inventory:
    """Result of :func:`parse_inventory`."""

    servers: List[Server]
    warnings: List[InventoryWarning]
    stats: Dict[str, int]


# Name columns in order of preference (lib/inventory.js NAME_HEADERS, Turkish included,
# then a few CLI extras): 'Display Name,Hostname' takes the host name.
_NAME_HEADERS = (
    'hostname', 'host_name', 'name', 'host', 'server', 'server_name', 'servername', 'sunucu',
    'sunucu_adi', 'sunucu_ismi', 'makine', 'makine_adi', 'host_adi', 'hostadi', 'node',
    'node_name', 'fqdn', 'instance_name', 'instance', 'vm', 'vm_name', 'computer_name',
    'computername', 'device', 'device_name', 'cihaz', 'cihaz_adi', 'ad', 'adi', 'isim', 'label',
    'display_name', 'tag_name', 'inventory_hostname', 'dns_name',
    'vmname', 'machine', 'computer', 'dnsname',
)
_NAME_RANK = {header: rank for rank, header in enumerate(_NAME_HEADERS)}
_GROUP_HEADERS = {'group', 'groups', 'grup', 'gruplar', 'role', 'roles', 'rol', 'env',
                  'environment', 'ortam', 'tag', 'tags', 'etiket', 'etiketler', 'cluster',
                  'project', 'proje', 'site'}
_IP_HEADER_RE = re.compile(
    r'(?:^|_)(?:ip|ips|ip\d+|ipv4|ipv6|ipaddr|ipaddress|ipaddresses|addr|address|addresses'
    r'|adres|adresi|adresleri|ansible_host|ansible_ssh_host)(?:_|$)')
# Address columns that are not the server's own (lib/inventory.js IP_KEY_EXCLUDE_RE):
# gateway, DNS / NTP servers, iLO / iDRAC / IPMI / BMC, MAC, e-mail, URLs.
_IP_HEADER_EXCLUDE_RE = re.compile(
    r'(?:^|_)(?:mac|e?mail|eposta|url|uri|link|web|website|site|gateway|gw|netmask|mask'
    r'|subnet|dns|ilo|idrac|ipmi|bmc|ntp)(?:_|$)')
_IP_KEYS = {'ansible_host', 'ansible_ssh_host', 'host', 'ip', 'ip_address', 'address', 'ipv4',
            'ipv6'}
_JSON_NAME_KEYS = ('name', 'hostname', 'host', 'Name', 'Hostname', 'HostName', 'server',
                   'fqdn', 'inventory_hostname')
_JSON_SKIP_KEY_RE = re.compile(r'mask|gateway|(?:^|_)gw$|dns|broadcast|subnet|cidr|route',
                               re.I)
_IPV4_LIKE_RE = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
_IPV6_LIKE_RE = re.compile(r'^\[?[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,}(%\w+)?\]?$')
_TARGET_FILE_EXT_RE = re.compile(
    r'\.(txt|csv|tsv|ini|json|ya?ml|lst|list|conf|cfg|inv|hosts|pem|crt|cer|der)$', re.I)


def _normalize_header(value: str) -> str:
    """Snake-case a header/key like lib/inventory.js ``normalizeKey``: ``'Public IP'``,
    ``'PublicIp'`` -> ``'public_ip'``; accents and dotless i folded (``'Sunucu Adı'`` ->
    ``'sunucu_adi'``, ``'İP'`` -> ``'ip'``)."""
    value = re.sub(r'(?<=[a-z0-9])(?=[A-Z])', '_', value.strip())
    value = ''.join(char for char in unicodedata.normalize('NFD', value)
                    if not unicodedata.combining(char)).replace('ı', 'i')
    return re.sub(r'[^a-z0-9]+', '_', value.lower()).strip('_')


def _is_ip_header(header: str) -> bool:
    """A (normalized) column header that holds the server's own IPs (``ip``, ``public_ip``,
    ``ip_adresi``), not a gateway / DNS / BMC / MAC / e-mail column."""
    return (bool(header) and not _IP_HEADER_EXCLUDE_RE.search(header)
            and bool(_IP_HEADER_RE.search(header)))


def _is_host_word(token: str) -> bool:
    """A word no heading has: a dot or a digit group other than ``ip2`` / ``ipv4`` / ``ipv6``
    (``ip-10-0-1-23.ec2.internal``, ``ipv6.example.com``, ``web01``) makes it a host name."""
    return '.' in token or any(re.search(r'\d', part) and not re.match(r'^ipv?\d+$', part)
                               for part in _normalize_header(token).split('_'))


def _is_header_like(tokens: Sequence[str]) -> bool:
    """A plain line that is a column heading (``hostname   ip``), as lib/inventory.js skips.

    Only a line of two or more words, none of them host-like (:func:`_is_host_word`). The
    web app also skips a lone ``hostname`` or ``ip``; here a lone word (``node``, ``vm``)
    is a server to resolve, since dropping it would lose a server without a word.
    """
    if len(tokens) < 2 or any(_is_host_word(token) for token in tokens):
        return False
    keys = [_normalize_header(token) for token in tokens]
    return (any(_is_ip_header(key) for key in keys)
            and any(key in _NAME_RANK or key in _GROUP_HEADERS for key in keys))


def _looks_like_ip(token: str) -> bool:
    return bool(_IPV4_LIKE_RE.match(token) or _IPV6_LIKE_RE.match(token))


def _is_comment(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith(('#', ';', '//'))


def _strip_comment(line: str) -> str:
    """Remove full-line (#, ;, //) and inline (`` #``, `` //``) comments."""
    if _is_comment(line):
        return ''
    return re.split(r'\s(?:#|//)', line, maxsplit=1)[0].strip()


# Topology keys (lib/inventory.js TOPOLOGY_KEYS), read in every inventory format: where TLS
# really terminates. Keys are compared after _normalize_header (Terminates-TLS, terminatesTls).
# In JSON / YAML only tls_ports gives TLS ports: a `ports` key there (Shodan, an Ansible var) is
# read as before.
TOPOLOGY_KEYS = ('ports', 'tls_ports', 'terminates_tls', 'vip', 'backends', 'nat')
_PORTS_KEYS = ('ports', 'tls_ports')
_TOPOLOGY_MALFORMED = {'ports': 'ports', 'tls_ports': 'ports', 'terminates_tls': 'terminatesTls',
                       'vip': 'vip', 'nat': 'nat', 'backends': 'backends'}
# Ports that carry no TLS the scan can reach: kept in a ports= list, warned about. The ports
# PORT_PROTOCOLS names (21, 25, 110, 143, 389, 587, 3389, 5222, 5432) are scanned through their
# protocol (STARTTLS, RDP's negotiation).
_PLAIN_PORTS = frozenset((20, 22, 23, 53, 80, 119, 3306, 6379, 8080, 27017))
_TOPOLOGY_HELP = {
    'ports': 'ports= takes TLS ports 1-65535, comma separated (ports=443,8443)',
    'tls_ports': 'tls_ports= takes TLS ports 1-65535, comma separated (tls_ports=443,8443)',
    'terminates_tls': 'terminates_tls= takes yes or no',
    'vip': 'vip= takes IP addresses without a port',
    'nat': 'nat= takes IP addresses without a port',
    'backends': 'backends= takes server names (or their addresses), comma separated',
}
# Keys a letter off one, on a line or as a CSV header: a 'nearMiss' warning, never read
_NEAR_MISS = {'backend': 'backends', 'port': 'ports', 'tls_port': 'tls_ports', 'vips': 'vip',
              'nats': 'nat', 'terminate_tls': 'terminates_tls', 'terminatestls': 'terminates_tls',
              'terminates_ssl': 'terminates_tls', 'terminate_ssl': 'terminates_tls'}
_TLS_YES = ('yes', 'true', 'on', '1')
_TLS_NO = ('no', 'false', 'off', '0')
# key=value on a line: the value runs to the next space; a ';' or '|' in it continues it
# (ports=443;8443) unless the next key= follows (ports=443;terminates_tls=no)
_TOPOLOGY_TOKEN_RE = re.compile(
    r'(^|[\s,;|])([A-Za-z][A-Za-z0-9_.-]*)=("[^"]*"|\'[^\']*\'|'
    r'(?:[^\s;|"\']|[;|](?![A-Za-z][A-Za-z0-9_.-]*=)(?=[^\s;|"\']))*)')
_QUOTED_RE = re.compile(r'^(["\'])(.*)\1$', re.S)

TopologyValue = Tuple[str, Any, str, int]   # (key, value, raw, line)


def _topology_key(key: Any, structured: bool = False) -> Optional[str]:
    """The topology key ``key`` is (normalised), or None; ``structured`` (JSON / YAML): ``ports``
    is none there, ``tls_ports`` is."""
    normalized = _normalize_header(str(key))
    if normalized not in TOPOLOGY_KEYS or (structured and normalized == 'ports'):
        return None
    return normalized


def _unquote(text: Any) -> str:
    text = str(text).strip()
    match = _QUOTED_RE.match(text)
    return (match.group(2) if match else text).strip()


def _topology_items(value: Any, structured: bool = False) -> Optional[List[str]]:
    """The items of a topology value: a string, a number, a boolean (yes / no) or a list of
    those; None for anything else (an object, a list holding one: ``ports: [{containerPort:
    80}]``), which is then read as before. A line's value splits on whitespace, ',', ';' and
    '|'; a ``structured`` one (JSON / YAML, a CSV cell) on ',' and ';' only, so a name may hold
    spaces (an AWS Name tag). Mirrors lib/inventory.js topologyItems()."""
    if value is None:
        return []
    if isinstance(value, bool):
        return ['yes' if value else 'no']
    if isinstance(value, int):
        return [str(value)]
    if isinstance(value, float):
        return [str(int(value)) if value.is_integer() else str(value)]
    if isinstance(value, str):
        pattern = r'[,;]+' if structured else r'[\s,;|]+'
        return [item for item in (_unquote(v) for v in re.split(pattern, _unquote(value))) if item]
    if isinstance(value, list):
        out = []  # type: List[str]
        for item in value:
            if isinstance(item, (dict, list)):
                return None
            out.extend(_topology_items(item, structured) or [])
        return out
    return None


def _topology_address(item: str) -> Optional[str]:
    """An address of vip= / nat= / backends=: bare (a /32 or /128 is fine), never with a port."""
    if re.match(r'^\d{1,3}(?:\.\d{1,3}){3}:', item) or ']:' in item:
        return None
    text = re.sub(r'["\'`)>},;]+$', '', re.sub(r'^["\'`(<{]+', '', item.strip()))
    if not text or len(text) > 64:
        return None
    if text.endswith('.') and ':' not in text:
        text = text[:-1]
    match = re.match(r'^([^/]+)/(\d{1,3})$', text)
    if match:
        ip = normalize_ip(match.group(1))
        return ip if ip and int(match.group(2)) == (128 if ':' in ip else 32) else None
    return normalize_ip(text)


def _topology_value(key: str, items: Sequence[str]) -> Any:
    """The value of topology ``key`` from its items, or None when it is malformed (no item; a
    port that is not 1-65535; terminates_tls other than one yes / no / true / false / on /
    off / 1 / 0; a vip / nat that is not one address without a port; a backend meant as an
    address that is none). Mirrors lib/inventory.js topologyValue()."""
    if not items:
        return None
    if key == 'terminates_tls':
        word = items[0].lower() if len(items) == 1 else ''
        return True if word in _TLS_YES else False if word in _TLS_NO else None
    out = []  # type: List[Any]
    for item in items:
        if key in _PORTS_KEYS:
            if not (item.isascii() and item.isdigit() and 1 <= int(item) <= 65535):
                return None
            value = int(item)  # type: Any
        elif key in ('vip', 'nat'):
            value = _topology_address(item)
            if value is None:
                return None
        else:
            value = _topology_address(item)
            if value is None and (_looks_like_ip(item) or _ENDPOINT_V4_RE.match(item)
                                  or _BRACKETED_ADDRESS_RE.match(item)):
                return None
            value = value or item
        if all(str(x).lower() != str(value).lower() for x in out):
            out.append(value)
    return out


def _split_topology(line: str) -> Tuple[str, List[Tuple[str, str]], List[str]]:
    """Take the topology ``key=value`` tokens out of a line before it is split on commas
    (``ports=443,8443`` is one value): the rest of the line, each (key, raw value) and the
    warning text of each key a letter off one (``backend=``), which is left in the line."""
    found = []  # type: List[Tuple[str, str]]
    near = []  # type: List[str]

    def take(match: Any) -> str:
        key = _topology_key(match.group(2))
        if key is None:
            guess = _NEAR_MISS.get(_normalize_header(match.group(2)))
            if guess:
                near.append('%s=%s is no topology key - did you mean %s=? It is not read'
                            % (match.group(2), _unquote(match.group(3)), guess))
            return match.group(0)
        found.append((key, match.group(3)))
        return match.group(1) + ' '

    rest = _TOPOLOGY_TOKEN_RE.sub(take, line)
    return (rest if found else line), found, near


def is_ip_block(token: str) -> bool:
    """Cheap syntax check: is ``token`` a CIDR or an IP range (without expanding it)?"""
    token = token.strip()
    if '/' in token:
        return _parse_network(token) is not None
    if '-' in token:
        start_text, end_text = token.split('-', 1)
        start = normalize_ip(start_text)
        if start is None:
            return False
        return normalize_ip(end_text) is not None or (end_text.isdigit() and '.' in start)
    return False


def expand_ip_block(token: str, allow_large: bool = False) -> Optional[List[str]]:
    """Expand ``a.b.c.d/nn`` or ``first-last`` (``10.0.0.5-10.0.0.9`` or ``10.0.0.5-9``).

    Returns ``None`` when ``token`` is not a CIDR/range. Network and broadcast addresses
    of IPv4 networks larger than /31 are skipped. Raises :class:`UsageError` for blocks
    with more than 65536 addresses unless ``allow_large`` (hard cap 1,048,576).
    """
    token = token.strip()
    if '/' in token:
        network = _parse_network(token)
        if network is None:
            return None
        _check_block_size(token, network.num_addresses, allow_large)
        if network.num_addresses == 1:
            return [_ip_text(network.network_address)]
        return [_ip_text(host) for host in network.hosts()]
    if '-' in token:
        start_text, end_text = token.split('-', 1)
        start = normalize_ip(start_text)
        if start is None:
            return None
        end = normalize_ip(end_text)
        if end is None and end_text.isdigit() and '.' in start:
            end = normalize_ip(start.rsplit('.', 1)[0] + '.' + end_text)  # 10.0.0.5-9
        if end is None:
            return None
        first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
        if first.version != last.version or int(last) < int(first):
            raise UsageError('invalid IP range %r' % token)
        _check_block_size(token, int(last) - int(first) + 1, allow_large)
        cls = type(first)
        return [_ip_text(cls(value)) for value in range(int(first), int(last) + 1)]
    return None


def _malformed_ip_block(token: str) -> bool:
    """An IP address followed by a broken range end or prefix: ``10.0.0.5-300``,
    ``10.0.0.5-9x``, ``10.0.0.5-09``, ``10.0.0.0/33``.

    Such typos are valid LDH names, so without this check they would go to the resolver
    (and a search domain could even answer). A name whose last label or range end starts
    with a letter (``10.0.0.5-web.example.com``, ``192.0.2.1-db``) is a host name.
    """
    token = token.strip()
    head = re.split(r'[/-]', token, maxsplit=1)[0]
    if head == token or normalize_ip(head) is None:
        return False
    if re.match(r'[a-z]', token.rsplit('.', 1)[-1], re.I):
        return False
    if token[len(head)] == '/':
        return _parse_network(token) is None
    end_text = token[len(head) + 1:]
    if ':' not in head and re.match(r'[a-z]', end_text, re.I):
        return False  # 10.0.0.5-web: a short host name, not a range with a typo
    if normalize_ip(end_text) is not None:
        return False
    if end_text.isdigit() and '.' in head:  # 10.0.0.5-9, as expand_ip_block reads it
        return normalize_ip(head.rsplit('.', 1)[0] + '.' + end_text) is None
    return True


def _malformed_block_error(token: str, block: str) -> str:
    if '/' in block:
        return 'invalid target %r: not a valid CIDR (write e.g. 192.0.2.0/24)' % token
    return ('invalid target %r: not a valid IP range (write 192.0.2.5-192.0.2.9 or '
            '192.0.2.5-9)' % token)


def _ip_text(addr: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]) -> str:
    if isinstance(addr, ipaddress.IPv6Address):
        return _format_ipv6(addr)
    return str(addr)


def _check_block_size(token: str, count: int, allow_large: bool) -> None:
    if count > CIDR_HARD_LIMIT:
        raise UsageError('%s has %d addresses; the maximum is %d (a /12) even with --allow-large'
                         % (token, count, CIDR_HARD_LIMIT))
    if count > CIDR_LIMIT and not allow_large:
        raise UsageError('%s has %d addresses (more than a /16); pass --allow-large to scan it'
                         % (token, count))


# A target with its own port, as lib/inventory.js reads one: an IPv4 address or a host name
# followed by ":port", or a bracketed IPv6 (or IPv4) address with an optional ":port". An
# empty port ("203.0.113.10:", "ip: name" lines) means none. An IPv6 address needs the
# brackets: 2001:db8::1:8443 is itself a valid address.
_ENDPOINT_BRACKET_RE = re.compile(r'^\[([^\[\]\s:]*:[^\[\]\s]*|\d{1,3}(?:\.\d{1,3}){3})\]'
                                  r'(?::(.*))?$')
_ENDPOINT_V4_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3}):(.*)$')
_ENDPOINT_HOST_RE = re.compile(r'^([^\s:\[\]@=]+):(\d+)$')
# A token that starts as a bracketed address but is no [ADDRESS] / [ADDRESS]:PORT form
# ("[2001:db8::1]8443"): meant as an address, so a warning rather than a word to skip.
_BRACKETED_ADDRESS_RE = re.compile(
    r'^\[(?:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*|\d{1,3}(?:\.\d{1,3}){3})(?:%[^\]\s]*)?\]')
# A time of day in a free-form line ("backup 10:30 203.0.113.10"): neither a host and its port
# nor an IPv6 address (lib/inventory.js looksLikeIp skips it the same way).
_CLOCK_RE = re.compile(r'^\d{1,2}:\d{2}(?::\d{2})?$')


def _endpoint_port(text: Optional[str]) -> Optional[int]:
    if not text:
        return None
    if not text.isascii() or not text.isdigit():
        raise ValueError('%r is not a port number' % text)
    port = int(text)
    if not 1 <= port <= 65535:
        raise ValueError('port %s is outside 1-65535' % text)
    return port


def split_endpoint(token: str) -> Optional[Tuple[str, Optional[int]]]:
    """``203.0.113.10:8443`` -> ``('203.0.113.10', 8443)``; ``None`` when ``token`` is no
    ``target:port`` form at all.

    Also ``[2001:db8::1]:8443`` (the address canonical) and ``web01.example.net:8443`` (the
    host text as written, validated by the caller). An empty port gives ``(target, None)``.
    Raises ``ValueError`` for such a form that cannot be used: a port outside 1-65535 or not
    a number, a bracketed text or dotted quad that is no IP address, a bracketed address
    with a zone id and a port (``[fe80::1%eth0]:8443``) or with text after it that is no
    port (``[2001:db8::1]8443``), or a CIDR / range with a port - the caller warns about it
    instead of dropping it silently.
    """
    token = token.strip()
    match = _ENDPOINT_BRACKET_RE.match(token) or _ENDPOINT_V4_RE.match(token)
    if match:
        ip = normalize_ip(match.group(1))
        if ip is None:
            raise ValueError('%s is not a valid IP address' % match.group(1))
        if match.group(2) and '%' in match.group(1):
            # normalize_ip drops the zone, and a link-local address is unreachable without it
            raise ValueError('an IPv6 zone id (%%%s) is not supported in a target'
                             % match.group(1).split('%', 1)[1])
        return ip, _endpoint_port(match.group(2))
    if _BRACKETED_ADDRESS_RE.match(token):
        raise ValueError('expected [ADDRESS] or [ADDRESS]:PORT')
    match = _ENDPOINT_HOST_RE.match(token)
    if match is None:
        return None
    target = match.group(1)
    if '/' in target or is_ip_block(target) or _malformed_ip_block(target):
        raise ValueError('a CIDR or IP range takes no port; scan it with -p')
    return target, _endpoint_port(match.group(2))


def format_endpoint(ip: str, port: Optional[int]) -> str:
    """``203.0.113.10:8443`` / ``[2001:db8::1]:8443``, or the bare address without a port."""
    if port is None:
        return ip
    return '[%s]:%d' % (ip, port) if ':' in ip else '%s:%d' % (ip, port)


def endpoint_text(ip: str, port: int, protocol: str = PROTO_TLS) -> str:
    """``203.0.113.10:443``, ``203.0.113.25:25/smtp``: :func:`format_endpoint` with the
    protocol spoken before TLS, as a -t target writes it (none for TLS)."""
    text = format_endpoint(ip, port)
    return text if protocol == PROTO_TLS else '%s/%s' % (text, protocol)


def _bad_port(text: str) -> Optional[str]:
    """Why ``text``, an IP address written with a port, cannot be used (``203.0.113.10:99999``,
    ``[fe80::1%eth0]:8443``); None for anything else, a good endpoint included."""
    text = text.strip()
    match = _ENDPOINT_BRACKET_RE.match(text) or _ENDPOINT_V4_RE.match(text)
    if match is None or normalize_ip(match.group(1)) is None:
        return None
    try:
        split_endpoint(text)
    except ValueError as exc:
        return str(exc)
    return None


def _address_token(text: str) -> Optional[str]:
    """An IP address (``ip``) or address with a port (``ip:port``), canonical; else None."""
    ip = normalize_ip(text)
    if ip is not None:
        return ip
    try:
        endpoint = split_endpoint(text)
    except ValueError:
        return None
    if endpoint is None or normalize_ip(endpoint[0]) is None:
        return None
    return format_endpoint(endpoint[0], endpoint[1])


TargetItem = Union[str, Tuple[str, Optional[int]]]


def _target_item(item: TargetItem) -> Tuple[str, Optional[int]]:
    """An address / host name of a server, with its own port (None: the -p ports)."""
    return (item, None) if isinstance(item, str) else item


class _InventoryBuilder:
    """Collects servers, merging entries that share a name (case-insensitive)."""

    def __init__(self, source: str = '', allow_large: bool = False) -> None:
        self.source = source
        self.allow_large = allow_large
        self.servers = {}  # type: Dict[str, Server]
        self.warnings = []  # type: List[InventoryWarning]
        self.unnamed = set()  # type: Set[str]  # servers an address-only line named

    def warn(self, line: int, code: str, text: str, reason: str = '') -> None:
        """Record an :class:`InventoryWarning` for ``line``."""
        self.warnings.append(InventoryWarning(line, code, text, self.source, reason))

    def read_topology(self, key: str, items: Optional[Sequence[str]], raw: str,
                      line: int) -> Optional[TopologyValue]:
        """One topology key read, or None after a TOPOLOGY warning for a malformed value."""
        value = _topology_value(key, items or [])
        if value is None:
            self.warn(line, 'TOPOLOGY', '%s=%s: %s' % (key, raw, _TOPOLOGY_HELP[key]),
                      _TOPOLOGY_MALFORMED[key])
            return None
        plain = [str(port) for port in value if port in _PLAIN_PORTS] if key in _PORTS_KEYS else []
        if plain:
            self.warn(line, 'TOPOLOGY', '%s=%s: %s usually carry no TLS - the server is scanned on '
                      'these ports instead of -p' % (key, raw, ', '.join(plain)), 'plainPorts')
        return key, value, raw, line

    def line_topology(self, found: Sequence[Tuple[str, str]], line: int,
                      structured: bool = False) -> List[TopologyValue]:
        """The topology of one line or CSV row (``structured``; malformed values warned about)."""
        out = []  # type: List[TopologyValue]
        for key, raw in found:
            value = self.read_topology(key, _topology_items(raw, structured), _unquote(raw), line)
            if value is not None:
                out.append(value)
        return out

    def apply_topology(self, server: Server, topology: Sequence[TopologyValue]) -> None:
        """Merge a line's topology into ``server``: ports, VIPs, NAT addresses and backends add
        up; terminates_tls given both ways is a 'conflict' and yes, the safe value."""
        for key, value, raw, line in topology:
            if key == 'terminates_tls':
                if server.terminates_tls is not None and server.terminates_tls != value:
                    self.warn(line, 'TOPOLOGY', _conflict_text(raw, server.name,
                                                               server.terminates_tls), 'conflict')
                    server.terminates_tls = True
                else:
                    server.terminates_tls = value
                continue
            if key == 'backends':
                server.backend_refs.extend((ref, line, self.source) for ref in value)
                continue
            target = {'ports': server.tls_ports, 'tls_ports': server.tls_ports, 'vip': server.vips,
                      'nat': server.nats}[key]
            for item in value:
                if item not in target:
                    target.append(item)

    def add(self, name: Optional[str], ips: Sequence[TargetItem], line: int,
            groups: Sequence[str] = (), hostnames: Sequence[TargetItem] = ()
            ) -> Optional[Server]:
        """Add (or merge into) server ``name``; unscannable IPs become warnings.

        An address or host name may come with its own port as an ``(target, port)`` pair.
        Returns the server (None when nothing was added).
        """
        usable = []  # type: List[Tuple[str, Optional[int]]]
        for item in ips:
            ip, port = _target_item(item)
            reason = _unscannable_reason(ip)
            if reason is None:
                usable.append((ip, port))
            else:
                self.warn(line, 'INVALID_IP', '%s is not scannable (%s)' % (ip, reason))
        hosts = [_target_item(item) for item in hostnames]
        if not usable and not hosts:
            if ips:
                return None
            self.warn(line, 'NO_IP', name or '')
            return None
        given = (name or '').strip()
        name = given or (usable[0][0] if usable else hosts[0][0])
        key = name.lower()
        server = self.servers.get(key)
        if server is None:
            server = Server(name=name, line=line, source=self.source)
            self.servers[key] = server
            if not given:
                self.unnamed.add(key)
        for ip, port in usable:
            server.add_ip(ip, port)
        for group in groups:
            if group and group not in server.groups:
                server.groups.append(group)
        for host, port in hosts:
            server.add_hostname(host, port)
        return server

    def add_hostname(self, name: str, line: int, groups: Sequence[str] = (),
                     fallback: Optional[str] = None) -> List[Server]:
        """Add a server known only by ``name`` (resolved later), or warn why it cannot be.

        A numeric name (``2026092401``, ``127.1``) is an INVALID_IP, never resolved;
        anything else that is not a hostname is NO_IP (text: ``fallback`` or the name).
        ``web01.example.net:8443`` or ``203.0.113.10:8443`` keeps its port. Returns the
        servers added to.
        """
        try:
            endpoint = split_endpoint(name)
        except ValueError as exc:
            self.warn(line, 'INVALID_IP', '%s (%s)' % (name, exc))
            return []
        if endpoint is not None:
            return self.add_token_values(None, [name], line, groups)
        if _malformed_ip_block(name):  # 10.0.0.5-300: a typo'd range, not a host to resolve
            self.warn(line, 'INVALID_IP', name)
            return []
        host = normalize_hostname(name)
        if host:
            server = self.add(name, [], line, groups, [host])
            return [server] if server is not None else []
        if is_numeric_host(name):
            self.warn(line, 'INVALID_IP', numeric_host_note(name))
        else:
            self.warn(line, 'NO_IP', name if fallback is None else fallback)
        return []

    def add_token_values(self, name: Optional[str], values: Sequence[str], line: int,
                         groups: Sequence[str] = ()) -> List[Server]:
        """Add ``name`` with IPs / hostnames / CIDRs taken from free-form ``values``.

        An address or host name written with a port (``203.0.113.10:8443``,
        ``[2001:db8::1]:8443``, ``web01.example.net:8443``) keeps it; one whose port or
        address cannot be read is an INVALID_IP warning, never dropped silently. Host names
        are resolved only when the entry has no address; there, one without a port is a
        hosts-file alias, but one with a port (``web01 203.0.113.10 db.example.net:5432``)
        was meant as a target, so it is a PARSE warning, as lib/inventory.js has it.
        Returns the servers added to (one per address of a CIDR / range).
        """
        ips, hosts = [], []  # type: List[TargetItem], List[TargetItem]
        ported = []  # type: List[str]
        touched = []  # type: List[Server]
        for value in values:
            value = value.strip().strip('\'"')
            if not value:
                continue
            ip = normalize_ip(value)
            if ip:
                ips.append(ip)
                continue
            block = expand_ip_block(value, self.allow_large)
            if block is not None:
                for block_ip in block:
                    server = self.add(block_ip, [block_ip], line,
                                      list(groups) + ([name] if name else []))
                    if server is not None:
                        touched.append(server)
                continue
            try:
                endpoint = split_endpoint(value)
            except ValueError as exc:
                self.warn(line, 'INVALID_IP', '%s (%s)' % (value, exc))
                continue
            if endpoint is not None:
                target, port = endpoint
                ip = normalize_ip(target)
                host = None if ip or is_numeric_host(target) else normalize_hostname(target)
                if ip:
                    ips.append((ip, port))
                elif host:
                    hosts.append((host, port))
                    if port is not None:
                        ported.append(value)
                elif is_numeric_host(target):
                    self.warn(line, 'INVALID_IP', numeric_host_note(target))
                else:
                    self.warn(line, 'PARSE', value)
                continue
            if _looks_like_ip(value) or _malformed_ip_block(value):
                self.warn(line, 'INVALID_IP', value)
                continue
            if is_numeric_host(value):
                self.warn(line, 'INVALID_IP', numeric_host_note(value))
                continue
            if '@' in value and '://' not in value:
                # an e-mail address: its domain is the mail provider, not this server
                self.warn(line, 'PARSE', value)
                continue
            host = normalize_hostname(value)
            if host:
                hosts.append(host)
            else:
                self.warn(line, 'PARSE', value)
        if ips:
            for value in ported:
                self.warn(line, 'PARSE', '%s: a host name with a port next to an address is not '
                          'resolved - write the address with the port (ADDRESS:PORT); ignored'
                          % value)
        if ips or hosts:
            server = self.add(name, ips, line, groups, [] if ips else hosts)
            if server is not None:
                touched.append(server)
        return touched

    def merge_unnamed(self) -> None:
        """An address-only line with topology keys whose addresses all belong to named servers
        (``10.0.0.1 terminates_tls=no`` next to ``web01 10.0.0.1``, in either order) gives its
        keys and ports to those servers, as lib/inventory.js does, rather than standing as a
        second server with a DUPLICATE_IP warning. Without keys it stays as before."""
        owners = {}  # type: Dict[str, List[Server]]
        for key, server in self.servers.items():
            if key not in self.unnamed:
                for ip in server.ips:
                    owners.setdefault(ip, []).append(server)
        for key in sorted(self.unnamed, key=lambda k: self.servers[k].line):
            server = self.servers[key]
            if not server.has_topology() or not server.ips or server.hostnames \
                    or not all(ip in owners for ip in server.ips):
                continue
            for owner in {id(o): o for ip in server.ips for o in owners[ip]}.values():
                for ip in server.ips:
                    if ip in owner.ips:
                        for port in server.port_spec(ip):
                            owner.add_ip(ip, port)
                if server.terminates_tls is not None:
                    if owner.terminates_tls is not None and owner.terminates_tls != server.terminates_tls:
                        self.warn(server.line, 'TOPOLOGY', _conflict_text(
                            'yes' if server.terminates_tls else 'no', owner.name, owner.terminates_tls),
                            'conflict')
                        owner.terminates_tls = True
                    else:
                        owner.terminates_tls = server.terminates_tls
                for mine, theirs in ((server.tls_ports, owner.tls_ports), (server.vips, owner.vips),
                                     (server.nats, owner.nats)):
                    theirs.extend(item for item in mine if item not in theirs)
                owner.backend_refs.extend(server.backend_refs)
            del self.servers[key]
        self.unnamed = set()

    def result(self, line_count: int, link: bool = True) -> Inventory:
        """Finish: resolve ``backends=`` (unless ``link`` is False: :func:`load_targets` does
        it over every source), flag endpoints shared by several servers and compute stats.

        An endpoint is an address on its own port (or on the server's ``ports=``), or bare
        (the -p ports): one address on different ports (``web01 203.0.113.10:8443``,
        ``web02 203.0.113.10:9443``, a NAT forwarding each port to another machine) is no
        duplicate, as in lib/inventory.js. A shared address in ``vip=`` is none either.
        """
        self.merge_unnamed()
        servers = list(self.servers.values())
        if link:
            self.warnings.extend(link_backends(servers))
            self.warnings.extend(topology_checks(servers))
        seen = {}  # type: Dict[str, str]
        for server in servers:
            warned = set()  # type: Set[str]
            for ip in server.ips:
                for port in server.endpoint_spec(ip):
                    endpoint = format_endpoint(ip, port)
                    owner = seen.setdefault(endpoint, server.name)
                    if owner != server.name and ip not in warned:
                        warned.add(ip)
                        self.warn(server.line, 'DUPLICATE_IP', '%s is listed for %s and %s'
                                  % (endpoint, owner, server.name))
        stats = {'lines': line_count, 'servers': len(servers),
                 'ips': len({ip for server in servers for ip in server.ips})}
        return Inventory(servers, self.warnings, stats)


def link_backends(servers: Sequence[Server]) -> List[InventoryWarning]:
    """Resolve each server's ``backends=`` (:attr:`Server.backend_refs`) to the names of other
    servers, as lib/inventory.js does: by name (case-insensitive; a server known only by a host
    name to resolve included), else an address one of them has. A name no server has is an
    'unknownBackend', the server itself a 'selfBackend' TOPOLOGY warning."""
    by_name = {server.name.lower(): server for server in servers}
    warnings = []  # type: List[InventoryWarning]
    for server in servers:
        if not server.backend_refs:
            continue
        out = list(server.backends)
        for ref, line, source in server.backend_refs:
            named = by_name.get(str(ref).lower())
            ip = None if named is not None else normalize_ip(str(ref))
            targets = [named] if named is not None else (
                [s for s in servers if ip in s.ips] if ip else [])
            if not targets:
                warnings.append(InventoryWarning(
                    line, 'TOPOLOGY', 'backends=%s on %s: no server of that name or address in '
                    'the inventory' % (ref, server.name), source, 'unknownBackend'))
                continue
            for target in targets:
                if target is server:
                    warnings.append(InventoryWarning(
                        line, 'TOPOLOGY', 'backends=%s: %s cannot be its own backend'
                        % (ref, server.name), source, 'selfBackend'))
                elif target.name not in out:
                    out.append(target.name)
        server.backends = out
        server.backend_refs = []
    return warnings


def _terminates_behind(server: Server, by_name: Dict[str, Server]) -> bool:
    """Whether a server behind ``server`` terminates TLS, through every passthrough
    (terminates_tls=no) tier of load balancers; ``by_name`` is keyed by the lower-case name."""
    seen, queue = {server.name.lower()}, [server]
    while queue:
        for name in queue.pop(0).backends:
            backend = by_name.get(name.lower())
            if backend is None or backend.name.lower() in seen:
                continue
            seen.add(backend.name.lower())
            if backend.gets_certificate:
                return True
            queue.append(backend)
    return False


def servers_set_aside(servers: Sequence[Server]) -> List[Server]:
    """The servers a scan leaves out without --include-backends: those with terminates_tls=no
    (a plain-HTTP backend, a load balancer passing TLS through), except a load balancer with no
    server behind it terminating TLS: TLS would terminate nowhere, so the inventory is wrong
    somewhere and the scan shows what answers there (erring toward the certificate)."""
    by_name = {server.name.lower(): server for server in servers}
    return [server for server in servers if not server.gets_certificate
            and not (server.backends and not _terminates_behind(server, by_name))]


def topology_checks(servers: Sequence[Server]) -> List[InventoryWarning]:
    """Checks over the linked inventory (lib/inventory.js topologyChecks alike): a load balancer
    that passes TLS through (terminates_tls=no) with no backend terminating it is a
    'noTermination' TOPOLOGY warning; the holders of one VIP that disagree on terminates_tls a
    'vipMixed' one (on the first holder saying no); a server its backends lead back to a
    'cycle'; a vip= / nat= that is a server's own address an 'ownedAddress' one."""
    by_name = {server.name.lower(): server for server in servers}
    warnings = []  # type: List[InventoryWarning]
    for server in servers:
        if not server.gets_certificate and server.backends \
                and not _terminates_behind(server, by_name):
            warnings.append(InventoryWarning(
                server.line, 'TOPOLOGY', '%s passes TLS through (terminates_tls=no), but no backend '
                'behind it terminates TLS - check the inventory' % server.name, server.source,
                'noTermination'))
    holders = {}  # type: Dict[str, List[Server]]
    for server in servers:
        for vip in server.vips:
            holders.setdefault(vip, []).append(server)
    for vip, held in holders.items():
        off = [server for server in held if not server.gets_certificate]
        if off and len(off) < len(held):
            warnings.append(InventoryWarning(
                off[0].line, 'TOPOLOGY', 'vip=%s: %s say terminates_tls=no, %s do not - the holders '
                'of one VIP disagree: check the inventory' % (
                    vip, ', '.join(s.name for s in off),
                    ', '.join(s.name for s in held if s.gets_certificate)), off[0].source, 'vipMixed'))
    owner = {}  # type: Dict[str, str]
    for server in servers:
        for ip in server.ips:
            owner.setdefault(ip, server.name)
        start = server.name.lower()
        prev = {}  # type: Dict[str, str]
        queue = [start]
        while queue and start not in prev:
            name = queue.pop(0)
            for backend in (by_name[name].backends if name in by_name else []):
                if backend.lower() not in prev:
                    prev[backend.lower()] = name
                    queue.append(backend.lower())
        if start in prev:
            loop, name = [start], prev[start]
            while name != start:
                loop.insert(0, name)
                name = prev[name]
            warnings.append(InventoryWarning(
                server.line, 'TOPOLOGY', '%s: its backends lead back to it (%s) - a load balancer '
                'cannot sit behind itself: check the inventory' % (server.name, ' -> '.join(
                    by_name[n].name for n in [start] + loop)), server.source, 'cycle'))
    for server in servers:
        for key, ips in (('vip', server.vips), ('nat', server.nats)):
            for ip in ips:
                if ip in owner:
                    warnings.append(InventoryWarning(
                        server.line, 'TOPOLOGY', '%s=%s on %s is also the own address of %s - which '
                        'server answers there is unclear: check the inventory'
                        % (key, ip, server.name, owner[ip]), server.source, 'ownedAddress'))
    return warnings


def parse_inventory(text: str, source: str = '', allow_large: bool = False,
                    link: bool = True) -> Inventory:
    """Parse a server inventory in any of the formats the web app accepts.

    * ``name ip [ip...]``, ``ip name``, bare ``ip`` lines (separators: space, tab, ``,`` ``;``)
    * ``/etc/hosts`` (``ip canonical-name alias...``)
    * CSV/TSV/semicolon files with a header row (name/hostname/host/server... and
      ip/ip_address/public_ip/private_ip/ipv4/ipv6/address... columns, Turkish headers
      such as ``Sunucu Adı`` / ``IP Adresi`` / ``Ortam`` too; gateway, DNS, NTP, BMC,
      MAC and e-mail columns are skipped, as in the web app)
    * Ansible INI (``web01 ansible_host=1.2.3.4``, ``[group]`` headers become groups,
      ``[x:vars]`` / ``[x:children]`` sections are skipped)
    * simple Ansible YAML (``web01:`` / ``  ansible_host: 1.2.3.4``) and JSON (arrays,
      objects, ``_meta.hostvars``, AWS-style ``Tags``)
    * CIDRs / ranges (expanded, one server per IP) and hostnames without an IP (kept in
      :attr:`Server.hostnames` for :func:`resolve_servers`)
    * topology keys in every format (``key=value`` on a line, a CSV column, an Ansible host
      variable, a JSON key): ``ports=443,8443``, ``terminates_tls=yes|no``, ``vip=``,
      ``backends=web01,web02``, ``nat=`` (see :class:`Server`); a malformed value is a
      TOPOLOGY warning. ``link=False`` leaves ``backends=`` unresolved for
      :func:`link_backends` over several files.
    Comments: ``#``, ``;``, ``//``. The same name on several lines merges its IPs.
    """
    builder = _InventoryBuilder(source, allow_large)
    text = text.lstrip('\ufeff')
    lines = text.splitlines()
    stripped = text.strip()
    if stripped[:1] in ('[', '{'):
        try:
            data = json.loads(stripped)
        except ValueError:
            data = None
        if data is not None:
            _parse_json(data, builder)
            return builder.result(len(lines), link)
    start, delimiter = _find_csv_header(lines)
    first = lines[start] if start < len(lines) else ''
    if delimiter:
        _parse_csv(lines, delimiter, builder, start)
    elif first.strip() == '---' or any(
            re.match(r'^\s*(?:(?:ansible_host|ansible_ssh_host)\s*:\s*\S|hosts\s*:\s*$)', line)
            for line in lines):
        _parse_yaml(lines, builder)
    else:
        _parse_lines(lines, builder)
    return builder.result(len(lines), link)


def _find_csv_header(lines: List[str]) -> Tuple[int, Optional[str]]:
    """The first line that is not blank or a comment (its index) and, when it is a CSV header,
    its delimiter. Excel's ``sep=;`` line before it names the delimiter; a line that starts with
    ``;`` is a comment unless it is a ``;`` header with an empty first cell."""
    forced = None  # type: Optional[str]
    for index, line in enumerate(lines):
        text = line.strip()
        if not text:
            continue
        sep = re.match(r'^sep=(.)$', text, re.I)
        if sep and forced is None:
            forced = sep.group(1)
            continue
        if _is_comment(line):
            if (text.startswith(';') and forced in (None, ';')
                    and _detect_csv_delimiter(line, (';',)) == ';'):
                return index, ';'
            continue
        return index, _detect_csv_delimiter(line, (forced,) if forced else ('\t', ',', ';'))
    return len(lines), None


def _detect_csv_delimiter(line: str, delimiters: Tuple[str, ...] = ('\t', ',', ';')) -> Optional[str]:
    for delimiter in delimiters:
        if delimiter not in line:
            continue
        cells = [cell.strip().strip('"') for cell in line.split(delimiter)]
        if any(normalize_ip(cell) for cell in cells):
            return None  # a data line, not a header
        if any('=' in cell for cell in cells):
            return None  # key=value variables (backends=web01,web02): no header has them
        headers = [_normalize_header(cell) for cell in cells]
        if any(h in _NAME_RANK or _is_ip_header(h) for h in headers):
            return delimiter
    return None


def _parse_csv(lines: List[str], delimiter: str, builder: _InventoryBuilder, start: int = 0) -> None:
    """Rows after the header at ``lines[start]``. As in the web app, the first cell makes a
    comment (``#``, ``;``, ``//``): in a ``;`` file, ``;web02;10.0.0.2`` is a row with an empty
    first cell, and Excel's blank ``;;`` rows are skipped."""
    content = []  # type: List[Tuple[int, List[str]]]
    for number, line in enumerate(lines[start:], start + 1):
        if not line.strip():
            continue
        cells = next(csv.reader([line], delimiter=delimiter), [])
        if content and (not any(cell.strip() for cell in cells)
                        or cells[0].strip().startswith(('#', ';', '//'))):
            continue
        content.append((number, cells))
    if not content:
        return
    header = [_normalize_header(cell) for cell in content[0][1]]
    name_idx = min((i for i, h in enumerate(header) if h in _NAME_RANK),
                   key=lambda i: _NAME_RANK[header[i]], default=None)
    topology_idx = [i for i, h in enumerate(header) if h in TOPOLOGY_KEYS and i != name_idx]
    ip_idx = [i for i, h in enumerate(header)
              if _is_ip_header(h) and i != name_idx and i not in topology_idx]
    group_idx = [i for i, h in enumerate(header) if h in _GROUP_HEADERS]
    # Without an IP column the other columns are read for addresses, never a gateway / DNS /
    # iLO / subnet / MAC / e-mail column: such a row's own name is resolved instead.
    other_idx = [i for i, h in enumerate(header) if i != name_idx and i not in topology_idx
                 and not _IP_HEADER_EXCLUDE_RE.search(h)]
    host_idx = {i for i, h in enumerate(header) if h in ('ansible_host', 'ansible_ssh_host')}
    for h in header:
        if h in _NEAR_MISS:
            builder.warn(content[0][0], 'TOPOLOGY', 'column %s is no topology key - did you mean '
                         '%s? It is not read' % (h, _NEAR_MISS[h]), 'nearMiss')
    for number, row in content[1:]:
        cells = [cell.strip() for cell in row]
        name = cells[name_idx] if name_idx is not None and name_idx < len(cells) else ''
        columns = ip_idx or other_idx + list(range(len(header), len(cells)))
        values = []  # type: List[str]
        for i in columns:
            if i < len(cells) and cells[i]:
                # A word without a digit, a dot or a colon (DHCP, N/A, TBD, -) is no address and
                # no host but in an ansible_host column: the row's own name is resolved instead.
                values.extend(v for v in re.split(r'[\s,;|]+', cells[i])
                              if v and (i in host_idx or re.search(r'[\d.:]', v)))
        values = [v for v in values if ip_idx or _address_token(v) or is_ip_block(v)]
        groups = [cells[i] for i in group_idx if i < len(cells) and cells[i]]
        topology = builder.line_topology([(header[i], cells[i]) for i in topology_idx
                                          if i < len(cells) and cells[i]], number, True)
        name_ip = _address_token(name) if name else None
        if name_ip:
            values.insert(0, name_ip)
            if name_ip != normalize_ip(name):  # an address with a port names the address
                name = (split_endpoint(name) or (name_ip, None))[0]
        if not values:
            if name:
                touched = builder.add_hostname(name, number, groups, ','.join(cells))
            else:
                touched = []
                builder.warn(number, 'NO_IP', ','.join(cells))
        else:
            touched = builder.add_token_values(name or None, values, number, groups)
        for server in touched:
            builder.apply_topology(server, topology)


def _yaml_value(text: str) -> Any:
    """A YAML scalar or flow list as the web app's YAML reader gives it: ``[web01, web02]`` ->
    a list, quotes removed, ``~`` / ``null`` / nothing -> None."""
    text = text.strip()
    if text in ('', '~', 'null', 'Null', 'NULL'):
        return None
    if text.startswith('[') and text.endswith(']'):
        return [_unquote(item) for item in text[1:-1].split(',') if item.strip()]
    return _unquote(text)


def _yaml_flow_pairs(text: str) -> List[Tuple[str, str]]:
    """The ``key: value`` pairs of a YAML flow mapping (``{ansible_host: 10.0.0.1, ports:
    [443, 8443]}``): commas inside brackets or quotes split nothing."""
    items, buf, depth, quote = [], [], 0, ''  # type: List[str], List[str], int, str
    for char in text.strip()[1:-1]:
        if quote:
            quote = '' if char == quote else quote
        elif char in '\'"':
            quote = char
        elif char in '[{':
            depth += 1
        elif char in ']}':
            depth -= 1
        elif char == ',' and depth == 0:
            items.append(''.join(buf))
            buf = []
            continue
        buf.append(char)
    items.append(''.join(buf))
    pairs = []  # type: List[Tuple[str, str]]
    for item in items:
        key, sep, value = item.partition(':')
        if sep and key.strip():
            pairs.append((key.strip().strip('\'"'), value.strip()))
    return pairs


def _parse_yaml(lines: List[str], builder: _InventoryBuilder) -> None:
    """Very small subset of YAML: nested ``key:`` mappings with ``ansible_host`` leaves, and the
    topology keys of a host (a scalar, a flow list or a block list of ``- item`` lines); in a
    group's ``vars:`` they are a 'groupVars' TOPOLOGY warning."""
    kv_re = re.compile(r'^(\s*)(?:-\s+)?([^\s:#][^:#]*?)\s*:(?:\s+(.*?))?\s*$')
    item_re = re.compile(r'^(\s*)-\s+(.*?)\s*$')
    stack = []  # type: List[Tuple[int, str]]
    pending = {}  # type: Dict[str, Tuple[int, List[str]]]
    topology = {}  # type: Dict[str, List[TopologyValue]]
    open_list = None  # type: Optional[Tuple[int, str, str, int, List[str]]]

    def groups_of(path: List[Tuple[int, str]]) -> List[str]:
        keys = [key for _, key in path]
        return [keys[i - 1] for i, key in enumerate(keys)
                if key == 'hosts' and i > 0 and keys[i - 1] not in ('all', 'children')]

    def keep(host: str, key: str, value: Any, number: int) -> None:
        items = _topology_items(value, True)
        raw = ','.join(items or [])
        read = builder.read_topology(key, items, raw, number)
        if read is not None:
            topology.setdefault(host, []).append(read)

    for number, raw in enumerate(lines, 1):
        if not raw.strip() or _is_comment(raw) or raw.strip() in ('---', '...'):
            continue
        text = raw.split(' #', 1)[0]
        if open_list is not None:  # backends:\n  - web01\n  - web02
            item = item_re.match(text)
            if item and len(item.group(1)) >= open_list[0]:
                open_list[4].append(_unquote(item.group(2)))
                continue
            keep(open_list[2], open_list[1], open_list[4], open_list[3])
            open_list = None
        match = kv_re.match(text)
        if not match:
            continue
        indent = len(match.group(1))
        key = match.group(2).strip().strip('\'"')
        value = (match.group(3) or '').strip().strip('\'"')
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1] if stack else None
        topology_key = _topology_key(key, True)
        if topology_key is not None and parent == 'vars':
            builder.warn(number, 'TOPOLOGY', '%s in a group\'s vars: group variables are not read '
                         'for the topology - set it on each host' % topology_key, 'groupVars')
            continue
        if topology_key is not None and parent and len(stack) > 1 and stack[-2][1] == 'hosts':
            if value == '':
                open_list = (indent, topology_key, parent, number, [])
            else:
                keep(parent, topology_key, _yaml_value(match.group(3) or ''), number)
            continue
        if key in ('ansible_host', 'ansible_ssh_host'):
            if parent:
                pending.pop(parent, None)
                builder.add_token_values(parent, [value], number, groups_of(stack[:-1]))
            else:
                builder.add_token_values(None, [value], number)
            continue
        if parent == 'hosts' and value.startswith('{') and value.endswith('}'):
            # web01: {ansible_host: 10.0.0.1, ansible_user: deploy}: a host's vars in flow style
            pairs = _yaml_flow_pairs(value)
            hosts = [_unquote(v) for k, v in pairs if k in ('ansible_host', 'ansible_ssh_host')]
            if hosts:
                builder.add_token_values(key, hosts, number, groups_of(stack))
            else:
                pending[key] = (number, groups_of(stack))
            for name, item in pairs:
                if _topology_key(name, True) is not None:
                    keep(key, _topology_key(name, True), _yaml_value(item), number)
            continue
        if value in ('', 'null', '~', '{}'):
            stack.append((indent, key))
            if parent == 'hosts':
                pending[key] = (number, groups_of(stack[:-1]))
    if open_list is not None:
        keep(open_list[2], open_list[1], open_list[4], open_list[3])
    for key, (number, groups) in pending.items():
        builder.add_token_values(key, [key], number, groups)
    for host, values in topology.items():
        server = builder.servers.get(host.lower())
        if server is not None:
            builder.apply_topology(server, values)


def _ssh_port(token: str) -> Optional[Tuple[str, int]]:
    """An Ansible host pattern with its SSH port (``192.0.2.50:2222``,
    ``[2001:db8::1]:2222``, ``badwolf.example.com:5309``) -> ``(host, port)``; else None
    (a bad port included: the caller warns about it as for any other target)."""
    try:
        endpoint = split_endpoint(token)
    except ValueError:
        return None
    if endpoint is None or endpoint[1] is None:
        return None
    return endpoint[0], endpoint[1]


def _parse_lines(lines: List[str], builder: _InventoryBuilder) -> None:
    """Plain lists, /etc/hosts files and Ansible INI inventories."""
    group = None  # type: Optional[str]
    skip_section = False
    vars_section = False
    for number, raw in enumerate(lines, 1):
        line = _strip_comment(raw)
        if not line:
            continue
        section = re.match(r'^\[([^\]]+)\]$', line)
        if section and normalize_ip(section.group(1)) is None:
            name = section.group(1).strip()
            group, _, kind = name.partition(':')
            skip_section = kind in ('vars', 'children')
            vars_section = kind == 'vars'
            continue
        if skip_section:
            if vars_section:  # group variables are not read for the topology: say so
                for key, _raw in _split_topology(line)[1]:
                    builder.warn(number, 'TOPOLOGY', '%s in [%s:vars]: group variables are not '
                                 'read for the topology - set it on each host' % (key, group),
                                 'groupVars')
            continue
        # Topology keys first: their values hold commas (ports=443,8443), which split a line.
        said = len(builder.warnings)
        line, found, near = _split_topology(line)
        for text in near:
            builder.warn(number, 'TOPOLOGY', text, 'nearMiss')
        topology = builder.line_topology(found, number)
        touched = []  # type: List[Server]
        added = False
        groups = [group] if group else []
        name = None  # type: Optional[str]
        values = []  # type: List[str]
        had_invalid = False
        tokens = [t for t in re.split(r'[\s,;]+', line) if t]
        # Ansible INI: a line under a [group] header, or one with ansible_* variables. There a
        # port on the host pattern (the first token: "badwolf.example.com:5309",
        # "192.0.2.50:2222", "[2001:db8::1]:2222") is Ansible's SSH port (ansible_port), never
        # a TLS port: the host stays on the -p ports (lib/inventory.js reads it alike).
        ansible = group is not None or any(re.match(r'ansible_\w*=', t, re.I) for t in tokens)
        for index, token in enumerate(tokens):
            if index == 0 and ansible and '=' not in token and not _CLOCK_RE.match(token):
                ssh = _ssh_port(token)
                if ssh is not None:
                    builder.warn(number, 'PARSE', '%s: port %d on an Ansible host is its SSH '
                                 'port (ansible_port), not a TLS port - scanned on -p'
                                 % (token, ssh[1]))
                    token = ssh[0]
            if '=' in token:
                key, _, value = token.partition('=')
                if key.lower() in _IP_KEYS:
                    values.append(value)
                elif index == 0 and key and _CLOCK_RE.match(value):
                    continue  # "time=10:30": a time of day, not a host and its port
                elif index == 0 and key and not key.lower().startswith('ansible_'):
                    # "web01=203.0.113.10", "web01=203.0.113.10:8443", "web01=web01.example.net"
                    # or "web01=web01.example.net:8443": NAME=TARGET as -t takes it
                    # (lib/inventory.js reads the address forms and warns about the host names
                    # it cannot resolve); a bad address or port is a warning. A value without
                    # a dot or a port (user=root) stays a variable.
                    try:
                        endpoint = split_endpoint(value)
                    except ValueError as exc:
                        builder.warn(number, 'INVALID_IP', '%s (%s)' % (value, exc))
                        had_invalid = True
                        continue
                    if (normalize_ip(value) or endpoint is not None
                            or ('.' in value and not _looks_like_ip(value)
                                and normalize_hostname(value))):
                        name = key
                        values.append(value)
                    elif _looks_like_ip(value):
                        builder.warn(number, 'INVALID_IP', value)
                        had_invalid = True
                continue  # other Ansible variables (ansible_user=...) are irrelevant
            if _CLOCK_RE.match(token):
                continue  # "backup 10:30 203.0.113.10": a time of day, not a host and its port
            if normalize_ip(token) or is_ip_block(token):
                values.append(token)
                continue
            try:
                endpoint = split_endpoint(token)
            except ValueError as exc:  # 203.0.113.10:99999, [2001:db8::1]:https
                builder.warn(number, 'INVALID_IP', '%s (%s)' % (token, exc))
                had_invalid = True
                continue
            if endpoint is not None and (normalize_ip(endpoint[0]) or name is not None):
                values.append(token)  # an address with its port, or host:port after the name
            elif _looks_like_ip(token) or _malformed_ip_block(token):
                builder.warn(number, 'INVALID_IP', token)
                had_invalid = True
            elif name is None:
                name = token  # first word = name; later words (hosts-file aliases) ignored
        if values:
            named = split_endpoint(name) if name is not None else None
            if named is not None:  # "web01.example.net:8443 203.0.113.10"
                builder.warn(number, 'PARSE', '%s: a server name takes no port - write it after '
                             'the address (ADDRESS:PORT); ignored' % name)
                name = named[0]
            touched, added = builder.add_token_values(name, values, number, groups), True
        elif had_invalid:
            added = True  # "web01 10.0.0.300": a typo, do not silently resolve "web01" instead
        elif _is_header_like(tokens):
            pass  # "hostname   ip": a column heading, not a server called "hostname"
        elif name is not None:
            # A zone file's "2026092401 ; serial" line must never be resolved (glibc -> IP).
            touched, added = builder.add_hostname(name, number, groups, line), True
        for server in touched:
            builder.apply_topology(server, topology)
        if found and not added and len(builder.warnings) == said:  # nothing else said about it
            builder.warn(number, 'TOPOLOGY', '%s: no server on this line - write the keys after '
                         'the server\'s name and address' % ', '.join(k for k, _ in found),
                         'noServer')


def _json_name(obj: Dict[str, Any]) -> Optional[str]:
    for key in _JSON_NAME_KEYS:
        value = obj.get(key)
        if (isinstance(value, str) and value.strip() and _address_token(value) is None
                and _bad_port(value) is None):
            return value.strip()
    tags = obj.get('tags', obj.get('Tags'))
    if isinstance(tags, dict):
        value = tags.get('Name', tags.get('name'))
        if isinstance(value, str) and value.strip():
            return value.strip()
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict) and tag.get('Key') in ('Name', 'name'):
                value = tag.get('Value')
                if isinstance(value, str) and value.strip():
                    return value.strip()
    return None


def _json_ips(node: Any, out: List[str], key: str = '',
              invalid: Optional[List[str]] = None) -> None:
    """Collect IP strings anywhere below ``node`` (skipping netmask/gateway/dns-like keys);
    an address whose port cannot be used (``203.0.113.10:99999``) goes to ``invalid``."""
    if key and _JSON_SKIP_KEY_RE.search(key):
        return
    if isinstance(node, str):
        ip = _address_token(node)  # 203.0.113.10, or 203.0.113.10:8443 with its port
        if ip and ip not in out:
            out.append(ip)
        elif not ip and invalid is not None and _bad_port(node) and node.strip() not in invalid:
            invalid.append(node.strip())
    elif isinstance(node, list):
        for item in node:
            _json_ips(item, out, key, invalid)
    elif isinstance(node, dict):
        for child_key, child in node.items():
            _json_ips(child, out, str(child_key), invalid)


def _json_host_values(obj: Dict[str, Any]) -> List[str]:
    """ansible_host-like values that are hostnames rather than IPs."""
    out = []
    for key in ('ansible_host', 'ansible_ssh_host'):
        value = obj.get(key)
        if isinstance(value, str) and _address_token(value) is None and _bad_port(value) is None:
            out.append(value)
    return out


def _is_ip_key(key: str) -> bool:
    key = _normalize_header(key)
    return ((key in _IP_KEYS or bool(_IP_HEADER_RE.search(key)))
            and not _JSON_SKIP_KEY_RE.search(key))


def _json_has_ip_field(obj: Dict[str, Any]) -> bool:
    """Does this object carry an IP under an IP-ish key (``ip``, ``PrivateIpAddress``...)?"""
    for key, value in obj.items():
        if not _is_ip_key(str(key)):
            continue
        items = value if isinstance(value, list) else [value]
        if any(isinstance(item, str) and (_address_token(item) or _bad_port(item))
               for item in items):
            return True
    return False


def _json_target_tokens(text: str) -> List[str]:
    """Tokens of a JSON string that can be targets: IPs (with a port too), CIDRs/ranges,
    dotted hostnames (with a port too: ``web01.example.net:8443``, as ``NAME=HOST:PORT``
    in a file), and addresses whose port cannot be used, which
    :meth:`_InventoryBuilder.add_token_values` reports instead of dropping them."""
    out = []
    for token in (t for t in re.split(r'[\s,;]+', text) if t):
        if _address_token(token) or is_ip_block(token) or _bad_port(token):
            out.append(token)
        elif _is_dotted_host(token) or _is_dotted_host(_host_of(token)):
            out.append(token)
    return out


def _is_dotted_host(token: Optional[str]) -> bool:
    return (bool(token) and '.' in token and not _looks_like_ip(token)
            and normalize_hostname(token) is not None)


def _host_of(token: str) -> Optional[str]:
    """The host of ``host.name:port`` (a port 1-65535); else None."""
    match = _ENDPOINT_HOST_RE.match(token)
    if match is None or _CLOCK_RE.match(token):
        return None
    try:
        _endpoint_port(match.group(2))
    except ValueError:
        return None
    return match.group(1)


def _parse_json(data: Any, builder: _InventoryBuilder, key_hint: Optional[str] = None) -> None:
    """Walk JSON: server objects (name and/or IP fields), name->IP maps, lists, hostvars."""
    if isinstance(data, str):
        tokens = [t for t in re.split(r'[\s,;]+', data) if t]
        targets = _json_target_tokens(data)
        if not targets:
            return
        if key_hint is not None or len(tokens) == 1:
            builder.add_token_values(key_hint, targets, 0)       # {"web01": "10.0.0.5"}
        elif any(_address_token(t) or _bad_port(t) for t in tokens):
            first_ip = _address_token(tokens[0]) or _bad_port(tokens[0])  # "ip name" / "name ip"
            name = tokens[1] if first_ip else tokens[0]
            builder.add_token_values(name, [t for t in targets if t != name], 0)
        return
    if isinstance(data, list):
        for item in data:
            _parse_json(item, builder, None if isinstance(item, dict) else key_hint)
        return
    if not isinstance(data, dict):
        return
    name = _json_name(data)
    # Topology keys of this record holding a scalar or a list of scalars (anything else, e.g.
    # kubectl's "ports": [{"containerPort": 80}], is read as before).
    topology_keys = {key: (topology_key, items) for key, topology_key, items in
                     ((k, _topology_key(k, True), _topology_items(v, True)) for k, v in data.items())
                     if topology_key is not None and items is not None}
    record = {k: v for k, v in data.items() if k not in topology_keys}
    if name is not None or _json_has_ip_field(record) or _json_host_values(record):
        topology = [read for read in (builder.read_topology(key, items, ','.join(items), 0)
                                      for key, items in topology_keys.values())
                    if read is not None]
        ips, invalid = [], []  # type: List[str], List[str]
        _json_ips(record, ips, invalid=invalid)
        values = ips or _json_host_values(record)
        for token in invalid:
            builder.warn(0, 'INVALID_IP', '%s (%s)' % (token, _bad_port(token)))
        touched = []  # type: List[Server]
        if values:
            touched = builder.add_token_values(name or key_hint, values, 0)
        elif name and not invalid:
            # "web01" with a mistyped port is a warning, never the name resolved instead
            touched = builder.add_hostname(name, 0)
        for server in touched:
            builder.apply_topology(server, topology)
        return
    for child_key, child in data.items():
        if child_key == '_meta' and isinstance(child, dict):
            _parse_json(child.get('hostvars', {}), builder)
            continue
        if child_key == 'vars' and isinstance(child, dict):  # a group's vars
            for key, value in child.items():
                topology_key = _topology_key(key, True)
                if topology_key is not None and _topology_items(value, True) is not None:
                    builder.warn(0, 'TOPOLOGY', '%s in a group\'s vars: group variables are not '
                                 'read for the topology - set it on each host' % topology_key,
                                 'groupVars')
        _parse_json(child, builder, str(child_key))


def read_text_file(path: str) -> str:
    """Read a text file, honouring UTF-8/UTF-16 BOMs (PowerShell ``>`` writes UTF-16LE)."""
    with open(path, 'rb') as handle:
        data = handle.read()
    if data.startswith(b'\xff\xfe') or data.startswith(b'\xfe\xff'):
        return data.decode('utf-16', 'replace')
    if data.startswith(b'\xef\xbb\xbf'):
        return data[3:].decode('utf-8', 'replace')
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        return data.decode('latin-1')


def _looks_like_path(value: str) -> bool:
    return ('/' in value or '\\' in value or bool(_TARGET_FILE_EXT_RE.search(value)))


def parse_target_tokens(value: str, allow_large: bool = False) -> Inventory:
    """Parse a ``-t`` argument that is not a file: IPs, CIDRs, ranges, ``name=ip``, hostnames.

    Unlike inventory lines, every token is its own server. An address or host name may
    carry its own port (``203.0.113.10:8443``, ``[2001:db8::1]:8443``,
    ``web01.example.net:8443``, ``web01=203.0.113.10:8443``): it is scanned on that port
    instead of ``-p``. Raises :class:`UsageError` for tokens that are none of these, a bad
    port, and numeric "hostnames" the system resolver would read as an IPv4 address
    (``2026092401``, ``127.1``, ``0x7f.0x1``).
    """
    builder = _InventoryBuilder('argument', allow_large)
    for token in (t for t in re.split(r'[\s,]+', value) if t):
        # 203.0.113.10:2525/smtp, web01=203.0.113.10:2525/smtp: that endpoint speaks the protocol
        suffix = _PROTOCOL_SUFFIX_RE.match(token)
        if suffix:
            protocol = parse_protocol(suffix.group(2), token)
            name, sep, target = suffix.group(1).partition('=')
            if sep and not name:
                raise UsageError('invalid target %r (expected NAME=IP)' % token)
            if not _add_endpoint_token(builder, target if sep else name, name if sep else None,
                                       protocol, token):
                raise UsageError('invalid target %r: a protocol goes after a port '
                                 '(203.0.113.10:2525/smtp)' % token)
            continue
        if '=' in token:
            name, _, target = token.partition('=')
            if not name or not target:
                raise UsageError('invalid target %r (expected NAME=IP)' % token)
            try:
                split_endpoint(target)
            except ValueError as exc:
                raise UsageError('invalid target %r: %s' % (token, exc))
            if is_numeric_host(target):
                raise UsageError('invalid target %r: %s; write addresses as a.b.c.d'
                                 % (token, numeric_host_note(target)))
            if _malformed_ip_block(target):
                raise UsageError(_malformed_block_error(token, target))
            builder.add_token_values(name, [target], 0)
            continue
        ip = normalize_ip(token)
        if ip:
            builder.add(ip, [ip], 0)
            continue
        block = expand_ip_block(token, allow_large)
        if block is not None:
            for block_ip in block:
                builder.add(block_ip, [block_ip], 0, [token])
            continue
        if _add_endpoint_token(builder, token):
            continue
        # 010.0.0.1, and the address part of 010.0.0.0/24 or 010.0.0.1-5
        if _has_ambiguous_ipv4_part(token) and _looks_like_ip(re.split(r'[/-]', token)[0]):
            legacy = _legacy_ipv4(token)
            raise UsageError('invalid target %r: an IPv4 part with a leading zero is ambiguous '
                             '(the system resolver reads it as octal%s)'
                             % (token, ': ' + legacy if legacy else ''))
        if is_numeric_host(token) and not _looks_like_ip(token):
            raise UsageError('invalid target %r: %s; write addresses as a.b.c.d'
                             % (token, numeric_host_note(token)))
        if _malformed_ip_block(token):  # 10.0.0.5-300, 10.0.0.0/33 (not a missing file)
            raise UsageError(_malformed_block_error(token, token))
        if _looks_like_path(token):
            raise UsageError('target file not found: %s' % value)
        host = normalize_hostname(token)
        if host is None or _looks_like_ip(token):
            raise UsageError('invalid target %r (expected a file, IP, CIDR, range or hostname)'
                             % token)
        builder.add(token, [], 0, (), [host])
    return builder.result(0)


# A -t token whose port names its protocol (203.0.113.10:2525/smtp, [2001:db8::1]:2525/smtp,
# web01=mail.example.net:2525/smtp); a CIDR (2001:db8::1/128) has digits after the slash
_PROTOCOL_SUFFIX_RE = re.compile(r'^(.*:\d{1,5})/([A-Za-z][A-Za-z0-9-]*)$')


def _add_endpoint_token(builder: _InventoryBuilder, token: str, name: Optional[str] = None,
                        protocol: Optional[str] = None, written: Optional[str] = None) -> bool:
    """A ``-t`` token with its own port (``203.0.113.10:8443``, ``[2001:db8::1]:8443``,
    ``web01.example.net:8443``) -> one server (called ``name`` when given); False when
    ``token`` has no port. ``protocol`` is the one written after the port (``/smtp``)."""
    written = written or token
    try:
        endpoint = split_endpoint(token)
    except ValueError as exc:
        raise UsageError('invalid target %r: %s' % (written, exc))
    if endpoint is None or (protocol is not None and endpoint[1] is None):
        return False
    target, port = endpoint
    if protocol is not None and port is not None:
        port = ProtocolPort(port, protocol)
    ip = normalize_ip(target)
    if ip:
        builder.add(name or ip, [(ip, port)], 0)
        return True
    if is_numeric_host(target):
        raise UsageError('invalid target %r: %s; write addresses as a.b.c.d'
                         % (written, numeric_host_note(target)))
    host = normalize_hostname(target)
    if host is None:
        raise UsageError('invalid target %r (expected an IP address or hostname before the '
                         'port)' % written)
    builder.add(name or target, [], 0, (), [(host, port)])
    return True


def resolve_host(host: str) -> List[str]:
    """Resolve ``host`` with the system resolver (getaddrinfo) -> unique IPv4 + IPv6 addresses."""
    infos = socket.getaddrinfo(host, None, 0, socket.SOCK_STREAM)
    out = []  # type: List[str]
    for family, _type, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, getattr(socket, 'AF_INET6', -1)):
            continue
        ip = normalize_ip(str(sockaddr[0]))
        if ip and ip not in out:
            out.append(ip)
    return out


def resolve_servers(servers: List[Server], resolver: Callable[[str], List[str]] = resolve_host,
                    workers: int = 16, cancel: Optional[threading.Event] = None
                    ) -> Tuple[List[Server], List[InventoryWarning]]:
    """Resolve the hostnames of servers that have no IP; drop servers that stay without IP.

    Numeric names (:func:`is_numeric_host`) are never handed to the resolver, which would
    turn them into an IPv4 address; unscannable answers (0.0.0.0/8, multicast...) are
    dropped.
    """
    todo = []  # type: List[str]
    for server in servers:
        if not server.ips:
            for host in server.hostnames:
                if host not in todo:
                    todo.append(host)
    answers = {}  # type: Dict[str, Tuple[List[str], Optional[str]]]

    def lookup(host: str) -> Tuple[List[str], Optional[str]]:
        if is_numeric_host(host):
            return [], 'not resolved - %s' % numeric_host_note(host)
        try:
            ips = [ip for ip in resolver(host) if is_scannable_ip(ip)]
            return ips, None if ips else 'no address'
        except (OSError, UnicodeError) as exc:
            return [], getattr(exc, 'strerror', None) or str(exc) or type(exc).__name__

    def store(host: str, answer: Tuple[List[str], Optional[str]]) -> None:
        answers[host] = answer

    if todo:
        _parallel(lookup, todo, max(1, min(workers, len(todo))), store,
                  cancel or threading.Event())
    kept, warnings = [], []  # type: List[Server], List[InventoryWarning]
    for server in servers:
        if not server.ips:
            for host in server.hostnames:
                ips, error = answers.get(host, ([], 'not resolved'))
                for ip in ips:
                    for port in server.port_spec(host):  # web01.example.net:8443
                        server.add_ip(ip, port)
                if error:
                    warnings.append(InventoryWarning(server.line, 'RESOLVE',
                                                     'cannot resolve %s: %s' % (host, error),
                                                     server.source))
        if server.ips:
            kept.append(server)
    return kept, warnings


def load_targets(values: Sequence[str], allow_large: bool = False,
                 stdin: Optional[TextIO] = None,
                 resolver: Callable[[str], List[str]] = resolve_host,
                 workers: int = 16, cancel: Optional[threading.Event] = None
                 ) -> Tuple[List[Server], List[InventoryWarning]]:
    """Turn ``-t`` values (files, ``-`` for stdin, IPs, CIDRs, ranges, hostnames) into servers.

    Servers with the same name across sources are merged. Hostnames are resolved via
    ``resolver`` (getaddrinfo, IPv4 + IPv6). Raises :class:`UsageError` for missing files,
    invalid tokens and oversized CIDRs.
    """
    merged = {}  # type: Dict[str, Server]
    warnings = []  # type: List[InventoryWarning]
    for value in values:
        if value == '-':
            inventory = parse_inventory((stdin or sys.stdin).read(), '<stdin>', allow_large,
                                        link=False)
        elif os.path.isfile(value):
            try:
                text = read_text_file(value)
            except OSError as exc:
                raise UsageError('cannot read %s: %s' % (value, exc.strerror or exc))
            inventory = parse_inventory(text, value, allow_large, link=False)
        else:
            inventory = parse_target_tokens(value, allow_large)
        warnings.extend(inventory.warnings)
        for server in inventory.servers:
            existing = merged.get(server.name.lower())
            if existing is None:
                merged[server.name.lower()] = server
                continue
            for ip in server.ips:
                for port in server.port_spec(ip):
                    existing.add_ip(ip, port)
            for group in server.groups:
                if group not in existing.groups:
                    existing.groups.append(group)
            for host in server.hostnames:
                for port in server.port_spec(host):
                    existing.add_hostname(host, port)
            warnings.extend(_merge_topology(existing, server))
    # backends= may name a server of another file: resolved once every file is read
    warnings.extend(link_backends(list(merged.values())))
    warnings.extend(topology_checks(list(merged.values())))
    servers, resolve_warnings = resolve_servers(list(merged.values()), resolver, workers, cancel)
    return servers, warnings + resolve_warnings


def _merge_topology(existing: Server, server: Server) -> List[InventoryWarning]:
    """The topology of ``server`` (the same name in another -t source) merged into
    ``existing``, as the same server on two lines of one file."""
    for source, target in ((server.tls_ports, existing.tls_ports), (server.vips, existing.vips),
                           (server.nats, existing.nats)):
        for item in source:
            if item not in target:
                target.append(item)
    existing.backend_refs.extend(server.backend_refs)
    if server.terminates_tls is None or existing.terminates_tls == server.terminates_tls:
        return []
    if existing.terminates_tls is None:
        existing.terminates_tls = server.terminates_tls
        return []
    text = _conflict_text('yes' if server.terminates_tls else 'no', server.name,
                          existing.terminates_tls)
    existing.terminates_tls = True
    return [InventoryWarning(server.line, 'TOPOLOGY', text, server.source, 'conflict')]


def _conflict_text(raw: str, name: str, before: bool) -> str:
    """The TOPOLOGY 'conflict' text: terminates_tls given both ways keeps yes, the safe value."""
    return ('terminates_tls=%s for %s: it was already %s - yes is kept (the safe value)'
            % (raw, name, 'yes' if before else 'no'))


# =====================================================================================
# --exclude: target addresses that must never be probed
# =====================================================================================

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
_V4_MAPPED_FIRST = 0xFFFF << 32               # ::ffff:0:0/96 - IPv4-mapped IPv6,
_V4_MAPPED_LAST = _V4_MAPPED_FIRST + 0xFFFFFFFF  # dialled as IPv4 (_connect_address)
# (version, first, last) as integers.
_Span = Tuple[int, int, int]


@dataclass(frozen=True)
class ExcludeRule:
    """One ``--exclude`` entry: its canonical text and the networks it covers."""

    label: str                        # '192.0.2.10', '192.0.2.0/28', '192.0.2.5-192.0.2.9'
    networks: Tuple[IpNetwork, ...]

    def spans(self) -> List[_Span]:
        """Integer spans per IP version.

        A network written in IPv4-mapped form (``::ffff:192.0.2.0/120``) also covers the
        plain IPv4 addresses; a wider IPv6 network (``::/0``) does not.
        """
        out = []  # type: List[_Span]
        for net in self.networks:
            first, last = int(net.network_address), int(net.broadcast_address)
            out.append((net.version, first, last))
            if net.version == 6 and _V4_MAPPED_FIRST <= first and last <= _V4_MAPPED_LAST:
                out.append((4, first - _V4_MAPPED_FIRST, last - _V4_MAPPED_FIRST))
        return out

    def contains(self, ip: str) -> bool:
        """Whether target ``ip`` falls in this rule (``::ffff:a.b.c.d`` also as ``a.b.c.d``)."""
        spans = self.spans()
        return any(v == version and first <= value <= last
                   for version, value in _match_keys(ip) for v, first, last in spans)


@dataclass
class ExcludedAddress:
    """A target address removed by ``--exclude`` before the scan (never probed)."""

    server: str
    ip: str
    rule: str  # label of the first ExcludeRule that matched


def _match_keys(ip: str) -> List[Tuple[int, int]]:
    """``(version, integer)`` forms of a target: an IPv4-mapped IPv6 address has both."""
    addr = ipaddress.ip_address(ip)  # type: Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
    keys = [(addr.version, int(addr))]
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        keys.append((4, int(addr.ipv4_mapped)))
    return keys


def parse_exclude_token(token: str) -> Optional[ExcludeRule]:
    """An IP, a CIDR or a range (``a-b``, ``a.b.c.d-N``) -> :class:`ExcludeRule`.

    ``None`` for anything else - hostnames included: an exclusion must name addresses,
    never something a resolver could answer differently later. Host bits of a CIDR are
    tolerated (``192.0.2.7/28`` = ``192.0.2.0/28``). Raises :class:`UsageError` for a
    reversed or mixed-version range.
    """
    token = token.strip()
    if not token:
        return None
    ip = normalize_ip(token)
    if ip is not None:
        return ExcludeRule(ip, (ipaddress.ip_network(ip),))
    if '/' in token:
        network = _parse_network(token)
        if network is None:
            return None
        address = _ip_text(network.network_address)
        label = address if network.num_addresses == 1 else '%s/%d' % (address, network.prefixlen)
        return ExcludeRule(label, (network,))
    if '-' in token:
        start_text, end_text = token.split('-', 1)
        start = normalize_ip(start_text)
        if start is None:
            return None
        end = normalize_ip(end_text)
        if end is None and end_text.isdigit() and '.' in start:
            end = normalize_ip(start.rsplit('.', 1)[0] + '.' + end_text)  # 192.0.2.5-9
        if end is None:
            return None
        first, last = ipaddress.ip_address(start), ipaddress.ip_address(end)
        if first.version != last.version or int(last) < int(first):
            raise UsageError('--exclude: invalid IP range %r' % token)
        networks = tuple(ipaddress.summarize_address_range(first, last))  # type: ignore[arg-type]
        return ExcludeRule(start if start == end else '%s-%s' % (start, end), networks)
    return None


def _exclude_error(token: str) -> str:
    if _has_ambiguous_ipv4_part(token):
        return ('--exclude: %r has an IPv4 part with a leading zero, which is ambiguous (octal '
                'for the system resolver) - write it without leading zeros' % token)
    if is_numeric_host(token):
        address = _legacy_ipv4(_numeric_candidate(token) or token)
        return ('--exclude: %r is not an IP address or CIDR - write IPv4 addresses as a.b.c.d%s'
                % (token, ' (the system resolver would read it as %s)' % address
                   if address else ''))
    if '-' in token and normalize_ip(token.split('-', 1)[0]):  # 192.0.2.5-09, 192.0.2.5-x
        return ('--exclude: %r is not a valid IP range (write 192.0.2.5-192.0.2.9 or '
                '192.0.2.5-9)' % token)
    if normalize_hostname(token, allow_wildcard=True):
        return ('--exclude takes IP addresses and CIDRs, not hostnames: %r (exclude the '
                'address itself, e.g. 192.0.2.10 or 192.0.2.0/28)' % token)
    return '--exclude: %r is not an IP address, CIDR or range' % token


def _exclude_looks_like_file(value: str) -> bool:
    """A missing file rather than a bad address (``192.0.2.0/33`` is a bad CIDR)."""
    if '\\' in value or _TARGET_FILE_EXT_RE.search(value):
        return True
    if '/' not in value:
        return False
    head = value.split('/', 1)[0].strip()
    return not (':' in head or _looks_like_ip(head) or re.match(r'^[0-9.]+$', head))


def _exclude_text(text: str, source: str, add: Callable[[ExcludeRule], None]) -> None:
    """Rules from an exclude file: IPs/CIDRs/ranges, ``#`` ``;`` ``//`` comments."""
    for number, raw in enumerate(text.lstrip('\ufeff').splitlines(), 1):
        for token in (t for t in re.split(r'[\s,;]+', _strip_comment(raw)) if t):
            rule = parse_exclude_token(token)
            if rule is None:
                raise UsageError('%s:%d: %s' % (source, number, _exclude_error(token)))
            add(rule)


def load_excludes(values: Sequence[str], stdin: Optional[TextIO] = None) -> List[ExcludeRule]:
    """``--exclude`` values -> rules (input order, deduplicated); strict.

    Each value is one or more IPs / CIDRs / ranges (separated by spaces, ``,`` or ``;``),
    ``-`` for stdin, or a file with one or more of them per line (``#`` comments). Raises
    :class:`UsageError` for hostnames (including numeric ones such as ``2026092401``),
    malformed addresses and missing files - an exclusion is a safety list, so nothing in
    it is silently ignored.
    """
    rules = []  # type: List[ExcludeRule]
    seen = set()  # type: Set[str]

    def add(rule: ExcludeRule) -> None:
        if rule.label not in seen:
            seen.add(rule.label)
            rules.append(rule)

    for value in values:
        if value == '-':
            _exclude_text((stdin or sys.stdin).read(), '<stdin>', add)
            continue
        tokens = [t for t in re.split(r'[\s,;]+', value) if t]
        parsed = [parse_exclude_token(token) for token in tokens]
        if tokens and all(rule is not None for rule in parsed):
            for rule in parsed:
                add(rule)  # type: ignore[arg-type]
            continue
        if os.path.isfile(value):
            try:
                text = read_text_file(value)
            except OSError as exc:
                raise UsageError('cannot read %s: %s' % (value, exc.strerror or exc))
            _exclude_text(text, value, add)
            continue
        if not tokens:
            raise UsageError('--exclude: empty value')
        if _exclude_looks_like_file(value):
            raise UsageError('--exclude file not found: %s' % value)
        bad = next(token for token, rule in zip(tokens, parsed) if rule is None)
        raise UsageError(_exclude_error(bad))
    return rules


def _as_rules(items: Iterable[Union[str, ExcludeRule]]) -> List[ExcludeRule]:
    rules = []  # type: List[ExcludeRule]
    for item in items:
        if isinstance(item, ExcludeRule):
            rules.append(item)
            continue
        rule = parse_exclude_token(item)
        if rule is None:
            raise UsageError(_exclude_error(item))
        rules.append(rule)
    return rules


class _ExcludeMatcher:
    """Address -> first matching rule, with a merged-interval fast path (bisect)."""

    def __init__(self, rules: Sequence[ExcludeRule]) -> None:
        self.rules = [(rule, rule.spans()) for rule in rules]
        merged = {4: [], 6: []}  # type: Dict[int, List[Tuple[int, int]]]
        for _rule, spans in self.rules:
            for version, first, last in spans:
                merged[version].append((first, last))
        self.starts = {}  # type: Dict[int, List[int]]
        self.ends = {}  # type: Dict[int, List[int]]
        for version, spans in merged.items():
            out = []  # type: List[Tuple[int, int]]
            for first, last in sorted(spans):
                if out and first <= out[-1][1] + 1:
                    out[-1] = (out[-1][0], max(out[-1][1], last))
                else:
                    out.append((first, last))
            self.starts[version] = [first for first, _ in out]
            self.ends[version] = [last for _, last in out]

    def _inside(self, version: int, value: int) -> bool:
        index = bisect.bisect_right(self.starts[version], value) - 1
        return index >= 0 and value <= self.ends[version][index]

    def match(self, ip: str) -> Optional[ExcludeRule]:
        keys = [key for key in _match_keys(ip) if self._inside(*key)]
        if not keys:
            return None
        for rule, spans in self.rules:
            if any(v == version and first <= value <= last
                   for version, value in keys for v, first, last in spans):
                return rule
        return None


def apply_excludes(servers: Sequence[Server], rules: Iterable[Union[str, ExcludeRule]]
                   ) -> Tuple[List[Server], List[ExcludedAddress]]:
    """Remove every excluded address from ``servers`` -> ``(kept servers, excluded)``.

    ``rules`` are :class:`ExcludeRule` objects or IP / CIDR / range strings. Servers left
    without any address are dropped; the others are copies with the remaining IPs (the
    inputs are not modified). An IPv4-mapped IPv6 target (``::ffff:a.b.c.d``, dialled as
    IPv4) is excluded by a rule covering ``a.b.c.d``, and a rule written in mapped form
    (``::ffff:a.b.c.d[/n]``) excludes the plain IPv4 target too.
    """
    rule_list = _as_rules(rules)
    if not rule_list:
        return list(servers), []
    matcher = _ExcludeMatcher(rule_list)
    kept = []  # type: List[Server]
    excluded = []  # type: List[ExcludedAddress]
    for server in servers:
        ips = []  # type: List[str]
        for ip in server.ips:
            rule = matcher.match(ip)
            if rule is None:
                ips.append(ip)
            else:
                excluded.append(ExcludedAddress(server.name, ip, rule.label))
        if len(ips) == len(server.ips):
            kept.append(server)
        elif ips:
            kept.append(replace(server, ips=ips, groups=list(server.groups),
                                hostnames=list(server.hostnames),
                                ports={key: list(spec) for key, spec in server.ports.items()
                                       if key in ips or key in server.hostnames}))
    return kept, excluded


def unused_excludes(rules: Iterable[Union[str, ExcludeRule]],
                    excluded: Sequence[ExcludedAddress]) -> List[str]:
    """Labels of the rules that matched no target address (typo guard for a warning).

    Sorted address keys + bisect per rule span: O((rules + addresses) log n), so a long
    exclude file against a large excluded block stays instant (was rules x addresses).
    """
    keys = {4: set(), 6: set()}  # type: Dict[int, Set[int]]
    for ip in {entry.ip for entry in excluded}:
        for version, value in _match_keys(ip):
            keys[version].add(value)
    ordered = {version: sorted(values) for version, values in keys.items()}

    def matched(rule: ExcludeRule) -> bool:
        for version, first, last in rule.spans():
            values = ordered[version]
            index = bisect.bisect_left(values, first)
            if index < len(values) and values[index] <= last:
                return True
        return False

    return [rule.label for rule in _as_rules(rules) if not matched(rule)]


def excluded_address_count(excluded: Sequence[ExcludedAddress]) -> int:
    """Distinct addresses among ``excluded`` (one IP may belong to several servers)."""
    return len({entry.ip for entry in excluded})


# =====================================================================================
# Names to probe
# =====================================================================================

@dataclass(frozen=True)
class ProbeName:
    """A name to ask every server about.

    ``name`` is what the user cares about (``www.example.com`` or ``*.example.com``);
    ``sni`` is what goes into the ClientHello. For a wildcard the SNI is a synthetic
    label under it, so servers with a wildcard vhost answer with their wildcard cert.
    """

    name: str
    sni: str
    wildcard: bool = False


def parse_names_text(text: str) -> Tuple[List[str], List[str]]:
    """Split a names list (newlines, spaces, ``,`` ``;``; ``#`` comments) -> ``(valid, invalid)``.

    Valid names are normalized (lowercase punycode, wildcards kept) and deduplicated;
    names need at least one dot. IP literals are invalid (they are targets, not names).
    """
    valid, invalid = [], []  # type: List[str], List[str]
    for raw in text.lstrip('\ufeff').splitlines():
        line = _strip_comment(raw)
        for token in re.split(r'[\s,;]+', line):
            if not token:
                continue
            name = normalize_hostname(token, allow_wildcard=True)
            if name is None or '.' not in name.lstrip('*.'):
                invalid.append(token)
            elif name not in valid:
                valid.append(name)
    return valid, invalid


def load_names(values: Sequence[str], stdin: Optional[TextIO] = None
               ) -> Tuple[List[str], List[str]]:
    """Names from ``-n`` values: files, ``-`` (stdin) or literal names -> ``(names, warnings)``.

    A numeric "name" (``2026092401``, ``127.1``, ``0x7f.0x1``) given on the command line
    raises :class:`UsageError`; in a file or stdin it is skipped with a warning.
    """
    names, warnings = [], []  # type: List[str], List[str]
    for value in values:
        if value == '-':
            text, source = (stdin or sys.stdin).read(), '<stdin>'
        elif os.path.isfile(value):
            try:
                text, source = read_text_file(value), value
            except OSError as exc:
                raise UsageError('cannot read %s: %s' % (value, exc.strerror or exc))
        elif '://' not in value and _looks_like_path(value):
            raise UsageError('names file not found: %s' % value)
        else:
            text, source = value, 'argument'
        valid, invalid = parse_names_text(text)
        for name in valid:
            if name not in names:
                names.append(name)
        for token in invalid:
            if normalize_ip(token):
                warnings.append('%s: %s is an IP address - put IPs in -t targets' % (source, token))
            elif is_numeric_host(token):
                if source == 'argument':
                    raise UsageError('invalid name %r (-n): %s' % (token, numeric_host_note(token)))
                warnings.append('%s: skipped - %s' % (source, numeric_host_note(token)))
            else:
                warnings.append('%s: ignoring invalid name %r' % (source, token))
    return names, warnings


def inventory_names(servers: Iterable[Server]) -> List[str]:
    """The host names among the targets (``--estate`` asks every server for them too): a
    server named by a host name (``web01.example.com 192.0.2.10``, ``-t www.example.com``)
    and the host names a server was resolved from. Plain labels (``web01``), addresses and
    numeric names are not host names."""
    names = []  # type: List[str]
    for server in servers:
        for candidate in [server.name] + list(server.hostnames):
            if normalize_ip(candidate) or is_numeric_host(candidate):
                continue
            host = normalize_hostname(candidate)
            if host and '.' in host and host not in names:
                names.append(host)
    return names


def build_probe_names(names: Iterable[str], wildcard_probe: bool = True) -> List[ProbeName]:
    """Deduplicated probes for ``names``.

    ``*.example.com`` becomes the base ``example.com`` (probed like any name) plus, when
    ``wildcard_probe``, a wildcard probe with SNI ``ssl-origin-scan-wildcard-probe.example.com``
    that is "covered" only by certificates carrying the ``*.example.com`` SAN.
    """
    out = []  # type: List[ProbeName]
    seen = set()  # type: Set[str]

    def add(probe: ProbeName) -> None:
        if probe.name not in seen:
            seen.add(probe.name)
            out.append(probe)

    for raw in names:
        name = raw.strip().lower().rstrip('.')
        if not name:
            continue
        if name.startswith('*.'):
            base = name[2:]
            add(ProbeName(base, base))
            sni = '%s.%s' % (WILDCARD_PROBE_LABEL, base)
            if wildcard_probe and len(sni) <= 253:
                add(ProbeName(name, sni, True))
        else:
            add(ProbeName(name, name))
    return out


# =====================================================================================
# Certificate kinds: Cloudflare Origin CA, self-signed, private CAs (--private-ca)
# =====================================================================================

# The Cloudflare Origin CA roots (developers.cloudflare.com/ssl/static/origin_ca_rsa_root.pem
# and origin_ca_ecc_root.pem, checked 2026-09-27) have no CN: their subject is
# "ST=California, L=San Francisco, OU=CloudFlare Origin SSL [ECC ]Certificate Authority,
# O=CloudFlare, Inc., C=US", and they sign the origin certificates directly (subject
# "O=CloudFlare, Inc., OU=CloudFlare Origin CA, CN=CloudFlare Origin Certificate"). Only
# Cloudflare's edge trusts them. Matched case-insensitively on O plus OU (or CN).
ORIGIN_CA_ORGANIZATION = 'CloudFlare, Inc.'
ORIGIN_CA_NAMES = ('CloudFlare Origin SSL Certificate Authority',
                   'CloudFlare Origin SSL ECC Certificate Authority')

# Kinds of certificate (the JSON's certificates[].kind).
KIND_ORIGIN_CA = 'origin-ca'      # issued by the Cloudflare Origin CA
KIND_SELF_SIGNED = 'self-signed'  # issuer = subject (and the same key identifier)
KIND_PRIVATE_CA = 'private-ca'    # issued by a CA given with --private-ca
KIND_OTHER = 'other'              # anything else: a public CA, or a private CA not listed
_KIND_STATUS = {KIND_ORIGIN_CA: ORIGIN_CERT, KIND_SELF_SIGNED: PRIVATE_CERT,
                KIND_PRIVATE_CA: PRIVATE_CERT}


def _dn_key(dn: str) -> str:
    """A DN for comparison: case-folded, runs of whitespace collapsed (RFC 5280 7.1 lite)."""
    return re.sub(r'\s+', ' ', dn.strip()).casefold()


def is_origin_ca_certificate(cert: CertInfo) -> bool:
    """True when ``cert`` was issued by the Cloudflare Origin CA (RSA or ECC root)."""
    org = (cert.issuer.get('O') or '').strip().casefold()
    names = {(cert.issuer.get(attr) or '').strip().casefold() for attr in ('OU', 'CN')}
    return (org == ORIGIN_CA_ORGANIZATION.casefold()
            and any(name.casefold() in names for name in ORIGIN_CA_NAMES))


def issued_by(cert: CertInfo, ca: CertInfo) -> bool:
    """``cert`` names ``ca`` as its issuer: the issuer DN is the CA's subject DN, and the
    authority key identifier is the CA's subject key identifier when both are present
    (lib/x509.js ``issuedBy``). Signatures are not verified: this sorts certificates for
    a report, it never decides trust."""
    if _dn_key(cert.issuer_dn) != _dn_key(ca.subject_dn):
        return False
    return (not cert.authority_key_id or not ca.subject_key_id
            or cert.authority_key_id == ca.subject_key_id)


def certificate_kind(cert: CertInfo, private_cas: Sequence[CertInfo] = ()
                     ) -> Tuple[str, Optional[CertInfo]]:
    """``(kind, the --private-ca certificate that issued it or None)`` of a certificate.

    Origin CA first (a leaf, or the root itself), then self-signed, then the first
    ``--private-ca`` certificate that issued it; anything else is :data:`KIND_OTHER`.
    """
    if is_origin_ca_certificate(cert):
        return KIND_ORIGIN_CA, None
    if cert.self_signed:
        return KIND_SELF_SIGNED, None
    for ca in private_cas:
        if issued_by(cert, ca):
            return KIND_PRIVATE_CA, ca
    return KIND_OTHER, None


def _kind_family(kind: str) -> str:
    """Self-signed and private-CA certificates are one family: both are private."""
    return 'private' if kind in (KIND_SELF_SIGNED, KIND_PRIVATE_CA) else kind


class HostedClassifier:
    """The status of a certificate that covers a name but is not the new one.

    NEEDS_UPDATE, unless the certificate comes from another kind of CA than every new
    certificate: a Cloudflare Origin CA certificate is ORIGIN_CERT, a self-signed or
    ``--private-ca``-issued one PRIVATE_CERT. So a public certificate rollout does not
    list origins behind Cloudflare Full (strict) or internal hosts as still old, while
    rolling out an Origin CA (or a self-signed / private-CA) certificate still lists the
    older ones of that kind as NEEDS_UPDATE. A certificate with the same issuer DN as a
    new one is always NEEDS_UPDATE, and ``strict_public`` makes every one NEEDS_UPDATE.
    Without a new certificate every Origin CA / private certificate keeps its own status.
    """

    def __init__(self, new_certs: Sequence[CertInfo] = (), private_cas: Sequence[CertInfo] = (),
                 strict_public: bool = False) -> None:
        self.private_cas = list(private_cas)
        self.strict_public = strict_public
        self._cache = {}  # type: Dict[str, Tuple[str, Optional[CertInfo]]]
        self.new_families = {_kind_family(self.kind(cert)[0]) for cert in new_certs}
        self.new_issuers = {_dn_key(cert.issuer_dn) for cert in new_certs}

    def kind(self, cert: CertInfo) -> Tuple[str, Optional[CertInfo]]:
        """:func:`certificate_kind` with this scan's ``--private-ca`` list (memoised)."""
        if cert.sha256 not in self._cache:
            self._cache[cert.sha256] = certificate_kind(cert, self.private_cas)
        return self._cache[cert.sha256]

    def status(self, cert: CertInfo) -> str:
        """NEEDS_UPDATE, ORIGIN_CERT or PRIVATE_CERT for a covering, non-new certificate."""
        kind = self.kind(cert)[0]
        status = _KIND_STATUS.get(kind)
        if (status is None or self.strict_public or _kind_family(kind) in self.new_families
                or _dn_key(cert.issuer_dn) in self.new_issuers):
            return NEEDS_UPDATE
        return status


def load_private_cas(paths: Sequence[str]) -> Tuple[List[CertInfo], List[str]]:
    """``--private-ca FILE`` values -> ``(CA certificates, warning messages)``.

    Every certificate in each file counts (PEM with several blocks, DER, P7B), so a
    bundle with the root and its intermediates works. Raises :class:`UsageError` for an
    unreadable file or one without a certificate. A certificate that is not a CA
    (basicConstraints CA:FALSE) is kept with a warning: only what it issued would match.
    """
    cas = []  # type: List[CertInfo]
    messages = []  # type: List[str]
    for path in paths:
        try:
            with open(path, 'rb') as handle:
                data = handle.read()
        except OSError as exc:
            raise UsageError('cannot read --private-ca %s: %s' % (path, exc.strerror or exc))
        certs, cert_warnings = load_certificates(data)
        if not certs:
            details = '; '.join(detail for code, detail in cert_warnings if code == 'PARSE_ERROR')
            raise UsageError('--private-ca: no certificate found in %s%s'
                             % (path, ' (%s)' % details if details else ''))
        if any(code == 'PRIVATE_KEY_PRESENT' for code, _ in cert_warnings):
            messages.append('%s also contains a PRIVATE KEY - ignored (never needed; keep it '
                            'secret)' % path)
        for cert in certs:
            if not cert.is_ca:
                messages.append('--private-ca %s: %s is not a CA certificate; only certificates '
                                'it issued match' % (path, cert.short_label()))
            if all(cert.sha256 != known.sha256 for known in cas):
                cas.append(cert)
    return cas, messages


# =====================================================================================
# Scan engine
# =====================================================================================

@dataclass
class TlsResult:
    """Outcome of one TLS handshake: the peer certificate (DER) or a failure status."""

    der: Optional[bytes] = None
    version: Optional[str] = None
    cipher: Optional[str] = None
    status: Optional[str] = None   # set when the probe failed (TLS_ERROR, TIMEOUT, ...)
    error: Optional[str] = None
    elapsed_ms: int = 0
    # The server actively refused the handshake (TLS alert, EOF or reset). When other
    # names complete on the same ip:port, that means "this name is not hosted here".
    refused: bool = False
    # Closed, reset or refused below TLS (no alert): a per-client connection limiter does
    # that too, so run_scan retries such a handshake once before it counts.
    transient: bool = False


@dataclass
class Endpoint:
    """One ``ip:port`` and the result of the phase-1 TCP connect."""

    ip: str
    port: int
    state: str = 'PENDING'   # OPEN | CLOSED | TIMEOUT
    error: Optional[str] = None
    connect_ms: Optional[int] = None
    protocol: str = PROTO_TLS  # what is spoken before TLS: tls (nothing) or a STARTTLS one

    @property
    def label(self) -> str:
        """``203.0.113.10:443``, ``203.0.113.25:25/smtp``: the endpoint as a target names it."""
        return endpoint_text(self.ip, self.port, self.protocol)


@dataclass
class ProbeResult:
    """One result row: (server, ip, port, name) -> status."""

    server: str
    ip: str
    port: int
    probe: str                      # sni | wildcard | default | connect
    name: Optional[str]
    sni: Optional[str]
    status: str
    cert: Optional[CertInfo] = None
    covered_by: Optional[str] = None
    new_cert_covers: Optional[bool] = None   # None when no --cert was given
    tls_version: Optional[str] = None
    error: Optional[str] = None
    elapsed_ms: Optional[int] = None


@dataclass
class ServerSummary:
    """A server, its overall status and its result rows."""

    server: Server
    status: str
    rows: List[ProbeResult]
    # (ip, port) -> the STARTTLS protocol of the endpoints that spoke one (smtp, imap...)
    protocols: Dict[Tuple[str, int], str] = field(default_factory=dict)


@dataclass
class ScanReport:
    """Everything a scan produced; see :func:`report_to_dict` for the JSON shape."""

    servers: List[Server]
    probes: List[ProbeName]
    ports: List[int]
    new_certs: List[CertInfo]
    endpoints: List[Endpoint]
    results: List[ProbeResult]
    certificates: Dict[str, CertInfo]
    started_at: datetime
    finished_at: datetime
    timeout: float = DEFAULT_TIMEOUT
    workers: int = DEFAULT_WORKERS
    warnings: List[str] = field(default_factory=list)
    exclude: List[str] = field(default_factory=list)       # --exclude rules (labels)
    excluded: List[ExcludedAddress] = field(default_factory=list)  # removed, never probed
    private_cas: List[CertInfo] = field(default_factory=list)      # --private-ca certificates
    strict_public: bool = False                                    # --strict-public
    new_cert_files: Dict[str, str] = field(default_factory=dict)   # sha256 -> its --cert FILE
    # terminates_tls=no servers set aside (never connected to) without --include-backends
    skipped_backends: List[Server] = field(default_factory=list)
    include_backends: bool = False                                 # --include-backends
    audit: Optional['TlsAudit'] = None                             # --tls-audit
    profiles: List[str] = field(default_factory=list)              # --profile web|mail|all
    ari: bool = False                                              # --ari
    revocation: bool = False                                       # --revocation
    # sha256 -> {'ari': ..., 'revocation': ...} of every served certificate (check_certificate_status)
    cert_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    def protocol_of(self, ip: str, port: int) -> str:
        """The protocol endpoint ``ip:port`` was scanned with (tls when it is no endpoint)."""
        for endpoint in self.endpoints:
            if endpoint.ip == ip and endpoint.port == port:
                return endpoint.protocol
        return PROTO_TLS

    @property
    def has_topology(self) -> bool:
        """Whether the inventory gave any topology key (ports=, terminates_tls=, vip=,
        backends=, nat=): the reports then say where TLS terminates."""
        return any(server.has_topology() for server in self.servers + self.skipped_backends)

    @property
    def several_new_certs(self) -> bool:
        """Several new certificates (--cert repeated, e.g. an RSA + ECDSA pair or several
        certificates renewed together): the reports then name the one a server serves."""
        return len(self.new_certs) > 1

    def new_cert_file(self, cert: Optional[CertInfo]) -> Optional[str]:
        """The --cert FILE that ``cert`` came from, when it is one of several new
        certificates; None otherwise (one --cert, or a certificate that is not a new one)."""
        if cert is None or not self.several_new_certs:
            return None
        return self.new_cert_files.get(cert.sha256)

    def cert_kind(self, cert: CertInfo) -> Tuple[str, Optional[CertInfo]]:
        """:func:`certificate_kind` of ``cert`` with this scan's ``--private-ca`` list."""
        return certificate_kind(cert, self.private_cas)

    def excluded_count(self) -> int:
        """Distinct target addresses removed by --exclude."""
        return excluded_address_count(self.excluded)

    def rows_by_server(self) -> Dict[str, List[ProbeResult]]:
        """Result rows grouped by server name (input order)."""
        grouped = {server.name: [] for server in self.servers}  # type: Dict[str, List[ProbeResult]]
        for row in self.results:
            grouped.setdefault(row.server, []).append(row)
        return grouped

    def server_summaries(self) -> List[ServerSummary]:
        """One :class:`ServerSummary` per server, in input order."""
        grouped = self.rows_by_server()
        protocols = {(e.ip, e.port): e.protocol for e in self.endpoints
                     if e.protocol != PROTO_TLS}
        return [ServerSummary(server, server_status(grouped.get(server.name, [])),
                              grouped.get(server.name, []), protocols)
                for server in self.servers]

    def status_counts(self) -> Dict[str, int]:
        """Row counts per status over name probes and closed endpoints (not no-SNI probes)."""
        counts = {status: 0 for status in STATUSES}
        for row in self.results:
            if row.probe != PROBE_DEFAULT:
                counts[row.status] = counts.get(row.status, 0) + 1
        return counts

    def needs_update(self) -> bool:
        """True when at least one server has status NEEDS_UPDATE (so ORIGIN_CERT and
        PRIVATE_CERT servers do not count, unless --strict-public made them NEEDS_UPDATE)."""
        return any(s.status == NEEDS_UPDATE for s in self.server_summaries())


def is_relevant(row: ProbeResult) -> bool:
    """False for a name the new certificate does not cover (installing it would not help)."""
    return row.new_cert_covers is not False


def server_status(rows: Sequence[ProbeResult]) -> str:
    """Overall status of a server from its rows.

    NEEDS_UPDATE (any name the new cert covers, or its no-SNI default cert) > UPDATED >
    ORIGIN_CERT > PRIVATE_CERT > TLS_ERROR > TIMEOUT (handshake) > NOT_HOSTED (some port
    open) > TIMEOUT (connect) > CLOSED. A NEEDS_UPDATE / ORIGIN_CERT / PRIVATE_CERT row for
    a name the new certificate does not cover counts as NOT_HOSTED here: the server hosts
    that name with another certificate, and installing the new one would not change that.
    """
    named = set()  # type: Set[str]
    for row in rows:
        if row.probe in (PROBE_SNI, PROBE_WILDCARD):
            relevant = row.status not in HOSTED_STATUSES or is_relevant(row)
            named.add(row.status if relevant else NOT_HOSTED)
    default = {row.status for row in rows if row.probe == PROBE_DEFAULT}
    connect = {row.status for row in rows if row.probe == PROBE_CONNECT}
    for status in (NEEDS_UPDATE, UPDATED, ORIGIN_CERT, PRIVATE_CERT):
        if status in named or status in default:
            return status
    for status in (TLS_ERROR, TIMEOUT):
        if status in named:
            return status
    if named or default:
        return NOT_HOSTED
    if TIMEOUT in connect:
        return TIMEOUT
    return CLOSED


def make_client_context() -> ssl.SSLContext:
    """A deliberately permissive TLS client: we want *whatever* certificate is served.

    No verification (CERT_NONE, no hostname check), lowest protocol version the local
    OpenSSL allows, security level 0 ciphers and legacy renegotiation so very old
    servers still complete the handshake.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
    except (AttributeError, ValueError, ssl.SSLError):
        pass
    try:
        context.set_ciphers('ALL:@SECLEVEL=0')
    except ssl.SSLError:
        pass
    context.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
    return context


def _connect_address(ip: str) -> str:
    # IPv4-mapped IPv6 is dialled as plain IPv4 (dual-stack is not guaranteed).
    if ip.startswith('::ffff:') and '.' in ip:
        return ip[7:]
    return ip


def tcp_connect(ip: str, port: int, timeout: float) -> None:
    """Phase 1: open and immediately close a TCP connection (raises OSError on failure)."""
    sock = socket.create_connection((_connect_address(ip), port), timeout=timeout)
    sock.close()


def _clean_ssl_message(exc: BaseException) -> str:
    text = str(exc)
    text = re.sub(r'\s*\(_ssl\.c:\d+\)', '', text)
    return text or type(exc).__name__


def classify_exception(exc: BaseException) -> Tuple[str, str]:
    """Map a phase-2 (TLS handshake) exception to ``(status, short message)``.

    Phase 2 only dials ports phase 1 found open, so a refused connection here is a
    failure (a connection limiter, fail2ban, a restart), never CLOSED: a CLOSED name row
    would make the server "not hosting any of the names". Phase 1 uses
    :func:`classify_connect_exception`.
    """
    if isinstance(exc, StartTlsError):
        return TLS_ERROR, str(exc)
    if isinstance(exc, ssl.SSLError):
        if getattr(exc, 'reason', None) == 'TLSV1_UNRECOGNIZED_NAME':
            return NOT_HOSTED, 'server rejected the name (unrecognized_name alert)'
        if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
            return TLS_ERROR, 'connection closed during the TLS handshake'
        return TLS_ERROR, _clean_ssl_message(exc)
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return TIMEOUT, 'timed out'
    if isinstance(exc, ConnectionRefusedError):
        return TLS_ERROR, 'connection refused during the TLS phase (the port was open before)'
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return TLS_ERROR, 'connection reset during the TLS handshake'
    if isinstance(exc, OSError):
        return TLS_ERROR, exc.strerror or str(exc) or type(exc).__name__
    if isinstance(exc, (UnicodeError, ValueError)):
        return TLS_ERROR, 'invalid server name: %s' % exc
    return TLS_ERROR, '%s: %s' % (type(exc).__name__, exc)


def is_refusal(exc: BaseException) -> bool:
    """A TLS alert from the server, or the server closing/resetting during the handshake.

    Cloudflare, for example, answers an SNI it does not serve with a ``handshake_failure``
    alert, and HAProxy ``strict-sni`` simply closes the connection.
    """
    if isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError)):
        return True
    if isinstance(exc, ssl.SSLError):
        return 'ALERT' in str(getattr(exc, 'reason', '') or '')
    return isinstance(exc, (ConnectionResetError, ConnectionAbortedError))


def is_transient(exc: BaseException) -> bool:
    """The connection was closed, reset or refused without a TLS alert.

    A server that does not host a name says so with an alert or a close, but a per-client
    connection limiter (nginx stream ``limit_conn``, HAProxy ``src_conn_cur``, a WAF)
    also closes or resets - so these failures are worth one retry. On Linux a close before
    any TLS record can surface as ``SSLZeroReturnError`` instead of ``SSLEOFError``.
    """
    return isinstance(exc, (ssl.SSLEOFError, ssl.SSLZeroReturnError, ConnectionError))


def classify_connect_exception(exc: BaseException) -> Tuple[str, str]:
    """Map a phase-1 connect exception to ``(CLOSED|TIMEOUT, message)``."""
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return TIMEOUT, 'timed out'
    if isinstance(exc, ConnectionRefusedError):
        return CLOSED, 'connection refused'
    if isinstance(exc, OSError):
        return CLOSED, exc.strerror or str(exc) or type(exc).__name__
    return CLOSED, '%s: %s' % (type(exc).__name__, exc)


_TLS_HANDSHAKE, _TLS_CERTIFICATE, _TLS_CERTIFICATE_REQUEST = 22, 11, 13


def _watch_server_certificate(context: ssl.SSLContext, seen: threading.local) -> None:
    """Keep the server's Certificate and CertificateRequest messages of the handshake that runs
    on this thread in ``seen.messages`` (``SSLContext._msg_callback``, Python 3.8 and later; a
    no-op where it is missing)."""
    def callback(_conn: Any, direction: str, version: Any, content_type: int, msg_type: int,
                 data: bytes) -> None:
        try:
            messages = getattr(seen, 'messages', None)
            if (messages is not None and direction == 'read' and content_type == _TLS_HANDSHAKE
                    and msg_type in (_TLS_CERTIFICATE, _TLS_CERTIFICATE_REQUEST)):
                messages.append((int(msg_type), getattr(version, 'name', ''), bytes(data)))
        except Exception:  # noqa: BLE001 - an exception here would fail the handshake
            pass
    try:
        context._msg_callback = callback  # type: ignore[attr-defined]
    except (AttributeError, TypeError, ValueError):
        pass


def _certificate_before_client_request(messages: List[Tuple[int, str, bytes]]
                                       ) -> Tuple[Optional[bytes], Optional[str]]:
    """The server's leaf (DER) and TLS version when it sent its certificate and then asked for a
    client certificate (mutual TLS): in TLS 1.2 such a vhost aborts the handshake once the client
    has none, but the certificate it serves for the name has arrived."""
    if not any(msg_type == _TLS_CERTIFICATE_REQUEST for msg_type, _, _ in messages):
        return None, None
    for msg_type, version, data in messages:
        if msg_type != _TLS_CERTIFICATE:
            continue
        body = data[4:]  # type (1 byte) and length (3) of the handshake message
        if version == 'TLSv1_3' and body:
            body = body[1 + body[0]:]  # certificate_request_context
        size = int.from_bytes(body[3:6], 'big') if len(body) >= 6 else 0
        der = body[6:6 + size]
        if size and len(der) == size:
            return der, version.replace('_', '.') or None
    return None, None


# =====================================================================================
# STARTTLS: the plain-text exchange before TLS on mail, directory, file, chat and database ports
# =====================================================================================

STARTTLS_MAX_BYTES = 64 * 1024   # what a server may send before TLS starts
_STARTTLS_LINE_MAX = 4096
_LDAP_STARTTLS_OID = b'1.3.6.1.4.1.1466.20037'
# LDAPMessage { messageID 1, ExtendedRequest [APPLICATION 23] { requestName [0] StartTLS } }
_LDAP_STARTTLS_REQUEST = (b'\x30\x1d\x02\x01\x01\x77\x18\x80\x16' + _LDAP_STARTTLS_OID)
_PG_SSL_REQUEST = (8).to_bytes(4, 'big') + (80877103).to_bytes(4, 'big')   # SSLRequest
_XMPP_TLS_NS = 'urn:ietf:params:xml:ns:xmpp-tls'


class StartTlsError(Exception):
    """The exchange before TLS failed: no STARTTLS offered, refused, or not that protocol."""


class _PlainChannel:
    """The plain socket before STARTTLS: bounded reads of lines, bytes and XML up to a marker."""

    def __init__(self, sock: socket.socket, protocol: str) -> None:
        self.sock = sock
        self.label = PROTOCOL_LABELS.get(protocol, protocol)
        self.buffer = b''
        self.total = 0

    def fail(self, text: str) -> StartTlsError:
        return StartTlsError('%s: %s' % (self.label, text))

    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def _fill(self) -> None:
        chunk = self.sock.recv(4096)
        if not chunk:
            raise self.fail('the server closed the connection before TLS started')
        self.total += len(chunk)
        if self.total > STARTTLS_MAX_BYTES:
            raise self.fail('more than %d bytes before TLS started' % STARTTLS_MAX_BYTES)
        self.buffer += chunk

    def line(self) -> str:
        while b'\n' not in self.buffer:
            if len(self.buffer) > _STARTTLS_LINE_MAX:
                raise self.fail('a line longer than %d bytes' % _STARTTLS_LINE_MAX)
            self._fill()
        line, _, self.buffer = self.buffer.partition(b'\n')
        return line.rstrip(b'\r').decode('latin-1')

    def exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            self._fill()
        data, self.buffer = self.buffer[:size], self.buffer[size:]
        return data

    def element(self, *markers: bytes) -> Tuple[bytes, bytes]:
        """Read until one of ``markers`` and the ``>`` that closes it: (that marker, what was
        read up to there); the rest stays buffered."""
        while True:
            hits = [(self.buffer.find(m), m) for m in markers if m in self.buffer]
            if hits:
                at, marker = min(hits)
                close = self.buffer.find(b'>', at)
                if close >= 0:
                    data, self.buffer = self.buffer[:close + 1], self.buffer[close + 1:]
                    return marker, data
            self._fill()

    def reply(self, ftp: bool = False) -> Tuple[int, List[str]]:
        """An SMTP / FTP reply: its code and the text of its lines (``250-...`` continues;
        an FTP reply may hold lines without the code until ``NNN text``)."""
        first = self.line()
        if len(first) < 3 or not first[:3].isdigit() or first[3:4] not in ('', ' ', '-'):
            raise self.fail('not a %s reply: %s' % (self.label, _clip_text(first)))
        code, lines = first[:3], [first[4:]]
        more = first[3:4] == '-'
        while more:
            line = self.line()
            if line[:3] == code and line[3:4] in ('', ' ', '-'):
                lines.append(line[4:])
                more = line[3:4] == '-'
            elif ftp:
                lines.append(line)
            else:
                raise self.fail('not a %s reply: %s' % (self.label, _clip_text(line)))
        return int(code), lines

    def done(self) -> None:
        """TLS starts now: bytes the server sent past its go-ahead would not be TLS."""
        if self.buffer:
            raise self.fail('data after the go-ahead for TLS')


def _clip_text(text: str, limit: int = 120) -> str:
    text = ''.join(ch if ' ' <= ch <= '~' else '?' for ch in text.strip())
    return text if len(text) <= limit else text[:limit - 3] + '...'


def _starttls_smtp(channel: _PlainChannel, sni: Optional[str]) -> None:
    code, lines = channel.reply()
    if code != 220:
        raise channel.fail('greeting %d %s' % (code, _clip_text(lines[-1])))
    local = channel.sock.getsockname()[0]
    literal = '[IPv6:%s]' % local if ':' in local else '[%s]' % local  # RFC 5321 address literal
    channel.send(('EHLO %s\r\n' % literal).encode('ascii'))
    code, lines = channel.reply()
    if code != 250:
        raise channel.fail('EHLO answered %d %s' % (code, _clip_text(lines[-1])))
    if not any(line.split(' ', 1)[0].upper() == 'STARTTLS' for line in lines[1:]):
        raise channel.fail('the server does not offer STARTTLS')
    channel.send(b'STARTTLS\r\n')
    code, lines = channel.reply()
    if code != 220:
        raise channel.fail('STARTTLS answered %d %s' % (code, _clip_text(lines[-1])))


def _starttls_imap(channel: _PlainChannel, sni: Optional[str]) -> None:
    greeting = channel.line()
    if not greeting.upper().startswith(('* OK', '* PREAUTH')):
        raise channel.fail('greeting %s' % _clip_text(greeting))
    channel.send(b'a1 STARTTLS\r\n')
    while True:
        line = channel.line()
        if line.startswith('* '):  # untagged (a CAPABILITY list)
            continue
        if line.lower().startswith('a1 '):
            if line[3:].upper().startswith('OK'):
                return
            raise channel.fail('STARTTLS answered %s' % _clip_text(line[3:]))
        raise channel.fail('unexpected answer %s' % _clip_text(line))


def _starttls_pop3(channel: _PlainChannel, sni: Optional[str]) -> None:
    greeting = channel.line()
    if not greeting.startswith('+OK'):
        raise channel.fail('greeting %s' % _clip_text(greeting))
    channel.send(b'STLS\r\n')
    answer = channel.line()
    if not answer.startswith('+OK'):
        raise channel.fail('STLS answered %s' % _clip_text(answer))


def _starttls_ftp(channel: _PlainChannel, sni: Optional[str]) -> None:
    code, lines = channel.reply(ftp=True)
    if code != 220:
        raise channel.fail('greeting %d %s' % (code, _clip_text(lines[-1])))
    channel.send(b'AUTH TLS\r\n')
    code, lines = channel.reply(ftp=True)
    if code != 234:
        raise channel.fail('AUTH TLS answered %d %s' % (code, _clip_text(lines[-1])))


def _ber_tlv(data: bytes, pos: int, end: int) -> Tuple[int, int, int]:
    """(tag, content start, content end) of the BER TLV at ``pos`` (LDAP servers write lengths
    in long form, OpenLDAP with four bytes); ValueError when it does not fit before ``end``."""
    if pos + 2 > end:
        raise ValueError('truncated')
    tag, size = data[pos], data[pos + 1]
    pos += 2
    if size & 0x80:
        count = size & 0x7F
        if not 1 <= count <= 4 or pos + count > end:
            raise ValueError('bad length')
        size = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    if pos + size > end:
        raise ValueError('truncated')
    return tag, pos, pos + size


def _starttls_ldap(channel: _PlainChannel, sni: Optional[str]) -> None:
    channel.send(_LDAP_STARTTLS_REQUEST)
    head = channel.exact(2)
    if head[0] != 0x30:
        raise channel.fail('not an LDAP answer')
    count = head[1] & 0x7F if head[1] & 0x80 else 0
    if head[1] & 0x80 and not 1 <= count <= 4:
        raise channel.fail('not an LDAP answer')
    length = channel.exact(count) if count else b''
    size = int.from_bytes(length, 'big') if count else head[1]
    body = channel.exact(size)
    try:
        _tag, _start, after_id = _ber_tlv(body, 0, len(body))         # messageID
        tag, start, end = _ber_tlv(body, after_id, len(body))          # ExtendedResponse
        code_tag, code_start, code_end = _ber_tlv(body, start, end)    # resultCode
        detail = ''
        if code_end < end:
            _t, _s, matched_end = _ber_tlv(body, code_end, end)        # matchedDN
            if matched_end < end:
                _t, text_start, text_end = _ber_tlv(body, matched_end, end)  # diagnostic
                detail = body[text_start:text_end].decode('utf-8', 'replace')
    except ValueError:
        raise channel.fail('not an LDAP answer')
    if tag != 0x78 or code_tag != 0x0A:
        raise channel.fail('not an ExtendedResponse to StartTLS')
    code = int.from_bytes(body[code_start:code_end], 'big')
    if code != 0:
        raise channel.fail('StartTLS refused (result code %d%s)'
                           % (code, ': ' + _clip_text(detail) if detail.strip() else ''))


def _starttls_xmpp(channel: _PlainChannel, sni: Optional[str]) -> None:
    to = " to='%s'" % sni if sni else ''  # the XMPP domain; a host name never holds a quote
    channel.send(("<?xml version='1.0'?><stream:stream%s version='1.0' xmlns='jabber:client' "
                  "xmlns:stream='http://etherx.jabber.org/streams'>" % to).encode('ascii'))
    marker, data = channel.element(b'</stream:features', b'</features', b'<stream:error',
                                   b'</stream:stream')
    if marker != b'</stream:features' and marker != b'</features':
        raise channel.fail('the server ended the stream before its features')
    if _XMPP_TLS_NS.encode('ascii') not in data:
        raise channel.fail('the server does not offer STARTTLS')
    channel.send(("<starttls xmlns='%s'/>" % _XMPP_TLS_NS).encode('ascii'))
    marker, _data = channel.element(b'<proceed', b'<failure', b'<stream:error', b'</stream:stream')
    if marker != b'<proceed':
        raise channel.fail('STARTTLS refused')


def _starttls_postgres(channel: _PlainChannel, sni: Optional[str]) -> None:
    channel.send(_PG_SSL_REQUEST)
    answer = channel.exact(1)
    if answer == b'N':
        raise channel.fail('the server does not accept SSL connections (ssl = off)')
    if answer != b'S':
        raise channel.fail('unexpected answer to the SSLRequest')


# RDP (MS-RDPBCGR, the connection request and confirm PDUs): an X.224 Connection Request in a
# TPKT carrying an RDP_NEG_REQ that asks for TLS or CredSSP (requestedProtocols PROTOCOL_SSL |
# PROTOCOL_HYBRID); the Connection Confirm's RDP_NEG_RSP names the one chosen, and the TLS
# handshake follows on the same connection (CredSSP runs over TLS). A server on the RDP Security
# Layer alone answers RDP_NEG_FAILURE, or a Connection Confirm without negotiation data: no TLS.
_RDP_REQUEST = (b'\x03\x00\x00\x13'                # TPKT: version 3, 19 bytes
                b'\x0e\xe0\x00\x00\x00\x00\x00'      # X.224 CR, LI 14, class 0
                b'\x01\x00\x08\x00\x03\x00\x00\x00')  # RDP_NEG_REQ: SSL | HYBRID
_RDP_TLS_PROTOCOLS = {1: 'TLS', 2: 'CredSSP', 8: 'CredSSP'}   # PROTOCOL_SSL, _HYBRID, _HYBRID_EX
_RDP_FAILURES = {1: 'SSL_REQUIRED_BY_SERVER', 2: 'SSL_NOT_ALLOWED_BY_SERVER',
                 3: 'SSL_CERT_NOT_ON_SERVER', 4: 'INCONSISTENT_FLAGS',
                 5: 'HYBRID_REQUIRED_BY_SERVER', 6: 'SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER'}


def _starttls_rdp(channel: _PlainChannel, sni: Optional[str]) -> None:
    channel.send(_RDP_REQUEST)
    head = channel.exact(4)
    size = int.from_bytes(head[2:4], 'big')
    if head[0] != 3 or not 11 <= size <= 512:
        raise channel.fail('not an RDP answer (no TPKT header)')
    body = channel.exact(size - 4)
    # X.224 Connection Confirm: LI, CC (0xD0), DST-REF, SRC-REF, class; then RDP_NEG data
    if body[1] & 0xF0 != 0xD0:
        raise channel.fail('not an X.224 Connection Confirm')
    neg = body[7:15]
    if len(neg) < 8:
        raise channel.fail('the server offers only Standard RDP Security (no TLS)')
    kind, value = neg[0], int.from_bytes(neg[4:8], 'little')
    if kind == 0x03:
        raise channel.fail('the server refused TLS (%s)'
                           % _RDP_FAILURES.get(value, 'failure code %d' % value))
    if kind != 0x02:
        raise channel.fail('not an RDP negotiation response')
    if value not in _RDP_TLS_PROTOCOLS:
        raise channel.fail('the server chose Standard RDP Security (no TLS)' if value == 0 else
                           'the server chose an unknown security protocol (0x%x)' % value)


_STARTTLS = {PROTO_SMTP: _starttls_smtp, PROTO_IMAP: _starttls_imap, PROTO_POP3: _starttls_pop3,
             PROTO_FTP: _starttls_ftp, PROTO_LDAP: _starttls_ldap, PROTO_XMPP: _starttls_xmpp,
             PROTO_POSTGRES: _starttls_postgres, PROTO_RDP: _starttls_rdp}


def starttls(sock: socket.socket, protocol: str, sni: Optional[str] = None) -> None:
    """Speak ``protocol`` on the connected ``sock`` up to where TLS starts (nothing for TLS).

    SMTP: greeting, EHLO, STARTTLS; IMAP: ``STARTTLS``; POP3: ``STLS``; FTP: ``AUTH TLS``
    (RFC 4217); LDAP: the StartTLS extended operation; XMPP: the client stream to the domain
    ``sni`` and ``<starttls/>``; PostgreSQL: the SSLRequest; RDP: the X.224 connection request
    asking for TLS or CredSSP. Raises :class:`StartTlsError` (or the socket's OSError /
    timeout).
    """
    if protocol == PROTO_TLS:
        return
    handler = _STARTTLS.get(protocol)
    if handler is None:
        raise StartTlsError('unknown protocol %s' % protocol)
    channel = _PlainChannel(sock, protocol)
    handler(channel, sni)
    channel.done()


class TlsProber:
    """Phase 2: TLS handshake with optional SNI, returning the peer certificate (DER); on a
    STARTTLS endpoint, after the protocol's plain-text exchange (:func:`starttls`)."""

    def __init__(self, context: Optional[ssl.SSLContext] = None) -> None:
        self.context = context or make_client_context()
        self._seen = threading.local()
        _watch_server_certificate(self.context, self._seen)

    def __call__(self, ip: str, port: int, sni: Optional[str], timeout: float,
                 protocol: str = PROTO_TLS) -> TlsResult:
        started = time.monotonic()
        sock = None
        self._seen.messages = []
        try:
            sock = socket.create_connection((_connect_address(ip), port), timeout=timeout)
            starttls(sock, protocol, sni)
            tls = self.context.wrap_socket(sock, server_hostname=sni,
                                           do_handshake_on_connect=False)
            sock = tls  # closing the wrapper closes the underlying socket
            tls.settimeout(timeout)
            tls.do_handshake()
            der = tls.getpeercert(binary_form=True)
            cipher = tls.cipher()
            result = TlsResult(der=der, version=tls.version(),
                               cipher=cipher[0] if cipher else None)
            if not der:
                result = TlsResult(status=TLS_ERROR, error='server sent no certificate')
        except Exception as exc:  # noqa: BLE001 - every failure becomes a status
            status, message = classify_exception(exc)
            der, version = _certificate_before_client_request(self._seen.messages)
            if der and is_refusal(exc):
                # mutual TLS: the vhost hosts the name and serves this certificate for it
                result = TlsResult(der=der, version=version)
            else:
                result = TlsResult(status=status, error=message, refused=is_refusal(exc),
                                   transient=is_transient(exc))
        finally:
            self._seen.messages = None
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass
        result.elapsed_ms = int((time.monotonic() - started) * 1000)
        return result


# Yielded by a _parallel item source: its next item has to wait for a running task.
_WAIT = object()


def _parallel(func: Callable[[Any], Any], items: Iterable[Any], workers: int,
              on_result: Callable[[Any, Any], None], cancel: threading.Event,
              poll: float = 0.2) -> None:
    """Run ``func`` over ``items`` on a thread pool, calling ``on_result`` in this thread.

    At most ``2 * workers`` tasks are in flight, so huge CIDRs do not create millions of
    futures. ``items`` may yield :data:`_WAIT` (never while nothing runs): the next item
    is then asked for after the next ``on_result``. Waits in short slices so Ctrl-C
    (KeyboardInterrupt) is delivered promptly; on any exception pending work is cancelled
    and the pool is abandoned (not joined).
    """
    executor = ThreadPoolExecutor(max_workers=max(1, workers),
                                  thread_name_prefix='ssl-origin-scan')
    iterator = iter(items)
    inflight = {}  # type: Dict[Any, Any]
    try:
        exhausted = False
        while True:
            while not exhausted and len(inflight) < workers * 2 and not cancel.is_set():
                try:
                    item = next(iterator)
                except StopIteration:
                    exhausted = True
                    break
                if item is _WAIT:
                    break
                inflight[executor.submit(func, item)] = item
            if not inflight:
                break
            done, _ = wait(list(inflight), timeout=poll, return_when=FIRST_COMPLETED)
            for future in done:
                on_result(inflight.pop(future), future.result())
            if cancel.is_set() and not done:
                break
    except BaseException:
        cancel.set()
        for future in inflight:
            future.cancel()
        try:
            executor.shutdown(wait=False, cancel_futures=True)  # type: ignore[call-arg]
        except TypeError:  # Python 3.8
            executor.shutdown(wait=False)
        raise
    executor.shutdown(wait=True)


ProgressCallback = Callable[[str, int, int, Dict[str, int]], None]


def run_scan(servers: Sequence[Server], probes: Sequence[ProbeName], ports: Sequence[int],
             new_certs: Sequence[CertInfo] = (), timeout: float = DEFAULT_TIMEOUT,
             workers: int = DEFAULT_WORKERS,
             connect_fn: Optional[Callable[[str, int, float], None]] = None,
             tls_fn: Optional[Callable[[str, int, Optional[str], float], TlsResult]] = None,
             progress: Optional[ProgressCallback] = None,
             cancel: Optional[threading.Event] = None,
             default_probe: bool = True, warnings: Optional[List[str]] = None,
             exclude: Iterable[Union[str, ExcludeRule]] = (),
             private_cas: Sequence[CertInfo] = (), strict_public: bool = False,
             new_cert_files: Optional[Dict[str, str]] = None,
             include_backends: bool = False) -> ScanReport:
    """Probe every ``server IP x port`` for every name and classify the results.

    A served certificate that is any of ``new_certs`` is UPDATED; ``new_cert_files``
    (sha256 -> the --cert FILE) lets the reports name which one when there are several.

    ``ports`` apply to every address except those with ports of their own
    (:attr:`Server.ports`), and to no address of a server with TLS ports of its own
    (``ports=``, :attr:`Server.tls_ports`): each server is scanned only on its own ports. A
    server with ``terminates_tls=no`` (a plain-HTTP backend, never given the certificate) is
    set aside, never connected to, and listed in :attr:`ScanReport.skipped_backends` unless
    ``include_backends`` - but a load balancer with TLS terminating nowhere behind it is
    scanned (:func:`servers_set_aside`). A certificate that covers a name but is not the new one is
    NEEDS_UPDATE, ORIGIN_CERT or PRIVATE_CERT (:class:`HostedClassifier` with
    ``private_cas`` and ``strict_public``).
    Addresses matching ``exclude`` (:class:`ExcludeRule` objects or IP / CIDR / range
    strings) are removed first - never connected to - and listed in
    :attr:`ScanReport.excluded`. Phase 1 TCP-connects each unique ip:port
    (``connect_fn``); phase 2 runs one TLS handshake per open endpoint and unique SNI
    plus one without SNI (``tls_fn``), at most :data:`MAX_PER_ENDPOINT` at a time per
    endpoint unless its last ones all timed out, and retries a closed / reset / refused
    handshake (:func:`is_transient`) once where others completed. Both functions are
    injectable for tests. ``progress(phase, done, total, info)`` is called from this
    thread with phase ``connect``, ``tls`` or ``retry``. KeyboardInterrupt propagates.
    """
    connect_fn = connect_fn or tcp_connect
    tls_fn = tls_fn or TlsProber()
    cancel = cancel or threading.Event()
    started = _utcnow()
    ports = list(ports)
    exclude_rules = _as_rules(exclude)
    servers, excluded = apply_excludes(servers, exclude_rules)
    skipped = [] if include_backends else servers_set_aside(servers)
    if skipped:
        set_aside = {id(server) for server in skipped}
        servers = [server for server in servers if id(server) not in set_aside]

    # The protocol spoken before TLS follows the port (25: SMTP), unless the port was written
    # with one (203.0.113.10:2525/smtp), or -p names one for that number (-p 2525/smtp).
    overrides = port_protocols(ports)
    endpoints = {}  # type: Dict[Tuple[str, int], Endpoint]
    for server in servers:
        for ip in server.ips:
            for port in server.ports_for(ip, ports):
                if (ip, port) not in endpoints:
                    endpoints[(ip, port)] = Endpoint(ip, int(port),
                                                     protocol=endpoint_protocol(port, overrides))

    # Phase 1 - which ports are open at all.
    counters = {'done': 0, 'open': 0}

    def do_connect(endpoint: Endpoint) -> Tuple[str, Optional[str], int]:
        begun = time.monotonic()
        try:
            connect_fn(endpoint.ip, endpoint.port, timeout)
            state, message = OPEN, None  # type: str, Optional[str]
        except Exception as exc:  # noqa: BLE001
            state, message = classify_connect_exception(exc)
        return state, message, int((time.monotonic() - begun) * 1000)

    def on_connect(endpoint: Endpoint, outcome: Tuple[str, Optional[str], int]) -> None:
        endpoint.state, endpoint.error, endpoint.connect_ms = outcome
        counters['done'] += 1
        if endpoint.state == OPEN:
            counters['open'] += 1
        if progress:
            progress('connect', counters['done'], len(endpoints), {'open': counters['open']})

    _parallel(do_connect, list(endpoints.values()), workers, on_connect, cancel)

    # Phase 2 - one handshake per open endpoint and distinct SNI (None = no SNI). The jobs
    # go name by name across the endpoints and at most MAX_PER_ENDPOINT run against one
    # ip:port at a time: dozens of simultaneous handshakes from one client trip per-client
    # connection limits, and the resets would read as "server refused this name". The cap
    # is kept by handing out jobs, so a job that has to wait never holds a worker thread.
    snis = [None] if default_probe else []  # type: List[Optional[str]]
    seen_snis = set()  # type: Set[str]
    for probe in probes:
        if probe.sni not in seen_snis:
            seen_snis.add(probe.sni)
            snis.append(probe.sni)
    open_keys = [key for key, endpoint in endpoints.items() if endpoint.state == OPEN]
    tls_total = len(open_keys) * len(snis)
    handed = dict.fromkeys(open_keys, 0)    # SNIs handed out, in the order of snis
    running = dict.fromkeys(open_keys, 0)
    timeout_run = dict.fromkeys(open_keys, 0)  # handshakes in a row that ended in TIMEOUT
    handshakes = {}  # type: Dict[Tuple[str, int, Optional[str]], TlsResult]
    tls_done = [0]

    def capped(key: Tuple[str, int]) -> bool:
        # A silent endpoint - its last MAX_PER_ENDPOINT handshakes all timed out: a
        # tarpit, a balancer without a backend, an SNI router whose backend for the rest
        # of the names hangs - is not capped: there is no limiter to spare, and one
        # timeout per MAX_PER_ENDPOINT names would stall the scan. The cap is back as
        # soon as a handshake there ends otherwise.
        silent = timeout_run[key] >= MAX_PER_ENDPOINT
        return running[key] >= MAX_PER_ENDPOINT and not silent

    def tls_jobs() -> Iterable[Any]:
        pending = list(open_keys) if snis else []  # probes=[] and no default probe: nothing to do
        while pending:
            progressed = False
            for key in pending:
                if not capped(key):
                    progressed = True
                    running[key] += 1
                    handed[key] += 1
                    yield endpoints[key], snis[handed[key] - 1]
            pending = [key for key in pending if handed[key] < len(snis)]
            if not progressed:
                yield _WAIT  # every endpoint left is at its cap: wait for a handshake

    def do_tls(job: Tuple[Endpoint, Optional[str]]) -> TlsResult:
        endpoint, sni = job
        try:
            if endpoint.protocol != PROTO_TLS:  # STARTTLS first (an injected tls_fn takes it)
                return tls_fn(endpoint.ip, endpoint.port, sni, timeout, endpoint.protocol)
            return tls_fn(endpoint.ip, endpoint.port, sni, timeout)
        except Exception as exc:  # noqa: BLE001 - injected/unknown failures
            status, message = classify_exception(exc)
            return TlsResult(status=status, error=message, refused=is_refusal(exc),
                             transient=is_transient(exc))

    def on_tls(job: Tuple[Endpoint, Optional[str]], result: TlsResult) -> None:
        key = (job[0].ip, job[0].port)
        handshakes[(key[0], key[1], job[1])] = result
        running[key] -= 1
        timeout_run[key] = timeout_run[key] + 1 if result.status == TIMEOUT else 0
        tls_done[0] += 1
        if progress:
            progress('tls', tls_done[0], tls_total, {})

    _parallel(do_tls, tls_jobs(), workers, on_tls, cancel)

    # Endpoints where at least one handshake completed: TLS itself works there, so a
    # handshake the server refuses for one particular name means "not hosted".
    working = {(ip, port) for (ip, port, _sni), result in handshakes.items() if result.der}
    # Before that rule applies, a close / reset / refusal there is retried once, one
    # handshake at a time per endpoint (endpoints in parallel): a connection limiter lets
    # it through now, a server that does not host the name refuses it again.
    retries = {}  # type: Dict[Tuple[str, int], List[Optional[str]]]
    for (ip, port, sni), result in handshakes.items():
        if result.transient and (ip, port) in working:
            retries.setdefault((ip, port), []).append(sni)
    retry_total = sum(len(names) for names in retries.values())
    retry_done = [0]

    def do_retries(key: Tuple[str, int]) -> List[Tuple[Optional[str], TlsResult]]:
        return [(sni, do_tls((endpoints[key], sni))) for sni in retries[key]]

    def on_retries(key: Tuple[str, int], outcomes: List[Tuple[Optional[str], TlsResult]]
                   ) -> None:
        for sni, result in outcomes:
            handshakes[(key[0], key[1], sni)] = result
        retry_done[0] += len(outcomes)
        if progress:
            progress('retry', retry_done[0], retry_total, {})

    if retries and not cancel.is_set():
        _parallel(do_retries, list(retries), workers, on_retries, cancel)

    # Verdicts.
    new_fps = {cert.sha256 for cert in new_certs}
    hosted = HostedClassifier(new_certs, private_cas, strict_public).status
    parsed = {}  # type: Dict[bytes, Union[CertInfo, str]]
    certificates = {}  # type: Dict[str, CertInfo]

    def cert_of(result: TlsResult) -> Union[CertInfo, str]:
        der = result.der or b''
        if der not in parsed:
            try:
                cert = parse_certificate(der)
                certificates.setdefault(cert.sha256, cert)
                parsed[der] = cert
            except _CERT_PARSE_ERRORS as exc:
                parsed[der] = 'unparseable certificate: %s' % exc
        return parsed[der]

    def new_covers(sni: str) -> Optional[bool]:
        if not new_certs:
            return None
        return any(cert.covers(sni)[0] for cert in new_certs)

    # The no-SNI default cert only matters for names the new certificate is meant for.
    relevant_probes = [probe for probe in probes if new_covers(probe.sni) is not False]
    results = []  # type: List[ProbeResult]
    for server in servers:
        for ip in server.ips:
            for port in server.ports_for(ip, ports):
                endpoint = endpoints[(ip, port)]
                port = endpoint.port  # the number (a 2525/smtp target's port is one too)
                if endpoint.state != OPEN:
                    results.append(ProbeResult(server.name, ip, port, PROBE_CONNECT, None, None,
                                               endpoint.state, error=endpoint.error,
                                               elapsed_ms=endpoint.connect_ms))
                    continue
                works = (ip, port) in working
                if default_probe:
                    results.append(_verdict(server.name, endpoint, None, None,
                                            handshakes.get((ip, port, None)), cert_of, new_fps,
                                            relevant_probes, None, works=works, hosted=hosted))
                for probe in probes:
                    results.append(_verdict(server.name, endpoint, probe.name, probe.sni,
                                            handshakes.get((ip, port, probe.sni)), cert_of,
                                            new_fps, probes, new_covers(probe.sni),
                                            PROBE_WILDCARD if probe.wildcard else PROBE_SNI,
                                            works=works, hosted=hosted))
    return ScanReport(servers=list(servers), probes=list(probes), ports=ports,
                      new_certs=list(new_certs), endpoints=list(endpoints.values()),
                      results=results, certificates=certificates, started_at=started,
                      finished_at=_utcnow(), timeout=timeout, workers=workers,
                      warnings=list(warnings or []),
                      exclude=[rule.label for rule in exclude_rules], excluded=excluded,
                      private_cas=list(private_cas), strict_public=strict_public,
                      new_cert_files=dict(new_cert_files or {}), skipped_backends=skipped,
                      include_backends=include_backends)


def _verdict(server: str, endpoint: Endpoint, name: Optional[str], sni: Optional[str],
             result: Optional[TlsResult], cert_of: Callable[[TlsResult], Union[CertInfo, str]],
             new_fps: Set[str], probes: Sequence[ProbeName], new_cert_covers: Optional[bool],
             kind: str = PROBE_DEFAULT, works: bool = False,
             hosted: Callable[[CertInfo], str] = lambda cert: NEEDS_UPDATE) -> ProbeResult:
    """Classify one handshake result into a :class:`ProbeResult` row.

    ``works`` tells whether any other handshake on the same ip:port completed; ``hosted``
    gives the status of a covering certificate that is not the new one
    (:meth:`HostedClassifier.status`).
    """
    row = ProbeResult(server, endpoint.ip, endpoint.port, kind, name, sni, TLS_ERROR,
                      new_cert_covers=new_cert_covers)
    if result is None:  # interrupted before this handshake ran
        row.error = 'not probed'
        return row
    row.elapsed_ms = result.elapsed_ms
    row.tls_version = result.version
    if result.status:
        row.status, row.error = result.status, result.error
        if result.status == TLS_ERROR and result.refused and works:
            row.status = NOT_HOSTED
            row.error = '%s (%s)' % ('server requires SNI' if kind == PROBE_DEFAULT
                                     else 'server refused this name', result.error)
        return row
    cert = cert_of(result)
    if isinstance(cert, str):
        row.error = cert
        return row
    row.cert = cert
    if kind == PROBE_DEFAULT:
        # No name asked: the default cert matters when it is the new cert or covers any name.
        if cert.sha256 in new_fps:
            row.status = UPDATED
            return row
        for probe in probes:
            covered, by = cert.covers(probe.sni)
            if covered:
                row.status, row.covered_by = hosted(cert), by
                return row
        row.status = NOT_HOSTED
        return row
    covered, by = cert.covers(sni or '')
    row.covered_by = by
    if not covered:
        row.status = NOT_HOSTED
    elif cert.sha256 in new_fps:
        row.status = UPDATED
    else:
        row.status = hosted(cert)
    return row


# =====================================================================================
# Output: JSON, CSV, human summary
# =====================================================================================

# =====================================================================================
# --tls-audit: the TLS versions, weak cipher suites and key types each endpoint accepts
# =====================================================================================

AUDIT_VERSIONS = ('TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3')
LEGACY_VERSIONS = ('TLSv1.0', 'TLSv1.1')
_AUDIT_VERSION_ATTRS = {'TLSv1.0': 'TLSv1', 'TLSv1.1': 'TLSv1_1', 'TLSv1.2': 'TLSv1_2',
                        'TLSv1.3': 'TLSv1_3'}
# Weak cipher suites, offered one family at a time with TLS 1.2 at most (OpenSSL cipher strings)
WEAK_CIPHER_GROUPS = (('null', 'eNULL'), ('anon', 'aNULL'), ('export', 'EXP'), ('rc4', 'RC4'),
                      ('des', 'DES'), ('3des', '3DES'))
WEAK_CIPHER_LABELS = {'null': 'NULL (no encryption)', 'anon': 'anonymous (no authentication)',
                      'export': 'export grade', 'rc4': 'RC4', 'des': 'DES', '3des': '3DES'}
# The certificate key types, told apart by offering only the suites one key type signs (TLS 1.2;
# Python cannot narrow the signature algorithms of TLS 1.3)
AUDIT_KEY_TYPES = (('RSA', 'aRSA'), ('ECDSA', 'aECDSA'))
AUDIT_ACCEPTED, AUDIT_REFUSED, AUDIT_UNTESTED, AUDIT_FAILED = (
    'accepted', 'refused', 'untested', 'failed')
AUDIT_OUTCOMES = (AUDIT_ACCEPTED, AUDIT_REFUSED, AUDIT_UNTESTED, AUDIT_FAILED)
AUDIT_DONE, AUDIT_TIMEOUT, AUDIT_NOT_TLS = 'done', 'timeout', 'no-tls'
AUDIT_STATUSES = (AUDIT_DONE, AUDIT_TIMEOUT, AUDIT_NOT_TLS)
# Raised by the local TLS library before anything is sent: the check cannot be made from here
_LOCAL_SSL_REASONS = ('NO_PROTOCOLS_AVAILABLE', 'NO_CIPHERS_AVAILABLE')
MAX_AUDIT_LINES = 10   # endpoints per audit finding in the summary without --show-all
# The chain check (one more handshake per endpoint, two when it is not trusted): whether this
# machine's trust store accepts the chain the endpoint sends for the name asked (OpenSSL decides
# trust; nothing here verifies a signature), and that chain read in order (Python 3.10+). What a
# client fails on comes first; the last four (CHAIN_WARNINGS) only cost bytes or old clients:
# expired-extra is an expired certificate sent that a trusted chain does without (a cross-signed
# copy of a root this machine trusts, as the AddTrust and DST Root CA X3 cross-signs expired).
CHAIN_PROBLEMS = ('expired', 'not-yet-valid', 'name-mismatch', 'self-signed',
                  'missing-intermediate', 'untrusted-root', 'unknown-issuer', 'expired-chain',
                  'untrusted', 'expired-extra', 'wrong-order', 'extra-root', 'unrelated')
CHAIN_WARNINGS = ('expired-extra', 'wrong-order', 'extra-root', 'unrelated')
CHAIN_TRUSTED, CHAIN_UNTRUSTED, CHAIN_UNTESTED = 'trusted', 'untrusted', 'untested'
# OpenSSL verify codes (X509_V_ERR_*) the chain check reads
_V_NOT_YET_VALID, _V_EXPIRED, _V_SELF_SIGNED, _V_SELF_SIGNED_IN_CHAIN = 9, 10, 18, 19
_V_LOCAL_ISSUER, _V_LEAF_SIGNATURE, _V_HOSTNAME = 20, 21, 62
# Python 3.10+ reads the certificates a server sends (SSLSocket.get_unverified_chain from 3.13,
# the SSL object's before); older versions see the leaf alone.
CAN_READ_CHAIN = hasattr(getattr(getattr(ssl, '_ssl', None), '_SSLSocket', None),
                         'get_unverified_chain')


@dataclass
class AuditCheck:
    """One audit handshake: accepted (what was agreed on), refused, untested here or failed."""

    outcome: str
    version: Optional[str] = None
    cipher: Optional[str] = None
    cert_sha256: Optional[str] = None
    key_algorithm: Optional[str] = None
    error: Optional[str] = None
    timed_out: bool = False
    cert: Optional[CertInfo] = field(default=None, repr=False)   # the certificate served (not in the JSON)

    def to_dict(self) -> Dict[str, Any]:
        return {'outcome': self.outcome, 'version': self.version, 'cipher': self.cipher,
                'certSha256': self.cert_sha256, 'keyAlgorithm': self.key_algorithm,
                'error': self.error}


@dataclass
class ChainProbe:
    """One handshake of the chain check: the certificates the server sent (DER, as sent; None
    where this Python cannot read them) and its leaf, the chain OpenSSL built when it trusted it,
    and how verification ended (``verified`` None: no verifying handshake, ``error`` why)."""

    verified: Optional[bool] = None
    verify_code: Optional[int] = None
    verify_message: Optional[str] = None
    chain: Optional[List[bytes]] = None
    leaf: Optional[bytes] = None
    built: Optional[List[bytes]] = None
    error: Optional[str] = None
    timed_out: bool = False


@dataclass
class ChainCheck:
    """The chain an endpoint sends: trusted by this machine for the name asked (or through a
    --private-ca), and what is wrong with it (:data:`CHAIN_PROBLEMS`, each with a sentence)."""

    status: str = CHAIN_UNTESTED
    problems: List[str] = field(default_factory=list)
    notes: Dict[str, str] = field(default_factory=dict)
    verify_code: Optional[int] = None
    verify_message: Optional[str] = None
    sent: Optional[List[CertInfo]] = None      # what the server sent, as sent (Python 3.10+)
    private_ca: Optional[str] = None           # trusted through this --private-ca (its subject DN)
    error: Optional[str] = None
    timed_out: bool = False

    @property
    def breaking(self) -> List[str]:
        """The problems a client fails on (not :data:`CHAIN_WARNINGS`)."""
        return [p for p in self.problems if p not in CHAIN_WARNINGS]

    def to_dict(self) -> Dict[str, Any]:
        return {'status': self.status, 'problems': list(self.problems),
                'notes': {p: self.notes[p] for p in self.problems if p in self.notes},
                'verifyCode': self.verify_code, 'verifyMessage': self.verify_message,
                'privateCa': self.private_ca, 'error': self.error,
                'sent': None if self.sent is None else [{
                    'subjectCN': c.subject_cn, 'issuerCN': c.issuer_cn, 'serialHex': c.serial_hex,
                    'notAfter': iso_utc(c.not_after), 'selfSigned': c.self_signed, 'isCA': c.is_ca,
                    'sha256': c.sha256} for c in self.sent]}


@dataclass
class EndpointAudit:
    """The audit of one open ``ip:port``: the name it was asked for (None: no SNI) and the
    outcome of each version, weak cipher family and key type."""

    ip: str
    port: int
    protocol: str = PROTO_TLS
    servers: List[str] = field(default_factory=list)
    sni: Optional[str] = None
    status: str = AUDIT_DONE   # done | timeout (the checks after it skipped) | no-tls (skipped)
    versions: Dict[str, AuditCheck] = field(default_factory=dict)
    ciphers: Dict[str, AuditCheck] = field(default_factory=dict)
    key_types: Dict[str, AuditCheck] = field(default_factory=dict)
    chain: Optional[ChainCheck] = None

    @property
    def label(self) -> str:
        return endpoint_text(self.ip, self.port, self.protocol)

    @property
    def legacy_versions(self) -> List[str]:
        """TLS 1.0 / 1.1, where accepted."""
        return [v for v in LEGACY_VERSIONS
                if v in self.versions and self.versions[v].outcome == AUDIT_ACCEPTED]

    @property
    def weak_ciphers(self) -> List[str]:
        """The weak cipher families accepted (``3des``, ``rc4`` ...)."""
        return [g for g, check in self.ciphers.items() if check.outcome == AUDIT_ACCEPTED]

    @property
    def key_types_served(self) -> List[str]:
        """``RSA`` / ``ECDSA``: the key types of the certificates served."""
        return [k for k, check in self.key_types.items() if check.outcome == AUDIT_ACCEPTED]


def _version_text(label: str) -> str:
    return label.replace('TLSv', 'TLS ')


def _audit_base_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
    return context


def _set_ciphers(context: ssl.SSLContext, spec: str) -> bool:
    for candidate in (spec + ':@SECLEVEL=0', spec):  # LibreSSL has no security levels
        try:
            context.set_ciphers(candidate)
            return True
        except ssl.SSLError:
            continue
    return False


AuditContext = Tuple[Optional[ssl.SSLContext], Optional[str]]   # (context, or why there is none)


def _pinned_context(label: str) -> AuditContext:
    """A client context offering TLS version ``label`` only, or why this Python cannot."""
    attr = _AUDIT_VERSION_ATTRS[label]
    cannot = '%s cannot offer %s' % (ssl.OPENSSL_VERSION, _version_text(label))
    if not getattr(ssl, 'HAS_' + attr, False):
        return None, cannot
    context = _audit_base_context()
    try:
        version = getattr(ssl.TLSVersion, attr)
        context.minimum_version = version
        context.maximum_version = version
    except (AttributeError, ValueError, ssl.SSLError):
        return None, cannot
    _set_ciphers(context, 'ALL')
    return context, None


def _cipher_context(spec: str, label: str) -> AuditContext:
    """A client context offering only the suites ``spec`` selects, TLS 1.2 at most."""
    context = _audit_base_context()
    try:
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    except (AttributeError, ValueError, ssl.SSLError):
        return None, '%s cannot cap a handshake at TLS 1.2' % ssl.OPENSSL_VERSION
    suites = [c for c in context.get_ciphers()] if _set_ciphers(context, spec) else []
    if not [c for c in suites if c.get('protocol') != 'TLSv1.3'
            and not str(c.get('name', '')).startswith('TLS_')]:
        return None, '%s has no %s cipher suites' % (ssl.OPENSSL_VERSION, label)
    return context, None


def verify_context(check_hostname: bool = True) -> ssl.SSLContext:
    """The chain check's verifying client: this machine's trust store (ssl.create_default_context)
    and, with ``check_hostname``, the name asked. VERIFY_X509_STRICT (on from Python 3.13) is
    taken off: clients do not refuse what it adds, so neither does the check. Like today's
    clients it stops at the first certificate it trusts (VERIFY_X509_TRUSTED_FIRST, OpenSSL's
    default from 1.1.0): an expired cross-signed copy of a trusted root is not followed."""
    context = ssl.create_default_context()
    context.check_hostname = check_hostname
    strict = getattr(ssl, 'VERIFY_X509_STRICT', 0)
    if strict and context.verify_flags & strict:
        context.verify_flags &= ~strict
    context.verify_flags |= getattr(ssl, 'VERIFY_X509_TRUSTED_FIRST', 0)
    context.options |= getattr(ssl, 'OP_LEGACY_SERVER_CONNECT', 0)
    return context


class AuditContexts:
    """The audit's client contexts, made once in the calling thread (setting TLS 1.0 / 1.1
    warns on Python 3.10 and later): one per version, weak cipher family and key type, each
    with why this Python cannot make it when it cannot; and the chain check's: a verifying one
    with and one without the name check (an endpoint asked without SNI), and a permissive one
    that reads what a server sends."""

    def __init__(self) -> None:
        self.library = ssl.OPENSSL_VERSION
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', DeprecationWarning)
            self.versions = {label: _pinned_context(label)
                             for label in AUDIT_VERSIONS}  # type: Dict[str, AuditContext]
            self.ciphers = {group: _cipher_context(spec, WEAK_CIPHER_LABELS[group])
                            for group, spec in WEAK_CIPHER_GROUPS}  # type: Dict[str, AuditContext]
            self.key_types = {key: _cipher_context(spec, key)
                              for key, spec in AUDIT_KEY_TYPES}  # type: Dict[str, AuditContext]
            self.verify = {True: verify_context(True), False: verify_context(False)}
            self.plain = make_client_context()
        self.chain_why = None if CAN_READ_CHAIN else (
            'Python %d.%d cannot read the certificates a server sends (3.10 and later can): a '
            'missing intermediate and a root this machine does not trust look alike'
            % sys.version_info[:2])

    def untestable(self) -> Dict[str, Any]:
        """What this Python cannot offer, and why: ``{versions, weakCiphers, keyTypes}``, and
        ``chain`` when it cannot read the certificates a server sends."""
        out = {'versions': {k: why for k, (c, why) in self.versions.items() if c is None and why},
               'weakCiphers': {k: why for k, (c, why) in self.ciphers.items()
                               if c is None and why},
               'keyTypes': {k: why for k, (c, why) in self.key_types.items()
                            if c is None and why}}  # type: Dict[str, Any]
        if getattr(self, 'chain_why', None):
            out['chain'] = self.chain_why
        return out


def _audit_failure(exc: BaseException) -> AuditCheck:
    """The outcome of a handshake that did not complete: refused by the server (an alert, a
    close), untested (this Python would not send it), or failed (timeout, network, STARTTLS)."""
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return AuditCheck(AUDIT_FAILED, error='timed out', timed_out=True)
    if isinstance(exc, StartTlsError):
        return AuditCheck(AUDIT_FAILED, error=str(exc))
    if isinstance(exc, ssl.SSLError) and getattr(exc, 'reason', None) in _LOCAL_SSL_REASONS:
        return AuditCheck(AUDIT_UNTESTED, error='%s would not send it: %s'
                          % (ssl.OPENSSL_VERSION, _clean_ssl_message(exc)))
    if isinstance(exc, (ssl.SSLError, ConnectionResetError, ConnectionAbortedError,
                        BrokenPipeError)):
        return AuditCheck(AUDIT_REFUSED, error=classify_exception(exc)[1])
    return AuditCheck(AUDIT_FAILED, error=classify_exception(exc)[1])


AuditAttempt = Callable[[str, int, str, Optional[str], ssl.SSLContext, float], AuditCheck]


def audit_handshake(ip: str, port: int, protocol: str, sni: Optional[str],
                    context: ssl.SSLContext, timeout: float) -> AuditCheck:
    """One audit handshake with ``context`` (after STARTTLS where ``protocol`` says so)."""
    sock = None
    try:
        sock = socket.create_connection((_connect_address(ip), port), timeout=timeout)
        starttls(sock, protocol, sni)
        tls = context.wrap_socket(sock, server_hostname=sni, do_handshake_on_connect=False)
        sock = tls
        tls.settimeout(timeout)
        tls.do_handshake()
        cipher = tls.cipher()
        version = tls.version() or ''
        check = AuditCheck(AUDIT_ACCEPTED, version='TLSv1.0' if version == 'TLSv1' else version,
                           cipher=cipher[0] if cipher else None)
        der = tls.getpeercert(binary_form=True)
        if der:
            try:
                cert = parse_certificate(der)
                check.cert_sha256, check.key_algorithm, check.cert = (
                    cert.sha256, cert.key_algorithm, cert)
            except _CERT_PARSE_ERRORS:
                pass
        return check
    except Exception as exc:  # noqa: BLE001 - every failure becomes an outcome
        return _audit_failure(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _chain_ders(tls: ssl.SSLSocket, verified: bool = False) -> Optional[List[bytes]]:
    """The certificates the server sent, as sent (``verified``: the chain OpenSSL built, ending
    at a certificate of this machine's store), DER; None where this Python cannot read them."""
    name = 'get_verified_chain' if verified else 'get_unverified_chain'
    method = getattr(tls, name, None) or getattr(getattr(tls, '_sslobj', None), name, None)
    if method is None:
        return None
    try:
        chain = method()
    except (ssl.SSLError, ValueError, TypeError, AttributeError):
        return None
    encoding = getattr(getattr(ssl, '_ssl', None), 'ENCODING_DER', 2)
    out = []  # type: List[bytes]
    for cert in chain or []:
        if isinstance(cert, (bytes, bytearray)):
            out.append(bytes(cert))
            continue
        try:
            out.append(cert.public_bytes(encoding))
        except (AttributeError, ValueError, TypeError, ssl.SSLError):
            return None
    return out


ChainAttempt = Callable[[str, int, str, Optional[str], ssl.SSLContext, float], ChainProbe]


def chain_probe(ip: str, port: int, protocol: str, sni: Optional[str], context: ssl.SSLContext,
                timeout: float) -> ChainProbe:
    """One handshake of the chain check with ``context`` (after STARTTLS where ``protocol``
    says so): what the server sent and, with a verifying context, whether this machine trusts it
    for ``sni`` (OpenSSL's verify code and message when not)."""
    probe = ChainProbe()
    sock = None
    try:
        sock = socket.create_connection((_connect_address(ip), port), timeout=timeout)
        starttls(sock, protocol, sni)
        tls = context.wrap_socket(sock, server_hostname=sni, do_handshake_on_connect=False)
        sock = tls
        tls.settimeout(timeout)
        tls.do_handshake()
        probe.leaf = tls.getpeercert(binary_form=True)
        probe.chain = _chain_ders(tls)
        if context.verify_mode == ssl.CERT_REQUIRED:
            probe.verified = True
            probe.built = _chain_ders(tls, verified=True)
    except ssl.SSLCertVerificationError as exc:
        probe.verified = False
        probe.verify_code = getattr(exc, 'verify_code', None)
        probe.verify_message = getattr(exc, 'verify_message', None) or _clean_ssl_message(exc)
    except Exception as exc:  # noqa: BLE001 - every failure becomes an outcome
        failure = _audit_failure(exc)
        probe.error, probe.timed_out = failure.error, failure.timed_out
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    return probe


def _cert_name(cert: CertInfo) -> str:
    """A certificate in a sentence: its subject CN (or DN), with the organisation when it adds one."""
    org = cert.subject.get('O')
    label = cert.short_label()
    return '%s (%s)' % (label, org) if org and org not in label else label


def _ca_key(cert: CertInfo) -> Tuple[str, Optional[str]]:
    """A CA's identity across its cross-signed copies: its subject and public key."""
    return _dn_key(cert.subject_dn), cert.spki_sha256


def analyze_chain(trusted: Optional[bool], verify_code: Optional[int] = None,
                  verify_message: Optional[str] = None, sent: Optional[Sequence[bytes]] = None,
                  leaf: Optional[bytes] = None, built: Optional[Sequence[bytes]] = None,
                  sni: Optional[str] = None, private_cas: Sequence[CertInfo] = (),
                  now: Optional[datetime] = None) -> ChainCheck:
    """What the chain check found. ``trusted``: the verifying handshake (this machine's trust
    store and the name ``sni``) completed (True) or failed verification with OpenSSL's
    ``verify_code`` / ``verify_message`` (False); None: it did not complete. ``sent``: the
    certificates the server sent, as sent (DER; None before Python 3.10, then the ``leaf`` alone);
    ``built``: the chain OpenSSL built when it trusted it.

    Read from what was sent: the leaf's dates, the issuing path through the certificates sent
    (:func:`issued_by`: names and key identifiers; in a trusted chain along the one OpenSSL
    built, another copy of one of its CAs - the same subject and key, a cross-sign - standing in
    for it), an expired certificate on it, the order (the leaf first, then each issuer), a root
    sent along, certificates that are no part of it (another copy of a CA on the path, and what
    issued that copy, are part of it), and a missing intermediate - the leaf sent alone while
    its issuer is no root this machine trusts, or an intermediate OpenSSL took from this
    machine's store because the server did not send it. In a trusted chain an expired
    certificate a client needs is ``expired-chain`` (a copy of an intermediate whose current one
    came from this machine's store), and one the chain does without is the warning
    ``expired-extra`` (a cross-signed copy of the root OpenSSL trusted, a second copy of a CA
    sent, a certificate past that root): only old clients that build through it fail. OpenSSL's
    verdict names the rest: a self-signed leaf, a root this machine does not trust (on Windows
    possibly a public root it has not fetched yet), another name; with nothing read at all its
    message alone. A chain a ``--private-ca`` issued is trusted through it (its dates still
    count)."""
    now = now or _utcnow()
    check = ChainCheck(status=(CHAIN_UNTESTED if trusted is None else
                               CHAIN_TRUSTED if trusted else CHAIN_UNTRUSTED),
                       verify_code=verify_code, verify_message=verify_message)

    def parse(ders: Optional[Sequence[bytes]]) -> List[CertInfo]:
        out = []  # type: List[CertInfo]
        for der in ders or []:
            try:
                out.append(parse_certificate(der))
            except _CERT_PARSE_ERRORS:
                continue
        return out

    def add(code: str, note: str) -> None:
        if code not in check.problems:
            check.problems.append(code)
            check.notes[code] = note

    sent_certs = parse(sent) if sent is not None else None
    check.sent = sent_certs
    leaf_cert = (parse([leaf]) or [None])[0] if leaf else None
    if leaf_cert is None and sent_certs:
        leaf_cert = sent_certs[0]
    if trusted is None:
        return check
    day = lambda when: when.strftime('%Y-%m-%d')  # noqa: E731
    path = [leaf_cert] if leaf_cert is not None else []  # type: List[CertInfo]
    if leaf_cert is not None:
        if leaf_cert.not_after < now:
            add('expired', 'the certificate expired on %s' % day(leaf_cert.not_after))
        elif leaf_cert.not_before > now:
            add('not-yet-valid', 'the certificate is not valid before %s' % day(leaf_cert.not_before))
    if leaf_cert is not None and sent_certs is not None:
        others = [c for c in sent_certs if c.sha256 != leaf_cert.sha256]
        built_certs = parse(built) if trusted and built else []
        built_shas = {c.sha256 for c in built_certs}
        built_keys = {_ca_key(c) for c in built_certs[1:]}
        sent_shas = {c.sha256 for c in sent_certs}

        def rank(cert: CertInfo) -> int:
            """The issuer OpenSSL used first, then another copy of one of its CAs, then the
            order sent."""
            return 0 if cert.sha256 in built_shas else 1 if _ca_key(cert) in built_keys else 2

        in_path = {leaf_cert.sha256}
        while not path[-1].self_signed:
            issuers = [c for c in others if c.sha256 not in in_path and issued_by(path[-1], c)]
            if not issuers:
                break
            path.append(min(issuers, key=rank))
            in_path.add(path[-1].sha256)
        # another copy of a CA on the path or of one OpenSSL used (a cross-sign), then what
        # issued each copy: no part of the path, yet no unrelated certificate either
        keys = {_ca_key(c) for c in path[1:]} | built_keys
        copies = [c for c in others if c.sha256 not in in_path and _ca_key(c) in keys]
        related = in_path | {c.sha256 for c in copies}
        index = 0
        while index < len(copies):
            for issuer in others:
                if issuer.sha256 not in related and issued_by(copies[index], issuer):
                    copies.append(issuer)
                    related.add(issuer.sha256)
            index += 1
        anchor = built_certs[-1] if built_certs else None

        def needed(cert: CertInfo) -> bool:
            """Whether a client lacking this machine's store needs ``cert`` (a trusted chain):
            OpenSSL used it, or it is the copy sent of an intermediate OpenSSL took from the
            store. A copy of the root OpenSSL trusted (a cross-sign), a CA sent twice and what
            lies past the root are not needed."""
            if cert.sha256 in built_shas:
                return True
            if anchor is not None and anchor.self_signed and _ca_key(cert) == _ca_key(anchor):
                return False
            used = next((c for c in built_certs[1:] if _ca_key(c) == _ca_key(cert)), None)
            return used is not None and used.sha256 not in sent_shas

        for cert in path[1:] + copies:
            if cert.not_after >= now:
                continue
            if built_certs and not needed(cert):
                add('expired-extra', '%s, issued by %s, expired on %s: this machine trusts the '
                    'chain without it, older clients that build through it fail'
                    % (_cert_name(cert), cert.issuer_label(), day(cert.not_after)))
            elif built_certs or cert.sha256 in in_path:
                add('expired-chain', '%s in the chain expired on %s'
                    % (_cert_name(cert), day(cert.not_after)))
        order = []  # type: List[str]
        for cert in sent_certs:
            if cert.sha256 in in_path and cert.sha256 not in order:
                order.append(cert.sha256)
        if order != [c.sha256 for c in path]:
            add('wrong-order', 'the chain is sent out of order (the certificate comes first, then '
                'each certificate\'s issuer)')
        roots = [c for c in path[1:] + copies if c.self_signed]
        if len(roots) == 1:
            add('extra-root', 'the root %s is sent too: clients use their own copy'
                % _cert_name(roots[0]))
        elif roots:
            add('extra-root', 'the roots %s are sent too: clients use their own copies'
                % ', '.join(_cert_name(c) for c in roots))
        extra = [c for c in others if c.sha256 not in related]
        if extra:
            add('unrelated', '%s %s sent but no part of the chain' % (
                ', '.join(_cert_name(c) for c in extra[:3]) + (' +%d' % (len(extra) - 3)
                                                               if len(extra) > 3 else ''),
                'is' if len(extra) == 1 else 'are'))
        if built_certs:
            sent_keys = {_ca_key(c) for c in sent_certs}
            lacking = [c for c in built_certs[1:] if not c.self_signed
                       and _ca_key(c) not in sent_keys]
            if lacking:
                add('missing-intermediate', 'the server does not send %s: this machine had it, a '
                    'client without it fails' % ', '.join(_cert_name(c) for c in lacking))
    top = path[-1] if path else None
    issuer_text = display_text(leaf_cert.issuer_label()) if leaf_cert is not None else 'its issuer'
    aia = (' (the CA publishes it at %s)' % display_text(', '.join(leaf_cert.ca_issuers))
           if leaf_cert is not None and leaf_cert.ca_issuers else '')
    if not trusted:
        code = verify_code
        if code in (_V_EXPIRED, _V_NOT_YET_VALID):
            if not {'expired', 'not-yet-valid', 'expired-chain'} & set(check.problems):
                add('untrusted', 'not trusted: %s' % (verify_message or 'a date is out of range'))
        elif code == _V_HOSTNAME:
            add('name-mismatch', 'the certificate does not cover %s' % (sni or 'the name asked'))
        elif code == _V_SELF_SIGNED:
            add('self-signed', 'self-signed: clients trust it only when told to (here: '
                '--private-ca)')
        elif code == _V_SELF_SIGNED_IN_CHAIN:
            add('untrusted-root', 'the chain ends at %s, a root this machine does not trust'
                % _cert_name(top) if top is not None and len(path) > 1 else
                'the chain ends at a root this machine does not trust')
        elif code in (_V_LOCAL_ISSUER, _V_LEAF_SIGNATURE):
            if leaf_cert is None:   # nothing read: OpenSSL's verdict alone
                add('untrusted', 'not trusted: %s' % (verify_message or 'verify error %s' % code))
            elif sent_certs is None and code == _V_LOCAL_ISSUER:
                add('unknown-issuer', 'this machine has no issuer for it (%s): a missing '
                    'intermediate or a root it does not trust; %s' % (
                        issuer_text, 'the chain it sends could not be read' if CAN_READ_CHAIN
                        else 'Python 3.10 and later tell which'))
            elif top is not None and (len(path) > 1 or top.self_signed):
                add('untrusted-root', 'the chain ends at %s, issued by %s, which this machine '
                    'does not trust: a private CA (give it with --private-ca) or, on Windows, a '
                    'public root Windows has not fetched yet' % (
                        _cert_name(top), display_text(top.issuer_label())))
            else:
                add('missing-intermediate', 'the server does not send %s, the issuer of its '
                    'certificate%s' % (issuer_text, aia))
        else:
            add('untrusted', 'not trusted: %s' % (verify_message or 'verify error %s' % code))
        dated = {'expired', 'not-yet-valid', 'expired-chain', 'name-mismatch'}
        ca = next((ca for cert in path for ca in private_cas
                   if issued_by(cert, ca) or cert.sha256 == ca.sha256), None)
        if ca is not None and not dated & set(check.problems):
            check.status, check.private_ca = CHAIN_TRUSTED, ca.subject_dn
            keep = []  # type: List[str]
            for problem in check.problems:
                if problem in ('untrusted-root', 'unknown-issuer', 'self-signed', 'untrusted'):
                    continue
                # the private CA issued the leaf directly: a root needs no intermediate sent
                if problem == 'missing-intermediate' and ca.self_signed:
                    continue
                keep.append(problem)
            check.problems = keep
    check.problems.sort(key=CHAIN_PROBLEMS.index)   # what a client fails on first
    return check


def check_chain(target: EndpointAudit, contexts: AuditContexts, timeout: float,
                probe: Optional[ChainAttempt] = None, private_cas: Sequence[CertInfo] = (),
                now: Optional[datetime] = None) -> ChainCheck:
    """The chain check of one endpoint (:func:`analyze_chain`): a verifying handshake for the
    name it was asked for, then, when that fails verification, one that reads what it sends.
    When that second one fails too, OpenSSL's verdict stands and each note says the chain could
    not be read (``error``: why)."""
    verify = getattr(contexts, 'verify', None)
    if not verify:
        return ChainCheck(error='no chain check with these contexts')
    probe = probe or chain_probe
    first = probe(target.ip, target.port, target.protocol, target.sni,
                  verify[bool(target.sni)], timeout)
    if first.verified is None:
        return ChainCheck(error=first.error or 'the handshake did not complete',
                          timed_out=first.timed_out)
    if first.verified:
        return analyze_chain(True, sent=first.chain, leaf=first.leaf, built=first.built,
                             sni=target.sni, private_cas=private_cas, now=now)
    second = probe(target.ip, target.port, target.protocol, target.sni, contexts.plain, timeout)
    check = analyze_chain(False, first.verify_code, first.verify_message, sent=second.chain,
                          leaf=second.leaf, sni=target.sni, private_cas=private_cas, now=now)
    if second.error:
        check.error = second.error
        for problem in check.problems:
            check.notes[problem] += ('; the chain it sends could not be read (a second handshake '
                                     'failed: %s)' % second.error)
    check.timed_out = second.timed_out
    return check


def audit_endpoint(target: EndpointAudit, contexts: AuditContexts, timeout: float,
                   attempt: Optional[AuditAttempt] = None,
                   chain_attempt: Optional[ChainAttempt] = None,
                   private_cas: Sequence[CertInfo] = (),
                   now: Optional[datetime] = None) -> EndpointAudit:
    """Fill ``target``: each TLS version, each weak cipher family and each key type, one
    handshake at a time (``attempt``, :func:`audit_handshake` by default), then its chain
    (:func:`check_chain`, ``chain_attempt``: :func:`chain_probe`). After a timeout the
    remaining checks are skipped (status ``timeout``); when TLS 1.2 and older are refused (TLS
    1.3 only) no weak suite can be agreed on and the key types cannot be told apart."""
    attempt = attempt or audit_handshake
    timed_out = [False]

    def check(entry: AuditContext) -> AuditCheck:
        context, why = entry
        if context is None:
            return AuditCheck(AUDIT_UNTESTED, error=why)
        if timed_out[0]:
            return AuditCheck(AUDIT_UNTESTED, error='skipped after a timeout')
        result = attempt(target.ip, target.port, target.protocol, target.sni, context, timeout)
        timed_out[0] = timed_out[0] or result.timed_out
        return result

    for label in AUDIT_VERSIONS:
        target.versions[label] = check(contexts.versions[label])
    tls13_only = (target.versions['TLSv1.2'].outcome == AUDIT_REFUSED
                  and not target.legacy_versions)
    for group, _spec in WEAK_CIPHER_GROUPS:
        if tls13_only and contexts.ciphers[group][0] is not None:
            target.ciphers[group] = AuditCheck(AUDIT_REFUSED, error='TLS 1.2 and older refused')
        else:
            target.ciphers[group] = check(contexts.ciphers[group])
    for key_type, _spec in AUDIT_KEY_TYPES:
        if tls13_only and contexts.key_types[key_type][0] is not None:
            target.key_types[key_type] = AuditCheck(
                AUDIT_UNTESTED, error='TLS 1.3 only: Python cannot ask for one key type there')
        else:
            target.key_types[key_type] = check(contexts.key_types[key_type])
    if timed_out[0]:
        target.chain = ChainCheck(error='skipped after a timeout')
    else:
        target.chain = check_chain(target, contexts, timeout, chain_attempt, private_cas, now)
        timed_out[0] = target.chain.timed_out
    target.status = AUDIT_TIMEOUT if timed_out[0] else AUDIT_DONE
    return target


def audit_targets(report: ScanReport) -> List[EndpointAudit]:
    """One :class:`EndpointAudit` per open endpoint, in scan order. It is asked for the first
    name it hosts (else without SNI: its default certificate); one where no handshake
    completed in the scan is not audited (``no-tls``)."""
    hosted = (UPDATED,) + HOSTED_STATUSES
    rows = {}  # type: Dict[Tuple[str, int], List[ProbeResult]]
    for row in report.results:
        rows.setdefault((row.ip, row.port), []).append(row)
    out = []  # type: List[EndpointAudit]
    for endpoint in report.endpoints:
        if endpoint.state != OPEN:
            continue
        mine = rows.get((endpoint.ip, endpoint.port), [])
        servers = []  # type: List[str]
        for row in mine:
            if row.server not in servers:
                servers.append(row.server)
        sni = next((row.sni for probe in (PROBE_SNI, PROBE_WILDCARD) for row in mine
                    if row.probe == probe and row.status in hosted), None)
        answered = any(row.cert is not None for row in mine)
        out.append(EndpointAudit(endpoint.ip, endpoint.port, endpoint.protocol, servers, sni,
                                 AUDIT_DONE if answered else AUDIT_NOT_TLS))
    return out


@dataclass
class TlsAudit:
    """--tls-audit: the audit of every open endpoint, and what this Python could not test."""

    library: str
    untestable: Dict[str, Any]
    endpoints: List[EndpointAudit]
    new_certs: List[CertInfo] = field(default_factory=list)   # --cert: an RSA + ECDSA pair?
    mismatches: List[Dict[str, Any]] = field(default_factory=list)   # serial_mismatches()


def run_tls_audit(report: ScanReport, timeout: float = DEFAULT_TIMEOUT,
                  workers: int = DEFAULT_WORKERS, attempt: Optional[AuditAttempt] = None,
                  contexts: Optional[AuditContexts] = None,
                  progress: Optional[ProgressCallback] = None,
                  cancel: Optional[threading.Event] = None,
                  chain_attempt: Optional[ChainAttempt] = None) -> TlsAudit:
    """Audit the open endpoints of ``report`` (:func:`audit_targets`): endpoints in parallel,
    one handshake at a time to each, then the fleet's certificates per name
    (:func:`serial_mismatches`). ``progress('audit', done, total, {})``."""
    contexts = contexts or AuditContexts()
    targets = audit_targets(report)
    todo = [target for target in targets if target.status != AUDIT_NOT_TLS]
    done = [0]

    def run(target: EndpointAudit) -> EndpointAudit:
        return audit_endpoint(target, contexts, timeout, attempt, chain_attempt,
                              report.private_cas, report.finished_at)

    def on_done(_target: EndpointAudit, _result: EndpointAudit) -> None:
        done[0] += 1
        if progress:
            progress('audit', done[0], len(todo), {})

    if todo:
        _parallel(run, todo, workers, on_done, cancel or threading.Event())
    return TlsAudit(contexts.library, contexts.untestable(), targets, list(report.new_certs),
                    serial_mismatches(report, targets))


KEY_TYPE_LABELS = {'RSA': 'RSA', 'EC': 'ECDSA'}


def _key_type(cert: CertInfo) -> str:
    """``RSA`` / ``ECDSA`` (:data:`KEY_TYPE_LABELS`), else the key algorithm itself."""
    return KEY_TYPE_LABELS.get(cert.key_algorithm, cert.key_algorithm or '?')


def _pair_covers(certs: Sequence[CertInfo], name: str) -> bool:
    """An RSA and an ECDSA certificate of ``certs`` (the --cert files) both cover ``name``."""
    return (any(c.key_algorithm == 'RSA' and c.covers(name)[0] for c in certs)
            and any(c.key_algorithm == 'EC' and c.covers(name)[0] for c in certs))


def serial_mismatches(report: ScanReport, audits: Sequence[EndpointAudit] = ()
                      ) -> List[Dict[str, Any]]:
    """One name served with different certificates of one key type and kind (public, the
    Cloudflare Origin CA's, private) on different endpoints: a load-balancer pool member or a
    server the last renewal missed. An RSA + ECDSA pair, or an Origin CA certificate next to a
    public one, is no mismatch. The scan's rows give the certificate each endpoint serves for
    each name; the audit's key-type handshakes add the other half of a pair (for the name an
    endpoint was asked for) and tell a pair from a renewal that changed the key type: where the
    audit tried both key types at the endpoints serving a name and none serves it with both (nor
    does an RSA + ECDSA pair of --cert cover it), its certificates are compared across key types
    (``keyTypeChanged``). Per name and key type: the certificates newest first (``older``:
    another of them was issued later), each with its key type, the endpoints serving it, their
    servers and the load balancers (``behind``) and VIPs they sit behind."""
    hosted = (UPDATED,) + HOSTED_STATUSES
    certs = {}  # type: Dict[str, CertInfo]
    served = {}  # type: Dict[str, Dict[str, Set[Tuple[str, int]]]]  name -> sha256 -> endpoints
    servers_of = {}  # type: Dict[Tuple[str, int], List[str]]
    names_of = {}  # type: Dict[str, str]  sni -> name
    sni_of = {}  # type: Dict[str, str]  name -> sni
    for row in report.results:
        key = (row.ip, row.port)
        if row.server and row.server not in servers_of.setdefault(key, []):
            servers_of[key].append(row.server)
        if (row.probe not in (PROBE_SNI, PROBE_WILDCARD) or not row.name or row.cert is None
                or row.status not in hosted):
            continue
        names_of.setdefault(row.sni or row.name, row.name)
        sni_of.setdefault(row.name, row.sni or row.name)
        certs[row.cert.sha256] = row.cert
        served.setdefault(row.name, {}).setdefault(row.cert.sha256, set()).add(key)
    key_sets = {}  # type: Dict[str, List[Set[str]]]  name -> the key types each endpoint serves
    for target in audits:
        name = names_of.get(target.sni or '')
        if not name:
            continue
        served_with = set()  # type: Set[str]
        tried = True
        for key_type, _spec in AUDIT_KEY_TYPES:
            check = target.key_types.get(key_type)
            if check is None or check.outcome not in (AUDIT_ACCEPTED, AUDIT_REFUSED):
                tried = False
                continue
            cert = check.cert
            if check.outcome != AUDIT_ACCEPTED or (
                    cert is not None and not cert.covers(target.sni or '')[0]):
                continue
            served_with.add(key_type)
            if cert is not None:
                certs[cert.sha256] = cert
                served[name].setdefault(cert.sha256, set()).add((target.ip, target.port))
        if tried:
            key_sets.setdefault(name, []).append(served_with)

    def key_type_changed(name: str) -> bool:
        """No endpoint serves ``name`` with both key types where the audit tried both: one key
        type replaced the other (the scan alone cannot tell this from an RSA + ECDSA pair)."""
        sets = key_sets.get(name, [])
        return (any(sets) and all(len(s) < len(AUDIT_KEY_TYPES) for s in sets)
                and not _pair_covers(report.new_certs, sni_of.get(name, name)))

    behind = {}  # type: Dict[str, List[str]]
    vips = {}  # type: Dict[str, List[str]]
    for server in list(report.servers) + list(report.skipped_backends):
        vips[server.name.lower()] = list(server.vips)
        for backend in server.backends:
            behind.setdefault(backend.lower(), []).append(server.name)
    order = {(e.ip, e.port): i for i, e in enumerate(report.endpoints)}
    probe_order = {p.name: i for i, p in enumerate(report.probes)}

    def endpoint(key: Tuple[str, int]) -> Dict[str, Any]:
        names = servers_of.get(key, [])
        lbs, shared = [], []  # type: List[str], List[str]
        for name in names:
            lbs.extend(lb for lb in behind.get(name.lower(), []) if lb not in lbs)
            shared.extend(vip for vip in vips.get(name.lower(), []) if vip not in shared)
        return {'ip': key[0], 'port': key[1], 'protocol': report.protocol_of(*key),
                'servers': list(names), 'behind': lbs, 'vips': shared}

    out = []  # type: List[Dict[str, Any]]
    for name in sorted(served, key=lambda n: (probe_order.get(n, len(probe_order)), n)):
        across = key_type_changed(name)
        families = {}  # type: Dict[Tuple[str, str], List[CertInfo]]
        for sha in served[name]:
            cert = certs[sha]
            family = ('' if across else _key_type(cert), _kind_family(report.cert_kind(cert)[0]))
            families.setdefault(family, []).append(cert)
        for (_key, kind), group in sorted(families.items()):
            if len(group) < 2:
                continue
            group.sort(key=lambda c: (c.not_before, c.not_after, c.sha256), reverse=True)
            newest = group[0]
            types = []  # type: List[str]  newest first
            for cert in group:
                if _key_type(cert) not in types:
                    types.append(_key_type(cert))
            entries = [{
                'sha256': cert.sha256, 'serialHex': cert.serial_hex, 'keyType': _key_type(cert),
                'issuer': cert.issuer_label(), 'notBefore': iso_utc(cert.not_before),
                'notAfter': iso_utc(cert.not_after),
                'older': (newest.not_before, newest.not_after) > (cert.not_before, cert.not_after),
                'endpoints': [endpoint(key) for key in sorted(
                    served[name][cert.sha256], key=lambda k: (order.get(k, len(order)), k))],
            } for cert in group]
            out.append({'name': name, 'keyType': types[0], 'keyTypeChanged': len(types) > 1,
                        'kind': kind, 'certificates': entries})
    return out


def _expected_pairs(audit: TlsAudit) -> Set[Optional[str]]:
    """The names asked for (None: no SNI) that RSA and ECDSA are both expected for: some
    endpoint serves both for it, or the --cert certificates hold an RSA and an ECDSA one
    covering it."""
    pairs = {e.sni for e in audit.endpoints
             if len(e.key_types_served) == len(AUDIT_KEY_TYPES)}  # type: Set[Optional[str]]
    for e in audit.endpoints:
        if e.sni and _pair_covers(audit.new_certs, e.sni):
            pairs.add(e.sni)
    return pairs


def audit_summary(audit: TlsAudit) -> Dict[str, Any]:
    """The fleet: endpoints still accepting TLS 1.0 / 1.1, accepting weak cipher suites, and
    serving one key type only where RSA + ECDSA are expected (:func:`_expected_pairs`)."""
    audited = [e for e in audit.endpoints if e.status != AUDIT_NOT_TLS]

    def where(e: EndpointAudit) -> Dict[str, Any]:
        return {'ip': e.ip, 'port': e.port, 'protocol': e.protocol, 'servers': list(e.servers),
                'sni': e.sni}

    pairs = _expected_pairs(audit)
    halves = []  # type: List[Dict[str, Any]]
    for e in audited:
        served = e.key_types_served
        tested = [k for k, c in e.key_types.items() if c.outcome in (AUDIT_ACCEPTED, AUDIT_REFUSED)]
        if e.sni in pairs and len(served) == 1 and len(tested) == len(AUDIT_KEY_TYPES):
            entry = where(e)
            entry['served'] = served[0]
            entry['missing'] = [k for k, _spec in AUDIT_KEY_TYPES if k not in served][0]
            halves.append(entry)
    legacy, weak, chains = [], [], []  # type: List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]
    for e in audited:
        if e.legacy_versions:
            entry = where(e)
            entry['versions'] = e.legacy_versions
            legacy.append(entry)
        if e.weak_ciphers:
            entry = where(e)
            entry['groups'] = e.weak_ciphers
            entry['ciphers'] = [e.ciphers[g].cipher for g in e.weak_ciphers if e.ciphers[g].cipher]
            weak.append(entry)
        if e.chain is not None and e.chain.problems:
            entry = where(e)
            entry.update({'status': e.chain.status, 'problems': list(e.chain.problems),
                          'notes': {p: e.chain.notes.get(p, p) for p in e.chain.problems},
                          'verifyMessage': e.chain.verify_message,
                          'privateCa': e.chain.private_ca})
            chains.append(entry)
    checked = [e for e in audited if e.chain is not None and e.chain.status != CHAIN_UNTESTED]
    return {'endpoints': len(audit.endpoints), 'audited': len(audited),
            'notAudited': len(audit.endpoints) - len(audited),
            'timedOut': sum(1 for e in audited if e.status == AUDIT_TIMEOUT),
            'acceptingTls10': sum(1 for e in audited if 'TLSv1.0' in e.legacy_versions),
            'acceptingTls11': sum(1 for e in audited if 'TLSv1.1' in e.legacy_versions),
            'legacyVersions': legacy, 'weakCiphers': weak, 'oneKeyType': halves,
            'chainsChecked': len(checked),
            'chainsBroken': sum(1 for e in checked if e.chain.breaking),
            'chainProblems': chains,
            'serialMismatches': [dict(m) for m in audit.mismatches]}


def audit_to_dict(audit: TlsAudit) -> Dict[str, Any]:
    """The ``tlsAudit`` section of the JSON report."""
    return {
        'library': audit.library,
        'untestable': audit.untestable,
        'summary': audit_summary(audit),
        'endpoints': [{
            'ip': e.ip, 'port': e.port, 'protocol': e.protocol, 'servers': list(e.servers),
            'sni': e.sni, 'status': e.status,
            'versions': {k: c.to_dict() for k, c in e.versions.items()},
            'weakCiphers': {k: c.to_dict() for k, c in e.ciphers.items()},
            'keyTypes': {k: c.to_dict() for k, c in e.key_types.items()},
            'legacyVersions': e.legacy_versions, 'weakCipherGroups': e.weak_ciphers,
            'keyTypesServed': e.key_types_served,
            'chain': e.chain.to_dict() if e.chain is not None else None,
        } for e in audit.endpoints],
    }


def render_tls_audit(audit: TlsAudit, color: bool = False, show_all: bool = False) -> str:
    """The audit in the human summary: the findings first, then what was not tested."""
    style = Style(color)
    summary = audit_summary(audit)
    limit = None if show_all else MAX_AUDIT_LINES
    lines = [style.paint('TLS audit', 'bold') + ' - %d of %d open endpoint(s) checked with %s'
             % (summary['audited'], summary['endpoints'], display_text(audit.library))]

    def who(entry: Dict[str, Any]) -> str:
        names = list(entry['servers'])
        text = ', '.join(names[:3]) + (' +%d' % (len(names) - 3) if len(names) > 3 else '')
        return '%s  %s' % (endpoint_text(entry['ip'], entry['port'], entry['protocol']),
                           display_text(text))

    def finding(title: str, entries: List[Dict[str, Any]], detail: Callable[[Dict[str, Any]], str],
                clean: str) -> None:
        if not entries:
            lines.append('  ' + style.paint(clean, 'green'))
            return
        lines.append('  ' + style.paint('%s: %d endpoint(s)' % (title, len(entries)),
                                        'yellow', 'bold'))
        for entry in entries[:limit]:
            lines.append('    %s  %s' % (who(entry), detail(entry)))
        if limit is not None and len(entries) > limit:
            lines.append('    ... and %d more (--show-all lists them)' % (len(entries) - limit))

    untestable = audit.untestable
    legacy_untested = [v for v in LEGACY_VERSIONS if v in untestable.get('versions', {})]
    finding('Still accepting TLS 1.0 / 1.1', summary['legacyVersions'],
            lambda e: ', '.join(_version_text(v) for v in e['versions']),
            'No endpoint accepts %s' % ' or '.join(
                _version_text(v) for v in LEGACY_VERSIONS if v not in legacy_untested)
            if len(legacy_untested) < len(LEGACY_VERSIONS) else 'TLS 1.0 / 1.1 not tested')
    finding('Weak cipher suites accepted', summary['weakCiphers'],
            lambda e: ', '.join(WEAK_CIPHER_LABELS[g] for g in e['groups'])
            + (' (%s)' % ', '.join(e['ciphers']) if e['ciphers'] else ''),
            'No endpoint accepts the weak cipher suites tried')
    finding('One key type of an RSA + ECDSA pair', summary['oneKeyType'],
            lambda e: '%s only, no %s certificate%s' % (
                e['served'], e['missing'], ' for %s' % display_text(e['sni']) if e['sni'] else ''),
            'Every RSA + ECDSA pair is served whole')

    def chain_detail(e: Dict[str, Any]) -> str:
        notes = [display_text(e['notes'][p]) for p in e['problems'] if p not in CHAIN_WARNINGS]
        notes += [display_text(e['notes'][p]) for p in e['problems'] if p in CHAIN_WARNINGS]
        via = (' (trusted through the --private-ca %s)' % display_text(e['privateCa'])
               if e.get('privateCa') else '')
        return '; '.join(notes) + via

    if summary['chainsChecked']:
        broken = [e for e in summary['chainProblems']
                  if any(p not in CHAIN_WARNINGS for p in e['problems'])]
        finding('Certificate chain not trusted or incomplete', broken, chain_detail,
                'Every chain checked (%d) is trusted for its name and complete'
                % summary['chainsChecked'])
        finding('Chain sent with extra or misordered certificates',
                [e for e in summary['chainProblems'] if e not in broken], chain_detail,
                'Every chain is sent in order, without certificates it does not need')
    else:
        lines.append('  ' + style.paint('Certificate chains not checked: no verifying handshake '
                                        'completed', 'dim'))
    render_serial_mismatches(summary['serialMismatches'], lines, style, limit)
    gaps = ['%s (%s)' % (', '.join(_version_text(v) for v in untestable['versions']),
                         'versions')] if untestable.get('versions') else []
    if untestable.get('weakCiphers'):
        gaps.append('%s (cipher suites)' % ', '.join(WEAK_CIPHER_LABELS[g]
                                                       for g in untestable['weakCiphers']))
    if untestable.get('keyTypes'):
        gaps.append('%s (key types)' % ', '.join(untestable['keyTypes']))
    if gaps:
        lines.append('  ' + style.paint('Not tested - this Python (%s) cannot offer: %s'
                                        % (display_text(audit.library), '; '.join(gaps)), 'dim'))
    if untestable.get('chain'):
        lines.append('  ' + style.paint('Chains read in part - %s' % untestable['chain'], 'dim'))
    if summary['notAudited']:
        lines.append('  ' + style.paint('%d endpoint(s) not audited: no TLS handshake completed '
                                        'there in the scan' % summary['notAudited'], 'dim'))
    if summary['timedOut']:
        lines.append('  ' + style.paint('%d endpoint(s) timed out during the audit: the checks '
                                        'after it were skipped' % summary['timedOut'], 'dim'))
    if show_all:
        for e in audit.endpoints:
            if e.status == AUDIT_NOT_TLS:
                continue
            versions = [_version_text(v) for v in AUDIT_VERSIONS
                        if e.versions[v].outcome == AUDIT_ACCEPTED]
            chain = e.chain.status if e.chain is not None else CHAIN_UNTESTED
            if e.chain is not None and e.chain.problems:
                chain += ' (%s)' % ', '.join(e.chain.problems)
            lines.append('    %s  %s  versions: %s | weak: %s | keys: %s | chain: %s' % (
                e.label, display_text(', '.join(e.servers)), ', '.join(versions) or 'none',
                ', '.join(e.weak_ciphers) or 'none', ', '.join(e.key_types_served) or 'none',
                chain))
    return '\n'.join(lines) + '\n'


_MISMATCH_KINDS = {KIND_ORIGIN_CA: ', Cloudflare Origin CA', 'private': ', private'}


def render_serial_mismatches(mismatches: Sequence[Dict[str, Any]], lines: List[str], style: Style,
                             limit: Optional[int] = MAX_AUDIT_LINES) -> None:
    """The audit's fleet check in the summary (:func:`serial_mismatches`): each name and key
    type served with several certificates (each name, where the key type changed), newest
    first, an older one marked OLDER, with the endpoints serving it and the load balancers or
    VIPs they sit behind."""
    if not mismatches:
        lines.append('  ' + style.paint('Every name is served with one certificate per key type '
                                        'across the endpoints', 'green'))
        return
    lines.append('  ' + style.paint('One name served with different certificates across the '
                                    'endpoints: %d name(s)' % len(mismatches), 'yellow', 'bold'))

    def where(endpoint: Dict[str, Any]) -> str:
        text = endpoint_text(endpoint['ip'], endpoint['port'], endpoint['protocol'])
        if endpoint['servers']:
            text += ' ' + display_text(', '.join(endpoint['servers']))
        pools = ['behind %s' % display_text(lb) for lb in endpoint['behind']]
        pools += ['VIP %s' % vip for vip in endpoint['vips']]
        return text + (' (%s)' % ', '.join(pools) if pools else '')

    for mismatch in list(mismatches)[:limit]:
        kind = _MISMATCH_KINDS.get(mismatch['kind'], '')
        changed = mismatch.get('keyTypeChanged')
        if changed:   # RSA to ECDSA: the older key types, then the newest one's
            before = []  # type: List[str]
            for cert in mismatch['certificates']:
                if cert['keyType'] != mismatch['keyType'] and cert['keyType'] not in before:
                    before.append(cert['keyType'])
            label = '%s to %s%s: the key type changed, no endpoint serves both' % (
                '/'.join(before), mismatch['keyType'], kind)
        else:
            label = mismatch['keyType'] + kind
        lines.append('    %s (%s)' % (display_text(mismatch['name']), label))
        for cert in mismatch['certificates']:
            endpoints = cert['endpoints']
            shown = endpoints if limit is None else endpoints[:limit]
            more = len(endpoints) - len(shown)
            lines.append('      %sserial %s%s, issued %s, expires %s: %s%s' % (
                style.paint('OLDER ', 'red', 'bold') if cert['older'] else '',
                display_text(cert['serialHex'] or '?'),
                ' (%s)' % cert['keyType'] if changed else '', _iso_day(cert['notBefore']),
                _iso_day(cert['notAfter']), '; '.join(where(e) for e in shown),
                ' +%d more' % more if more else ''))
    if limit is not None and len(mismatches) > limit:
        lines.append('    ... and %d more (--show-all lists them)' % (len(mismatches) - limit))


def _row_dict(row: ProbeResult, now: datetime) -> Dict[str, Any]:
    cert = row.cert
    return {
        'server': row.server,
        'ip': row.ip,
        'port': row.port,
        'probe': row.probe,
        'name': row.name,
        'sni': row.sni,
        'status': row.status,
        'coveredBy': row.covered_by,
        'newCertCovers': row.new_cert_covers,
        'certSha256': cert.sha256 if cert else None,
        'certSubjectCN': cert.subject_cn if cert else None,
        'certIssuer': cert.issuer_label() if cert else None,
        'certSerial': cert.serial_hex if cert else None,
        'certNotAfter': iso_utc(cert.not_after) if cert else None,
        'certDaysLeft': cert.days_left(now) if cert else None,
        'tlsVersion': row.tls_version,
        'error': row.error,
        'elapsedMs': row.elapsed_ms,
    }


def _new_cert_dict(report: ScanReport, cert: CertInfo, now: datetime) -> Dict[str, Any]:
    """A ``newCertificates`` entry; with several new certificates it names its --cert FILE."""
    entry = cert.to_dict(now)
    if report.several_new_certs:
        entry['file'] = report.new_cert_files.get(cert.sha256)
    return entry


def _result_dict(report: ScanReport, row: ProbeResult, now: datetime) -> Dict[str, Any]:
    """A ``results`` entry; with several new certificates ``newCertFile`` names the --cert
    FILE of the certificate served (null when it is none of them)."""
    entry = _row_dict(row, now)
    if report.several_new_certs:
        entry['newCertFile'] = report.new_cert_file(row.cert)
    return entry


def report_to_dict(report: ScanReport, monitor: Optional[MonitorResult] = None,
                   estate: bool = False) -> Dict[str, Any]:
    """The ``--json`` document (see the module docstring / README for field meanings).

    With ``monitor`` (:func:`build_monitor`) the document also carries ``baseline`` and
    ``changes`` (with ``--baseline``), ``expiring`` and ``options.warnDays`` (with
    ``--warn-days``); ``estate`` (``--estate``) adds the ``estate`` section
    (:func:`estate_from_report`) and ``options.estate``. Without them, it is exactly the plain
    scan report.
    """
    now = report.finished_at
    new_fps = {cert.sha256 for cert in report.new_certs}
    summaries = report.server_summaries()
    behind = {}  # type: Dict[str, List[str]]
    for server in list(report.servers) + list(report.skipped_backends):
        for name in server.backends:
            behind.setdefault(name.lower(), []).append(server.name)
    servers = []
    for summary in summaries:
        by_status = {}  # type: Dict[str, List[str]]
        for row in summary.rows:
            if row.probe in (PROBE_SNI, PROBE_WILDCARD) and row.name:
                key = 'OTHER' if row.status in HOSTED_STATUSES and not is_relevant(row) \
                    else row.status
                names = by_status.setdefault(key, [])
                if row.name not in names:
                    names.append(row.name)
        default_rows = [row for row in summary.rows if row.probe == PROBE_DEFAULT]
        servers.append({
            'name': summary.server.name,
            'ips': list(summary.server.ips),
            # addresses scanned on ports of their own (203.0.113.10:8443); null = the -p ports
            'ports': {ip: summary.server.port_spec(ip) for ip in summary.server.ips
                      if ip in summary.server.ports},
            'groups': list(summary.server.groups),
            'status': summary.status,
            'needsUpdate': by_status.get(NEEDS_UPDATE, []),
            'updated': by_status.get(UPDATED, []),
            # hosted with a Cloudflare Origin CA / a self-signed or --private-ca certificate
            'originCert': by_status.get(ORIGIN_CERT, []),
            'privateCert': by_status.get(PRIVATE_CERT, []),
            'errors': by_status.get(TLS_ERROR, []) + by_status.get(TIMEOUT, []),
            # hosted with another certificate that the new one does not cover
            'hostedNotInNewCert': by_status.get('OTHER', []),
            'defaultCertNeedsUpdate': any(r.status == NEEDS_UPDATE for r in default_rows),
        })
        # only with topology keys, so an old inventory's report is unchanged; a backend without
        # keys of its own still says which load balancers it is behind
        if summary.server.has_topology() or behind.get(summary.server.name.lower()):
            servers[-1]['topology'] = _topology_dict(summary.server, behind)
    certificates = {}
    for sha, cert in report.certificates.items():
        entry = cert.to_dict(now)
        entry['isNewCert'] = sha in new_fps
        kind, ca = report.cert_kind(cert)
        entry['kind'] = kind  # origin-ca | self-signed | private-ca | other
        entry['privateCa'] = ca.subject_dn if ca is not None else None
        # --ari / --revocation: the CA's renewal window and the CRL's answer (served ones only)
        entry.update(report.cert_status.get(sha) or {})
        certificates[sha] = entry
    doc = {
        'tool': 'ssl_origin_scan',
        'version': __version__,
        'startedAt': iso_utc(report.started_at),
        'finishedAt': iso_utc(report.finished_at),
        'elapsedSeconds': round((report.finished_at - report.started_at).total_seconds(), 3),
        'options': {'ports': list(report.ports), 'timeoutSeconds': report.timeout,
                    'workers': report.workers, 'exclude': list(report.exclude),
                    'strictPublic': report.strict_public,
                    'privateCa': [{'subjectDN': ca.subject_dn, 'sha256': ca.sha256,
                                   'subjectKeyId': ca.subject_key_id}
                                  for ca in report.private_cas]},
        'newCertificates': [_new_cert_dict(report, cert, now) for cert in report.new_certs],
        'names': [{'name': p.name, 'sni': p.sni, 'wildcard': p.wildcard} for p in report.probes],
        'summary': {
            'servers': len(report.servers),
            'endpoints': len(report.endpoints),
            'openEndpoints': sum(1 for e in report.endpoints if e.state == OPEN),
            'serversNeedingUpdate': sum(1 for s in summaries if s.status == NEEDS_UPDATE),
            'serversUpdated': sum(1 for s in summaries if s.status == UPDATED),
            'serversWithOriginCert': sum(1 for s in summaries if s.status == ORIGIN_CERT),
            'serversWithPrivateCert': sum(1 for s in summaries if s.status == PRIVATE_CERT),
            'statusCounts': report.status_counts(),
            'excludedAddresses': report.excluded_count(),
        },
        'servers': servers,
        'endpoints': [_endpoint_dict(e) for e in report.endpoints],
        'results': [_result_dict(report, row, now) for row in report.results],
        # target addresses --exclude removed before the scan (never connected to)
        'excluded': [{'server': e.server, 'ip': e.ip, 'excludedBy': e.rule}
                     for e in report.excluded],
        'certificates': certificates,
        'warnings': list(report.warnings),
    }  # type: Dict[str, Any]
    if monitor is not None:
        if monitor.warn_days is not None:
            doc['options']['warnDays'] = monitor.warn_days
        if monitor.changes is not None:
            doc['baseline'] = monitor.baseline
            doc['changes'] = monitor.changes
        if monitor.expiring is not None:
            doc['expiring'] = monitor.expiring
        if monitor.notify_open:
            doc['notify'] = {'open': monitor.notify_open}
    if report.has_topology:
        # where TLS terminates: the servers with terminates_tls=no left out of the scan
        doc['options']['includeBackends'] = report.include_backends
        doc['skippedBackends'] = [{'name': server.name, 'ips': list(server.ips),
                                   'topology': _topology_dict(server, behind)}
                                  for server in report.skipped_backends]
    named = port_protocols(report.ports)
    if named:  # -p 2525/smtp: the protocol each such port number speaks
        doc['options']['portProtocols'] = {str(port): named[port] for port in sorted(named)}
    if report.profiles:  # --profile: where options.ports came from
        doc['options']['profiles'] = list(report.profiles)
    if report.ari:
        doc['options']['ari'] = True
    if report.revocation:
        doc['options']['revocation'] = True
    if estate:
        doc['options']['estate'] = True
        doc['estate'] = estate_from_report(doc, report.finished_at)
    if report.audit is not None:
        doc['options']['tlsAudit'] = True
        doc['tlsAudit'] = audit_to_dict(report.audit)
    return doc


def _endpoint_dict(endpoint: Endpoint) -> Dict[str, Any]:
    """An ``endpoints`` entry; ``protocol`` only where STARTTLS came first (smtp, imap...)."""
    entry = {'ip': endpoint.ip, 'port': endpoint.port, 'state': endpoint.state,
             'error': endpoint.error, 'connectMs': endpoint.connect_ms}  # type: Dict[str, Any]
    if endpoint.protocol != PROTO_TLS:
        entry['protocol'] = endpoint.protocol
    return entry


def _topology_dict(server: Server, behind: Dict[str, List[str]]) -> Dict[str, Any]:
    """A server's topology in the JSON report: does it get the certificate, its own TLS ports,
    the shared and public addresses it is reached at, its backends and its load balancers."""
    return {'terminatesTls': server.gets_certificate, 'tlsPorts': list(server.tls_ports),
            'vips': list(server.vips), 'nats': list(server.nats),
            'backends': list(server.backends), 'behind': list(behind.get(server.name.lower(), []))}


def render_json(report: ScanReport, ensure_ascii: bool = False,
                monitor: Optional[MonitorResult] = None, estate: bool = False) -> str:
    """Pretty-printed JSON text of :func:`report_to_dict` (UTF-8, 2-space indent).

    ``ensure_ascii=True`` escapes non-ASCII characters (``\\u00fc``) - used when stdout is
    not UTF-8, so every consumer decodes the JSON correctly whatever the code page.
    """
    return json.dumps(report_to_dict(report, monitor, estate), indent=2,
                      ensure_ascii=ensure_ascii) + '\n'


CSV_COLUMNS = ('server', 'ip', 'port', 'probe', 'name', 'sni', 'status', 'covered_by',
               'new_cert_covers', 'cert_subject_cn', 'cert_issuer', 'cert_serial',
               'cert_not_after', 'cert_days_left', 'cert_sha256', 'tls_version', 'error')
# Added after CSV_COLUMNS only when --cert is given several times: the FILE of the new
# certificate a server serves (empty when it serves none of them).
NEW_CERT_CSV_COLUMN = 'new_cert'

# Leading characters that make a spreadsheet evaluate a cell (CSV injection); the same set
# as FORMULA_START in assets/js/lib/export.js.
_CSV_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')


# Escaped in a CSV file: C0 / C1 controls and the bidi embeddings, overrides and isolates,
# which can make a cell show other text than it holds. ZWNJ, ZWJ, the soft hyphen and
# LRM / RLM are part of real names (a Persian O=) and stay as they are.
_CSV_ESCAPE_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]')


def _csv_cell(value: Any, terminal: bool = False) -> Any:
    """A spreadsheet-safe cell: text starting with ``= + - @`` TAB or CR gets a leading
    apostrophe, like the web app's ``toCsv``, and :data:`_CSV_ESCAPE_RE` characters are
    escaped; for ``--csv -`` (``terminal``) every character :func:`display_text` escapes.
    Numbers are left untouched."""
    if not isinstance(value, str):
        return value
    if value.startswith(_CSV_FORMULA_START):
        value = "'" + value
    if terminal:
        return display_text(value)
    return _CSV_ESCAPE_RE.sub(lambda match: _escape_char(match.group()), value)


def render_csv(report: ScanReport, lineterminator: str = '\r\n',
               terminal: bool = False) -> str:
    """One CSV row per result (RFC 4180 quoting); columns are :data:`CSV_COLUMNS`, plus
    :data:`NEW_CERT_CSV_COLUMN` when --cert was given several times.

    With ``--exclude``, one more row per excluded target address follows the results:
    probe ``excluded``, status ``EXCLUDED``, empty port, the matching rule in ``error``.
    Certificate fields come from whatever server answered, so every text cell goes
    through :func:`_csv_cell` (a certificate CN ``=HYPERLINK(...)`` stays text in Excel;
    ``terminal`` for ``--csv -``); the JSON report keeps the exact values.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator=lineterminator)
    several = report.several_new_certs
    columns = CSV_COLUMNS + ((NEW_CERT_CSV_COLUMN,) if several else ()) \
        + (ARI_CSV_COLUMNS if report.ari else ()) + (REVOCATION_CSV_COLUMNS if report.revocation else ())
    writer.writerow(columns)
    for row in report.results:
        data = _row_dict(row, report.finished_at)
        covers = data['newCertCovers']
        values = [
            data['server'], data['ip'], data['port'], data['probe'], data['name'] or '',
            data['sni'] or '', data['status'], data['coveredBy'] or '',
            '' if covers is None else ('yes' if covers else 'no'),
            data['certSubjectCN'] or '', data['certIssuer'] or '', data['certSerial'] or '',
            data['certNotAfter'] or '',
            '' if data['certDaysLeft'] is None else data['certDaysLeft'],
            data['certSha256'] or '', data['tlsVersion'] or '', data['error'] or '',
        ]  # type: List[Any]
        if several:
            values.append(report.new_cert_file(row.cert) or '')
        if report.ari or report.revocation:
            values.extend(status_csv_cells(report.cert_status.get(row.cert.sha256) if row.cert else None,
                                           report.ari, report.revocation))
        writer.writerow([_csv_cell(value, terminal) for value in values])
    for entry in report.excluded:
        row = dict.fromkeys(columns, '')  # type: Dict[str, Any]
        row.update(server=entry.server, ip=entry.ip, probe=PROBE_EXCLUDED, status=EXCLUDED,
                   error='excluded by --exclude %s (never probed)' % entry.rule)
        writer.writerow([_csv_cell(row[column], terminal) for column in columns])
    return buffer.getvalue()


class Style:
    """ANSI styling that degrades to plain text when disabled."""

    _CODES = {'bold': '1', 'dim': '2', 'red': '31', 'green': '32', 'yellow': '33',
              'blue': '34', 'magenta': '35', 'cyan': '36', 'gray': '90'}
    _STATUS = {NEEDS_UPDATE: ('red', 'bold'), UPDATED: ('green', 'bold'), ORIGIN_CERT: ('cyan',),
               PRIVATE_CERT: ('blue',), NOT_HOSTED: ('gray',), TLS_ERROR: ('magenta',),
               TIMEOUT: ('yellow',), CLOSED: ('gray',)}

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, text: str, *styles: str) -> str:
        """Wrap ``text`` in the given styles (``'red'``, ``'bold'`` ...)."""
        if not self.enabled or not styles:
            return text
        codes = ';'.join(self._CODES[s] for s in styles)
        return '\x1b[%sm%s\x1b[0m' % (codes, text)

    def status(self, status: str, width: int = 0) -> str:
        """A status label padded to ``width`` and coloured by severity."""
        return self.paint(status.ljust(width), *self._STATUS.get(status, ()))


def use_color(no_color: bool, stream: TextIO, env: Optional[Dict[str, str]] = None) -> bool:
    """Colours only for a TTY, without ``--no-color`` and without a non-empty ``NO_COLOR``."""
    env = os.environ if env is None else env
    if no_color or env.get('NO_COLOR', ''):
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    return _enable_windows_ansi(stream)


def _enable_windows_ansi(stream: TextIO) -> bool:
    """Turn on VT processing for the Windows console (no-op elsewhere)."""
    if os.name != 'nt':
        return True
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)  # type: ignore[attr-defined]
        handle = msvcrt.get_osfhandle(stream.fileno())  # type: ignore[attr-defined]
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if mode.value & 0x0004:  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            return True
        return bool(kernel32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:  # noqa: BLE001 - no console / no ctypes: just no colours
        return False


def display_text(text: str) -> str:
    """``text`` made safe for a terminal: control, format and line-separator characters
    (ESC, BEL, CR, the C1 CSI, bidi overrides, U+2028) become ``\\xNN`` / ``\\uNNNN``.

    A certificate's subject and issuer come from whatever server answered: printed raw,
    they could erase or rewrite earlier lines of the summary or set the window title,
    ``--no-color`` or not. Only the display is escaped; the JSON keeps the exact values.
    """
    if text.isprintable():
        return text
    return ''.join(_escape_char(char) if unicodedata.category(char) in ('Cc', 'Cf', 'Zl', 'Zp')
                   else char for char in text)


def _escape_char(char: str) -> str:
    """``char`` as the text ``\\xNN``, ``\\uNNNN`` or ``\\UNNNNNNNN``."""
    code = ord(char)
    return ('\\x%02x' % code if code < 0x100 else
            '\\u%04x' % code if code < 0x10000 else '\\U%08x' % code)


def _endpoint_label(ip: str, port: int) -> str:
    return '[%s]:%d' % (ip, port) if ':' in ip else '%s:%d' % (ip, port)


def _days_text(cert: CertInfo, now: datetime, style: Style) -> str:
    days = cert.days_left(now)
    if days < 0:
        return style.paint('EXPIRED %d day%s ago' % (-days, '' if days == -1 else 's'), 'red',
                           'bold')
    text = '%d day%s left' % (days, '' if days == 1 else 's')
    if days <= 30:
        return style.paint(text, 'red', 'bold')
    if days <= 60:
        return style.paint(text, 'yellow')
    return style.paint(text, 'green')


def cert_line(cert: CertInfo, now: datetime, style: Style) -> str:
    """``CN | expires DATE (N days left) | issuer: X`` - what an operator needs first."""
    return '%s | expires %s (%s) | issuer: %s' % (
        display_text(cert.short_label()), cert.not_after.strftime('%Y-%m-%d'),
        _days_text(cert, now, style), display_text(cert.issuer_label()))


def cert_ids(cert: CertInfo) -> str:
    """``serial HEX | sha256 PREFIX...`` - to recognise the exact certificate."""
    return 'serial %s | sha256 %s...' % (cert.serial_hex, cert.sha256[:16])


def _wrap(prefix: str, plain_prefix_len: int, text: str, width: int) -> List[str]:
    body = textwrap.wrap(text, width=max(20, width - plain_prefix_len),
                         break_long_words=False, break_on_hyphens=False) or ['']
    pad = ' ' * plain_prefix_len
    return [prefix + body[0]] + [pad + line for line in body[1:]]


def _group_rank(status: str, relevant: bool) -> int:
    # Relevant NEEDS_UPDATE first; hits the new cert does not cover come after UPDATED.
    order = [(NEEDS_UPDATE, True), (UPDATED, True), (ORIGIN_CERT, True), (PRIVATE_CERT, True),
             (UPDATED, False), (NEEDS_UPDATE, False), (ORIGIN_CERT, False),
             (PRIVATE_CERT, False), (TLS_ERROR, True), (TLS_ERROR, False), (TIMEOUT, True),
             (TIMEOUT, False), (NOT_HOSTED, True), (NOT_HOSTED, False)]
    key = (status, relevant)
    return order.index(key) if key in order else len(order)


def kind_label(kind: str, ca: Optional[CertInfo] = None) -> str:
    """What a certificate kind means in the summary ('' for :data:`KIND_OTHER`)."""
    if kind == KIND_ORIGIN_CA:
        return 'Cloudflare Origin CA'
    if kind == KIND_SELF_SIGNED:
        return 'self-signed'
    if kind == KIND_PRIVATE_CA and ca is not None:
        return 'private CA: %s' % ca.short_label()
    return ''


# Explanations under the ORIGIN_CERT / PRIVATE_CERT sections of the summary.
_ORIGIN_NOTE = ('Only Cloudflare trusts a Cloudflare Origin CA certificate: right for an origin '
                'behind Cloudflare Full (strict) while its names stay proxied (orange cloud).')
_PRIVATE_NOTE = ('Self-signed, or issued by a CA given with --private-ca: usual on internal '
                 'hosts. Public clients do not trust it.')
_NOT_COUNTED_NOTE = ('Not counted as needing the new certificate (--fail-on-needs-update '
                     'ignores them); --strict-public counts them as NEEDS_UPDATE.')


def _render_server(summary: ServerSummary, style: Style, show_all: bool, width: int,
                   now: datetime, has_new_cert: bool,
                   note: Optional[Callable[[str, CertInfo], str]] = None,
                   tag: Optional[Callable[[Server], str]] = None) -> List[str]:
    """Lines for one server: per endpoint, names grouped by (status, served certificate).

    ``note(status, cert)`` may add why a group has its status (``self-signed``); ``tag(server)``
    where TLS terminates (:func:`topology_tag`).
    """
    server = summary.server
    head = '  ' + style.paint(display_text(server.name), 'bold')
    extra_ips = [ip for ip in server.ips if ip != server.name]
    if extra_ips:
        head += '  ' + style.paint(', '.join(extra_ips), 'dim')
    if server.groups:
        head += '  ' + style.paint(display_text('[%s]' % ', '.join(server.groups)), 'dim')
    label = tag(server) if tag is not None else ''
    if label:
        head += '  ' + style.paint(display_text('[%s]' % label), 'dim')
    out = [head]
    by_endpoint = {}  # type: Dict[Tuple[str, int], List[ProbeResult]]
    for row in summary.rows:
        by_endpoint.setdefault((row.ip, row.port), []).append(row)
    label_width = max(len(s) for s in STATUSES)
    indent = 8 + label_width
    for (ip, port), rows in by_endpoint.items():
        label = endpoint_text(ip, port, summary.protocols.get((ip, port), PROTO_TLS))
        connect = next((r for r in rows if r.probe == PROBE_CONNECT), None)
        if connect is not None:
            if show_all or summary.status in (CLOSED, TIMEOUT):
                out.append('    %s  %s  %s' % (label, style.status(connect.status),
                                               style.paint(display_text(connect.error or ''),
                                                           'dim')))
            continue
        default = next((r for r in rows if r.probe == PROBE_DEFAULT), None)
        all_named = [r for r in rows if r.probe in (PROBE_SNI, PROBE_WILDCARD)]
        named = [r for r in all_named if show_all or r.status != NOT_HOSTED]
        show_default = default is not None and (
            show_all or default.status in HOSTED_STATUSES or default.status == UPDATED)
        if not named and not show_default:
            continue
        out.append('    ' + style.paint(label, 'bold'))
        groups = {}  # type: Dict[Tuple[str, bool, str, str], List[ProbeResult]]
        for row in named:
            # Coverage by the new cert is irrelevant for failed handshakes.
            relevant = row.status in (TLS_ERROR, TIMEOUT) or is_relevant(row)
            key = (row.status, relevant, row.cert.sha256 if row.cert else '', row.error or '')
            groups.setdefault(key, []).append(row)
        ordered = sorted(groups.items(), key=lambda item: _group_rank(item[0][0], item[0][1]))
        for (status, relevant, _sha, error), group in ordered:
            prefix = '      %s  ' % style.status(status, label_width)
            if status in (TLS_ERROR, TIMEOUT) and len(group) == len(all_named) > 1:
                text = 'all %d names' % len(group)
            else:
                text = ', '.join(row.name or '' for row in group)
            cert = group[0].cert
            why = note(status, cert) if note is not None and cert is not None else ''
            if why:
                text += '  (%s)' % display_text(why)
            if has_new_cert and not relevant and (status in HOSTED_STATUSES
                                                  or status == UPDATED):
                text += '  (not covered by the new certificate)'
            out.extend(_wrap(prefix, indent, text, width))
            if (status in HOSTED_STATUSES or status == NOT_HOSTED) and cert is not None:
                out.append(' ' * indent + 'current: ' + cert_line(cert, now, style))
                out.append(' ' * (indent + 9) + style.paint(cert_ids(cert), 'dim'))
            elif error:  # handshake failures, names the server refused
                out.append(' ' * indent + style.paint(display_text(error), 'dim'))
        if show_default and default is not None:
            text = '      default certificate (no SNI): %s' % style.status(default.status)
            if default.cert is not None:
                text += '  ' + cert_line(default.cert, now, style)
                why = (note(UPDATED, default.cert)
                       if note is not None and default.status == UPDATED else '')
                if why:
                    text += '  (%s)' % display_text(why)
            elif default.error:
                text += '  ' + style.paint(display_text(default.error), 'dim')
            out.append(text)
    return out


def _section(lines: List[str], title: str, summaries: Sequence[ServerSummary], style: Style,
             colors: Sequence[str], show_all: bool, width: int, now: datetime,
             has_new: bool, note: Optional[Callable[[str, CertInfo], str]] = None,
             explain: Sequence[str] = (), tag: Optional[Callable[[Server], str]] = None) -> None:
    lines.append(style.paint('%s: %d' % (title, len(summaries)), *colors))
    for text in explain:
        lines.extend(style.paint(line, 'dim') for line in _wrap('  ', 2, text, width))
    for summary in summaries:
        lines.extend(_render_server(summary, style, show_all, width, now, has_new, note, tag))
    lines.append('')


def topology_tag(servers: Sequence[Server], answered: Iterable[str] = ()) -> Callable[[Server], str]:
    """``tag(server)``: where TLS terminates for ``server``, from the topology of ``servers``
    (``LB: web01, web02``, ``behind lb01``, ``VIP 203.0.113.50 with lb02``, ``NAT
    203.0.113.10``, ``TLS ports 443,8443``); '' for a server the inventory says nothing about.
    A terminates_tls=no server among ``answered`` (the names of the servers that answered TLS
    for the names) says the inventory looks wrong."""
    answered = set(answered)
    behind = {}  # type: Dict[str, List[str]]
    holders = {}  # type: Dict[str, List[str]]
    for server in servers:
        for name in server.backends:
            behind.setdefault(name.lower(), []).append(server.name)
        for vip in server.vips:
            holders.setdefault(vip, []).append(server.name)

    def tag(server: Server) -> str:
        parts = []  # type: List[str]
        if server.backends:
            parts.append('LB: %s%s' % (', '.join(server.backends),
                                       '' if server.gets_certificate else ', TLS passed through'))
        lbs = behind.get(server.name.lower(), [])
        wrong = not server.gets_certificate and not server.backends and server.name in answered
        if lbs:
            parts.append('behind %s, %s' % (', '.join(lbs), 're-encrypts' if server.gets_certificate
                                            else _ANSWERS_ANYWAY if wrong else 'plain HTTP'))
        elif not server.gets_certificate and not server.backends:
            parts.append(_ANSWERS_ANYWAY if wrong else 'terminates_tls=no')
        for vip in server.vips:
            others = [name for name in holders.get(vip, []) if name != server.name]
            parts.append('VIP %s%s' % (vip, ' with %s' % ', '.join(others) if others else ''))
        parts.extend('NAT %s' % nat for nat in server.nats)
        if server.tls_ports:
            parts.append('TLS ports %s' % ','.join(str(port) for port in server.tls_ports))
        return '; '.join(parts)
    return tag


# A terminates_tls=no server that served a certificate covering the names (UPDATED, NEEDS_UPDATE,
# ORIGIN_CERT, PRIVATE_CERT): the inventory looks wrong, never "no certificate needed".
_ANSWERS_TLS = (UPDATED,) + HOSTED_STATUSES
_ANSWERS_ANYWAY = 'terminates_tls=no but answers TLS - check the inventory'


def render_topology(report: ScanReport, summaries: Sequence[ServerSummary], style: Style,
                    width: int = 100) -> List[str]:
    """The summary's topology lines, grouped by load balancer: each load balancer with its
    status and the servers behind it (plain HTTP - no certificate, or re-encrypting - needs it
    too), every VIP and the servers to install on, the NAT pairs, and the servers with
    terminates_tls=no that were not scanned. [] without a topology key in the targets."""
    servers = list(report.servers) + list(report.skipped_backends)
    if not any(server.has_topology() for server in servers):
        return []
    by_name = {server.name.lower(): server for server in servers}
    status = {summary.server.name: summary.status for summary in summaries}
    skipped = {server.name for server in report.skipped_backends}

    def state(server: Server) -> str:
        if server.name in skipped:
            return style.paint('not scanned', 'dim')
        return style.status(status[server.name]) if server.name in status else \
            style.paint('excluded', 'dim')

    lines = []  # type: List[str]
    lbs = [server for server in servers if server.backends]
    if lbs:
        lines.append(style.paint('By load balancer: %d' % len(lbs), 'bold'))
        for lb in lbs:
            ends = _terminates_behind(lb, by_name)
            if lb.gets_certificate:
                role = 'terminates TLS: install the certificate here'
            elif status.get(lb.name) in _ANSWERS_TLS:
                role = ('passes TLS through (terminates_tls=no) and answers TLS for the names: its '
                        'backends\' certificate, or the inventory is wrong - check it' if ends else
                        'says terminates_tls=no, yet answers TLS for the names and no backend '
                        'terminates TLS: the inventory is wrong - check it')
            elif ends:
                role = 'passes TLS through (terminates_tls=no): no certificate here'
            else:
                role = ('passes TLS through (terminates_tls=no), but no backend behind it '
                        'terminates TLS: TLS terminates nowhere - check the inventory')
            vips = ['VIP %s' % vip for vip in lb.vips]
            plain = '  %s  %s  ' % (display_text(lb.name), _plain_state(lb, skipped, status))
            lines.extend(_wrap('  %s  %s  ' % (style.paint(display_text(lb.name), 'bold'), state(lb)),
                               len(plain), display_text('; '.join([role] + vips)), width))
            for name in lb.backends:
                backend = by_name.get(name.lower())
                if backend is None:
                    lines.append('    -> %s  %s' % (display_text(name), style.paint('not in the targets', 'dim')))
                    continue
                if backend.gets_certificate:
                    what = 're-encrypts: needs the certificate too'
                elif status.get(backend.name) in _ANSWERS_TLS:
                    what = ('answers TLS for the names although the inventory says plain HTTP '
                            '(terminates_tls=no) - check the inventory')
                else:
                    what = 'plain HTTP, no certificate needed'
                    if backend.name in skipped:
                        what += ' (--include-backends scans it)'
                prefix = '    -> %s  %s  ' % (display_text(backend.name), state(backend))
                plain = '    -> %s  %s  ' % (display_text(backend.name),
                                             _plain_state(backend, skipped, status))
                lines.extend(_wrap(prefix, len(plain), what, width))
        lines.append('')
    holders = {}  # type: Dict[str, List[Server]]
    for server in servers:
        for vip in server.vips:
            holders.setdefault(vip, []).append(server)
    for vip, held in holders.items():
        # install on the holders that terminate TLS; say when the inventory disagrees with itself
        names = [server.name for server in held if server.gets_certificate]
        plain = [server.name for server in held if not server.gets_certificate]
        if names and plain:
            text = 'install the certificate on %s; %s %s terminates_tls=no - check the inventory' % (
                ', '.join(names), ', '.join(plain), 'says' if len(plain) == 1 else 'say')
        elif plain:
            text = '%s - plain HTTP (terminates_tls=no), no certificate' % ', '.join(plain)
        else:
            text = '%s - %s' % (', '.join(names), 'install the certificate on both' if len(names) == 2
                                else 'install the certificate on all %d' % len(names)
                                if len(names) > 2 else 'held by %s only' % names[0])
        lines.extend(_wrap('Shared address (VIP) %s: ' % vip, 2, display_text(text), width))
    for server in servers:
        for nat in server.nats:
            lines.append(display_text('NAT %s -> %s (%s)' % (nat, server.name, ', '.join(server.ips))))
    behind = {name.lower() for server in servers for name in server.backends}
    loose = [server.name for server in report.skipped_backends
             if server.name.lower() not in behind and not server.backends]
    if loose:
        lines.extend(_wrap('Not scanned (terminates_tls=no): ', 2, display_text(
            '%s - --include-backends scans them' % ', '.join(loose)), width))
    if lines and lines[-1] != '':
        lines.append('')
    return lines


def _plain_state(server: Server, skipped: Set[str], status: Dict[str, str]) -> str:
    """The state :func:`render_topology` prints for ``server``, without colours (its width)."""
    if server.name in skipped:
        return 'not scanned'
    return status.get(server.name, 'excluded')


def _excluded_line(report: ScanReport, style: Style, limit: int = 10) -> str:
    """``Excluded by --exclude (never probed): N address(es) - rule, rule ...``."""
    count = report.excluded_count()
    text = 'Excluded by --exclude (never probed): %d address%s' % (count,
                                                                  '' if count == 1 else 'es')
    used = list(dict.fromkeys(entry.rule for entry in report.excluded))
    if used:
        text += ' - ' + ', '.join(used[:limit]) + (' ...' if len(used) > limit else '')
    elif report.exclude:
        text += ' (no target matched %s%s)' % (', '.join(report.exclude[:limit]),
                                               ' ...' if len(report.exclude) > limit else '')
    return style.paint(text, 'yellow') if count else text


def render_summary(report: ScanReport, color: bool = False, show_all: bool = False,
                   width: int = 100, monitor: Optional[MonitorResult] = None) -> str:
    """Human-readable report, most actionable first.

    Sections: with ``monitor``, the changes since the baseline and the certificates
    expiring soon (:func:`render_monitor`); then servers that need the new certificate
    (with the certificate they serve now, its expiry, days left and issuer), servers
    already serving it, servers serving a Cloudflare Origin CA certificate and servers
    serving a self-signed or private-CA one (each explained, not counted as needing the
    new certificate), handshake errors, servers that host only names the new certificate
    does not cover, and - only with ``show_all`` - servers not hosting any name and
    unreachable ones (otherwise counted). With topology keys in the targets (ports=,
    terminates_tls=, vip=, backends=, nat=) the servers are first grouped by load balancer
    (:func:`render_topology`) and each server line says where TLS terminates for it.
    """
    style = Style(color)
    now = report.finished_at
    summaries = report.server_summaries()
    has_new = bool(report.new_certs)
    elapsed = (report.finished_at - report.started_at).total_seconds()
    open_count = sum(1 for e in report.endpoints if e.state == OPEN)
    # -p plus the ports written with addresses (203.0.113.10:8443)
    ports = list(dict.fromkeys(e.port for e in report.endpoints)) or list(report.ports)
    header = 'SSL origin scan: %d server(s), %d endpoint(s) (%d open), %d name(s), ' \
        'ports %s, %.1fs' % (len(report.servers), len(report.endpoints), open_count,
                             len(report.probes), ','.join(str(p) for p in ports), elapsed)
    lines = [style.paint(header, 'bold')]
    if report.exclude:
        lines.append(_excluded_line(report, style))
    for cert in report.new_certs:
        source = report.new_cert_file(cert)
        lines.append('New certificate%s: %s | %s' % (
            ' (%s)' % display_text(source) if source else '', cert_line(cert, now, style),
            cert_ids(cert)))
    if report.private_cas:
        labels = [ca.short_label() for ca in report.private_cas]
        lines.append(display_text('Private CAs (--private-ca): %s%s' % (
            ', '.join(labels[:5]), ' ...' if len(labels) > 5 else '')))
    if not has_new:
        lines.append(style.paint('No --cert given: every server whose certificate covers a name '
                                 'is listed (status NEEDS_UPDATE; ORIGIN_CERT / PRIVATE_CERT for '
                                 'Cloudflare Origin CA, self-signed and private-CA '
                                 'certificates).', 'dim'))
    if report.strict_public:
        lines.append(style.paint('--strict-public: Cloudflare Origin CA, self-signed and '
                                 'private-CA certificates count as NEEDS_UPDATE.', 'dim'))
    lines.append('')
    if monitor is not None:
        lines.extend(render_monitor(report, monitor, style, show_all, width))
    # Where TLS terminates (the inventory's topology keys): grouped by load balancer first.
    lines.extend(render_topology(report, summaries, style, width))
    tag = topology_tag(list(report.servers) + list(report.skipped_backends),
                       [s.server.name for s in summaries if s.status in _ANSWERS_TLS]) \
        if report.has_topology else None

    def note(status: str, cert: CertInfo) -> str:
        # Why a group is ORIGIN_CERT / PRIVATE_CERT, or why --strict-public made it NEEDS_UPDATE;
        # with several --cert files, which one an UPDATED group serves.
        if status in (ORIGIN_CERT, PRIVATE_CERT) or (status == NEEDS_UPDATE
                                                     and report.strict_public):
            return kind_label(*report.cert_kind(cert))
        source = report.new_cert_file(cert) if status == UPDATED else None
        return 'matches %s' % source if source else ''

    buckets = {}  # type: Dict[str, List[ServerSummary]]
    for summary in summaries:
        buckets.setdefault(summary.status, []).append(summary)
    needs = buckets.get(NEEDS_UPDATE, [])
    _section(lines, 'Servers that need the new certificate' if has_new
             else 'Servers hosting the names', needs, style,
             ('red', 'bold') if needs else ('green', 'bold'), show_all, width, now, has_new,
             note, tag=tag)
    if has_new:
        _section(lines, 'Already serving the new certificate', buckets.get(UPDATED, []), style,
                 ('green', 'bold'), show_all, width, now, has_new, note, tag=tag)
    if buckets.get(ORIGIN_CERT):
        _section(lines, 'Serving a Cloudflare Origin CA certificate', buckets[ORIGIN_CERT],
                 style, ('cyan', 'bold'), show_all, width, now, has_new, note,
                 (_ORIGIN_NOTE, _NOT_COUNTED_NOTE) if has_new else (_ORIGIN_NOTE,), tag=tag)
    if buckets.get(PRIVATE_CERT):
        _section(lines, 'Serving a self-signed or private-CA certificate', buckets[PRIVATE_CERT],
                 style, ('blue', 'bold'), show_all, width, now, has_new, note,
                 (_PRIVATE_NOTE, _NOT_COUNTED_NOTE) if has_new else (_PRIVATE_NOTE,), tag=tag)

    errors = [s for s in buckets.get(TLS_ERROR, []) + buckets.get(TIMEOUT, [])
              if any(r.probe != PROBE_CONNECT for r in s.rows)]
    if errors:
        _section(lines, 'Handshake errors', errors, style, ('magenta', 'bold'), show_all, width,
                 now, has_new, tag=tag)

    not_hosted = buckets.get(NOT_HOSTED, [])
    other_cert = [s for s in not_hosted if any(r.status in HOSTED_STATUSES and not is_relevant(r)
                                               for r in s.rows)]
    not_hosted = [s for s in not_hosted if s not in other_cert]
    if other_cert:
        _section(lines, 'Hosting only names the new certificate does not cover', other_cert,
                 style, ('bold',), show_all, width, now, has_new, note, tag=tag)
    unreachable = [s for s in summaries if s.status in (CLOSED, TIMEOUT)
                   and all(r.probe == PROBE_CONNECT for r in s.rows)]
    if show_all:
        if not_hosted:
            _section(lines, 'Not hosting any of the names', not_hosted, style, ('bold',), True,
                     width, now, has_new, tag=tag)
        if unreachable:
            _section(lines, 'Unreachable (no open port)', unreachable, style, ('bold',), True,
                     width, now, has_new, tag=tag)
    else:
        hidden = []
        if not_hosted:
            hidden.append('%d not hosting any of the names' % len(not_hosted))
        if unreachable:
            hidden.append('%d unreachable (no open port)' % len(unreachable))
        if hidden:
            lines.append(style.paint('Other servers: %s - use --show-all to list them.'
                                     % '; '.join(hidden), 'dim'))
            lines.append('')

    lines.extend(render_cert_status(report, style, width, show_all))  # --ari / --revocation
    counts = report.status_counts()
    # ORIGIN_CERT / PRIVATE_CERT only when there are any: the line stays short otherwise.
    shown = [status for status in (NEEDS_UPDATE, UPDATED, ORIGIN_CERT, PRIVATE_CERT, NOT_HOSTED,
                                   TLS_ERROR, TIMEOUT, CLOSED)
             if counts.get(status) or status not in (ORIGIN_CERT, PRIVATE_CERT)]
    totals = ', '.join('%s %d' % (style.status(status), counts.get(status, 0))
                       for status in shown)
    lines.append('Results (server/port/name): ' + totals)
    return '\n'.join(lines) + '\n'


class ProgressPrinter:
    """Single-line progress on stderr (only when it is a TTY)."""

    _LABELS = {'connect': 'Checking ports', 'tls': 'TLS handshakes', 'resolve': 'Resolving',
               'retry': 'Retrying reset handshakes', 'audit': 'TLS audit'}

    def __init__(self, stream: TextIO, enabled: bool) -> None:
        self.stream = stream
        self.enabled = enabled
        self._last = 0.0
        self._width = 0

    def update(self, phase: str, done: int, total: int, info: Dict[str, int]) -> None:
        """Redraw the progress line (throttled to ~10 updates per second)."""
        if not self.enabled:
            return
        now = time.monotonic()
        if done < total and now - self._last < 0.1:
            return
        self._last = now
        text = '%s: %d/%d (%d%%)' % (self._LABELS.get(phase, phase), done, total,
                                     (done * 100 // total) if total else 100)
        if 'open' in info:
            text += ' - %d open' % info['open']
        pad = max(0, self._width - len(text))
        self._width = len(text)
        self.stream.write('\r' + text + ' ' * pad)
        self.stream.flush()

    def finish(self) -> None:
        """Erase the progress line."""
        if self.enabled and self._width:
            self.stream.write('\r' + ' ' * self._width + '\r')
            self.stream.flush()
            self._width = 0


# =====================================================================================
# Monitoring: changes since a --baseline report, --warn-days expiry, --notify webhooks
# =====================================================================================

# "No certificate answer"; every other row status but NOT_HOSTED (see _covers_name).
_FAILED_STATUSES = (TLS_ERROR, TIMEOUT, CLOSED)
_NOT_COVERING = _FAILED_STATUSES + (NOT_HOSTED, OPEN, EXCLUDED)
_ROW_PROBES = (PROBE_SNI, PROBE_WILDCARD, PROBE_DEFAULT)
# A status as a report spells it: a later version may add some, compared as plain text.
_STATUS_TOKEN_RE = re.compile(r'^[A-Z][A-Z0-9_]{0,31}$')
_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
_ISO_UTC_RE = re.compile(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2})')
MAX_SUMMARY_CHANGES = 50    # change lines in the summary without --show-all
MAX_SUMMARY_ENDPOINTS = 10  # endpoints per expiring certificate without --show-all


@dataclass
class MonitorResult:
    """What ``--baseline`` and ``--warn-days`` add to a scan (see :func:`build_monitor`).

    ``changes`` (:func:`compare_reports`, the ones that count first: :func:`order_changes`)
    and ``baseline`` (:func:`baseline_info`) are None without a baseline, ``expiring`` (:func:`expiring_certificates`) is None
    without ``--warn-days``; the JSON keys follow the same rule. ``notify_open``: the PagerDuty
    keys still open after this run (:func:`pagerduty_plan`), the JSON's ``notify.open``.
    """

    baseline: Optional[Dict[str, Any]] = None
    changes: Optional[List[Dict[str, Any]]] = None
    warn_days: Optional[int] = None
    expiring: Optional[List[Dict[str, Any]]] = None
    notify_open: Optional[List[Dict[str, Any]]] = None


def _baseline_row_problem(row: Any) -> Optional[str]:
    if not isinstance(row, dict):
        return 'is not an object'
    ip = row.get('ip')
    if not isinstance(ip, str) or normalize_ip(ip) is None:
        return 'has no valid "ip"'
    port = row.get('port')
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        return 'has no valid "port"'
    status = row.get('status')
    if not isinstance(status, str) or not _STATUS_TOKEN_RE.match(status):
        return 'has no valid "status"'
    if not isinstance(row.get('probe'), str):
        return 'has no "probe"'
    for key in ('server', 'name', 'certSubjectCN', 'certIssuer', 'certNotAfter', 'error'):
        if row.get(key) is not None and not isinstance(row.get(key), str):
            return 'has a "%s" that is not text' % key
    sha = row.get('certSha256')
    if sha is not None and not (isinstance(sha, str) and _SHA256_RE.match(sha)):
        return 'has no valid "certSha256"'
    return None


def baseline_problem(doc: Any) -> Optional[str]:
    """Why ``doc`` cannot be a baseline, or None: it must be a ``--json`` report of this
    tool, written by a version with the same major number, with well-formed rows."""
    if not isinstance(doc, dict) or doc.get('tool') != 'ssl_origin_scan':
        return 'it is not a --json report of %s (no "tool": "ssl_origin_scan")' % PROG
    version = doc.get('version')
    if not isinstance(version, str) or version.split('.')[0] != __version__.split('.')[0]:
        return 'it was written by version %r, which this version (%s) cannot compare' % (
            version, __version__)
    results = doc.get('results')
    if not isinstance(results, list):
        return 'it has no "results" list'
    # the containers the comparison walks: a damaged one is a usage error, never a traceback
    for key in ('names', 'newCertificates'):
        if doc.get(key) is not None and not isinstance(doc.get(key), list):
            return 'its "%s" is not a list' % key
    options = doc.get('options')
    if options is not None and not isinstance(options, dict):
        return 'its "options" is not an object'
    if isinstance(options, dict) and options.get('ports') is not None \
            and not isinstance(options.get('ports'), list):
        return 'its "options.ports" is not a list'
    for index, row in enumerate(results):
        problem = _baseline_row_problem(row)
        if problem:
            return 'results[%d] %s' % (index, problem)
    return None


def load_baseline(path: str, allow_missing: bool = False) -> Optional[Dict[str, Any]]:
    """Read ``--baseline FILE``, a previous ``--json`` report of this tool.

    UTF-8 or UTF-16 with a BOM (PowerShell 5.1's ``>``). Returns None for a file that
    does not exist when ``allow_missing`` is set: the first run of a job whose ``--json``
    report is also its baseline. Raises :class:`UsageError` for a file that cannot be
    read, is not JSON or is not a report it can compare (:func:`baseline_problem`).
    """
    try:
        text = read_text_file(path)
    except FileNotFoundError:
        if allow_missing:
            return None
        raise UsageError('--baseline: %s does not exist (give a report written with --json)'
                         % path)
    except OSError as exc:
        raise UsageError('--baseline: cannot read %s: %s' % (path, exc.strerror or exc))
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError) as exc:
        raise UsageError('--baseline: %s is not JSON (%s)' % (path, exc))
    problem = baseline_problem(doc)
    if problem:
        raise UsageError('--baseline: cannot compare with %s: %s' % (path, problem))
    return doc


def _row_view(row: Dict[str, Any]) -> Dict[str, Any]:
    """The ``before`` / ``after`` side of a row change."""
    return {key: row.get(key) for key in ('status', 'certSha256', 'certSubjectCN', 'certIssuer',
                                           'certNotAfter', 'error')}


def _index_report(doc: Dict[str, Any]
                  ) -> Tuple[Dict[Tuple[str, int], Dict[str, Any]], List[str]]:
    """``{(ip, port): endpoint}`` in report order, and the probed names, of a report dict.

    An endpoint is ``{status: OPEN | CLOSED | TIMEOUT, error, servers, rows}``, where
    ``rows`` maps a probe name (None for the no-SNI probe) to ``{probe, servers, view}``.
    Servers sharing an address have the same handshakes, so their rows are one entry
    listing every server. Rows of a probe kind this version does not know are skipped.
    """
    endpoints = {}  # type: Dict[Tuple[str, int], Dict[str, Any]]
    for row in doc.get('results') or []:
        if not isinstance(row, dict) or row.get('probe') not in _ROW_PROBES + (PROBE_CONNECT,):
            continue
        ip = str(row.get('ip'))
        key = (normalize_ip(ip) or ip, row.get('port'))
        endpoint = endpoints.setdefault(key, {'status': OPEN, 'error': None, 'servers': [],
                                              'rows': {}})
        server = row.get('server')
        if server and server not in endpoint['servers']:
            endpoint['servers'].append(server)
        if row['probe'] == PROBE_CONNECT:
            endpoint['status'], endpoint['error'] = row.get('status'), row.get('error')
            continue
        name = None if row['probe'] == PROBE_DEFAULT else row.get('name')
        entry = endpoint['rows'].setdefault(name, {'probe': row['probe'], 'servers': [],
                                                   'view': _row_view(row)})
        if server and server not in entry['servers']:
            entry['servers'].append(server)
    names = {}  # type: Dict[str, None]
    for probe in doc.get('names') or []:
        name = probe.get('name') if isinstance(probe, dict) else None
        if isinstance(name, str):
            names.setdefault(name)
    if not names:  # a report without "names": what its rows probed
        for endpoint in endpoints.values():
            for name in endpoint['rows']:
                if name:
                    names.setdefault(name)
    return endpoints, list(names)


def _status_counts(statuses: Iterable[str]) -> Dict[str, int]:
    """``{status: rows}`` in :data:`STATUSES` order (statuses of later versions last)."""
    counts = {}  # type: Dict[str, int]
    for status in statuses:
        counts[status] = counts.get(status, 0) + 1
    order = list(STATUSES) + sorted(status for status in counts if status not in STATUSES)
    return {status: counts[status] for status in order if status in counts}


def _endpoint_view(endpoint: Dict[str, Any]) -> Dict[str, Any]:
    named = [entry['view']['status'] for name, entry in endpoint['rows'].items() if name]
    return {'status': endpoint['status'], 'error': endpoint['error'], 'names': len(named),
            'statusCounts': _status_counts(named)}


def _name_view(endpoints: Dict[Tuple[str, int], Dict[str, Any]], name: str) -> Dict[str, Any]:
    statuses = [endpoint['rows'][name]['view']['status'] for endpoint in endpoints.values()
                if name in endpoint['rows']]
    return {'endpoints': len(statuses), 'statusCounts': _status_counts(statuses)}


def _covers_name(status: Any) -> bool:
    """True for a row status that means "serves a certificate covering the name":
    UPDATED, NEEDS_UPDATE, ORIGIN_CERT, PRIVATE_CERT and any status this version does
    not know (a later one, such as another kind of certificate), so a baseline from
    another version still compares.
    NOT_HOSTED, TLS_ERROR, TIMEOUT, CLOSED and the endpoint states are not."""
    return isinstance(status, str) and status not in _NOT_COVERING


def status_transition(before: str, after: str) -> str:
    """How a status moved: ``failed`` (to TLS_ERROR / TIMEOUT / CLOSED), ``recovered``
    (from one), ``failing`` (from one of them to another, see :func:`counts_as_change`),
    ``regressed`` (UPDATED -> NEEDS_UPDATE or another covering status), ``updated`` (to
    UPDATED from one), ``unhosted`` (a covering status -> NOT_HOSTED), ``hosted`` (the
    reverse), or ``changed`` (e.g. between two covering statuses other than UPDATED).
    Endpoint states count OPEN as a success (see :func:`_covers_name`)."""
    if after in _FAILED_STATUSES and before in _FAILED_STATUSES:
        return 'failing'
    if after in _FAILED_STATUSES and before not in _FAILED_STATUSES:
        return 'failed'
    if before in _FAILED_STATUSES and after not in _FAILED_STATUSES:
        return 'recovered'
    if before == UPDATED and _covers_name(after):
        return 'regressed'
    if after == UPDATED and _covers_name(before):
        return 'updated'
    if _covers_name(before) and after == NOT_HOSTED:
        return 'unhosted'
    if before == NOT_HOSTED and _covers_name(after):
        return 'hosted'
    return 'changed'


def counts_as_change(change: Dict[str, Any]) -> bool:
    """False for a move from one failure state to another (``failing``: CLOSED ->
    TIMEOUT, TLS_ERROR -> TIMEOUT): nothing was served either way, and on a sweep with a
    short --timeout a refused connection and a timeout can take turns from run to run.
    Such a move is listed (summary, JSON, message) but does not trigger --notify or
    --fail-on-change, nor keep a baseline whose message was not delivered."""
    return (change.get('transition') != 'failing'
            and (change.get('after') or {}).get('status') != SKIPPED)


def notable_changes(changes: Optional[Sequence[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """The changes that count (:func:`counts_as_change`), in their order."""
    return [change for change in changes or [] if counts_as_change(change)]


def order_changes(changes: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The changes that count first, then the FAILING moves, each group in its order: the
    summary's cap, the JSON ``changes``, the webhook payload's cap and the message all cut
    the moves between failure states, never a change that counts."""
    return notable_changes(changes) + [c for c in changes if not counts_as_change(c)]


def _change(kind: str, scope: str, servers: Sequence[str] = (), ip: Optional[str] = None,
            port: Optional[int] = None, probe: Optional[str] = None,
            name: Optional[str] = None, before: Optional[Dict[str, Any]] = None,
            after: Optional[Dict[str, Any]] = None, transition: Optional[str] = None,
            cert_changed: bool = False) -> Dict[str, Any]:
    return {'kind': kind, 'scope': scope, 'transition': transition, 'servers': list(servers),
            'ip': ip, 'port': port, 'probe': probe, 'name': name, 'before': before,
            'after': after, 'certChanged': cert_changed}


def _row_change(old: Optional[Dict[str, Any]], new: Optional[Dict[str, Any]], ip: str,
                port: int, name: Optional[str]) -> Optional[Dict[str, Any]]:
    entry = new or old
    assert entry is not None
    where = dict(servers=entry['servers'], ip=ip, port=port, probe=entry['probe'], name=name)
    if old is None or new is None:
        return _change('appeared' if old is None else 'disappeared', 'row',
                       before=old['view'] if old else None, after=new['view'] if new else None,
                       **where)
    before, after = old['view'], new['view']
    cert_changed = bool(before['certSha256'] and after['certSha256']
                        and before['certSha256'] != after['certSha256'])
    if before['status'] != after['status']:
        return _change('status', 'row', before=before, after=after, cert_changed=cert_changed,
                       transition=status_transition(before['status'], after['status']), **where)
    # Another certificate for a name the server hosts, or a default certificate that
    # covers a probed name. A NOT_HOSTED row's certificate - for a name or without SNI -
    # is whatever the server falls back to (a proxy's self-signed certificate made anew on
    # every restart, another site's renewed one): not a change.
    if cert_changed and _covers_name(after['status']):
        return _change('cert', 'row', before=before, after=after, cert_changed=True, **where)
    return None


def compare_reports(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What changed from the report ``before`` (the baseline) to ``after``, both
    :func:`report_to_dict` documents, per IP, port and name.

    Each change is ``{kind, scope, transition, servers, ip, port, probe, name, before,
    after, certChanged}``:

    * scope ``name`` - a name probed in only one of the reports (``appeared`` /
      ``disappeared``), with its ``statusCounts`` over the endpoints; its rows are not
      listed one by one;
    * scope ``endpoint`` - an ip:port scanned in only one report (``appeared`` /
      ``disappeared``; ``after.status`` is ``EXCLUDED`` when ``--exclude`` removed it) or
      whose port state moved (``status``: OPEN / CLOSED / TIMEOUT), with the name counts
      on the open side; its rows are not listed one by one either;
    * scope ``row`` - on an endpoint open in both: a status that moved (``status``, with
      ``transition`` from :func:`status_transition` and ``certChanged``), another
      certificate with the same status (``cert``: only for rows whose certificate
      covers the name - UPDATED, NEEDS_UPDATE or a status of a later version - also
      for the no-SNI probe, ``name`` None; a NOT_HOSTED row's fallback certificate is not
      a change), or a row only one report has;
    * scope ``certificate`` - with --ari / --revocation, a certificate served now
      (:func:`_status_changes`): ``renew-now``, ``moved-up``, ``ca-notice``, ``revoked``.

    Order: names, then endpoints in the order of ``after`` followed by the ones only
    ``before`` has, each with its rows in probe order.
    """
    old_endpoints, old_names = _index_report(before)
    new_endpoints, new_names = _index_report(after)
    old_set, new_set = set(old_names), set(new_names)
    added = [name for name in new_names if name not in old_set]
    removed = [name for name in old_names if name not in new_set]
    changes = [_change('appeared', 'name', name=name, after=_name_view(new_endpoints, name))
               for name in added]
    changes.extend(_change('disappeared', 'name', name=name,
                           before=_name_view(old_endpoints, name)) for name in removed)
    skip = set(added) | set(removed)
    excluded = {}  # type: Dict[str, Any]
    for entry in after.get('excluded') or []:
        if isinstance(entry, dict) and isinstance(entry.get('ip'), str):
            excluded.setdefault(normalize_ip(entry['ip']) or entry['ip'], entry.get('excludedBy'))
    skipped = set()  # the addresses of servers left out for terminates_tls=no (skippedBackends)
    for entry in after.get('skippedBackends') or []:
        if isinstance(entry, dict) and isinstance(entry.get('ips'), list):
            skipped.update(normalize_ip(ip) or ip for ip in entry['ips'] if isinstance(ip, str))
    keys = list(new_endpoints) + [key for key in old_endpoints if key not in new_endpoints]
    for key in keys:
        old, new = old_endpoints.get(key), new_endpoints.get(key)
        ip, port = key
        if old is None or new is None or old['status'] != new['status']:
            before_view = _endpoint_view(old) if old else None
            after_view = _endpoint_view(new) if new else None
            if new is None and ip in excluded:
                after_view = {'status': EXCLUDED, 'excludedBy': excluded[ip]}
            elif new is None and ip in skipped:
                after_view = {'status': SKIPPED, 'reason': 'terminates_tls=no'}
            if old is None or new is None:
                kind, transition = ('appeared' if old is None else 'disappeared'), None
            else:
                kind, transition = 'status', status_transition(old['status'], new['status'])
            changes.append(_change(kind, 'endpoint', (new or old or {})['servers'], ip, port,
                                   before=before_view, after=after_view,
                                   transition=transition))
            continue
        if new['status'] != OPEN:
            continue
        names = [name for name in new['rows'] if name not in skip]
        names.extend(name for name in old['rows'] if name not in skip and name not in new['rows'])
        for name in names:
            change = _row_change(old['rows'].get(name), new['rows'].get(name), ip, port, name)
            if change is not None:
                changes.append(change)
    # --ari / --revocation: what the CAs say about the certificates served now
    changes.extend(_status_changes(before, after))
    return changes


def baseline_info(before: Dict[str, Any], after: Dict[str, Any],
                  file: Optional[str] = None) -> Dict[str, Any]:
    """The JSON ``baseline`` block: the baseline's file, version and times, and what the
    two runs did differently - ``portsAdded`` / ``portsRemoved`` and
    ``newCertificateChanged`` (another ``--cert``, so UPDATED and NEEDS_UPDATE moved
    with it; no ``--cert`` counts as one set of certificates too)."""
    def ports(doc: Dict[str, Any]) -> List[int]:
        options = doc.get('options') if isinstance(doc.get('options'), dict) else {}
        return [port for port in options.get('ports') or []
                if isinstance(port, int) and not isinstance(port, bool)]

    def new_fps(doc: Dict[str, Any]) -> List[str]:
        return sorted({cert.get('sha256') for cert in doc.get('newCertificates') or []
                       if isinstance(cert, dict) and isinstance(cert.get('sha256'), str)})

    def text(key: str) -> Optional[str]:
        value = before.get(key)
        return value if isinstance(value, str) else None

    old_ports, new_ports = ports(before), ports(after)
    old_set, new_set = set(old_ports), set(new_ports)
    return {'file': file, 'missing': False, 'version': text('version'),
            'startedAt': text('startedAt'), 'finishedAt': text('finishedAt'),
            'portsAdded': [port for port in new_ports if port not in old_set],
            'portsRemoved': [port for port in old_ports if port not in new_set],
            'newCertificateChanged': new_fps(before) != new_fps(after)}


def expiring_certificates(doc: Dict[str, Any], warn_days: int) -> List[Dict[str, Any]]:
    """Served certificates of a report dict that expire within ``warn_days`` days (or
    have expired), soonest first.

    Only certificates that cover a probed name count - UPDATED / NEEDS_UPDATE rows (and
    covering statuses of later versions, :func:`_covers_name`), also for the no-SNI
    probe; the certificate a server falls back to for a name it does not host
    (NOT_HOSTED) does not. Each entry is ``{sha256, subjectCN, issuer, serialHex,
    notAfter, daysLeft, expired, isNewCert, endpoints: [{server, ip, port, names,
    defaultCert}]}``.
    """
    certificates = doc.get('certificates') if isinstance(doc.get('certificates'), dict) else {}
    found = {}  # type: Dict[str, Dict[str, Any]]
    # (sha256, server, ip, port) -> (endpoint entry, its names as a set): a wildcard
    # certificate served by thousands of endpoints must not cost a scan of a list per row
    where_index = {}  # type: Dict[Tuple[Any, ...], Tuple[Dict[str, Any], Set[str]]]
    for row in doc.get('results') or []:
        if (not isinstance(row, dict) or row.get('probe') not in _ROW_PROBES
                or not _covers_name(row.get('status'))):
            continue
        sha, days = row.get('certSha256'), row.get('certDaysLeft')
        if not sha or not isinstance(days, int) or days > warn_days:
            continue
        entry = found.get(sha)
        if entry is None:
            info = certificates.get(sha) if isinstance(certificates.get(sha), dict) else {}
            entry = found[sha] = {
                'sha256': sha, 'subjectCN': row.get('certSubjectCN'),
                'issuer': row.get('certIssuer'), 'serialHex': row.get('certSerial'),
                'notAfter': row.get('certNotAfter'), 'daysLeft': days, 'expired': days < 0,
                'isNewCert': bool(info.get('isNewCert')), 'endpoints': []}
        where = (sha, row.get('server'), row.get('ip'), row.get('port'))
        if where not in where_index:
            endpoint = {'server': where[1], 'ip': where[2], 'port': where[3], 'names': [],
                        'defaultCert': False}
            entry['endpoints'].append(endpoint)
            where_index[where] = (endpoint, set())
        endpoint, seen = where_index[where]
        if row['probe'] == PROBE_DEFAULT:
            endpoint['defaultCert'] = True
        elif row.get('name') and row['name'] not in seen:
            seen.add(row['name'])
            endpoint['names'].append(row['name'])
    return sorted(found.values(), key=lambda entry: (entry['daysLeft'], entry['sha256']))


def build_monitor(report: ScanReport, baseline: Optional[Dict[str, Any]] = None,
                  baseline_file: Optional[str] = None,
                  warn_days: Optional[int] = None) -> MonitorResult:
    """Compare ``report`` with a loaded ``baseline`` report and / or list its
    certificates expiring within ``warn_days``.

    With ``baseline_file`` but no ``baseline`` (:func:`load_baseline` found no file on
    a first run) the result says so (``baseline.missing``) and lists no changes.
    """
    monitor = MonitorResult(warn_days=warn_days)
    doc = report_to_dict(report)
    if baseline is not None:
        monitor.changes = order_changes(compare_reports(baseline, doc))
        monitor.baseline = baseline_info(baseline, doc, baseline_file)
    elif baseline_file is not None:
        monitor.changes = []
        monitor.baseline = {'file': baseline_file, 'missing': True}
    if warn_days is not None:
        monitor.expiring = expiring_certificates(doc, warn_days)
    return monitor


# --- change and expiry text (summary and --notify) --------------------------------------

_CHANGE_TAGS = {'appeared': 'NEW', 'disappeared': 'GONE', 'cert': 'CERT',
                # --ari / --revocation (the runner's tags, tools/ds/tlsdiff.mjs)
                'renew-now': 'RENEW-NOW', 'moved-up': 'MOVED-UP', 'ca-notice': 'CA-NOTICE',
                'revoked': 'REVOKED'}
_TAG_STYLES = {'FAILED': ('red', 'bold'), 'REGRESSED': ('red', 'bold'), 'UNHOSTED': ('red',),
               'GONE': ('red',), 'RECOVERED': ('green',), 'UPDATED': ('green', 'bold'),
               'HOSTED': ('green',), 'NEW': ('cyan',), 'CERT': ('yellow',),
               'CHANGED': ('yellow',), 'FAILING': ('dim',), SKIPPED: ('dim',),
               'RENEW-NOW': ('red', 'bold'), 'MOVED-UP': ('red', 'bold'),
               'CA-NOTICE': ('red', 'bold'), 'REVOKED': ('red', 'bold')}
_BAD_TAGS = ('FAILED', 'REGRESSED', 'UNHOSTED', 'GONE', 'RENEW-NOW', 'MOVED-UP', 'CA-NOTICE',
             'REVOKED')
_GOOD_TAGS = ('RECOVERED', 'UPDATED', 'HOSTED')
_TAG_WIDTH = max(len(tag) for tag in _TAG_STYLES)


def tag_style(tag: str, change: Dict[str, Any]) -> Tuple[str, ...]:
    """The colours of a change's tag. HOSTED is green only when the name is served with
    the new certificate: a server that starts serving it with another one (in a renewal)
    needs the new one installed there, so it is yellow like CHANGED."""
    if tag == 'HOSTED' and (change.get('after') or {}).get('status') != UPDATED:
        return ('yellow',)
    return _TAG_STYLES.get(tag, ())


def change_tag(change: Dict[str, Any]) -> str:
    """A change's label: its transition in capitals (``FAILED``, ``RECOVERED`` ...),
    ``NEW`` / ``GONE`` for what appeared / disappeared, ``CERT`` for a new certificate."""
    if change.get('kind') == 'status':
        return str(change.get('transition') or 'changed').upper()
    if (change.get('after') or {}).get('status') == SKIPPED:
        return SKIPPED
    return _CHANGE_TAGS.get(str(change.get('kind')), 'CHANGED')


def _iso_day(value: Any) -> str:
    match = _ISO_UTC_RE.match(value) if isinstance(value, str) else None
    return match.group(1) if match else '?'


def _iso_minute(value: Any) -> str:
    match = _ISO_UTC_RE.match(value) if isinstance(value, str) else None
    return '%s %s UTC' % match.groups() if match else 'an unknown time'


def _counts_text(counts: Any) -> str:
    if not isinstance(counts, dict) or not counts:
        return 'no rows'
    return ', '.join('%s %s' % (status, count) for status, count in counts.items())


def _cert_brief(view: Dict[str, Any]) -> str:
    """``CN www.example.com, expires 2026-10-01, sha256 1f7337a3`` - a renewal keeps the
    CN, so the date and the fingerprint tell the two apart."""
    if not view.get('certSha256'):
        return 'no certificate'
    return 'CN %s, expires %s, sha256 %s' % (view.get('certSubjectCN') or '(none)',
                                             _iso_day(view.get('certNotAfter')),
                                             str(view['certSha256'])[:8])


def _cert_change_text(before: Dict[str, Any], after: Dict[str, Any]) -> str:
    """``certificate changed: <before> -> <after>``, the CN said once when both share it."""
    cn = before.get('certSubjectCN')
    if cn and cn == after.get('certSubjectCN') and before.get('certSha256') \
            and after.get('certSha256'):
        return 'certificate changed (CN %s): expires %s, sha256 %s -> expires %s, sha256 %s' % (
            cn, _iso_day(before.get('certNotAfter')), str(before['certSha256'])[:8],
            _iso_day(after.get('certNotAfter')), str(after['certSha256'])[:8])
    return 'certificate changed: %s -> %s' % (_cert_brief(before), _cert_brief(after))


def _row_state(view: Dict[str, Any]) -> str:
    text = str(view.get('status'))
    if _covers_name(view.get('status')) and view.get('certSha256'):
        text += ' with ' + _cert_brief(view)
    if view.get('error'):
        text += ' (%s)' % view['error']
    return text


def _endpoint_state(view: Dict[str, Any]) -> str:
    status = str(view.get('status'))
    if status == EXCLUDED:
        return 'excluded by --exclude %s' % view.get('excludedBy')
    if status == SKIPPED:
        return 'not scanned (terminates_tls=no; --include-backends scans it)'
    if status == OPEN:
        names = view.get('names') or 0
        if not names:
            return OPEN
        return '%s (%d name%s: %s)' % (OPEN, names, '' if names == 1 else 's',
                                       _counts_text(view.get('statusCounts')))
    return '%s (%s)' % (status, view['error']) if view.get('error') else status


def _servers_label(servers: Sequence[str], ip: Any, limit: int = 3) -> str:
    named = [server for server in servers if server != ip]
    text = ', '.join(named[:limit])
    return text + (' +%d' % (len(named) - limit) if len(named) > limit else '')


def change_text(change: Dict[str, Any]) -> str:
    """One line for a change - where (servers, ip:port, name) and what moved - for the
    summary and the ``--notify`` message. Certificate, inventory and baseline text is
    escaped with :func:`display_text`."""
    kind, scope = change.get('kind'), change.get('scope')
    before, after = change.get('before') or {}, change.get('after') or {}
    if scope == 'certificate':  # --ari / --revocation
        return _status_change_text(change)
    if scope == 'name':
        where = 'name %s' % change.get('name')
        if kind == 'appeared':
            what = 'now probed, on %d endpoint(s): %s' % (
                after.get('endpoints') or 0, _counts_text(after.get('statusCounts')))
        else:
            what = 'no longer probed; was %s' % _counts_text(before.get('statusCounts'))
        return display_text('%s: %s' % (where, what))
    ip = change.get('ip')
    where = _endpoint_label(str(ip), change.get('port') or 0)
    servers = _servers_label(change.get('servers') or [], ip)
    if servers:
        where = '%s %s' % (servers, where)
    if scope == 'endpoint':
        if kind == 'appeared':
            what = 'new endpoint, ' + _endpoint_state(after)
        elif kind == 'disappeared' and after.get('status') == SKIPPED:
            what = ('not scanned now (terminates_tls=no; --include-backends scans it); was '
                    + _endpoint_state(before))
        elif kind == 'disappeared' and after.get('status') == EXCLUDED:
            what = '%s now; was %s' % (_endpoint_state(after), _endpoint_state(before))
        elif kind == 'disappeared':
            what = 'no longer scanned; was ' + _endpoint_state(before)
        else:
            what = '%s -> %s' % (_endpoint_state(before), _endpoint_state(after))
        return display_text('%s: %s' % (where, what))
    name = change.get('name')
    where += ' ' + (name if name is not None else '(no SNI)')
    if kind == 'appeared':
        what = 'new row, ' + _row_state(after)
    elif kind == 'disappeared':
        what = 'no longer reported; was ' + _row_state(before)
    elif kind == 'cert':
        what = '%s, %s' % (after.get('status'), _cert_change_text(before, after))
    else:
        what = '%s -> %s' % (before.get('status'), after.get('status'))
        if change.get('certChanged'):
            what += ', ' + _cert_change_text(before, after)
        elif _covers_name(after.get('status')) and after.get('certSha256'):
            what += ', serving ' + _cert_brief(after)
        if after.get('error'):
            what += ' (%s)' % after['error']
    return display_text('%s: %s' % (where, what))


def baseline_notes(info: Dict[str, Any]) -> List[str]:
    """What the two runs did differently, as sentences (see :func:`baseline_info`)."""
    notes = []
    added, removed = info.get('portsAdded') or [], info.get('portsRemoved') or []
    if added or removed:
        parts = (['added %s' % ', '.join(str(port) for port in added)] if added else []) + \
            (['removed %s' % ', '.join(str(port) for port in removed)] if removed else [])
        notes.append('Ports differ from the baseline: %s.' % '; '.join(parts))
    if info.get('newCertificateChanged'):
        notes.append("The new certificate (--cert) differs from the baseline's: UPDATED / "
                     'NEEDS_UPDATE moves can come from that rather than from the servers.')
    return notes


def _days_left_text(days: Any) -> str:
    if not isinstance(days, int):
        return '? days left'
    if days < 0:
        return 'EXPIRED %d day%s ago' % (-days, '' if days == -1 else 's')
    return '%d day%s left' % (days, '' if days == 1 else 's')


def _expiring_endpoint_text(endpoint: Dict[str, Any]) -> str:
    where = _endpoint_label(str(endpoint.get('ip')), endpoint.get('port') or 0)
    servers = _servers_label([endpoint.get('server') or ''], endpoint.get('ip'))
    names = list(endpoint.get('names') or [])
    if endpoint.get('defaultCert'):
        names.append('default certificate (no SNI)')
    return display_text('%s%s: %s' % (servers + ' ' if servers else '', where, ', '.join(names)))


def expiring_text(entry: Dict[str, Any], limit: int = 3) -> str:
    """One line for an expiring certificate: CN, expiry, fingerprint and where it is served."""
    endpoints = entry.get('endpoints') or []
    where = []
    for endpoint in endpoints[:limit]:
        label = _endpoint_label(str(endpoint.get('ip')), endpoint.get('port') or 0)
        servers = _servers_label([endpoint.get('server') or ''], endpoint.get('ip'))
        where.append('%s %s' % (servers, label) if servers else label)
    served = ', '.join(where) + (' +%d' % (len(endpoints) - limit) if len(endpoints) > limit
                                 else '')
    return display_text('CN %s, expires %s (%s), sha256 %s%s: served by %s' % (
        entry.get('subjectCN') or '(none)', _iso_day(entry.get('notAfter')),
        _days_left_text(entry.get('daysLeft')), str(entry.get('sha256'))[:8],
        ' (the new certificate)' if entry.get('isNewCert') else '', served))


def render_monitor(report: ScanReport, monitor: MonitorResult, style: Style,
                   show_all: bool = False, width: int = 100) -> List[str]:
    """Summary lines: "Changes since the baseline" (``--baseline``) and "Served
    certificates expiring within N days" (``--warn-days``), each ending with a blank line.
    Without ``show_all`` at most :data:`MAX_SUMMARY_CHANGES` changes and
    :data:`MAX_SUMMARY_ENDPOINTS` endpoints per certificate are listed."""
    lines = []  # type: List[str]
    if monitor.changes is not None:
        lines.extend(_render_changes(monitor, style, show_all, width))
    if monitor.expiring is not None:
        lines.extend(_render_expiring(report, monitor, style, show_all, width))
    return lines


def _render_changes(monitor: MonitorResult, style: Style, show_all: bool,
                    width: int) -> List[str]:
    info = monitor.baseline or {}
    source = display_text(str(info.get('file') or 'baseline'))
    if info.get('missing'):
        return [style.paint('Baseline %s does not exist yet: nothing to compare (first run). '
                            "This run's --json report is the next run's baseline." % source,
                            'yellow'), '']
    changes = monitor.changes or []
    tags = [change_tag(change) for change in changes]
    colors = (('green', 'bold') if not changes else
              ('red', 'bold') if any(tag in _BAD_TAGS for tag in tags) else ('yellow', 'bold'))
    lines = [style.paint('Changes since the baseline (%s, scan of %s): %s' % (
        source, _iso_minute(info.get('finishedAt')), len(changes) or 'none'), *colors)]
    shown = changes if show_all else changes[:MAX_SUMMARY_CHANGES]
    for change, tag in zip(shown, tags):
        prefix = '  %s  ' % style.paint(tag.ljust(_TAG_WIDTH), *tag_style(tag, change))
        lines.extend(_wrap(prefix, _TAG_WIDTH + 4, change_text(change), width))
    if len(shown) < len(changes):
        lines.append(style.paint('  ... and %d more - use --show-all or the --json report to '
                                 'list them.' % (len(changes) - len(shown)), 'dim'))
    failing = sum(1 for change in changes if change.get('transition') == 'failing')
    skipped = sum(1 for change in changes if (change.get('after') or {}).get('status') == SKIPPED)
    if failing:
        lines.append(style.paint(
            '  FAILING: %d moved from one failure state to another (TLS_ERROR, TIMEOUT, '
            'CLOSED) - nothing served either way, so not counted by --notify or '
            '--fail-on-change.' % failing, 'dim'))
    if skipped:
        lines.append(style.paint(
            '  SKIPPED: %d left out now for terminates_tls=no - the inventory changed, not the '
            'server, so not counted by --notify or --fail-on-change.' % skipped, 'dim'))
    lines.extend(style.paint('  ' + note, 'dim') for note in baseline_notes(info))
    lines.append('')
    return lines


def _render_expiring(report: ScanReport, monitor: MonitorResult, style: Style,
                     show_all: bool, width: int) -> List[str]:
    expiring = monitor.expiring or []
    days = monitor.warn_days or 0
    lines = [style.paint('Served certificates expiring within %d day%s: %s' % (
        days, '' if days == 1 else 's', len(expiring) or 'none'),
        *(('red', 'bold') if expiring else ('green', 'bold')))]
    for entry in expiring:
        cert = report.certificates.get(entry.get('sha256') or '')
        if cert is not None:
            head = '  %s | %s' % (cert_line(cert, report.finished_at, style),
                                  style.paint(cert_ids(cert), 'dim'))
        else:
            head = '  ' + display_text('%s | expires %s (%s)' % (
                entry.get('subjectCN') or '(none)', _iso_day(entry.get('notAfter')),
                _days_left_text(entry.get('daysLeft'))))
        if entry.get('isNewCert'):
            head += '  (the new certificate)'
        lines.append(head)
        endpoints = entry.get('endpoints') or []
        shown = endpoints if show_all else endpoints[:MAX_SUMMARY_ENDPOINTS]
        for endpoint in shown:
            lines.extend(_wrap('      ', 6, _expiring_endpoint_text(endpoint), width))
        if len(shown) < len(endpoints):
            lines.append(style.paint('      ... and %d more endpoint(s)'
                                     % (len(endpoints) - len(shown)), 'dim'))
    lines.append('')
    return lines


# --- --notify: webhook formats and delivery ---------------------------------------------

NOTIFY_FORMATS = ('auto', 'slack', 'teams', 'discord', 'telegram', 'googlechat', 'json',
                  'pagerduty', 'ntfy')
# Message text per format: Discord allows 2,000 characters, Telegram 4,096; Slack, Teams
# and Google Chat take more, but a longer chat message is not read either.
_NOTIFY_TEXT_LIMITS = {'slack': 3500, 'teams': 3500, 'discord': 1800, 'telegram': 3900,
                       'googlechat': 3500, 'json': 3500}
NOTIFY_MAX_CHANGES = 20       # change lines in a message (the JSON format has them all)
NOTIFY_MAX_EXPIRING = 10      # expiring certificates in a message
NOTIFY_MAX_JSON_CHANGES = 500
NOTIFY_MAX_JSON_EXPIRING = 50     # expiring certificates in the generic JSON payload
NOTIFY_MAX_JSON_ENDPOINTS = 20    # endpoints per expiring certificate there
_NOTIFY_LINE_LIMIT = 400
_NOTIFY_MAX_PORT_GROUPS = 8   # ports / port ranges named in a message footer
NOTIFY_MAX_EVENTS = 50        # PagerDuty events a run sends (triggers first)
PAGERDUTY_MAX_OPEN = 500      # PagerDuty keys a report keeps open (the oldest dropped)
_PAGERDUTY_SUMMARY_LIMIT = 1024
NTFY_MAX_BYTES = 4000         # a longer ntfy message is turned into an attachment
_PAGERDUTY_HOSTS = ('events.pagerduty.com', 'events.eu.pagerduty.com')
_NTFY_HOSTS = ('ntfy.sh',)
# PagerDuty severity critical (else error); the headless runner's tags of registration,
# delegation and trust changes, and an expired certificate here.
PAGERDUTY_CRITICAL_TAGS = ('REGISTRAR', 'NS', 'DS', 'LOCK', 'EXPIRED', 'UNTRUSTED')
_DEDUP_KEY_RE = re.compile(r'^[0-9a-f]{32}$')
_EVENT_TAG_RE = re.compile(r'^[A-Z][A-Z0-9_-]{0,23}$')
_DISCORD_HOSTS = ('discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com')
_TEAMS_HOSTS = ('outlook.office.com', 'outlook.office365.com')
# Teams incoming webhooks, Power Automate / Logic Apps workflow triggers
_TEAMS_HOST_SUFFIXES = ('.webhook.office.com', '.logic.azure.com', '.api.powerplatform.com')
_TELEGRAM_PATH_RE = re.compile(r'^/bot[^/]+/sendMessage$')
_DISCORD_PATH_RE = re.compile(r'^/api/(?:v\d{1,2}/)?webhooks/')   # also /api/v10/webhooks/
# Path words of the webhook services above: not secrets, kept in error texts.
_NOTIFY_PATH_WORDS = frozenset((
    'api', 'automations', 'direct', 'enqueue', 'hook', 'hooks', 'incomingwebhook', 'invoke',
    'manual', 'messages', 'paths', 'powerautomate', 'sendmessage', 'services', 'slack',
    'spaces', 'triggers', 'webhook', 'webhookb2', 'webhooks', 'workflows'))
_API_VERSION_RE = re.compile(r'^v\d{1,2}$')   # /api/v10/, /v1/spaces/: not a token either
_USER_AGENT = 'ssl_origin_scan/%s (+https://github.com/halilibrahimd27/domainscope)' % __version__


def detect_notify_format(url: str) -> str:
    """The payload a webhook URL expects: ``slack`` (hooks.slack.com, and Discord's
    Slack-compatible ``.../slack`` endpoint), ``discord`` (``/api/webhooks/``, also with
    an API version: ``/api/v10/webhooks/``), ``telegram`` (api.telegram.org), ``teams``
    (Teams incoming webhooks, Power Automate / Logic Apps workflows), ``googlechat``
    (chat.googleapis.com), ``pagerduty`` (PagerDuty's Events API v2), ``ntfy`` (ntfy.sh; a
    self-hosted server needs ``--notify-format ntfy``) or ``json`` for anything else."""
    parts = urllib.parse.urlsplit(url)
    host = (parts.hostname or '').rstrip('.')
    if host in ('hooks.slack.com', 'hooks.slack-gov.com'):
        return 'slack'
    if host in _DISCORD_HOSTS and _DISCORD_PATH_RE.match(parts.path):
        return 'slack' if parts.path.rstrip('/').endswith('/slack') else 'discord'
    if host == 'api.telegram.org':
        return 'telegram'
    if host in _TEAMS_HOSTS or host.endswith(_TEAMS_HOST_SUFFIXES):
        return 'teams'
    if host == 'chat.googleapis.com':
        return 'googlechat'
    if host in _PAGERDUTY_HOSTS:
        return 'pagerduty'
    if host in _NTFY_HOSTS:
        return 'ntfy'
    return 'json'


def _pagerduty_routing_key(query: str) -> Optional[str]:
    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if key == 'routing_key' and value:
            return value
    return None


def _telegram_chat_id(query: str) -> Optional[Union[int, str]]:
    for key, value in urllib.parse.parse_qsl(query, keep_blank_values=True):
        if key == 'chat_id' and value:
            return int(value) if re.match(r'^-?\d{1,20}$', value) else value
    return None


def ascii_url(url: str) -> str:
    """``url`` with the non-ASCII characters of its path, query and fragment
    percent-encoded as UTF-8 (``/hööks/1`` -> ``/h%C3%B6%C3%B6ks/1``): an HTTP request
    line is ASCII only. The host stays as it is (it is sent in its IDNA form)."""
    if url.isascii():
        return url
    parts = urllib.parse.urlsplit(url)

    def encode(text: str) -> str:
        return ''.join(char if ord(char) < 128 else urllib.parse.quote(char, safe='')
                       for char in text)

    return urllib.parse.urlunsplit(parts._replace(path=encode(parts.path),
                                                  query=encode(parts.query),
                                                  fragment=encode(parts.fragment)))


def check_notify_url(url: str, fmt: str = 'auto', source: str = '--notify') -> str:
    """Validate a ``--notify`` URL before the scan -> its payload format (``fmt``, or
    :func:`detect_notify_format` for ``auto``). The :class:`UsageError` never repeats
    the URL: it holds the webhook's secret. Credentials in it (``user:password@``) are
    sent as HTTP Basic authentication (:func:`split_credentials`)."""
    if not url.isprintable() or any(char.isspace() for char in url):
        raise UsageError('%s: the URL contains spaces or control characters' % source)
    try:
        parts = urllib.parse.urlsplit(url)
        _ = parts.port  # ValueError for a port that is not a number
    except ValueError:
        raise UsageError('%s: not a valid URL' % source)
    if parts.scheme.lower() not in ('http', 'https') or not parts.hostname:
        raise UsageError('%s: needs an http:// or https:// URL' % source)
    if fmt not in NOTIFY_FORMATS:
        raise UsageError('--notify-format must be one of %s' % ', '.join(NOTIFY_FORMATS))
    chosen = detect_notify_format(url) if fmt == 'auto' else fmt
    if chosen == 'telegram' and not (_TELEGRAM_PATH_RE.match(parts.path)
                                     and _telegram_chat_id(parts.query) is not None):
        raise UsageError('%s: a Telegram URL looks like https://api.telegram.org/bot<token>/'
                         'sendMessage?chat_id=<chat id>' % source)
    if chosen == 'pagerduty' and _pagerduty_routing_key(parts.query) is None:
        raise UsageError('%s: a PagerDuty URL looks like https://events.pagerduty.com/v2/enqueue'
                         '?routing_key=<integration key>' % source)
    return chosen


def split_credentials(url: str) -> Tuple[str, Optional[str]]:
    """``(URL without user info, Authorization header or None)``: urllib does not turn
    ``https://user:password@host/`` into Basic authentication - it would take
    ``password@host`` for a port and print it in the error."""
    parts = urllib.parse.urlsplit(url)
    userinfo, at, host = parts.netloc.rpartition('@')
    if not at:
        return url, None
    user, _, password = userinfo.partition(':')
    token = '%s:%s' % (urllib.parse.unquote(user), urllib.parse.unquote(password))
    return (urllib.parse.urlunsplit(parts._replace(netloc=host)),
            'Basic ' + base64.b64encode(token.encode('utf-8')).decode('ascii'))


def notify_host(url: str) -> str:
    """The webhook's host (and port) - all of the URL that is ever printed."""
    parts = urllib.parse.urlsplit(url)
    host = parts.hostname or '?'
    try:
        port = parts.port
    except ValueError:
        port = None
    host = '[%s]' % host if ':' in host else host
    return display_text('%s:%d' % (host, port) if port else host)


def notify_is_plaintext(url: str) -> bool:
    """True for an ``http://`` URL to another machine: the token would travel unencrypted."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() != 'http':
        return False
    host = (parts.hostname or '').rstrip('.')
    if host == 'localhost':
        return False
    try:
        return not ipaddress.ip_address(host).is_loopback
    except ValueError:
        return True


def _secret_segment(segment: str) -> bool:
    """A URL path segment that may be a token: 8 or more characters or a digit, and not
    a path word of the webhook services (``services``, ``webhooks``, ``sendMessage``) or
    an API version (``v10``)."""
    return (segment.lower() not in _NOTIFY_PATH_WORDS and not _API_VERSION_RE.match(segment)
            and (len(segment) >= 8 or any(char.isdigit() for char in segment)))


def _segment_forms(segment: str) -> List[str]:
    """How a secret path segment may be written in an error text or an echoed request:
    as in the URL, decoded, and encoded (``123:abc`` / ``123%3Aabc``) - for Telegram's
    ``bot<token>`` also the token alone, and its part after the ``:``."""
    plain = urllib.parse.unquote(segment)
    tokens = [plain]
    if plain[:3].lower() == 'bot' and ':' in plain:
        tokens.extend((plain[3:], plain.partition(':')[2]))
    forms = [segment]
    for token in tokens:
        if token:
            forms.extend((token, urllib.parse.quote(token, safe='')))
    return forms


def _redaction_secrets(url: str, extra: Sequence[str] = ()) -> List[str]:
    """The texts :func:`redact_url` takes out of a text for ``url`` and ``extra``, longest
    first."""
    unquote = urllib.parse.unquote
    parts = urllib.parse.urlsplit(url)
    target, auth = split_credentials(url)
    secrets = {url, target, parts.path, parts.query, parts.fragment,
               unquote(parts.path), unquote(parts.query)}
    for segment in parts.path.split('/'):
        if _secret_segment(unquote(segment)):
            secrets.update(_segment_forms(segment))
    for _key, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        secrets.add(value)
    secrets.update(pair.split('=', 1)[-1] for pair in parts.query.split('&'))
    userinfo, at, _host = parts.netloc.rpartition('@')
    always = set()  # type: Set[str]
    if at:
        user, colon, password = userinfo.partition(':')
        secrets.update((userinfo, unquote(userinfo), user, unquote(user)))
        # the password however short - or the user name when it is the only credential
        always.update((password, unquote(password)) if colon else (user, unquote(user)))
    if auth:  # an error body that echoes the request headers
        always.update((auth, auth.split(' ', 1)[1]))
    always.update(secret for secret in extra if secret)
    found = {secret for secret in secrets if len(secret) >= 4} | {s for s in always if s}
    return sorted(found, key=len, reverse=True)


def _redact_with(text: str, secrets: Sequence[str], cut: bool = False) -> str:
    """``text`` without ``secrets`` (longest first). ``cut``: the text is the start of a
    longer one, so it may end inside a secret - whatever it ends with that begins a secret
    goes too."""
    for secret in secrets:
        text = text.replace(secret, '***')
    if not cut:
        return text
    text = text.rstrip('\ufffd')  # a character cut in two
    strip = 0
    for secret in secrets:
        for size in range(min(len(secret) - 1, len(text)), strip, -1):
            if text.endswith(secret[:size]):
                strip = size
                break
    return text[:len(text) - strip]


def redact_url(text: str, url: str, extra: Sequence[str] = ()) -> str:
    """``text`` (an error message, a response body) without the secret parts of ``url``:
    the URL (also without its user info), its path, query and fragment, the query
    values, the path segments that may be tokens (:func:`_secret_segment`, in the forms
    of :func:`_segment_forms`), the user name and password, the Basic
    authentication header made of them (:func:`split_credentials`) and ``extra`` (the ntfy
    token, the signing secret). Webhook URLs are credentials - whoever has one can post."""
    return _redact_with(text, _redaction_secrets(url, extra))


def should_notify(monitor: Optional[MonitorResult], always: bool = False) -> bool:
    """Notify when something changed since the baseline (:func:`notable_changes`) or a
    certificate expires soon (or ``always``, e.g. as a heartbeat)."""
    if always:
        return True
    return monitor is not None and bool(notable_changes(monitor.changes) or monitor.expiring)


def ports_text(ports: Sequence[Any], limit: int = _NOTIFY_MAX_PORT_GROUPS) -> str:
    """``443,8000-9023``: the ports in their order, runs of consecutive ports as ranges;
    after ``limit`` ports / ranges the rest is counted (``+1022 more``)."""
    groups = []  # type: List[List[int]]
    for port in ports:
        if not isinstance(port, int) or isinstance(port, bool):
            continue
        if groups and port == groups[-1][1] + 1:
            groups[-1][1] = port
        else:
            groups.append([port, port])
    text = ','.join(str(first) if first == last else '%d-%d' % (first, last)
                    for first, last in groups[:limit])
    rest = sum(last - first + 1 for first, last in groups[limit:])
    return (text or '?') + (' +%d more' % rest if rest else '')


def notification_message(doc: Dict[str, Any], monitor: Optional[MonitorResult] = None
                         ) -> Tuple[str, List[str], List[str]]:
    """The notification text of a report dict: ``(title, items, footer)``.

    ``items`` are the changes (at most :data:`NOTIFY_MAX_CHANGES`, FAILING moves last)
    and the expiring certificates (at most :data:`NOTIFY_MAX_EXPIRING`), ``footer`` sums
    up the scan.
    Plain text; untrusted text is escaped (:func:`change_text`).
    """
    parts, items = [], []  # type: List[str], List[str]
    if monitor is not None and monitor.changes is not None:
        info = monitor.baseline or {}
        if info.get('missing'):
            parts.append('first run, no baseline to compare yet')
        else:
            count, since = len(monitor.changes), _iso_minute(info.get('finishedAt'))
            parts.append('%d change%s since %s' % (count, '' if count == 1 else 's', since)
                         if count else 'no changes since %s' % since)
            # FAILING moves come last (order_changes): they are the ones cut
            shown = monitor.changes[:NOTIFY_MAX_CHANGES]
            items.extend('- %s %s' % (change_tag(change), change_text(change))
                         for change in shown)
            if len(monitor.changes) > len(shown):
                items.append('- ... and %d more changes' % (len(monitor.changes) - len(shown)))
            items.extend(baseline_notes(info) if monitor.changes else [])
    if monitor is not None and monitor.expiring is not None:
        count, days = len(monitor.expiring), monitor.warn_days or 0
        expired = any(entry.get('expired') for entry in monitor.expiring)
        parts.append('%d certificate%s %s within %d day%s' % (
            count, '' if count == 1 else 's', 'expired or expiring' if expired else 'expiring',
            days, '' if days == 1 else 's') if count else
            'no certificate expiring within %d day%s' % (days, '' if days == 1 else 's'))
        shown_expiring = monitor.expiring[:NOTIFY_MAX_EXPIRING]
        items.extend('- EXPIRES %s' % expiring_text(entry) for entry in shown_expiring)
        if count > len(shown_expiring):
            items.append('- ... and %d more certificates' % (count - len(shown_expiring)))
    title = 'SSL origin scan: ' + ('; '.join(parts) if parts else 'finished')
    summary = doc.get('summary') if isinstance(doc.get('summary'), dict) else {}
    names = [probe.get('name') for probe in doc.get('names') or [] if isinstance(probe, dict)]
    ports = (doc.get('options') or {}).get('ports') or []
    shown_names = ', '.join(str(name) for name in names[:3]) + (
        ' +%d' % (len(names) - 3) if len(names) > 3 else '')
    footer = [display_text('Scan of %s: %s server(s), %s endpoint(s) (%s open), ports %s, '
                           'names %s.' % (_iso_minute(doc.get('finishedAt')),
                                          summary.get('servers', '?'),
                                          summary.get('endpoints', '?'),
                                          summary.get('openEndpoints', '?'),
                                          ports_text(ports), shown_names or 'none'))]
    if doc.get('newCertificates'):
        footer.append('Servers that need the new certificate: %s; serving it: %s.' % (
            summary.get('serversNeedingUpdate', '?'), summary.get('serversUpdated', '?')))
    return title, items, footer


def _clip(line: str, limit: int = _NOTIFY_LINE_LIMIT) -> str:
    return line if len(line) <= limit else line[:limit - 3] + '...'


def _fit_lines(title: str, items: Sequence[str], footer: Sequence[str],
               limit: int, measure: Callable[[str], int] = len) -> List[str]:
    """``items`` then ``footer``, as many items as fit in ``limit`` characters (or what
    ``measure`` counts: UTF-8 bytes for ntfy) with the title; the rest are counted in a last
    "... and N more" line. Every line is cut at :data:`_NOTIFY_LINE_LIMIT` characters, the
    footer's too."""
    footer = [_clip(line) for line in footer]
    budget = limit - measure(title) - sum(measure(line) + 1 for line in footer) - 60
    out = []  # type: List[str]
    for index, line in enumerate(items):
        line = _clip(line)
        if measure(line) + 1 > budget:
            out.append('- ... and %d more line(s) - see the --json report'
                       % (len(items) - index))
            break
        out.append(line)
        budget -= measure(line) + 1
    return out + list(footer)


def _slack_escape(text: str) -> str:
    # Slack reads <...> as links and mentions (<!channel>): a certificate CN must not ping.
    return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


def _no_backticks(text: str) -> str:
    # The message body goes into a ``` code block (no markdown, no mentions inside);
    # a backtick in a certificate CN must not close it.
    return text.replace('`', 'ˋ')


def _no_angle_brackets(text: str) -> str:
    # Google Chat reads <users/all> as a mention and <url|text> as a link, and does not
    # document decoding Slack's &lt; (which would then show as it is): an opening
    # bracket becomes a lookalike instead, so no certificate text can ping a space.
    return text.replace('<', '‹')


def _teams_card(title: str, lines: Sequence[str]) -> Dict[str, Any]:
    """A plain Adaptive Card: TextRuns are never read as markdown, unlike TextBlocks."""
    body = [{'type': 'RichTextBlock', 'inlines': [
        {'type': 'TextRun', 'text': title, 'weight': 'Bolder', 'size': 'Medium'}]}]
    body.extend({'type': 'RichTextBlock', 'spacing': 'None',
                 'inlines': [{'type': 'TextRun', 'text': line}]} for line in lines if line)
    return {'type': 'message', 'attachments': [{
        'contentType': 'application/vnd.microsoft.card.adaptive', 'contentUrl': None,
        'content': {'$schema': 'http://adaptivecards.io/schemas/adaptive-card.json',
                    'type': 'AdaptiveCard', 'version': '1.2', 'msteams': {'width': 'Full'},
                    'body': body}}]}


def build_notification(fmt: str, url: str, doc: Dict[str, Any],
                       monitor: Optional[MonitorResult] = None) -> Tuple[str, Dict[str, Any]]:
    """``(URL to POST to, JSON payload)`` for a report dict in a webhook format.

    * ``slack`` - ``{text}``: a bold title and the lines in a code block (``& < >``
      escaped, so no text from a certificate becomes a mention or a link);
    * ``teams`` - a message with one Adaptive Card of plain TextRuns;
    * ``discord`` - ``{content, allowed_mentions: {parse: []}}`` (no @everyone);
    * ``telegram`` - ``{chat_id, text}`` without link previews, ``chat_id`` moved from
      the URL's query into the body;
    * ``googlechat`` - ``{text}`` like Slack's, with ``<`` turned into a lookalike
      rather than escaped (:func:`_no_angle_brackets`);
    * ``json`` - ``{tool, version, title, text, finishedAt, summary, baseline, changes,
      changesTotal, warnDays, expiring, expiringTotal}`` (``baseline.file`` as a base
      name): at most
      :data:`NOTIFY_MAX_JSON_CHANGES` changes and :data:`NOTIFY_MAX_JSON_EXPIRING`
      certificates, each with at most :data:`NOTIFY_MAX_JSON_ENDPOINTS` endpoints and
      their ``endpointsTotal`` - a receiver may refuse a large body.
    """
    title, items, footer = notification_message(doc, monitor)
    lines = _fit_lines(title, items, footer, _NOTIFY_TEXT_LIMITS.get(fmt, 3500))
    body = '\n'.join(lines)
    if fmt == 'slack':
        return url, {'text': '*%s*\n```\n%s\n```' % (_slack_escape(title),
                                                     _slack_escape(_no_backticks(body)))}
    if fmt == 'discord':
        return url, {'content': '**%s**\n```\n%s\n```' % (title, _no_backticks(body)),
                     'allowed_mentions': {'parse': []}}
    if fmt == 'teams':
        return url, _teams_card(title, lines)
    if fmt == 'googlechat':
        return url, {'text': '*%s*\n```\n%s\n```' % (
            _no_angle_brackets(title), _no_angle_brackets(_no_backticks(body)))}
    if fmt == 'telegram':
        parts = urllib.parse.urlsplit(url)
        query = [(key, value) for key, value in
                 urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if key != 'chat_id']
        post_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                            urllib.parse.urlencode(query), ''))
        return post_url, {'chat_id': _telegram_chat_id(parts.query),
                          'text': '%s\n\n%s' % (title, body),
                          'link_preview_options': {'is_disabled': True}}
    changes = list(monitor.changes or []) if monitor is not None else []
    expiring = None  # type: Optional[List[Dict[str, Any]]]
    if monitor is not None and monitor.expiring is not None:
        expiring = [dict(entry, endpoints=entry['endpoints'][:NOTIFY_MAX_JSON_ENDPOINTS],
                         endpointsTotal=len(entry['endpoints']))
                    for entry in monitor.expiring[:NOTIFY_MAX_JSON_EXPIRING]]
    return url, {
        'tool': 'ssl_origin_scan', 'version': __version__, 'title': title,
        'text': '%s\n%s' % (title, body), 'finishedAt': doc.get('finishedAt'),
        'summary': doc.get('summary'),
        'baseline': _payload_baseline(monitor.baseline if monitor is not None else None),
        'changes': (changes[:NOTIFY_MAX_JSON_CHANGES]
                    if monitor is not None and monitor.changes is not None else None),
        'changesTotal': len(changes),
        'warnDays': monitor.warn_days if monitor is not None else None,
        'expiring': expiring,
        'expiringTotal': len(monitor.expiring or []) if monitor is not None else 0,
    }


def sign_body(secret: str, timestamp: Union[int, str], body: bytes) -> str:
    """``sha256=`` and the hex HMAC-SHA256 of ``timestamp + "." + body`` with ``secret``: the
    X-DomainScope-Signature header of a signed JSON message (X-DomainScope-Timestamp carries
    ``timestamp``, Unix seconds). A receiver computes the same over the raw body it got, compares
    in constant time and refuses an old timestamp."""
    message = str(timestamp).encode('ascii') + b'.' + body
    return 'sha256=' + hmac.new(secret.encode('utf-8'), message, hashlib.sha256).hexdigest()


def _header_text(text: str) -> str:
    """A header value as it is when it is ASCII, else RFC 2047 encoded (ntfy decodes it)."""
    if text.isascii() and text.isprintable():
        return text
    return '=?UTF-8?B?%s?=' % base64.b64encode(text.encode('utf-8')).decode('ascii')


def _utf8_len(text: str) -> int:
    return len(text.encode('utf-8'))


def _bad_tag(change: Dict[str, Any]) -> bool:
    """A change that counts and whose tag the summary paints red (FAILED, REGRESSED,
    UNHOSTED, GONE)."""
    return counts_as_change(change) and change_tag(change) in _BAD_TAGS


def build_ntfy(url: str, doc: Dict[str, Any], monitor: Optional[MonitorResult] = None,
               token: Optional[str] = None) -> Tuple[str, bytes, Dict[str, str]]:
    """``(URL, body, headers)`` of an ntfy message: the lines in plain text (at most
    :data:`NTFY_MAX_BYTES` bytes), ``Title``, ``Priority`` 4 when a change is bad or a
    certificate expires (else 3), ``Tags: warning`` and ``Authorization: Bearer <token>``
    when a token is given and the URL carries no user info of its own."""
    title, items, footer = notification_message(doc, monitor)
    body = '\n'.join(_fit_lines('', items, footer, NTFY_MAX_BYTES, _utf8_len)).encode('utf-8')
    if len(body) > NTFY_MAX_BYTES:  # a footer line of wide characters
        body = body[:NTFY_MAX_BYTES].decode('utf-8', 'ignore').encode('utf-8')
    bad = monitor is not None and (any(_bad_tag(change) for change in monitor.changes or [])
                                   or bool(monitor.expiring))
    headers = {'Content-Type': 'text/plain; charset=utf-8', 'Title': _header_text(title),
               'Priority': '4' if bad else '3', 'Tags': 'warning'}
    if token and '@' not in urllib.parse.urlsplit(url).netloc:
        headers['Authorization'] = 'Bearer ' + token
    return url, body, headers


def notify_request(fmt: str, url: str, doc: Dict[str, Any],
                   monitor: Optional[MonitorResult] = None,
                   env: Optional[Dict[str, str]] = None,
                   now: Optional[datetime] = None) -> Tuple[str, bytes, Dict[str, str]]:
    """``(URL to POST to, body, extra headers)`` of a --notify message in a chat, JSON or
    ntfy format: :func:`build_ntfy` with :data:`NTFY_TOKEN_ENV` for ntfy, else
    :func:`build_notification`'s JSON - signed in the json format when
    :data:`NOTIFY_SECRET_ENV` is set (:func:`sign_body`, ``now`` the timestamp's clock)."""
    env = os.environ if env is None else env
    if fmt == 'ntfy':
        return build_ntfy(url, doc, monitor, (env.get(NTFY_TOKEN_ENV) or '').strip() or None)
    post_url, payload = build_notification(fmt, url, doc, monitor)
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    secret = (env.get(NOTIFY_SECRET_ENV) or '').strip()
    if fmt != 'json' or not secret:
        return post_url, body, {}
    timestamp = str(int((now or _utcnow()).timestamp()))
    return post_url, body, {'X-DomainScope-Timestamp': timestamp,
                            'X-DomainScope-Signature': sign_body(secret, timestamp, body)}


def pagerduty_dedup_key(command: str, target: str, item: Optional[str], tag: str) -> str:
    """A PagerDuty dedup_key: the first 32 hex characters of the SHA-256 of
    ``command|target|item|tag`` (no item: an empty one), as the headless runner's."""
    text = '%s|%s|%s|%s' % (command, target, item or '', tag)
    return hashlib.sha256(text.encode('utf-8')).hexdigest()[:32]


def _change_where(change: Dict[str, Any]) -> Tuple[str, Optional[str]]:
    """A change's ``(target, item)`` for PagerDuty: the name (scope ``name``), else the
    ip:port endpoint and, for a row, its name (``(no SNI)`` for the probe without one)."""
    if change.get('scope') == 'name':
        return str(change.get('name')), None
    target = _endpoint_label(str(change.get('ip')), change.get('port') or 0)
    if change.get('scope') == 'row':
        name = change.get('name')
        return target, str(name) if name is not None else '(no SNI)'
    return target, None


def open_keys_of(doc: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The PagerDuty keys a baseline left open (its ``notify.open``), each checked:
    ``{key, target, item, tag, since, over?}``; anything else in the list is dropped."""
    notify = doc.get('notify') if isinstance(doc, dict) else None
    entries = notify.get('open') if isinstance(notify, dict) else None
    out, seen = [], set()  # type: List[Dict[str, Any]], Set[str]
    for entry in entries if isinstance(entries, list) else []:
        if not isinstance(entry, dict):
            continue
        key, tag, item = entry.get('key'), entry.get('tag'), entry.get('item')
        if (not isinstance(key, str) or not _DEDUP_KEY_RE.match(key) or key in seen
                or not isinstance(entry.get('target'), str) or not isinstance(tag, str)
                or not _EVENT_TAG_RE.match(tag) or not (item is None or isinstance(item, str))):
            continue
        seen.add(key)
        clean = {'key': key, 'target': entry['target'], 'item': item, 'tag': tag,
                 'since': entry.get('since') if isinstance(entry.get('since'), str) else None}
        if entry.get('over') is True:
            clean['over'] = True
        out.append(clean)
    return out


def _report_where(doc: Dict[str, Any]) -> Tuple[Dict[str, Dict[str, Any]], Set[str]]:
    """``({ip:port label: endpoint}, the names probed)`` of a report dict
    (:func:`_index_report`), as PagerDuty keys name them."""
    indexed, probed = _index_report(doc)
    return ({_endpoint_label(ip, port): endpoint for (ip, port), endpoint in indexed.items()},
            set(probed))


def _problem_over(entry: Dict[str, Any], monitor: MonitorResult,
                  where: Optional[Tuple[Dict[str, Dict[str, Any]], Set[str]]] = None) -> bool:
    """Is the problem of an open PagerDuty key over, by what this run's report says (``where``:
    :func:`_report_where`)? An expiring certificate's when this run lists it no longer (it was
    renewed or replaced; a run without --warn-days says nothing). A row's or an endpoint's when
    the report shows it better - FAILED once it answers again, REGRESSED once the name is
    served with the new certificate (UPDATED), UNHOSTED once a certificate covering the name is
    served again, GONE once it is back - or out of what the run checks: its name no longer
    probed, its endpoint no longer scanned. Never because another change came by: a handshake
    or a port that fails says nothing of the certificate a name is served with, and the key
    stays open. Without the report nothing but an expiry is decided."""
    tag, target, item = entry['tag'], entry['target'], entry['item']
    if tag in ('EXPIRES', 'EXPIRED'):
        return monitor.expiring is not None
    if where is None:
        return False
    endpoints, names = where
    endpoint = endpoints.get(target)
    if item is None:
        if tag == 'GONE':  # an endpoint no longer scanned, a name no longer probed: back again
            return endpoint is not None or target in names
        return endpoint is None or endpoint['status'] == OPEN
    name = None if item == '(no SNI)' else item
    if endpoint is None or (name is not None and name not in names):
        return True
    if endpoint['status'] != OPEN:  # nothing was read from it this run
        return False
    row = endpoint['rows'].get(name)
    if row is None:
        return False
    status = row['view']['status']
    if tag == 'GONE':
        return True
    if status in _FAILED_STATUSES:  # failing still, or nothing read
        return False
    if tag == 'FAILED':
        return True
    if tag == 'REGRESSED':
        return status == UPDATED
    if tag == 'UNHOSTED':
        return _covers_name(status)
    return False


def pagerduty_plan(monitor: MonitorResult, baseline: Optional[Dict[str, Any]] = None,
                   since: Optional[str] = None, max_events: int = NOTIFY_MAX_EVENTS,
                   doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """What a run sends to PagerDuty and the keys it leaves open, as the headless runner's
    plan: a trigger per change that counts with a red tag (FAILED, REGRESSED, UNHOSTED, GONE)
    and per expiring certificate (EXPIRED, severity critical, or EXPIRES), one per
    :func:`pagerduty_dedup_key`; a resolve per open key of the baseline whose problem is over
    in this run's report ``doc`` (:func:`_problem_over`) or whose resolve a run could not send
    yet (``over``). At most ``max_events``: triggers first, the triggers left out are not sent
    (``cut``), the resolves left out stay open with ``over``. ``kept``, ``deferred`` and
    ``added`` are the parts of ``open`` (:func:`pagerduty_open_after`): the baseline's keys
    still open (a key triggered again keeps its ``since``), those whose resolve waits, the new
    ones - ``open`` as if every event were delivered, at most :data:`PAGERDUTY_MAX_OPEN`.
    -> ``{triggers, resolves, cut, open, kept, deferred, added}``."""
    triggered = {}  # type: Dict[str, Dict[str, Any]]
    for change in notable_changes(monitor.changes):
        tag = change_tag(change)
        if tag not in _BAD_TAGS:
            continue
        target, item = _change_where(change)
        key = pagerduty_dedup_key('scan', target, item, tag)
        triggered.setdefault(key, {
            'key': key, 'tag': tag, 'target': target, 'item': item,
            'summary': '%s %s' % (tag, change_text(change)),
            'details': {'tag': tag, 'item': item, 'before': change.get('before'),
                        'after': change.get('after'), 'run': None}})
    for entry in monitor.expiring or []:
        tag = 'EXPIRED' if entry.get('expired') else 'EXPIRES'
        target = str(entry.get('subjectCN') or str(entry.get('sha256'))[:16])
        item = str(entry.get('sha256'))
        key = pagerduty_dedup_key('scan', target, item, tag)
        triggered.setdefault(key, {
            'key': key, 'tag': tag, 'target': target, 'item': item,
            'summary': '%s %s' % (tag, expiring_text(entry)),
            'details': {'tag': tag, 'item': item, 'before': None,
                        'after': {'notAfter': entry.get('notAfter'),
                                  'daysLeft': entry.get('daysLeft')}, 'run': None}})
    previous = open_keys_of(baseline)
    where = _report_where(doc) if doc is not None and previous else None
    kept, ending = [], []  # type: List[Dict[str, Any]], List[Dict[str, Any]]
    for entry in previous:
        if entry['key'] in triggered:
            kept.append({k: v for k, v in entry.items() if k != 'over'})
        elif entry.get('over') or _problem_over(entry, monitor, where):
            ending.append(entry)
        else:
            kept.append(entry)
    triggers = list(triggered.values())[:max(0, max_events)]
    resolves = ending[:max(0, max_events - len(triggers))]
    deferred = [dict(entry, over=True) for entry in ending[len(resolves):]]
    known = {entry['key'] for entry in previous}
    added = [{'key': t['key'], 'target': t['target'], 'item': t['item'], 'tag': t['tag'],
              'since': since} for t in triggers if t['key'] not in known]
    plan = {'triggers': triggers, 'resolves': resolves, 'cut': len(triggered) - len(triggers),
            'kept': kept, 'deferred': deferred, 'added': added}
    plan['open'] = pagerduty_open_after(plan)
    return plan


def pagerduty_open_after(plan: Dict[str, Any], triggered: Optional[Set[str]] = None,
                         resolved: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """The PagerDuty keys open after a run, by what was delivered (``triggered``,
    ``resolved``: the keys of the events that went out; None: all of them): the baseline's keys
    still open, those whose resolve was not delivered (as they were: the next run decides
    again), those whose resolve waits for the event budget (``over``) and the new keys whose
    trigger was delivered - at most :data:`PAGERDUTY_MAX_OPEN`, the oldest dropped."""
    keys = (plan['kept'] + [entry for entry in plan['resolves']
                            if resolved is not None and entry['key'] not in resolved]
            + plan['deferred'] + [entry for entry in plan['added']
                                  if triggered is None or entry['key'] in triggered])
    return keys[max(0, len(keys) - PAGERDUTY_MAX_OPEN):]


def _with_open_keys(doc: Dict[str, Any], open_keys: List[Dict[str, Any]]) -> Dict[str, Any]:
    """A report dict with ``notify.open`` replaced by ``open_keys`` (none: no ``notify``),
    every other key as it was, in its place."""
    out = {key: value for key, value in doc.items() if key != 'notify' or open_keys}
    if open_keys:
        out['notify'] = {'open': open_keys}
    return out


def pagerduty_events(url: str, plan: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]]]:
    """``(URL to POST to, events)`` of a PagerDuty Events API v2 URL for a
    :func:`pagerduty_plan`: the triggers, then the resolves; ``routing_key`` moved from the
    query into each event."""
    parts = urllib.parse.urlsplit(url)
    routing_key = _pagerduty_routing_key(parts.query)
    query = [(key, value) for key, value in
             urllib.parse.parse_qsl(parts.query, keep_blank_values=True) if key != 'routing_key']
    post_url = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                        urllib.parse.urlencode(query), ''))
    events = [{'routing_key': routing_key, 'event_action': 'trigger', 'dedup_key': t['key'],
               'payload': {'summary': _clip(display_text(t['summary']),
                                            _PAGERDUTY_SUMMARY_LIMIT),
                           'source': 'domainscope:scan',
                           'severity': 'critical' if t['tag'] in PAGERDUTY_CRITICAL_TAGS
                           else 'error',
                           'component': t['target'], 'group': 'scan',
                           'custom_details': t['details']},
               'client': 'DomainScope'} for t in plan['triggers']]
    events.extend({'routing_key': routing_key, 'event_action': 'resolve',
                   'dedup_key': entry['key']} for entry in plan['resolves'])
    return post_url, events


def _payload_baseline(info: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The ``baseline`` block of a JSON webhook: the state file's base name only, never
    its local path, which a third-party endpoint has no use for."""
    if info is None or not isinstance(info.get('file'), str):
        return info
    return dict(info, file=os.path.basename(info['file'].replace('\\', '/')))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirected POST would come back as a GET without the message: report it."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        return None


def _response_detail(raw: bytes, redact: Optional[Callable[[str], str]] = None) -> str:
    """The reason in a webhook's error answer: Telegram's ``description``, Discord's
    ``message``, Power Automate's ``error.message``, or the body itself - ``redact``-ed, then on
    one line and cut at 200 characters (a secret echoed across the cut would leave its start,
    which no redaction finds)."""
    clean = redact or (lambda value: value)
    text = raw.decode('utf-8', 'replace')
    try:
        data = json.loads(text)
    except (ValueError, RecursionError):
        data = None
    if isinstance(data, dict):
        error = data.get('error')
        for value in (data.get('description'), data.get('message'),
                      error.get('message') if isinstance(error, dict) else error):
            if isinstance(value, str) and value.strip():
                text = value
                break
    # a secret with spaces may only show once they are one
    return clean(' '.join(clean(text).split()))[:200]


def _network_error_text(reason: Any) -> str:
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return 'timed out'
    if isinstance(reason, ssl.SSLError):
        return 'TLS: %s' % _clean_ssl_message(reason)
    if isinstance(reason, OSError) and reason.strerror:
        return reason.strerror
    return str(reason) or type(reason).__name__


def _post_once(opener: urllib.request.OpenerDirector, url: str, body: bytes,
               timeout: float, auth: Optional[str] = None,
               extra: Optional[Dict[str, str]] = None,
               redact: Optional[Callable[[str, bool], str]] = None
               ) -> Tuple[Optional[str], bool, Optional[float]]:
    """One POST -> ``(error or None, worth a retry, Retry-After seconds)``; what the answer
    says is ``redact``-ed (``redact(text, cut)``) before it is cut."""
    clean = redact or (lambda value, cut=False: value)
    headers = {'Content-Type': 'application/json; charset=utf-8', 'User-Agent': _USER_AGENT}
    headers.update(extra or {})
    if auth:
        headers['Authorization'] = auth
    request = urllib.request.Request(url, data=body, method='POST', headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(65536)
        return None, False, None
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(513) or b''
        except (OSError, http.client.HTTPException, ValueError):
            raw = b''
        finally:
            exc.close()
        cut = len(raw) > 512
        raw = raw[:512]
        text = 'HTTP %d %s' % (exc.code, clean(str(exc.reason or '')))
        if 300 <= exc.code < 400:
            text += ' (a redirect; not followed)'
        detail = _response_detail(raw, lambda value: clean(value, cut))
        if detail:
            text += ': ' + detail
        value = str(exc.headers.get('Retry-After') or '').strip() if exc.headers else ''
        retry_after = float(value) if value.isdigit() else None
        return text.strip(), exc.code >= 500 or exc.code == 429, retry_after
    except urllib.error.URLError as exc:
        return _network_error_text(exc.reason), True, None
    except (socket.timeout, TimeoutError) as exc:
        return _network_error_text(exc), True, None
    except (http.client.HTTPException, OSError) as exc:
        return _network_error_text(exc), True, None
    except ValueError:
        return 'not a valid URL', False, None


def send_notification(url: str, payload: Optional[Dict[str, Any]],
                      timeout: float = NOTIFY_TIMEOUT, retries: int = 1,
                      retry_delay: float = NOTIFY_RETRY_DELAY,
                      sleep: Callable[[float], None] = time.sleep,
                      data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None,
                      secrets: Sequence[str] = ()) -> Optional[str]:
    """POST ``payload`` as JSON (or the bytes ``data``, with ``headers`` added: ntfy's
    plain text, a signed body) to ``url`` -> None when delivered, else what went wrong.

    Certificate-verified HTTPS (the system proxy settings apply), no redirects,
    ``timeout`` seconds per attempt, ``retries`` more attempts after ``retry_delay``
    seconds (a 429's Retry-After, up to 10 s) for network errors, 5xx and 429 - a 4xx
    is the webhook's answer. A ``user:password@`` in the URL is sent as Basic
    authentication. The message never contains the URL nor ``secrets``
    (:func:`redact_url`).
    """
    body = data if data is not None else json.dumps(payload, ensure_ascii=False).encode('utf-8')
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect)
    target, auth = split_credentials(url)
    hidden = _redaction_secrets(url, secrets)

    def redact(text: str, cut: bool = False) -> str:
        return _redact_with(text, hidden, cut)

    problem = None  # type: Optional[str]
    for attempt in range(1 + max(0, retries)):
        problem, retry, retry_after = _post_once(opener, target, body, timeout, auth, headers,
                                                 redact)
        if problem is None:
            return None
        if not retry or attempt >= retries:
            break
        sleep(min(10.0, max(retry_delay, retry_after or 0.0)))
    return display_text(redact(problem or 'failed'))


# =====================================================================================
# Estate: every certificate the servers serve (--estate)
# =====================================================================================
# The estate is computed from a report dict (report_to_dict), like expiring_certificates:
# assets/js/lib/estate.js computes the same from one or more imported --json reports, and
# tests/fixtures/estate/ holds a report whose "estate" both must reproduce.

# Expiry buckets of a served certificate, by whole days left: expired (< 0), < 7, < 30,
# < 90 days, later.
ESTATE_BUCKETS = ('expired', '7d', '30d', '90d', 'later')
_ESTATE_BUCKET_LIMITS = ((0, 'expired'), (7, '7d'), (30, '30d'), (90, '90d'))
ESTATE_KINDS = (KIND_ORIGIN_CA, KIND_SELF_SIGNED, KIND_PRIVATE_CA, KIND_OTHER)
# Why a served certificate is weak: an RSA key under 2048 bits, a SHA-1 or an MD5 / MD2
# signature (public CAs stopped issuing all three years ago).
ESTATE_WEAK_REASONS = ('rsa-short', 'sha1', 'md5')
WEAK_RSA_BITS = 2048
# What is odd about a certificate (estate certificates[].flags, the CSV's flags column):
# served for a name that other endpoints serve with another certificate, the older one
# of such a pair (same key type, issued before), its key in several certificates or on
# many hosts (:func:`shared_key_needs_look`), weak, covering none of the names asked.
ESTATE_FLAGS = ('name-conflict', 'stale', 'shared-key', 'weak', 'covers-none')
# A key is listed as shared when this many hosts (distinct addresses) serve it, or when
# several certificates carry it. One certificate on the members of a load-balancer pool is
# listed but not flagged: only a key in several certificates, or on SHARED_KEY_WIDE_HOSTS
# addresses or more, is.
SHARED_KEY_MIN_HOSTS = 2
SHARED_KEY_WIDE_HOSTS = 5


def shared_key_needs_look(group: Dict[str, Any]) -> bool:
    """A shared key (estate ``sharedKeys`` entry) that flags its certificates: carried by
    several certificates (a renewal that kept the key, one key for several sites), or served
    by :data:`SHARED_KEY_WIDE_HOSTS` or more addresses."""
    return len(group['certificates']) >= 2 or group['hosts'] >= SHARED_KEY_WIDE_HOSTS


def expiry_bucket(days_left: int) -> str:
    """The :data:`ESTATE_BUCKETS` entry of a certificate with ``days_left`` whole days left."""
    for limit, bucket in _ESTATE_BUCKET_LIMITS:
        if days_left < limit:
            return bucket
    return 'later'


def weak_reasons(key_algorithm: Any, key_bits: Any, signature_algorithm: Any) -> List[str]:
    """The :data:`ESTATE_WEAK_REASONS` of a certificate (``[]`` when it is not weak)."""
    reasons = []  # type: List[str]
    if key_algorithm == 'RSA' and isinstance(key_bits, int) and key_bits < WEAK_RSA_BITS:
        reasons.append('rsa-short')
    signature = str(signature_algorithm or '').lower()
    if 'sha1' in signature:
        reasons.append('sha1')
    if signature.startswith(('md5', 'md2')):
        reasons.append('md5')
    return reasons


def key_label(key_algorithm: Any, key_bits: Any, curve: Any) -> str:
    """``RSA 2048``, ``EC P-256``, ``Ed25519`` from a report's certificate fields."""
    algorithm = str(key_algorithm or 'unknown')
    if algorithm == 'EC':
        return 'EC %s' % curve if curve else 'EC'
    if algorithm in ('RSA', 'DSA') and isinstance(key_bits, int):
        return '%s %d' % (algorithm, key_bits)
    return algorithm


def _parse_iso_utc(value: Any) -> Optional[datetime]:
    """An ISO time as this tool writes it (``2026-09-28T12:00:00.000Z``), or None."""
    if not isinstance(value, str):
        return None
    match = re.match(r'^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?Z$', value)
    if not match:
        return None
    parts = [int(part) for part in match.groups()[:6]]
    micro = int((match.group(7) or '0').ljust(6, '0'))
    try:
        return datetime(*parts, micro, tzinfo=timezone.utc)
    except ValueError:
        return None


def _report_probes(doc: Dict[str, Any]) -> List[Tuple[str, str]]:
    """``(name, sni)`` of every name a report asked for, in its order: ``names``, or what
    its rows probed when a report has none."""
    out = []  # type: List[Tuple[str, str]]
    seen = set()  # type: Set[str]
    entries = doc.get('names') if isinstance(doc.get('names'), list) else None
    if entries is None:
        entries = [{'name': row.get('name'), 'sni': row.get('sni')}
                   for row in doc.get('results') or []
                   if isinstance(row, dict) and row.get('probe') in (PROBE_SNI, PROBE_WILDCARD)]
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        name, sni = entry.get('name'), entry.get('sni')
        if isinstance(name, str) and name and name not in seen:
            seen.add(name)
            out.append((name, sni if isinstance(sni, str) and sni else name))
    return out


def estate_from_report(doc: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """The ``estate`` section of a report dict: every distinct certificate served, where and
    for which names, and what is odd about the whole.

    ``now`` counts the days left (default: the report's ``finishedAt``). Every handshake
    that returned a certificate counts - with SNI or without, covering the name or not (a
    server's fallback certificate is served too). Returns::

        {namesAsked, counts: {certificates, endpoints, openEndpoints, endpointsWithCertificate,
                              expiry: {bucket: n}, kinds: {kind: n}},
         certificates: [{sha256, subjectCN, subjectDN, issuer, issuerDN, serialHex, notBefore,
                         notAfter, daysLeft, expiry, hostnames, keyAlgorithm, keyBits, curve,
                         key, signatureAlgorithm, spkiSha256, kind, privateCa, isCA, weak,
                         coversAsked, flags, endpoints: [{servers, ip, port, defaultCert,
                         names}]}],                  # soonest expiry first
         nameConflicts: [{name, certificates: [{sha256, stale, endpoints: [{servers, ip,
                          port}]}]}],               # a name served with 2+ certificates
         sharedKeys: [{spkiSha256, key, hosts, servers, addresses, certificates}],
         weakKeys: [{sha256, reasons}],
         coversNone: [sha256] or None}              # None when no name was asked

    ``stale`` marks a certificate of a name conflict that another certificate of the same
    key type and kind family (public, Origin CA, private), issued later, replaces: the
    endpoints serving it are the ones left behind. An RSA + ECDSA pair, or an Origin CA
    certificate next to a public one, is a conflict without a stale side. A shared key's
    ``hosts`` counts distinct addresses; only one that :func:`shared_key_needs_look` flags
    its certificates ``shared-key``.
    """
    now = now or _parse_iso_utc(doc.get('finishedAt')) or _utcnow()
    probes = _report_probes(doc)
    info_of = doc.get('certificates') if isinstance(doc.get('certificates'), dict) else {}
    entries = {}  # type: Dict[str, Dict[str, Any]]
    endpoints_of = {}  # type: Dict[str, Dict[Tuple[str, int], Dict[str, Any]]]
    served = {}  # type: Dict[str, Dict[Tuple[str, int], str]]  name -> endpoint -> sha256
    seen_endpoints = {}  # type: Dict[Tuple[str, int], str]  every endpoint -> OPEN / state
    for row in doc.get('results') or []:
        if not isinstance(row, dict) or row.get('probe') not in _ROW_PROBES + (PROBE_CONNECT,):
            continue
        ip, port = row.get('ip'), row.get('port')
        if not isinstance(ip, str) or isinstance(port, bool) or not isinstance(port, int):
            continue
        key = (normalize_ip(ip) or ip, port)
        if row['probe'] == PROBE_CONNECT:
            seen_endpoints[key] = str(row.get('status'))
            continue
        seen_endpoints.setdefault(key, OPEN)
        sha = row.get('certSha256')
        if not isinstance(sha, str) or not _SHA256_RE.match(sha):
            continue
        entry = entries.get(sha)
        if entry is None:
            entry = entries[sha] = _estate_entry(sha, row, info_of.get(sha), probes, now)
            endpoints_of[sha] = {}
        endpoint = endpoints_of[sha].get(key)
        if endpoint is None:
            endpoint = endpoints_of[sha][key] = {'servers': [], 'ip': key[0], 'port': port,
                                                 'defaultCert': False, 'names': []}
            entry['endpoints'].append(endpoint)
        server = row.get('server')
        if isinstance(server, str) and server and server not in endpoint['servers']:
            endpoint['servers'].append(server)
        name = row.get('name')
        if row['probe'] == PROBE_DEFAULT:
            endpoint['defaultCert'] = True
        elif isinstance(name, str) and name:
            if name not in endpoint['names']:
                endpoint['names'].append(name)
            sni = row.get('sni') if isinstance(row.get('sni'), str) else name
            if cert_covers(entry['hostnames'], sni)[0]:
                served.setdefault(name, {}).setdefault(key, sha)
    certificates = sorted(entries.values(), key=lambda e: (e['daysLeft'], e['sha256']))

    conflicts = _name_conflicts(probes, served, entries, endpoints_of)
    shared = _shared_keys(certificates)
    weak = [{'sha256': e['sha256'], 'reasons': list(e['weak'])} for e in certificates
            if e['weak']]
    covers_none = ([e['sha256'] for e in certificates if not e['coversAsked']]
                   if probes else None)
    flags = {}  # type: Dict[str, Set[str]]
    for conflict in conflicts:
        for cert in conflict['certificates']:
            flags.setdefault(cert['sha256'], set()).add('name-conflict')
            if cert['stale']:
                flags[cert['sha256']].add('stale')
    for group in shared:
        if shared_key_needs_look(group):
            for sha in group['certificates']:
                flags.setdefault(sha, set()).add('shared-key')
    for item in weak:
        flags.setdefault(item['sha256'], set()).add('weak')
    for sha in covers_none or []:
        flags.setdefault(sha, set()).add('covers-none')
    for entry in certificates:
        entry['flags'] = [flag for flag in ESTATE_FLAGS if flag in flags.get(entry['sha256'], ())]

    report_endpoints = doc.get('endpoints') if isinstance(doc.get('endpoints'), list) else None
    if report_endpoints is not None:
        endpoint_count = len(report_endpoints)
        open_count = sum(1 for e in report_endpoints if isinstance(e, dict)
                         and e.get('state') == OPEN)
    else:
        endpoint_count = len(seen_endpoints)
        open_count = sum(1 for state in seen_endpoints.values() if state == OPEN)
    return {
        'namesAsked': [name for name, _sni in probes],
        'counts': {
            'certificates': len(certificates),
            'endpoints': endpoint_count,
            'openEndpoints': open_count,
            'endpointsWithCertificate': len({key for eps in endpoints_of.values() for key in eps}),
            'expiry': {bucket: sum(1 for e in certificates if e['expiry'] == bucket)
                       for bucket in ESTATE_BUCKETS},
            'kinds': {kind: sum(1 for e in certificates if e['kind'] == kind)
                      for kind in ESTATE_KINDS},
        },
        'certificates': certificates,
        'nameConflicts': conflicts,
        'sharedKeys': shared,
        'weakKeys': weak,
        'coversNone': covers_none,
    }


def _estate_entry(sha: str, row: Dict[str, Any], info: Any, probes: Sequence[Tuple[str, str]],
                  now: datetime) -> Dict[str, Any]:
    """A certificate of the estate from the report's ``certificates`` entry (the row's own
    fields when a report lacks it)."""
    info = info if isinstance(info, dict) else {}

    def text(key: str, fallback: Any = None) -> Optional[str]:
        value = info.get(key, fallback)
        return value if isinstance(value, str) else None

    hostnames = [name for name in info.get('hostnames') or [] if isinstance(name, str)]
    not_after = text('notAfter', row.get('certNotAfter'))
    when = _parse_iso_utc(not_after)
    days = days_until(when, now) if when else row.get('certDaysLeft')
    days = days if isinstance(days, int) and not isinstance(days, bool) else 0
    kind = text('kind')
    if kind not in ESTATE_KINDS:
        kind = KIND_SELF_SIGNED if info.get('selfSigned') is True else KIND_OTHER
    bits = info.get('keyBits')
    bits = bits if isinstance(bits, int) and not isinstance(bits, bool) else None
    algorithm = text('keyAlgorithm')
    signature = text('signatureAlgorithm')
    spki = text('spkiSha256')
    # --ari / --revocation: carried along only when the report has them (lib/estate.js alike)
    extra = {key: info[key] for key in ('ari', 'revocation') if isinstance(info.get(key), dict)}
    return {
        'sha256': sha,
        'subjectCN': text('subjectCN', row.get('certSubjectCN')),
        'subjectDN': text('subjectDN'),
        'issuer': row.get('certIssuer') if isinstance(row.get('certIssuer'), str) else None,
        'issuerDN': text('issuerDN'),
        'serialHex': text('serialHex', row.get('certSerial')),
        'notBefore': text('notBefore'),
        'notAfter': not_after,
        'daysLeft': days,
        'expiry': expiry_bucket(days),
        'hostnames': hostnames,
        'keyAlgorithm': algorithm,
        'keyBits': bits,
        'curve': text('curve'),
        'key': key_label(algorithm, bits, text('curve')),
        'signatureAlgorithm': signature,
        'spkiSha256': spki if spki and _SHA256_RE.match(spki) else None,
        'kind': kind,
        'privateCa': text('privateCa'),
        'isCA': info.get('isCA') is True,
        'weak': weak_reasons(algorithm, bits, signature),
        'coversAsked': [name for name, sni in probes if cert_covers(hostnames, sni)[0]],
        **extra,
        'flags': [],
        'endpoints': [],
    }


def _issued_after(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """``a`` was issued after ``b``: a later notBefore, else a later notAfter (ISO text as this
    tool writes it sorts like the time)."""
    for key in ('notBefore', 'notAfter'):
        x, y = a.get(key) or '', b.get(key) or ''
        if x != y:
            return x > y
    return False


def _name_conflicts(probes: Sequence[Tuple[str, str]],
                    served: Dict[str, Dict[Tuple[str, int], str]],
                    entries: Dict[str, Dict[str, Any]],
                    endpoints_of: Dict[str, Dict[Tuple[str, int], Dict[str, Any]]]
                    ) -> List[Dict[str, Any]]:
    """Names asked that endpoints serve with different certificates (each covering the name):
    a load-balancer member or a server the last renewal forgot."""
    out = []
    for name, _sni in probes:
        by_cert = {}  # type: Dict[str, List[Tuple[str, int]]]
        for key, sha in (served.get(name) or {}).items():
            by_cert.setdefault(sha, []).append(key)
        if len(by_cert) < 2:
            continue
        certs = [entries[sha] for sha in by_cert]
        certs.sort(key=lambda e: (e.get('notBefore') or '', e.get('notAfter') or ''), reverse=True)
        out.append({'name': name, 'certificates': [{
            'sha256': cert['sha256'],
            'stale': any(other is not cert and other['keyAlgorithm'] == cert['keyAlgorithm']
                         and _kind_family(other['kind']) == _kind_family(cert['kind'])
                         and _issued_after(other, cert) for other in certs),
            'endpoints': [{'servers': list(endpoints_of[cert['sha256']][key]['servers']),
                           'ip': key[0], 'port': key[1]} for key in by_cert[cert['sha256']]],
        } for cert in certs]})
    return out


def _shared_keys(certificates: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Public keys (SPKI SHA-256) served by :data:`SHARED_KEY_MIN_HOSTS` or more hosts, or
    carried by several certificates: one stolen key opens all of them. A host is an address
    (several inventory names of one address are one host, its ports too); ``servers`` names
    them as the inventory does."""
    groups = {}  # type: Dict[str, List[Dict[str, Any]]]
    for entry in certificates:
        if entry['spkiSha256']:
            groups.setdefault(entry['spkiSha256'], []).append(entry)
    out = []
    for spki, certs in groups.items():
        servers, addresses, folded = [], [], set()  # type: List[str], List[str], Set[str]
        for cert in certs:
            for endpoint in cert['endpoints']:
                if endpoint['ip'] not in addresses:
                    addresses.append(endpoint['ip'])
                for server in endpoint['servers'] or [endpoint['ip']]:
                    if server.casefold() not in folded:
                        folded.add(server.casefold())
                        servers.append(server)
        if len(addresses) >= SHARED_KEY_MIN_HOSTS or len(certs) >= 2:
            out.append({'spkiSha256': spki, 'key': certs[0]['key'], 'hosts': len(addresses),
                        'servers': servers, 'addresses': addresses,
                        'certificates': [cert['sha256'] for cert in certs]})
    out.sort(key=lambda g: (-g['hosts'], -len(g['certificates']), g['spkiSha256']))
    return out


# --- estate output: summary and CSV ------------------------------------------------

ESTATE_CSV_COLUMNS = ('sha256', 'subject_cn', 'issuer', 'kind', 'not_after', 'days_left',
                      'expiry', 'key', 'signature_algorithm', 'spki_sha256', 'hostnames',
                      'covers_asked', 'server', 'ip', 'port', 'default_cert', 'served_for',
                      'flags', 'weak')


def estate_status_columns(estate: Dict[str, Any]) -> Tuple[str, ...]:
    """The columns --ari / --revocation add to the estate CSV: :data:`ARI_CSV_COLUMNS` when a
    certificate has an ``ari`` record, :data:`REVOCATION_CSV_COLUMNS` when one has a
    ``revocation`` record (lib/estate.js estateStatusColumns)."""
    certs = estate.get('certificates') or []
    return (ARI_CSV_COLUMNS if any('ari' in cert for cert in certs) else ()) + \
        (REVOCATION_CSV_COLUMNS if any('revocation' in cert for cert in certs) else ())


def estate_csv_rows(estate: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One row per certificate, endpoint and server (:data:`ESTATE_CSV_COLUMNS`, then
    :func:`estate_status_columns`), in the estate's order; lib/estate.js estateCsvRows gives
    the same rows."""
    rows = []
    extra = estate_status_columns(estate)
    for cert in estate.get('certificates') or []:
        status = dict(zip(extra, status_csv_cells(cert, ARI_CSV_COLUMNS[0] in extra,
                                                  REVOCATION_CSV_COLUMNS[0] in extra)))
        for endpoint in cert['endpoints']:
            for server in endpoint['servers'] or ['']:
                rows.append({
                    'sha256': cert['sha256'], 'subject_cn': cert['subjectCN'] or '',
                    'issuer': cert['issuer'] or '', 'kind': cert['kind'],
                    'not_after': cert['notAfter'] or '', 'days_left': cert['daysLeft'],
                    'expiry': cert['expiry'], 'key': cert['key'],
                    'signature_algorithm': cert['signatureAlgorithm'] or '',
                    'spki_sha256': cert['spkiSha256'] or '',
                    'hostnames': ' '.join(cert['hostnames']),
                    'covers_asked': ' '.join(cert['coversAsked']),
                    'server': server, 'ip': endpoint['ip'], 'port': endpoint['port'],
                    'default_cert': 'yes' if endpoint['defaultCert'] else 'no',
                    'served_for': ' '.join(endpoint['names']),
                    'flags': ' '.join(cert['flags']), 'weak': ' '.join(cert['weak']),
                    **status,
                })
    return rows


def render_estate_csv(estate: Dict[str, Any], lineterminator: str = '\r\n',
                      terminal: bool = False) -> str:
    """The ``--estate --csv`` file: :func:`estate_csv_rows` under :data:`ESTATE_CSV_COLUMNS`,
    every text cell spreadsheet-safe (:func:`_csv_cell`)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator=lineterminator)
    columns = ESTATE_CSV_COLUMNS + estate_status_columns(estate)
    writer.writerow(columns)
    for row in estate_csv_rows(estate):
        writer.writerow([_csv_cell(row[column], terminal) for column in columns])
    return buffer.getvalue()


_BUCKET_TEXT = {'expired': 'expired', '7d': '< 7 days', '30d': '< 30 days', '90d': '< 90 days',
                'later': 'later'}
_KIND_TEXT = {KIND_ORIGIN_CA: 'Cloudflare Origin CA', KIND_SELF_SIGNED: 'self-signed',
              KIND_PRIVATE_CA: 'private CA', KIND_OTHER: 'other CA'}
_WEAK_TEXT = {'rsa-short': 'RSA key shorter than %d bits' % WEAK_RSA_BITS,
              'sha1': 'SHA-1 signature', 'md5': 'MD5 / MD2 signature'}


def _count_text(count: int, one: str, many: Optional[str] = None) -> str:
    return '%d %s' % (count, one if count == 1 else (many or one + 's'))


def _estate_endpoint_text(endpoint: Dict[str, Any], with_names: bool = True) -> str:
    """``web01 192.0.2.10:443 (default; www.example.com)``."""
    label = _endpoint_label(endpoint['ip'], endpoint['port'])
    servers = [s for s in endpoint['servers'] if s != endpoint['ip']]
    text = '%s %s' % (', '.join(servers), label) if servers else label
    what = ['default'] if endpoint.get('defaultCert') else []
    if with_names and endpoint.get('names'):
        what.append(', '.join(endpoint['names']))
    return '%s (%s)' % (text, '; '.join(what)) if what else text


def _estate_where(endpoints: Sequence[Dict[str, Any]], show_all: bool,
                  with_names: bool = True) -> str:
    """The endpoints of a certificate, :data:`MAX_SUMMARY_ENDPOINTS` without --show-all."""
    limit = len(endpoints) if show_all else MAX_SUMMARY_ENDPOINTS
    parts = [_estate_endpoint_text(e, with_names) for e in endpoints[:limit]]
    if len(endpoints) > limit:
        parts.append('+%d more' % (len(endpoints) - limit))
    return ', '.join(parts)


def render_estate(report: ScanReport, estate: Dict[str, Any], color: bool = False,
                  show_all: bool = False, width: int = 100,
                  monitor: Optional[MonitorResult] = None) -> str:
    """The ``--estate`` summary: what was scanned, the certificates by expiry and kind, then
    what needs a look first - one name served with different certificates, keys on several
    hosts or in several certificates, weak keys or signatures, certificates covering none of
    the names asked - and every certificate served, soonest expiry first, with where it is
    served."""
    style = Style(color)
    now = report.finished_at
    counts = estate['counts']
    elapsed = (report.finished_at - report.started_at).total_seconds()
    ports = list(dict.fromkeys(e.port for e in report.endpoints)) or list(report.ports)
    lines = [style.paint('SSL estate: %d server(s), %d endpoint(s) (%d open), %d name(s) asked, '
                         'ports %s, %.1fs' % (len(report.servers), counts['endpoints'],
                                              counts['openEndpoints'], len(estate['namesAsked']),
                                              ','.join(str(p) for p in ports), elapsed), 'bold')]
    if report.exclude:
        lines.append(_excluded_line(report, style))
    if report.private_cas:
        labels = [ca.short_label() for ca in report.private_cas]
        lines.append(display_text('Private CAs (--private-ca): %s%s' % (
            ', '.join(labels[:5]), ' ...' if len(labels) > 5 else '')))
    expiry = counts['expiry']
    lines.append('Certificates served: %d - %s' % (counts['certificates'], ', '.join(
        style.paint('%s %d' % (_BUCKET_TEXT[b], expiry[b]),
                    *(('red', 'bold') if b in ('expired', '7d') and expiry[b] else
                      ('yellow',) if b == '30d' and expiry[b] else ()))
        for b in ESTATE_BUCKETS)))
    lines.append('Kinds: %s' % ', '.join('%s %d' % (_KIND_TEXT[k], counts['kinds'][k])
                                         for k in ESTATE_KINDS))
    status_certs = [e for e in estate['certificates'] if 'ari' in e or 'revocation' in e]
    if status_certs:  # --ari / --revocation
        revoked = sum(1 for e in status_certs if (e.get('revocation') or {}).get('status') == 'revoked')
        due = sum(1 for e in status_certs if window_state(e.get('ari'), now) in ('open', 'past'))
        lines.append('Renewal windows and revocation: %s, %s' % (
            style.paint('%d revoked' % revoked, 'red', 'bold') if revoked else '0 revoked',
            style.paint('%d to renew now (ARI window open or ended)' % due, 'red', 'bold') if due
            else '0 to renew now (ARI)'))
    if not estate['namesAsked']:
        lines.append(style.paint('No names asked: every server was asked without SNI only. Give '
                                 'your host names with -n (or targets by host name) to see the '
                                 'certificate of each name.', 'dim'))
    lines.append('')
    if monitor is not None:
        lines.extend(render_monitor(report, monitor, style, show_all, width))

    certs = {entry['sha256']: entry for entry in estate['certificates']}

    def head(sha: str, indent: str, extra: str = '') -> List[str]:
        cert = report.certificates.get(sha)
        text = cert_line(cert, now, style) if cert is not None else sha
        return _wrap(indent, len(indent), text + extra, width)

    def section(title: str, count: int, colors: Tuple[str, ...]) -> None:
        lines.append(style.paint('%s: %d' % (title, count), *(colors if count else ('bold',))))

    conflicts = estate['nameConflicts']
    section('Same name, different certificates', len(conflicts), ('red', 'bold'))
    if conflicts:
        lines.extend(style.paint(line, 'dim') for line in _wrap('  ', 2, (
            'Endpoints serve these names with different certificates: a load-balancer member '
            'or a server the last renewal left out. OLDER: another certificate of the same key '
            'type and kind was issued after it.'), width))
    for conflict in conflicts:
        lines.append('  ' + style.paint(display_text(conflict['name']), 'bold'))
        for item in conflict['certificates']:
            lines.extend(head(item['sha256'], '    ',
                              '  ' + style.paint('OLDER', 'red', 'bold') if item['stale'] else ''))
            lines.extend(style.paint(line, 'dim') for line in _wrap(
                '      ', 6, display_text(_estate_where(item['endpoints'], show_all,
                                                        with_names=False)), width))
    lines.append('')

    shared = estate['sharedKeys']
    look = [group for group in shared if shared_key_needs_look(group)]
    section('Same key on several hosts or certificates', len(shared),
            ('yellow', 'bold') if look else ('bold',))
    if shared:
        lines.extend(style.paint(line, 'dim') for line in _wrap('  ', 2, (
            'One stolen key opens every address listed; one certificate on the members of '
            'a load-balancer pool is the usual case. NEEDS A LOOK: the key is in several '
            'certificates (a renewal that kept it) or on %d or more addresses.'
            % SHARED_KEY_WIDE_HOSTS), width))
    for group in shared:
        lines.append('  %s key %s...: %s, %s%s' % (
            group['key'], group['spkiSha256'][:16],
            _count_text(group['hosts'], 'address', 'addresses'),
            _count_text(len(group['certificates']), 'certificate'),
            '  ' + style.paint('NEEDS A LOOK', 'yellow', 'bold')
            if shared_key_needs_look(group) else ''))
        names = [certs[sha]['subjectCN'] or sha[:16] for sha in group['certificates']]
        lines.extend(_wrap('    ', 4, display_text('certificates: ' + ', '.join(names)), width))
        limit = len(group['servers']) if show_all else MAX_SUMMARY_ENDPOINTS
        servers = group['servers'][:limit] + (['+%d more' % (len(group['servers']) - limit)]
                                              if len(group['servers']) > limit else [])
        lines.extend(style.paint(line, 'dim') for line in _wrap(
            '    ', 4, display_text('servers: ' + ', '.join(servers)), width))
    lines.append('')

    weak = estate['weakKeys']
    section('Weak keys or signatures', len(weak), ('red', 'bold'))
    for item in weak:
        entry = certs[item['sha256']]
        lines.extend(head(item['sha256'], '  '))
        reasons = ['%s (%s)' % (_WEAK_TEXT[r], entry['key'] if r == 'rsa-short'
                                else entry['signatureAlgorithm']) for r in item['reasons']]
        lines.append('    ' + style.paint('; '.join(reasons), 'red'))
        lines.extend(style.paint(line, 'dim') for line in _wrap(
            '    ', 4, display_text(_estate_where(entry['endpoints'], show_all)), width))
    lines.append('')

    if estate['coversNone'] is not None:
        section('Covering none of the names asked', len(estate['coversNone']), ('yellow', 'bold'))
        for sha in estate['coversNone']:
            lines.extend(head(sha, '  '))
            lines.extend(style.paint(line, 'dim') for line in _wrap(
                '    ', 4, display_text(_estate_where(certs[sha]['endpoints'], show_all)), width))
        lines.append('')

    lines.append(style.paint('Every certificate served (%d), soonest expiry first'
                             % counts['certificates'], 'bold'))
    for entry in estate['certificates']:
        kind = _KIND_TEXT[entry['kind']] if entry['kind'] != KIND_OTHER else ''
        marks = [text for text in (kind, 'CA certificate' if entry['isCA'] else '') if text]
        lines.extend(head(entry['sha256'], '  ', '  [%s]' % ', '.join(marks) if marks else ''))
        detail = '%s, %s | sha256 %s... | key %s...' % (
            entry['key'], entry['signatureAlgorithm'] or '?', entry['sha256'][:16],
            (entry['spkiSha256'] or '?')[:16])
        lines.append('    ' + style.paint(detail, 'dim'))
        names = entry['hostnames']
        if names:
            shown = names if show_all else names[:8]
            more = ' (+%d)' % (len(names) - len(shown)) if len(names) > len(shown) else ''
            lines.extend(_wrap('    ', 4, display_text('names: ' + ', '.join(shown) + more), width))
        lines.extend(_wrap('    ', 4, display_text('served: ' + _estate_where(entry['endpoints'],
                                                                           show_all)), width))
        if isinstance(entry.get('ari'), dict):  # --ari
            lines.extend(_wrap('    ', 4, ari_text(entry['ari'], now, style), width))
        if isinstance(entry.get('revocation'), dict):  # --revocation
            lines.extend(_wrap('    ', 4, revocation_text(entry['revocation'], style), width))
    lines.append('')

    with_cert = {(e['ip'], e['port']) for c in estate['certificates'] for e in c['endpoints']}
    missing = [e for e in report.endpoints if (e.ip, e.port) not in with_cert]
    if missing:
        closed = sum(1 for e in missing if e.state != OPEN)
        parts = ['%d closed or not answering' % closed] if closed else []
        if len(missing) > closed:
            parts.append('%d open without a completed handshake' % (len(missing) - closed))
        text = 'No certificate from %s: %s' % (_count_text(len(missing), 'endpoint'),
                                               ', '.join(parts))
        if not show_all:
            lines.append(style.paint(text + ' - --show-all lists them.', 'dim'))
        else:
            lines.append(style.paint(text, 'bold'))
            failure = {}  # type: Dict[Tuple[str, int], ProbeResult]
            for row in report.results:
                if row.status in _FAILED_STATUSES + (NOT_HOSTED,):
                    failure.setdefault((row.ip, row.port), row)
            for endpoint in missing:
                row = failure.get((endpoint.ip, endpoint.port))
                status = endpoint.state if endpoint.state != OPEN else (
                    row.status if row else TLS_ERROR)
                error = endpoint.error if endpoint.state != OPEN else (row.error if row else '')
                lines.append('  %s  %s  %s' % (_endpoint_label(endpoint.ip, endpoint.port),
                                               style.status(status),
                                               style.paint(display_text(error or ''), 'dim')))
    return '\n'.join(lines) + '\n'


# =====================================================================================
# --ari / --revocation: the issuing CA's renewal window and revocation list of every
# certificate the scan found served
# =====================================================================================
# ARI (ACME Renewal Information, RFC 9773): the CA's ACME directory names its renewalInfo URL,
# and GET <renewalInfo>/<CertID> answers the window in which the CA wants the certificate
# renewed - a CA moves it earlier before a mass revocation. The CertID is the issuer's key
# identifier and the serial number, both public. Revocation: the CRL the certificate names,
# read with the DER reader above (Let's Encrypt has been CRL-only since 2025-08-06; OCSP is
# not asked). Python's standard library cannot check the CRL's signature, so the report says
# "CRL signature not verified" (the headless runner, tools/ds.mjs tls --revocation, checks it).
# The directories are the runner's (tools/ds/ari.mjs); tests/js/ds-tls.test.js keeps them in step.

ARI_DIRECTORIES = {
    'letsencrypt': ({'url': 'https://acme-v02.api.letsencrypt.org/directory',
                     'hosts': ('acme-v02.api.letsencrypt.org',)},),
    'google': ({'url': 'https://dv.acme-v02.api.pki.goog/directory',
                'hosts': ('dv.acme-v02.api.pki.goog',)},),
    'zerossl': ({'url': 'https://acme.zerossl.com/v2/DV90',
                 'hosts': ('ari.trust-provider.com',)},),
    'sectigo': ({'url': 'https://acme.sectigo.com/v2/DV', 'hosts': ('ari.sectigo.com',)},),
    # one directory per key type; its renewalInfo answered 403 (not routed) on 2026-10-09
    'sslcom': ({'url': 'https://acme.ssl.com/sslcom-dv-rsa', 'hosts': ('acme.ssl.com',),
                'keyType': 'RSA'},
               {'url': 'https://acme.ssl.com/sslcom-dv-ecc', 'hosts': ('acme.ssl.com',),
                'keyType': 'EC'}),
}  # type: Dict[str, Tuple[Dict[str, Any], ...]]

# The issuer -> CA mapping of lib/renewal.js caForIssuer for these CAs: the first match in the
# order of lib/health.js CAA_ISSUERS (ZeroSSL first: it issues from Sectigo intermediates); None
# for a CA without an ARI server here (DigiCert, GlobalSign ...) or a private one.
_ARI_CA_PATTERNS = (
    ('zerossl', re.compile(r'zerossl', re.I)),
    ('letsencrypt', re.compile(r"let'?s\s*encrypt|\bISRG\b", re.I)),
    ('google', re.compile(r'google trust services|\bGTS CA\b', re.I)),
    (None, re.compile(r'digicert|geotrust|rapidssl|thawte|symantec|verisign|encryption everywhere'
                      r'|cloudflare inc (?:ecc|rsa) ca', re.I)),
    ('sectigo', re.compile(r'sectigo|comodo|usertrust|gogetssl|cpanel', re.I)),
    (None, re.compile(r'globalsign|go\s*daddy|starfield|\bamazon\b|buypass', re.I)),
    ('sslcom', re.compile(r'ssl\.com|ssl corporation', re.I)),
)
ARI_TIMEOUT = 10.0                 # seconds per ARI request (the whole of it, as http_get)
ARI_MAX_RETRY = 7 * 86400          # a longer Retry-After (a broken header) is cut to a week
ARI_BENCH = 3600                   # a rate-limited CA without Retry-After: not asked for this long
CRL_MAX_BYTES = 20 << 20           # a larger CRL is not read
CRL_TIMEOUT = 15.0                 # seconds for a CRL download, its body included
STATUS_WORKERS = 4                 # ARI requests and CRL downloads in flight
MOVED_UP_SECONDS = 24 * 3600       # a window starting this much earlier than before: MOVED-UP
# RFC 5280 section 5.3.1 CRLReason (also what Cert Spotter's revocation.reason holds).
REVOCATION_REASONS = {0: 'unspecified', 1: 'keyCompromise', 2: 'cACompromise',
                      3: 'affiliationChanged', 4: 'superseded', 5: 'cessationOfOperation',
                      6: 'certificateHold', 8: 'removeFromCRL', 9: 'privilegeWithdrawn',
                      10: 'aACompromise'}
_OID_CRL_REASON = '2.5.29.21'
_OID_INVALIDITY = '2.5.29.24'
_OID_CRL_NUMBER = '2.5.29.20'
_OID_IDP = '2.5.29.28'
_OID_DELTA_CRL = '2.5.29.27'
_OID_FRESHEST_CRL = '2.5.29.46'
_KNOWN_CRL_EXTENSIONS = frozenset((_OID_AKI, _OID_CRL_NUMBER, _OID_IDP, _OID_DELTA_CRL,
                                   _OID_FRESHEST_CRL, _OID_AIA))
_KNOWN_ENTRY_EXTENSIONS = frozenset((_OID_CRL_REASON, _OID_INVALIDITY))
# The CSV columns --ari / --revocation add (after the others, the scan's and --estate's alike).
ARI_CSV_COLUMNS = ('ari_start', 'ari_end', 'ari_explanation', 'ari_error')
REVOCATION_CSV_COLUMNS = ('revocation', 'revoked_at', 'revocation_reason', 'revocation_error')
_RFC3339_RE = re.compile(r'^(\d{4})-(\d{2})-(\d{2})[Tt ](\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?'
                         r'([Zz]|[+-]\d{2}:\d{2})$')


def ari_ca_for_issuer(issuer_dn: Optional[str]) -> Optional[str]:
    """The ARI CA (an :data:`ARI_DIRECTORIES` key) of an issuer DN, or None."""
    for ca, pattern in _ARI_CA_PATTERNS:
        if pattern.search(issuer_dn or ''):
            return ca
    return None


def ari_directory_for(ca: Optional[str], key_algorithm: Optional[str],
                      directories: Optional[Dict[str, Tuple[Dict[str, Any], ...]]] = None
                      ) -> Optional[Dict[str, Any]]:
    """The ACME directory entry of ``ca`` for a certificate's key type, or None."""
    table = ARI_DIRECTORIES if directories is None else directories
    entries = table.get(ca) if ca else None
    if not entries:
        return None
    if len(entries) == 1:
        return entries[0]
    for entry in entries:
        if entry.get('keyType') == key_algorithm:
            return entry
    return None


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode('ascii').rstrip('=')


def ari_cert_id(cert: CertInfo) -> Optional[str]:
    """The RFC 9773 CertID: base64url of the AKI keyIdentifier, a dot, base64url of the serial
    number's DER content (a leading zero byte when its high bit is set); None without both."""
    if not cert.authority_key_id or not cert.serial_hex:
        return None
    try:
        key_id = bytes.fromhex(cert.authority_key_id)
        serial = bytes.fromhex(cert.serial_hex if len(cert.serial_hex) % 2 == 0
                               else '0' + cert.serial_hex)
    except ValueError:
        return None
    if not key_id or not serial:
        return None
    serial = serial.lstrip(b'\x00') or b'\x00'
    if serial[0] & 0x80:
        serial = b'\x00' + serial
    return '%s.%s' % (_b64url(key_id), _b64url(serial))


def _parse_rfc3339(value: Any) -> Optional[datetime]:
    """An RFC 3339 time as ARI writes it (``2026-11-02T17:18:36Z``), or None."""
    match = _RFC3339_RE.match(value) if isinstance(value, str) else None
    if not match:
        return None
    parts = [int(part) for part in match.groups()[:6]]
    micro = int((match.group(7) or '0')[:6].ljust(6, '0'))
    try:
        when = datetime(*parts, micro, tzinfo=timezone.utc)
    except ValueError:
        return None
    zone = match.group(8)
    if zone not in ('Z', 'z'):
        offset = timedelta(hours=int(zone[1:3]), minutes=int(zone[4:6]))
        when = when - offset if zone[0] == '+' else when + offset
    return when


def _parse_retry_after(value: Optional[str], now: datetime) -> Optional[float]:
    """A Retry-After header (seconds, or an HTTP date) in seconds from ``now``, or None."""
    text = (value or '').strip()
    if not text:
        return None
    if re.match(r'^\d+(?:\.\d+)?$', text):
        return float(text)
    try:
        when = email.utils.parsedate_to_datetime(text)
    except (TypeError, ValueError, IndexError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - now).total_seconds())


class StatusFetchError(Exception):
    """A request of --ari / --revocation that brought no answer: ``code`` is ``timeout``,
    ``network``, ``too-large``, ``http`` or ``parse``; ``status`` the HTTP status if any."""

    def __init__(self, code: str, message: str = '', status: Optional[int] = None) -> None:
        Exception.__init__(self, message or code)
        self.code = code
        self.status = status


FetchFn = Callable[[str, float, Optional[int]], Tuple[int, Dict[str, str], bytes]]


def _read_body(response: Any, size: Optional[int], deadline: float) -> Tuple[bytes, bool]:
    """At most ``size`` bytes of a response body (all of it with None), one socket read at a
    time until ``deadline`` (``time.monotonic()``): ``(body, done)``, ``done`` False when the
    deadline came first. A server that sends a byte now and then keeps each read under the
    socket timeout, never the download past its deadline."""
    read = getattr(response, 'read1', None) or response.read
    chunks = []  # type: List[bytes]
    total = 0
    while size is None or total < size:
        if time.monotonic() >= deadline:
            return b''.join(chunks), False
        chunk = read(65536 if size is None else min(65536, size - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b''.join(chunks), True


def http_get(url: str, timeout: float, max_bytes: Optional[int] = None
             ) -> Tuple[int, Dict[str, str], bytes]:
    """GET ``url`` (http or https, redirects followed): ``(status, headers, body)`` for any
    answer - a 4xx / 5xx one with its first 4 KiB -, :class:`StatusFetchError` for none, a
    body larger than ``max_bytes``, or one still arriving ``timeout`` seconds after the request
    began (``timeout`` bounds each socket operation and the whole download). Header names are
    lower case."""
    if not re.match(r'^https?://', url, re.I):
        raise StatusFetchError('network', 'not an http(s) URL')
    deadline = time.monotonic() + timeout
    request = urllib.request.Request(url, headers={'User-Agent': _USER_AGENT, 'Accept': '*/*'})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            headers = {key.lower(): value for key, value in response.headers.items()}
            declared = headers.get('content-length', '')
            if max_bytes is not None and declared.isdigit() and int(declared) > max_bytes:
                raise StatusFetchError('too-large', '%s bytes' % declared, response.status)
            body, done = _read_body(response, max_bytes + 1 if max_bytes is not None else None,
                                    deadline)
            if not done:
                raise StatusFetchError('timeout', 'the answer took more than %g s' % timeout)
            if max_bytes is not None and len(body) > max_bytes:
                raise StatusFetchError('too-large', 'more than %d bytes' % max_bytes,
                                       response.status)
            return response.status, headers, body
    except urllib.error.HTTPError as exc:
        headers = {key.lower(): value for key, value in (exc.headers.items() if exc.headers
                                                           else [])}
        try:
            body = _read_body(exc, 4096, deadline)[0]
        except Exception:  # noqa: BLE001 - the status is what matters
            body = b''
        finally:
            exc.close()
        return exc.code, headers, body
    except StatusFetchError:
        raise
    except urllib.error.URLError as exc:
        reason = exc.reason
        code = 'timeout' if isinstance(reason, (socket.timeout, TimeoutError)) else 'network'
        raise StatusFetchError(code, str(reason))
    except (socket.timeout, TimeoutError) as exc:
        raise StatusFetchError('timeout', str(exc))
    except (OSError, http.client.HTTPException, ValueError) as exc:
        raise StatusFetchError('network', str(exc))


class AriClient:
    """The ARI requests of one run: each directory read once, each certificate asked once, a
    CA not asked again in the run after it answered "rate limited", and a certificate not
    asked before the Retry-After its last answer gave (``prev``: that answer is carried).

    ``fetch``, ``directories``, ``ca_of`` and ``now`` are for tests."""

    def __init__(self, fetch: Optional[FetchFn] = None,
                 directories: Optional[Dict[str, Tuple[Dict[str, Any], ...]]] = None,
                 ca_of: Optional[Callable[[CertInfo], Optional[str]]] = None,
                 now: Optional[Callable[[], datetime]] = None, timeout: float = ARI_TIMEOUT
                 ) -> None:
        self._fetch = fetch or http_get
        self._directories = ARI_DIRECTORIES if directories is None else directories
        self._ca_of = ca_of or (lambda cert: ari_ca_for_issuer(cert.issuer_dn))
        self._now = now or _utcnow
        self._timeout = timeout
        self._lock = threading.Lock()
        self._bases = {}  # type: Dict[str, Optional[str]]
        self._benched = {}  # type: Dict[str, datetime]
        self._done = {}  # type: Dict[str, Dict[str, Any]]
        self.requests = 0

    def _renewal_info(self, entry: Dict[str, Any]) -> Optional[str]:
        url = entry['url']
        with self._lock:
            if url in self._bases:
                return self._bases[url]
        status, _headers, body = self._fetch(url, self._timeout, 1 << 20)
        if status != 200:
            raise StatusFetchError('http', 'the directory answered HTTP %d' % status, status)
        try:
            data = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            raise StatusFetchError('parse', 'the directory is not JSON')
        info = data.get('renewalInfo') if isinstance(data, dict) else None
        base = None
        if isinstance(info, str):
            parts = urllib.parse.urlsplit(info)
            secure = parts.scheme == 'https' or (parts.scheme == 'http' and url.startswith('http://'))
            if secure and parts.netloc.lower() in entry['hosts']:
                base = info.rstrip('/')
        with self._lock:
            self._bases[url] = base
        return base

    def check(self, cert: CertInfo, prev: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """The ``ari`` record of ``cert``: ``{ca, certId, start, end, explanationURL, checkedAt,
        retryAfter, status, error}`` (+ ``carried: {from}`` when not asked this run)."""
        now = self._now()
        ca = self._ca_of(cert)
        record = {'ca': ca, 'certId': None, 'start': None, 'end': None, 'explanationURL': None,
                  'checkedAt': iso_utc(now), 'retryAfter': None, 'status': None,
                  'error': None}  # type: Dict[str, Any]
        entry = ari_directory_for(ca, cert.key_algorithm, self._directories)
        if entry is None:
            record['error'] = 'unsupported'
            return record
        cert_id = ari_cert_id(cert)
        if cert_id is None:
            record['error'] = 'no-key-id'
            return record
        record['certId'] = cert_id
        with self._lock:
            if cert_id in self._done:
                return self._done[cert_id]
        same = isinstance(prev, dict) and prev.get('certId') == cert_id

        def carried() -> Dict[str, Any]:
            out = dict(prev or {})
            out['carried'] = {'from': ((prev or {}).get('carried') or {}).get('from')
                              or (prev or {}).get('checkedAt')}
            return out

        retry = _parse_iso_utc(prev.get('retryAfter')) if same else None
        if retry is not None and retry > now:
            return carried()
        with self._lock:
            bench = self._benched.get(entry['url'])
        if bench is not None and bench > now:
            if same:
                return carried()
            record.update(error='rate-limit', retryAfter=iso_utc(bench),
                          carried={'from': iso_utc(now)})
            return record
        try:
            base = self._renewal_info(entry)
            if base is None:
                record['error'] = 'no-renewal-info'
                return record
            with self._lock:
                self.requests += 1
            status, headers, body = self._fetch('%s/%s' % (base, cert_id), self._timeout, 1 << 20)
        except StatusFetchError as exc:
            record.update(error=exc.code if exc.code in ('timeout', 'network', 'http', 'parse')
                          else 'network', status=exc.status)
            return record
        checked = self._now()
        record.update(status=status, checkedAt=iso_utc(checked))
        wait = _parse_retry_after(headers.get('retry-after'), checked)
        if wait:
            wait = min(wait, ARI_MAX_RETRY)
            record['retryAfter'] = iso_utc(checked + timedelta(seconds=wait))
        if status == 404:
            record['error'] = 'not-found'
        elif status == 429 or (status == 503 and wait):
            record['error'] = 'rate-limit' if status == 429 else 'http'
            with self._lock:
                self._benched[entry['url']] = checked + timedelta(seconds=wait or ARI_BENCH)
        elif status != 200:
            record['error'] = 'http'
        else:
            self._window(record, body)
        with self._lock:
            self._done[cert_id] = record
        return record

    @staticmethod
    def _window(record: Dict[str, Any], body: bytes) -> None:
        try:
            data = json.loads(body.decode('utf-8'))
        except (ValueError, UnicodeDecodeError):
            record['error'] = 'parse'
            return
        window = data.get('suggestedWindow') if isinstance(data, dict) else None
        start = _parse_rfc3339(window.get('start')) if isinstance(window, dict) else None
        end = _parse_rfc3339(window.get('end')) if isinstance(window, dict) else None
        if start is None or end is None or end <= start:  # RFC 9773 4.2: end after start
            record['error'] = 'bad-window'
            return
        record['start'], record['end'] = iso_utc(start), iso_utc(end)
        explanation = data.get('explanationURL')
        if isinstance(explanation, str) and re.match(r'^https://\S+$', explanation):
            record['explanationURL'] = explanation


def window_state(ari: Optional[Dict[str, Any]], at: datetime) -> Optional[str]:
    """Where ``at`` is in an ARI window: ``before``, ``open``, ``past``, or None without one."""
    if not isinstance(ari, dict) or ari.get('error'):
        return None
    start, end = _parse_iso_utc(ari.get('start')), _parse_iso_utc(ari.get('end'))
    if start is None or end is None:
        return None
    if at < start:
        return 'before'
    return 'open' if at <= end else 'past'


# --- certificate revocation lists ---------------------------------------------------------

def _serial_text(raw: bytes) -> str:
    """An INTEGER's content as the serial_hex of :class:`CertInfo` (no leading 00 bytes)."""
    text = raw.hex()
    while len(text) > 2 and text.startswith('00'):
        text = text[2:]
    return text


def _normal_serial(text: Optional[str]) -> str:
    text = (text or '').lower()
    text = text if len(text) % 2 == 0 else '0' + text
    while len(text) > 2 and text.startswith('00'):
        text = text[2:]
    return text


def _extensions(buf: bytes, tlv: Tlv) -> List[Tuple[str, bool, Tlv]]:
    """``(oid, critical, extnValue)`` of an Extensions SEQUENCE."""
    out = []
    for ext in _children(buf, *_expect(tlv, 0x30, 'Extensions')[2:4]):
        parts = _children(buf, *_expect(ext, 0x30, 'Extension')[2:4])
        if len(parts) < 2 or len(parts) > 3:
            raise DerError('malformed Extension')
        critical = len(parts) == 3 and any(_content(buf, _expect(parts[1], 0x01, 'BOOLEAN')))
        out.append((_oid(buf, parts[0]), critical, _expect(parts[-1], 0x04, 'extnValue')))
    return out


def _parse_idp(buf: bytes, value: Tlv) -> Dict[str, Any]:
    """IssuingDistributionPoint: its URLs and which certificates the CRL covers."""
    idp = {'urls': [], 'onlyUser': False, 'onlyCA': False, 'onlySomeReasons': False,
           'indirect': False, 'onlyAttribute': False}  # type: Dict[str, Any]
    seq = _expect(_read_tlv(buf, value[2], value[3]), 0x30, 'IssuingDistributionPoint')
    flags = {0x81: 'onlyUser', 0x82: 'onlyCA', 0x84: 'indirect', 0x85: 'onlyAttribute'}
    for item in _children(buf, seq[2], seq[3]):
        if item[0] == 0xA0:  # distributionPoint [0]: fullName [0] GeneralNames
            for choice in _children(buf, item[2], item[3]):
                if choice[0] == 0xA0:
                    for general in _children(buf, choice[2], choice[3]):
                        if general[0] == 0x86:
                            idp['urls'].append(_content(buf, general).decode('ascii', 'replace'))
        elif item[0] in flags:
            idp[flags[item[0]]] = any(_content(buf, item))
        elif item[0] == 0x83:
            idp['onlySomeReasons'] = True
    return idp


def parse_crl(der: Union[bytes, bytearray, memoryview],
              serials: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """A DER CRL (RFC 5280 section 5): ``{version, issuerDN, thisUpdate, nextUpdate, entries,
    count, crlNumber, authorityKeyId, idp, delta, unsupportedCritical}``; ``entries`` are
    ``{serialHex, revocationDate, reasonCode, reason, unsupportedCritical}``, only for the
    ``serials`` given (every entry is counted). Raises :class:`DerError`. The signature is
    not checked (stdlib)."""
    buf = bytes(der)
    if not buf:
        raise DerError('empty CRL')
    top = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'CertificateList')
    if top[3] != len(buf):
        raise DerError('data after the CRL')
    parts = _children(buf, top[2], top[3])
    if len(parts) != 3:
        raise DerError('a CRL has 3 elements, found %d' % len(parts))
    tbs = _expect(parts[0], 0x30, 'TBSCertList')
    outer = _children(buf, *_expect(parts[1], 0x30, 'signatureAlgorithm')[2:4])
    _expect(parts[2], 0x03, 'signatureValue')
    fields = _children(buf, tbs[2], tbs[3])
    index = 0
    version = 1
    if fields and fields[0][0] == 0x02:
        version = int.from_bytes(_content(buf, fields[0]), 'big', signed=True) + 1
        index = 1
        if version != 2:
            raise DerError('unsupported CRL version %d' % version)
    if len(fields) < index + 3 or not outer:
        raise DerError('TBSCertList is missing fields')
    inner = _children(buf, *_expect(fields[index], 0x30, 'signature')[2:4])
    if not inner or _oid(buf, inner[0]) != _oid(buf, outer[0]):
        raise DerError("the CRL's two signature algorithms differ")
    issuer_rdns = _parse_name(buf, _expect(fields[index + 1], 0x30, 'issuer Name'))
    this_update = _parse_time(fields[index + 2][0], _content(buf, fields[index + 2]))
    index += 3
    next_update = None
    if index < len(fields) and fields[index][0] in (0x17, 0x18):
        next_update = _parse_time(fields[index][0], _content(buf, fields[index]))
        index += 1
    wanted = None if serials is None else {_normal_serial(s) for s in serials}
    entries = []  # type: List[Dict[str, Any]]
    count = 0
    if index < len(fields) and fields[index][0] == 0x30:
        listing = fields[index]
        index += 1
        pos = listing[2]
        while pos < listing[3]:
            entry = _expect(_read_tlv(buf, pos, listing[3]), 0x30, 'revokedCertificate')
            pos = entry[3]
            count += 1
            serial = _expect(_read_tlv(buf, entry[2], entry[3]), 0x02, 'userCertificate')
            serial_hex = _serial_text(_content(buf, serial))
            if wanted is not None and serial_hex not in wanted:
                continue
            items = _children(buf, entry[2], entry[3])
            if len(items) not in (2, 3):
                raise DerError('malformed revokedCertificate')
            record = {'serialHex': serial_hex,
                      'revocationDate': _parse_time(items[1][0], _content(buf, items[1])),
                      'reasonCode': None, 'reason': None,
                      'unsupportedCritical': []}  # type: Dict[str, Any]
            if len(items) == 3:
                for oid, critical, value in _extensions(buf, items[2]):
                    if oid == _OID_CRL_REASON:
                        code = _content(buf, _expect(_read_tlv(buf, value[2], value[3]), 0x0A,
                                                     'ENUMERATED'))
                        record['reasonCode'] = int.from_bytes(code, 'big') if code else 0
                        record['reason'] = REVOCATION_REASONS.get(record['reasonCode'])
                    elif critical and oid not in _KNOWN_ENTRY_EXTENSIONS:
                        record['unsupportedCritical'].append(oid)
            entries.append(record)
    crl_number = authority_key_id = idp = None
    delta = False
    unsupported = []  # type: List[str]
    if index < len(fields) and fields[index][0] == 0xA0:
        wrapper = _children(buf, fields[index][2], fields[index][3])
        index += 1
        if len(wrapper) != 1:
            raise DerError('malformed crlExtensions')
        for oid, critical, value in _extensions(buf, wrapper[0]):
            if oid == _OID_CRL_NUMBER:
                crl_number = _content(buf, _expect(_read_tlv(buf, value[2], value[3]), 0x02,
                                                   'CRLNumber')).hex()
            elif oid == _OID_AKI:
                aki = _expect(_read_tlv(buf, value[2], value[3]), 0x30, 'AuthorityKeyIdentifier')
                for item in _children(buf, aki[2], aki[3]):
                    if item[0] == 0x80:
                        authority_key_id = _content(buf, item).hex()
            elif oid == _OID_IDP:
                idp = _parse_idp(buf, value)
            elif oid == _OID_DELTA_CRL:
                delta = True
            elif critical and oid not in _KNOWN_CRL_EXTENSIONS:
                unsupported.append(oid)
    if index != len(fields):
        raise DerError('unexpected field in TBSCertList')
    return {'version': version, 'issuerDN': _dn_string(issuer_rdns), 'thisUpdate': this_update,
            'nextUpdate': next_update, 'entries': entries, 'count': count,
            'filtered': wanted, 'crlNumber': crl_number, 'authorityKeyId': authority_key_id,
            'idp': idp, 'delta': delta, 'unsupportedCritical': unsupported}


def crl_urls_of(cert: CertInfo) -> List[str]:
    """The http(s) CRL distribution points of a certificate, in order, each once."""
    out = []  # type: List[str]
    for url in cert.crl_urls:
        if re.match(r'^https?://\S+$', url, re.I) and url not in out:
            out.append(url)
    return out


def _same_url(a: str, b: str) -> bool:
    """Whether two URLs name the same resource (lib/crl.js sameUrl): the same text when one of
    them cannot be split - a CRL's IDP is whatever its issuer wrote, its signature unchecked."""
    try:
        x, y = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
        return (x.scheme.lower(), x.netloc.lower(), x.path, x.query) == \
            (y.scheme.lower(), y.netloc.lower(), y.path, y.query)
    except ValueError:
        return a == b


def crl_status(crl: Dict[str, Any], cert: CertInfo, url: Optional[str] = None,
               now: Optional[datetime] = None) -> Dict[str, Any]:
    """What a CRL says about ``cert`` (lib/crl.js crlStatus): ``{status: good|revoked|unknown,
    code, reasonCode, reason, time}`` - unknown for another CA's CRL, an unknown critical
    extension, a delta CRL, a CRL for other certificates or reasons, or a stale one."""
    now = now or _utcnow()
    serial = _normal_serial(cert.serial_hex)
    if crl['filtered'] is not None and serial not in crl['filtered']:
        raise ValueError('the CRL was read for other serial numbers')
    out = {'status': 'unknown', 'code': None, 'reasonCode': None, 'reason': None,
           'time': None}  # type: Dict[str, Any]

    def unknown(code: str) -> Dict[str, Any]:
        out['code'] = code
        return out

    aki = crl['authorityKeyId']
    if crl['issuerDN'] != cert.issuer_dn or (aki and cert.authority_key_id
                                             and aki != cert.authority_key_id.lower()):
        return unknown('issuer-mismatch')
    if crl['unsupportedCritical']:
        return unknown('critical-extension')
    if crl['delta']:
        return unknown('delta')
    idp = crl['idp']
    if idp and (idp['onlyCA'] or idp['onlyAttribute'] or idp['indirect']
                or (idp['onlyUser'] and cert.is_ca)):
        return unknown('scope')
    if idp and url and idp['urls'] and not any(_same_url(u, url) for u in idp['urls']):
        return unknown('scope')
    entry = next((e for e in crl['entries'] if e['serialHex'] == serial), None)
    if entry is not None and entry['unsupportedCritical']:
        return unknown('critical-extension')
    if entry is not None and entry['reasonCode'] != 8:  # removeFromCRL: no longer on hold
        out.update(status='revoked', reasonCode=entry['reasonCode'], reason=entry['reason'],
                   time=entry['revocationDate'])
        return out
    if idp and idp['onlySomeReasons']:
        return unknown('reasons')
    if crl['nextUpdate'] is not None and crl['nextUpdate'] < now:
        return unknown('stale')
    out['status'] = 'good'
    return out


class RevocationChecker:
    """The CRL downloads of one run: each URL read once (at most :data:`CRL_MAX_BYTES`) and
    parsed once for the serial numbers of every certificate that names it. ``fetch`` and
    ``now`` are for tests."""

    def __init__(self, fetch: Optional[FetchFn] = None,
                 now: Optional[Callable[[], datetime]] = None, timeout: float = CRL_TIMEOUT,
                 max_bytes: int = CRL_MAX_BYTES, workers: int = STATUS_WORKERS) -> None:
        self._fetch = fetch or http_get
        self._now = now or _utcnow
        self._timeout = timeout
        self._max_bytes = max_bytes
        self._workers = workers
        self.downloads = 0

    def _load(self, item: Tuple[str, Set[str]]) -> Tuple[str, Any]:
        url, serials = item
        self.downloads += 1
        try:
            status, _headers, body = self._fetch(url, self._timeout, self._max_bytes)
        except StatusFetchError as exc:
            return ('error', exc.code)
        if status != 200:
            return ('error', 'http')
        try:
            return ('ok', parse_crl(body, serials))
        except _CERT_PARSE_ERRORS:
            return ('error', 'parse')

    def check(self, certs: Dict[str, CertInfo]) -> Dict[str, Dict[str, Any]]:
        """The ``revocation`` record of every certificate (by SHA-256): ``{status, reason,
        reasonCode, time, crl, checkedAt, thisUpdate, nextUpdate, signature, error}``."""
        serials_of = {}  # type: Dict[str, Set[str]]
        for cert in certs.values():
            for url in crl_urls_of(cert):
                serials_of.setdefault(url, set()).add(_normal_serial(cert.serial_hex))
        loaded = {}  # type: Dict[str, Any]
        if serials_of:
            _parallel(self._load, list(serials_of.items()), self._workers,
                      lambda item, result: loaded.__setitem__(item[0], result), threading.Event())
        out = {}  # type: Dict[str, Dict[str, Any]]
        for sha, cert in certs.items():
            urls = crl_urls_of(cert)
            if not urls:
                out[sha] = self._record(error='no-crl')
                continue
            first = None  # type: Optional[Dict[str, Any]]
            for url in urls:
                got = loaded.get(url, ('error', 'network'))
                if got[0] != 'ok':
                    record = self._record(crl=url, error=got[1])
                else:
                    try:
                        record = self._judge(got[1], cert, url)
                    except Exception:  # noqa: BLE001 - one CRL it cannot judge never loses the scan
                        record = self._record(crl=url, error='unknown')
                if record['status'] != 'unknown':
                    out[sha] = record
                    break
                first = first or record
            else:
                out[sha] = first or self._record(error='network')
        return out

    def _judge(self, crl: Dict[str, Any], cert: CertInfo, url: str) -> Dict[str, Any]:
        """What one CRL read for ``cert`` says, as its ``revocation`` record."""
        verdict = crl_status(crl, cert, url, self._now())
        record = self._record(crl=url, thisUpdate=iso_utc(crl['thisUpdate']),
                              nextUpdate=iso_utc(crl['nextUpdate']), signature='not-verified')
        if verdict['status'] == 'unknown':
            record['error'] = verdict['code']
            if verdict['code'] == 'issuer-mismatch':
                record['signature'] = None
        else:
            record.update(status=verdict['status'], reason=verdict['reason'],
                          reasonCode=verdict['reasonCode'], time=iso_utc(verdict['time']))
        return record

    def _record(self, **fields: Any) -> Dict[str, Any]:
        record = {'status': 'unknown', 'reason': None, 'reasonCode': None, 'time': None,
                  'crl': None, 'checkedAt': iso_utc(self._now()), 'thisUpdate': None,
                  'nextUpdate': None, 'signature': None, 'error': None}  # type: Dict[str, Any]
        record.update(fields)
        return record


def check_certificate_status(report: ScanReport, ari: bool = False, revocation: bool = False,
                             baseline: Optional[Dict[str, Any]] = None,
                             ari_client: Optional[AriClient] = None,
                             revocation_checker: Optional[RevocationChecker] = None,
                             workers: int = STATUS_WORKERS) -> Dict[str, Dict[str, Any]]:
    """``--ari`` / ``--revocation`` for every certificate the scan found served (by SHA-256):
    ``{sha256: {'ari': ..., 'revocation': ...}}``. The baseline's ``ari`` of the same
    certificate is honoured: not asked again before its ``retryAfter``."""
    served = {}  # type: Dict[str, CertInfo]
    for row in report.results:
        if row.cert is not None and row.cert.sha256 not in served:
            served[row.cert.sha256] = row.cert
    status = {sha: {} for sha in served}  # type: Dict[str, Dict[str, Any]]
    if not served:
        return status
    if revocation:
        checker = revocation_checker or RevocationChecker()
        for sha, record in checker.check(served).items():
            status[sha]['revocation'] = record
    if ari:
        client = ari_client or AriClient()
        prev_certs = baseline.get('certificates') if isinstance(baseline, dict) else None
        prev_certs = prev_certs if isinstance(prev_certs, dict) else {}

        def ask(sha: str) -> Dict[str, Any]:
            prev = prev_certs.get(sha)
            prev_ari = prev.get('ari') if isinstance(prev, dict) else None
            return client.check(served[sha], prev_ari if isinstance(prev_ari, dict) else None)

        _parallel(ask, list(served), workers,
                  lambda sha, record: status[sha].__setitem__('ari', record), threading.Event())
    return status


# --- the CSV cells, the changes and the summary lines ---------------------------------------

def status_csv_cells(entry: Optional[Dict[str, Any]], ari: bool, revocation: bool) -> List[str]:
    """The :data:`ARI_CSV_COLUMNS` and / or :data:`REVOCATION_CSV_COLUMNS` cells of a
    certificate's records (empty cells without them)."""
    entry = entry or {}
    cells = []  # type: List[str]
    if ari:
        record = entry.get('ari') if isinstance(entry.get('ari'), dict) else {}
        cells += [record.get('start') or '', record.get('end') or '',
                  record.get('explanationURL') or '', record.get('error') or '']
    if revocation:
        record = entry.get('revocation') if isinstance(entry.get('revocation'), dict) else {}
        cells += [record.get('status') or '', record.get('time') or '',
                  record.get('reason') or '', record.get('error') or '']
    return cells


def _status_changes(before: Dict[str, Any], after: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The certificate changes of --ari / --revocation (the runner's tools/ds/tlsdiff.mjs):
    RENEW-NOW (the window opened, or ended, since the baseline's run - the window its answer
    gave, at that run's time, never at the answer's ``checkedAt``: an answer carried past its
    Retry-After keeps that time -; or a certificate first seen in it), MOVED-UP (it starts
    over :data:`MOVED_UP_SECONDS` earlier), CA-NOTICE (an explanation URL the baseline's
    answers did not carry) and REVOKED (listed on the CRL now, not then). Only certificates
    served in ``after``, an endpoint new to the baseline's included."""
    old = before.get('certificates') if isinstance(before.get('certificates'), dict) else {}
    new = after.get('certificates') if isinstance(after.get('certificates'), dict) else {}
    served = {}  # type: Dict[str, Dict[str, Any]]
    for row in after.get('results') or []:
        sha = row.get('certSha256') if isinstance(row, dict) else None
        if not isinstance(sha, str) or row.get('probe') not in _ROW_PROBES:
            continue
        where = served.setdefault(sha, {'servers': [], 'ip': row.get('ip'), 'port': row.get('port')})
        server = row.get('server')
        if isinstance(server, str) and server and server not in where['servers']:
            where['servers'].append(server)
    at = _parse_iso_utc(after.get('finishedAt')) or _utcnow()
    # the baseline's run saw the certificates it lists served at its end
    before_at = _parse_iso_utc(before.get('finishedAt')) or _parse_iso_utc(before.get('startedAt'))
    ok = lambda record: isinstance(record, dict) and not record.get('error')  # noqa: E731
    known_urls = set()  # type: Set[str]
    read_before = False
    for info in old.values():
        record = info.get('ari') if isinstance(info, dict) else None
        if ok(record):
            read_before = True
            if record.get('explanationURL'):
                known_urls.add(record['explanationURL'])
    changes = []  # type: List[Dict[str, Any]]
    ranks = {'before': 0, 'open': 1, 'past': 2}
    for sha, where in served.items():
        info = new.get(sha) if isinstance(new.get(sha), dict) else {}
        prev = old.get(sha) if isinstance(old.get(sha), dict) else {}
        view = {'sha256': sha, 'subjectCN': info.get('subjectCN'), 'notAfter': info.get('notAfter')}

        def add(kind: str, **detail: Any) -> None:
            changes.append(_change(kind, 'certificate', where['servers'], where['ip'], where['port'],
                                   before=None, after=dict(view, **detail)))

        ari, prev_ari = info.get('ari'), prev.get('ari')
        if ok(ari):
            state = window_state(ari, at)
            prev_state = None
            if ok(prev_ari):
                prev_state = window_state(prev_ari, before_at
                                          or _parse_iso_utc(prev_ari.get('checkedAt')) or at)
            if state in ('open', 'past') and ranks[state] > ranks.get(prev_state or '', -1):
                add('renew-now', state=state, start=ari.get('start'), end=ari.get('end'))
            start, prev_start = _parse_iso_utc(ari.get('start')), \
                _parse_iso_utc(prev_ari.get('start')) if ok(prev_ari) else None
            if start and prev_start and (prev_start - start).total_seconds() > MOVED_UP_SECONDS:
                add('moved-up', start=ari.get('start'), was=prev_ari.get('start'))
            url = ari.get('explanationURL')
            if url and read_before and url not in known_urls:
                add('ca-notice', explanationURL=url)
        rev, prev_rev = info.get('revocation'), prev.get('revocation')
        if isinstance(rev, dict) and rev.get('status') == 'revoked' and not (
                isinstance(prev_rev, dict) and prev_rev.get('status') == 'revoked'):
            add('revoked', time=rev.get('time'), reason=rev.get('reason'))
    return changes


def _status_change_text(change: Dict[str, Any]) -> str:
    after = change.get('after') or {}
    kind = change.get('kind')
    label = 'CN %s (sha256 %s)' % (after.get('subjectCN') or '(none)', str(after.get('sha256'))[:8])
    if kind == 'renew-now':
        what = ("the CA's renewal window opened (%s - %s): renew it now" % (
            _iso_day(after.get('start')), _iso_day(after.get('end'))) if after.get('state') == 'open'
                else "the CA's renewal window ended on %s: the renewal is overdue"
                % _iso_day(after.get('end')))
    elif kind == 'moved-up':
        start, was = _parse_iso_utc(after.get('start')), _parse_iso_utc(after.get('was'))
        # half a day up, as the runner's Math.round (Python's round() goes to the even number)
        days = int(math.floor((was - start).total_seconds() / 86400.0 + 0.5)) if start and was else 0
        what = ('the CA moved its renewal window %d day%s earlier (starts %s, was %s), as CAs do '
                'before a mass revocation' % (days, '' if days == 1 else 's',
                                              _iso_day(after.get('start')), _iso_day(after.get('was'))))
    elif kind == 'ca-notice':
        what = 'the CA explains its renewal window: %s' % after.get('explanationURL')
    else:
        what = 'revoked by its CA on %s (%s), still served' % (
            _iso_day(after.get('time')), after.get('reason') or 'no reason given')
    where = _endpoint_label(str(change.get('ip')), change.get('port') or 0)
    servers = _servers_label(change.get('servers') or [], change.get('ip'))
    return display_text('%s: %s; served by %s' % (label, what, '%s %s' % (servers, where)
                                                  if servers else where))


def _minute(value: Any) -> str:
    when = _parse_iso_utc(value)
    return when.strftime('%Y-%m-%d %H:%M UTC') if when else '?'


_ARI_WHY = {'not-found': 'the CA does not know this certificate (404)',
            'unsupported': 'no ARI server is known for this issuer',
            'no-key-id': 'the certificate has no authority key identifier',
            'no-renewal-info': "the CA's directory names no renewalInfo URL",
            'bad-window': "the CA's answer is no window",
            'rate-limit': 'the CA answered "rate limited"',
            'http': "the CA's ARI server answered an HTTP error",
            'timeout': "the CA's ARI server timed out",
            'network': "the CA's ARI server could not be reached",
            'parse': "the CA's answer could not be read"}
_REVOCATION_WHY = {'no-crl': 'the certificate names no CRL to read (OCSP is not asked)',
                   'too-large': 'its CRL is larger than %d MB' % (CRL_MAX_BYTES >> 20),
                   'http': 'its CRL could not be downloaded (HTTP error)',
                   'timeout': 'its CRL download timed out',
                   'network': 'its CRL could not be downloaded',
                   'parse': 'what its CRL URL returned is not a CRL',
                   'issuer-mismatch': "the CRL is another CA's",
                   'critical-extension': 'the CRL has a critical extension this tool does not read',
                   'delta': 'it is a delta CRL', 'scope': 'the CRL covers other certificates',
                   'reasons': 'the CRL covers some revocation reasons only',
                   'stale': 'the CRL is out of date (its nextUpdate has passed)'}


def ari_text(record: Dict[str, Any], now: datetime, style: Style) -> str:
    """One line of a certificate's ARI record for the summary."""
    head = 'ARI (%s): ' % display_text(str(record['ca'])) if record.get('ca') else 'ARI: '
    carried = record.get('carried')
    tail = (' (as of %s; not asked again before %s, as the CA asked)' % (
        _minute(carried.get('from')), _minute(record.get('retryAfter')))
            if isinstance(carried, dict) and record.get('retryAfter') else
            ' (as of %s)' % _minute(carried.get('from')) if isinstance(carried, dict) else '')
    if record.get('error'):
        code = record.get('status')  # a number, unless a hand-made baseline carried something else
        status = ' %d' % code if record.get('error') == 'http' and isinstance(code, int) \
            and not isinstance(code, bool) else ''
        return head + _ARI_WHY.get(record['error'], "the CA's answer could not be read") + status + tail
    text = head + 'renew between %s and %s' % (_minute(record.get('start')), _minute(record.get('end')))
    state = window_state(record, now)
    if state == 'before':
        start = _parse_iso_utc(record.get('start'))
        days = int(math.ceil((start - now).total_seconds() / 86400.0)) if start else 0
        text += ' - opens in %d day%s' % (days, '' if days == 1 else 's')
    elif state == 'open':
        text += ' - ' + style.paint('RENEW NOW: the window is open', 'red', 'bold')
    elif state == 'past':
        text += ' - ' + style.paint('the window has ended: the renewal is overdue', 'red', 'bold')
    if record.get('explanationURL'):  # the CA's text: escaped for the terminal
        text += '; the CA explains: %s' % display_text(str(record['explanationURL']))
    return text + tail


def revocation_text(record: Dict[str, Any], style: Style) -> str:
    """One line of a certificate's revocation record for the summary."""
    crl = 'CRL of %s' % _minute(record.get('thisUpdate')) if record.get('thisUpdate') else 'CRL'
    if record.get('status') == 'revoked':
        return '%s on %s (%s); %s, CRL signature not verified' % (
            style.paint('REVOKED', 'red', 'bold'), _minute(record.get('time')),
            record.get('reason') or 'no reason given', crl)
    if record.get('status') == 'good':
        return 'Not revoked (%s; CRL signature not verified)' % crl
    why = _REVOCATION_WHY.get(record.get('error') or '', 'the CRL could not be read')
    # the CRL URL comes from the certificate: escaped for the terminal
    return 'Revocation unknown: %s%s' % (why, ' (%s)' % display_text(str(record['crl']))
                                         if record.get('crl') else '')


def render_cert_status(report: ScanReport, style: Style, width: int = 100,
                       show_all: bool = False) -> List[str]:
    """The summary's "Renewal windows and revocation" section (--ari / --revocation): every
    served certificate, revoked ones first, then the windows open or past, then by window."""
    if not report.cert_status:
        return []
    now = report.finished_at
    asked = ' and '.join(what for what, on in (('ARI', report.ari), ('revocation', report.revocation))
                         if on)

    def rank(sha: str) -> Tuple[int, str]:
        entry = report.cert_status[sha]
        if (entry.get('revocation') or {}).get('status') == 'revoked':
            return (0, sha)
        state = window_state(entry.get('ari'), now)
        return ({'past': 1, 'open': 2, 'before': 3}.get(state or '', 4),
                (entry.get('ari') or {}).get('start') or sha)

    shas = sorted(report.cert_status, key=rank)
    limit = len(shas) if show_all else MAX_SUMMARY_CHANGES
    lines = [style.paint('Renewal windows and revocation (%s): %d certificate(s) served' % (
        asked, len(shas)), 'bold')]
    for sha in shas[:limit]:
        cert = report.certificates.get(sha)
        entry = report.cert_status[sha]
        lines.extend(_wrap('  ', 2, cert_line(cert, now, style) if cert else sha, width))
        if 'ari' in entry:
            lines.extend(_wrap('    ', 4, ari_text(entry['ari'], now, style), width))
        if 'revocation' in entry:
            lines.extend(_wrap('    ', 4, revocation_text(entry['revocation'], style), width))
    if len(shas) > limit:
        lines.append(style.paint('  ... and %d more - use --show-all or the --json report to list '
                                 'them.' % (len(shas) - limit), 'dim'))
    lines.append('')
    return lines


# =====================================================================================
# bundle-check: a certificate, its chain, private key and CSR checked before installing
# =====================================================================================
# Files are classified block by block (PEM or DER): certificates (also PKCS#7), private keys
# (PKCS#1, PKCS#8, SEC1; an encrypted one is named and skipped), CSRs and public keys. Keys
# are compared by their public half only: an RSA private key holds n and e, an EC one
# (SEC1 / PKCS#8) usually its public point. Nothing secret is ever printed; a key's PEM is
# kept only to write haproxy.pem when asked. Signatures are not verified: the chain is
# ordered by issuer / subject names and key identifiers, as issued_by() does for the scan.

BUNDLE_OK = 'OK'
BUNDLE_WARN = 'WARN'
BUNDLE_FAIL = 'FAIL'
BUNDLE_SKIPPED = 'SKIPPED'
BUNDLE_STATUSES = (BUNDLE_OK, BUNDLE_WARN, BUNDLE_FAIL, BUNDLE_SKIPPED)
ENCRYPTED_KEY_NOTE = 'encrypted key: cannot check without a password - skipped'
NO_PUBLIC_KEY_NOTE = ('the key file does not hold its public key (EC keys usually do): it '
                      'cannot be compared - skipped')
EDDSA_NO_PUBLIC_KEY_NOTE = ('%s key files usually do not hold the public key, and this tool does '
                            'not derive it: not compared - skipped')
_OID_EXTENSION_REQUEST = '1.2.840.113549.1.9.14'
_KEY_PEM_LABELS = {'PKCS#8': 'PRIVATE KEY', 'PKCS#1': 'RSA PRIVATE KEY', 'SEC1': 'EC PRIVATE KEY'}
CERT_FILE_MAX_BYTES = 10 << 20  # a bundle-check file larger than this is no certificate or key


@dataclass
class PrivateKeyInfo:
    """What bundle-check reads from a private key: its format and public key, never the
    private numbers. ``pem`` (the key as found) only goes into haproxy.pem, never on screen."""

    format: str                      # PKCS#1 | PKCS#8 | SEC1 | encrypted PKCS#8 | encrypted PEM ...
    algorithm: str                   # RSA | EC | Ed25519 | ... | unknown
    public_key: Optional[PublicKey] = None
    encrypted: bool = False
    note: Optional[str] = None       # why there is no public key to compare
    pem: str = field(default='', repr=False)


@dataclass
class CsrInfo:
    """A certificate signing request: who it names and the key it was made for."""

    subject_dn: str
    subject_cn: Optional[str]
    dns_names: List[str]
    public_key: Optional[PublicKey]
    signature_algorithm: str


@dataclass
class BundleItem:
    """One thing found in a bundle-check file (a PEM block, or a DER file)."""

    file: str
    kind: str                        # certificate | private-key | csr | public-key | pkcs12 | unknown
    cert: Optional[CertInfo] = None
    key: Optional[PrivateKeyInfo] = None
    csr: Optional[CsrInfo] = None
    public_key: Optional[PublicKey] = None
    detail: str = ''
    pkcs7: bool = False              # a certificate of a PKCS#7 (.p7b) file: its place says nothing


@dataclass
class BundleCheck:
    """One verdict line: :data:`BUNDLE_STATUSES` status, a topic and what it means."""

    status: str
    topic: str  # key | csr | chain | names | order | root | expiry | other | haproxy
    text: str


@dataclass
class BundleResult:
    """What :func:`check_bundle` found; ``chain`` is the leaf and each issuer found after it
    (a root included when a file holds it)."""

    items: List[BundleItem]
    leaf: Optional[CertInfo]
    chain: List[CertInfo]
    checks: List[BundleCheck]
    key: Optional[BundleItem] = None  # the unencrypted private key that belongs to the leaf
    complete: bool = False           # nothing is missing between the leaf and a trusted root

    @property
    def fullchain(self) -> List[CertInfo]:
        """The leaf and its intermediates, in the order servers send them (no root)."""
        return [cert for cert in self.chain if not (cert.self_signed and cert is not self.leaf)]

    @property
    def intermediates(self) -> List[CertInfo]:
        """The fullchain without the leaf (chain.pem)."""
        return self.fullchain[1:]

    @property
    def failed(self) -> bool:
        """Any FAIL check (exit code 1)."""
        return any(check.status == BUNDLE_FAIL for check in self.checks)


def pem_encode(der: bytes, label: str = 'CERTIFICATE') -> str:
    """``der`` as a PEM block (64-character lines, trailing newline)."""
    b64 = base64.b64encode(der).decode('ascii')
    body = '\n'.join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return '-----BEGIN %s-----\n%s\n-----END %s-----\n' % (label, body, label)


def _bit_string_bytes(buf: bytes, tlv: Tlv) -> bytes:
    """A BIT STRING's bytes after its "unused bits" octet."""
    data = _content(buf, tlv)
    if not data:
        raise DerError('empty BIT STRING')
    return data[1:]


def _rsa_private(der: bytes, fmt: str) -> PrivateKeyInfo:
    """RSAPrivateKey ::= SEQUENCE { version, modulus, publicExponent, privateExponent, ... }:
    only the modulus and the public exponent are read."""
    top = _expect(_read_tlv(der, 0, len(der)), 0x30, 'RSAPrivateKey')
    fields = _children(der, top[2], top[3])
    if len(fields) < 3 or any(item[0] != 0x02 for item in fields[:3]):
        raise DerError('malformed RSAPrivateKey')
    return PrivateKeyInfo(fmt, 'RSA', rsa_public_key(int.from_bytes(_content(der, fields[1]), 'big'),
                                                     int.from_bytes(_content(der, fields[2]), 'big')))


def _sec1_private(der: bytes, fmt: str, curve_oid: Optional[str] = None) -> PrivateKeyInfo:
    """ECPrivateKey ::= SEQUENCE { version 1, privateKey OCTET STRING, [0] parameters
    OPTIONAL, [1] publicKey OPTIONAL }: the curve and the public point, when present."""
    top = _expect(_read_tlv(der, 0, len(der)), 0x30, 'ECPrivateKey')
    fields = _children(der, top[2], top[3])
    if len(fields) < 2 or fields[0][0] != 0x02 or fields[1][0] != 0x04:
        raise DerError('malformed ECPrivateKey')
    point = None  # type: Optional[bytes]
    for item in fields[2:]:
        inner = _children(der, item[2], item[3])
        if item[0] == 0xA0 and inner and inner[0][0] == 0x06:
            curve_oid = _oid(der, inner[0])
        elif item[0] == 0xA1 and inner and inner[0][0] == 0x03:
            point = _bit_string_bytes(der, inner[0])
    if point is None:
        return PrivateKeyInfo(fmt, 'EC', note=NO_PUBLIC_KEY_NOTE)
    return PrivateKeyInfo(fmt, 'EC', ec_public_key(curve_oid, point))


def parse_private_key(der: Union[bytes, bytearray, memoryview]) -> PrivateKeyInfo:
    """The format and public key of a DER private key: PKCS#8 (``PRIVATE KEY``, also
    OneAsymmetricKey with its public key), encrypted PKCS#8, PKCS#1 (``RSA PRIVATE KEY``) or
    SEC1 (``EC PRIVATE KEY``). The private numbers are never kept. Raises
    :class:`DerError` for anything else."""
    buf = bytes(der)
    top = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'private key SEQUENCE')
    fields = _children(buf, top[2], top[3])
    tags = [item[0] for item in fields]
    if tags == [0x30, 0x04]:  # EncryptedPrivateKeyInfo { AlgorithmIdentifier, OCTET STRING }
        return PrivateKeyInfo('encrypted PKCS#8', 'unknown', encrypted=True,
                              note=ENCRYPTED_KEY_NOTE)
    if len(fields) >= 3 and tags[:3] == [0x02, 0x30, 0x04]:  # PrivateKeyInfo / OneAsymmetricKey
        alg = _children(buf, fields[1][2], fields[1][3])
        if not alg:
            raise DerError('empty AlgorithmIdentifier')
        oid = _oid(buf, alg[0])
        family = _KEY_FAMILIES.get(oid, 'unknown')
        inner = _content(buf, fields[2])
        # OneAsymmetricKey (RFC 5958) publicKey [1] IMPLICIT BIT STRING
        outer = next((item for item in fields[3:] if item[0] == 0x81), None)
        if family == 'RSA':
            return _rsa_private(inner, 'PKCS#8')
        if family == 'EC':
            curve_oid = _oid(buf, alg[1]) if len(alg) > 1 and alg[1][0] == 0x06 else None
            info = _sec1_private(inner, 'PKCS#8', curve_oid)
            if info.public_key is None and outer is not None:
                info = PrivateKeyInfo('PKCS#8', 'EC',
                                      ec_public_key(curve_oid, _bit_string_bytes(buf, outer)))
            return info
        if outer is not None and family in ('Ed25519', 'Ed448'):
            key = _bit_string_bytes(buf, outer)
            return PrivateKeyInfo('PKCS#8', family,
                                  PublicKey(family, 256 if family == 'Ed25519' else 456, None,
                                            (oid, key)))
        return PrivateKeyInfo('PKCS#8', family, note=EDDSA_NO_PUBLIC_KEY_NOTE % family
                              if family in ('Ed25519', 'Ed448') else
                              'a %s key: not compared by this tool - skipped' % family)
    if len(fields) >= 9 and all(tag == 0x02 for tag in tags[:9]):
        return _rsa_private(buf[top[1]:top[3]], 'PKCS#1')
    if len(fields) >= 2 and tags[:2] == [0x02, 0x04]:
        return _sec1_private(buf[top[1]:top[3]], 'SEC1')
    if len(fields) == 6 and all(tag == 0x02 for tag in tags):
        return PrivateKeyInfo('DSA', 'DSA', note='a DSA key: not compared by this tool - skipped')
    raise DerError('not a private key this tool reads')


def _general_names(buf: bytes, tlv: Tlv) -> List[str]:
    names = _expect(tlv, 0x30, 'GeneralNames')
    return [_content(buf, item).decode('ascii', 'replace')
            for item in _children(buf, names[2], names[3]) if item[0] == 0x82]


def parse_csr(der: Union[bytes, bytearray, memoryview]) -> CsrInfo:
    """A DER PKCS#10 CertificationRequest: subject, the DNS names of its extensionRequest
    and its public key. The signature is not verified. Raises :class:`DerError`."""
    buf = bytes(der)
    top = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'CertificationRequest')
    parts = _children(buf, top[2], top[3])
    if len(parts) != 3:
        raise DerError('a CertificationRequest has 3 elements, found %d' % len(parts))
    info = _children(buf, *_expect(parts[0], 0x30, 'CertificationRequestInfo')[2:4])
    if len(info) < 3:
        raise DerError('CertificationRequestInfo is missing fields')
    _expect(info[0], 0x02, 'version')
    subject = _parse_name(buf, _expect(info[1], 0x30, 'subject Name'))
    spki = _expect(info[2], 0x30, 'SubjectPublicKeyInfo')
    dns_names = []  # type: List[str]
    for attrs in info[3:]:
        if attrs[0] != 0xA0:
            continue
        for attr in _children(buf, attrs[2], attrs[3]):
            fields = _children(buf, *_expect(attr, 0x30, 'Attribute')[2:4])
            if len(fields) < 2 or _oid(buf, fields[0]) != _OID_EXTENSION_REQUEST:
                continue
            for extensions in _children(buf, fields[1][2], fields[1][3]):
                for ext in _children(buf, *_expect(extensions, 0x30, 'Extensions')[2:4]):
                    ext_parts = _children(buf, *_expect(ext, 0x30, 'Extension')[2:4])
                    if len(ext_parts) >= 2 and _oid(buf, ext_parts[0]) == _OID_SAN:
                        value = _expect(ext_parts[-1], 0x04, 'extnValue')
                        dns_names.extend(_general_names(buf, _read_tlv(buf, value[2], value[3])))
    try:
        public_key = public_key_from_spki(buf[spki[1]:spki[3]])  # type: Optional[PublicKey]
    except _CERT_PARSE_ERRORS:
        public_key = None
    sig = _children(buf, *_expect(parts[1], 0x30, 'signatureAlgorithm')[2:4])
    sig_oid = _oid(buf, sig[0]) if sig else ''
    attrs = _dn_attrs(subject)
    return CsrInfo(_dn_string(subject), attrs.get('CN'), dns_names, public_key,
                   _SIGNATURE_ALGORITHMS.get(sig_oid, sig_oid))


def _der_shape(buf: bytes) -> List[int]:
    """The tags of a DER SEQUENCE's children ([] when ``buf`` is not one)."""
    try:
        top = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'SEQUENCE')
        return [item[0] for item in _children(buf, top[2], top[3])]
    except DerError:
        return []


def _is_csr(buf: bytes) -> bool:
    """A signed structure whose to-be-signed part is { INTEGER, Name, SPKI, [0] }: a CSR."""
    try:
        top = _read_tlv(buf, 0, len(buf))
        info = _children(buf, top[2], top[3])[0]
        return [item[0] for item in _children(buf, info[2], info[3])][:4] == [0x02, 0x30, 0x30,
                                                                             0xA0]
    except (DerError, IndexError):
        return False


def _key_item(name: str, der: bytes, pem: Optional[str] = None) -> BundleItem:
    try:
        key = parse_private_key(der)
    except DerError as exc:
        return BundleItem(name, 'unknown', detail='unreadable private key (%s)' % exc)
    if not key.encrypted and key.format in _KEY_PEM_LABELS:
        key.pem = pem if pem is not None else pem_encode(der, _KEY_PEM_LABELS[key.format])
    return BundleItem(name, 'private-key', key=key)


def _der_items(name: str, der: bytes) -> List[BundleItem]:
    """Items of one DER structure: certificates (also PKCS#7), a CSR, a key or a public key."""
    if _looks_like_pkcs12(der):
        return [BundleItem(name, 'pkcs12', detail=PKCS12_HINT)]
    shape = _der_shape(der)
    if shape == [0x30, 0x30, 0x03] and _is_csr(der):
        try:
            return [BundleItem(name, 'csr', csr=parse_csr(der))]
        except _CERT_PARSE_ERRORS as exc:
            return [BundleItem(name, 'unknown', detail='unreadable CSR (%s)' % exc)]
    if shape == [0x30, 0x03]:
        try:
            return [BundleItem(name, 'public-key', public_key=public_key_from_spki(der))]
        except _CERT_PARSE_ERRORS as exc:
            return [BundleItem(name, 'unknown', detail='unreadable public key (%s)' % exc)]
    if shape[:1] == [0x06] or shape == [0x30, 0x30, 0x03]:
        certs, warnings = [], []  # type: List[CertInfo], List[CertWarning]
        _load_der(der, certs, warnings)
        # A PKCS#7 file keeps its certificates in a DER SET OF, sorted by their encoding: it
        # cannot say in which order they go.
        pkcs7 = shape[:1] == [0x06]
        return ([BundleItem(name, 'certificate', cert=cert, pkcs7=pkcs7) for cert in certs]
                + [BundleItem(name, 'unknown', detail=detail) for _code, detail in warnings])
    return [_key_item(name, der)] if shape else [
        BundleItem(name, 'unknown', detail='not PEM or DER')]


def _pem_items(name: str, label: str, body: str, block: str) -> List[BundleItem]:
    """Items of one PEM block (``block``: the whole block, kept for a key's haproxy.pem)."""
    if 'PRIVATE KEY' in label:
        if 'ENCRYPTED' in label or re.search(r'Proc-Type:\s*4\s*,\s*ENCRYPTED', body):
            return [BundleItem(name, 'private-key', key=PrivateKeyInfo(
                'encrypted PKCS#8' if 'ENCRYPTED' in label else 'encrypted PEM', 'unknown',
                encrypted=True, note=ENCRYPTED_KEY_NOTE))]
        if label == 'OPENSSH PRIVATE KEY':
            return [BundleItem(name, 'unknown', detail='an OpenSSH key (ssh-keygen), not a TLS key')]
    try:
        der = _b64decode(body)
    except (binascii.Error, ValueError) as exc:
        return [BundleItem(name, 'unknown', detail='%s: bad base64 (%s)' % (label, exc))]
    if 'PRIVATE KEY' in label:
        return [_key_item(name, der, re.sub(r'\r\n?', '\n', block).strip() + '\n')]
    if 'CERTIFICATE REQUEST' in label:
        try:
            return [BundleItem(name, 'csr', csr=parse_csr(der))]
        except _CERT_PARSE_ERRORS as exc:
            return [BundleItem(name, 'unknown', detail='unreadable CSR (%s)' % exc)]
    if label == 'RSA PUBLIC KEY':
        try:
            fields = _children(der, *_expect(_read_tlv(der, 0, len(der)), 0x30,
                                             'RSAPublicKey')[2:4])
            return [BundleItem(name, 'public-key', public_key=rsa_public_key(
                int.from_bytes(_content(der, fields[0]), 'big'),
                int.from_bytes(_content(der, fields[1]), 'big')))]
        except (DerError, IndexError) as exc:
            return [BundleItem(name, 'unknown', detail='unreadable RSA public key (%s)' % exc)]
    if label in _CERT_LABELS + ('PKCS7', 'CMS', 'PUBLIC KEY', 'PKCS12', 'PFX'):
        return _der_items(name, der)
    if label == 'EC PARAMETERS':
        return []  # the curve, written before its key by `openssl ecparam -genkey`
    return [BundleItem(name, 'unknown', detail='a PEM block labelled %s' % label)]


def bundle_items(data: Union[bytes, str], name: str) -> List[BundleItem]:
    """Everything in one bundle-check file, in file order: PEM blocks of any kind (text
    around them is ignored), or one DER structure. Never raises for bad input."""
    raw = (data.lstrip('﻿').encode('latin-1', 'replace') if isinstance(data, str)
           else _text_bytes(bytes(data)))
    text = raw.decode('latin-1')
    items = []  # type: List[BundleItem]
    if '-----BEGIN ' in text:
        for match in _PEM_RE.finditer(text):
            items.extend(_pem_items(name, match.group(1), match.group(2), match.group(0)))
    elif raw[:1] == b'\x30':
        items.extend(_der_items(name, raw))
    if not items:
        items.append(BundleItem(name, 'unknown', detail='no certificate, key or CSR found'))
    return items


def _cert_label(cert: CertInfo) -> str:
    return display_text(cert.short_label())


def _key_problem(item: BundleItem) -> Optional[str]:
    """Why a private key cannot be compared (None when it can)."""
    assert item.key is not None
    if item.key.encrypted:
        return ENCRYPTED_KEY_NOTE
    if item.key.public_key is None:
        return item.key.note or 'no public key to compare - skipped'
    return None


def check_bundle(items: Sequence[BundleItem], now: Optional[datetime] = None) -> BundleResult:
    """Classify the leaf, order the chain and check key, CSR and chain together.

    The leaf is the end-entity certificate a private key of the files belongs to, else the
    first one (not a CA, issuing no other certificate of the files). With none, a
    self-signed CA certificate is the leaf when it names hosts in subjectAltName, its key is
    in the files, or its subject CN is a host name and it may not sign certificates (no
    keyUsage keyCertSign, and it issued none of the others - ``openssl req -x509 -subj
    /CN=www.example.com`` makes such a CA:TRUE certificate; a WARN says clients may refuse
    it); files of CA certificates only
    have no leaf (FAIL: the server certificate is missing, nothing is written). Files with
    no certificate at all but a CSR compared with a private key SKIP the chain (a key and
    CSR checked before ordering); with neither it is a FAIL. A leaf without a
    subjectAltName gets a WARN (browsers refuse it). Its chain follows :func:`issued_by`
    (issuer / subject names and key identifiers; signatures are not verified) through the
    other certificates. A leaf nothing issued is a missing intermediate (FAIL) unless it is
    self-signed; a chain that ends at an intermediate whose issuer is not in the files is
    fine (a root clients trust); a root in the files is an extra root (WARN: servers need
    not send it). Files that list chain certificates in another order than servers send
    them get a WARN (not a PKCS#7 file, which holds no order); fullchain.pem is written in
    the right order anyway.
    """
    now = now or _utcnow()
    checks = []  # type: List[BundleCheck]
    certs = []  # type: List[CertInfo]
    where = {}  # type: Dict[str, Tuple[str, int]]  sha256 -> (file, position in all items)
    unordered = set()  # type: Set[str]  sha256 of certificates first found in a PKCS#7 file
    for position, item in enumerate(items):
        if item.cert is not None and item.cert.sha256 not in where:
            where[item.cert.sha256] = (item.file, position)
            certs.append(item.cert)
            if item.pkcs7:
                unordered.add(item.cert.sha256)
    keys = [item for item in items if item.kind == 'private-key']
    csrs = [item for item in items if item.kind == 'csr']

    def has_key(cert: CertInfo) -> bool:
        pk = cert.public_key()
        return pk is not None and any(item.key is not None and item.key.public_key is not None
                                      and item.key.public_key.ident == pk.ident for item in keys)

    def issues(cert: CertInfo) -> bool:
        return any(other is not cert and issued_by(other, cert) for other in certs)

    leaves = [cert for cert in certs if not cert.is_ca and not issues(cert)]
    if not leaves:
        leaves = [cert for cert in certs if cert.is_ca and cert.self_signed
                  and (cert.dns_names or cert.ip_addresses or has_key(cert)
                       or (cert.hostnames and not cert.key_cert_sign and not issues(cert)))]
    leaf = next((cert for cert in leaves if has_key(cert)), leaves[0] if leaves else None)
    leaf_key = leaf.public_key() if leaf is not None else None
    leaf_name = _cert_label(leaf) if leaf is not None else ''

    matching = None  # type: Optional[BundleItem]
    for item in keys:
        problem = _key_problem(item)
        assert item.key is not None
        if problem:
            checks.append(BundleCheck(BUNDLE_SKIPPED, 'key', '%s: %s' % (item.file, problem)))
        elif leaf is None:
            if not csrs:  # else compared with the CSR below
                checks.append(BundleCheck(BUNDLE_SKIPPED, 'key', '%s: no server certificate to '
                                          'compare it with' % item.file))
        elif leaf_key is not None and item.key.public_key.ident == leaf_key.ident:
            matching = matching or item
            checks.append(BundleCheck(BUNDLE_OK, 'key', '%s belongs to the certificate %s (%s)' % (
                item.file, leaf_name, leaf_key.label())))
        else:
            owner = next((cert for cert in certs if cert is not leaf and cert.public_key()
                          and cert.public_key().ident == item.key.public_key.ident), None)
            checks.append(BundleCheck(BUNDLE_FAIL, 'key', (
                '%s belongs to %s, not to the certificate %s' % (item.file, _cert_label(owner),
                                                                 leaf_name)
                if owner is not None else
                '%s does not belong to the certificate %s (the key: %s; the certificate: %s)'
                % (item.file, leaf_name, item.key.public_key.label(),
                   leaf_key.label() if leaf_key else 'unreadable'))))

    csr_with_key = False  # a CSR compared with a private key, there being no certificate
    for item in csrs:
        assert item.csr is not None
        csr_key = item.csr.public_key
        if csr_key is None:
            checks.append(BundleCheck(BUNDLE_SKIPPED, 'csr', '%s: its public key cannot be read'
                                      % item.file))
        elif leaf is not None:
            if leaf_key is not None and csr_key.ident == leaf_key.ident:
                checks.append(BundleCheck(BUNDLE_OK, 'csr', '%s holds the public key of the '
                                          'certificate %s' % (item.file, leaf_name)))
                asked = [normalize_hostname(n, allow_wildcard=True) or n.lower()
                         for n in item.csr.dns_names]
                extra = [n for n in asked if n not in leaf.hostnames]
                if extra:
                    checks.append(BundleCheck(BUNDLE_WARN, 'csr', '%s asks for names the '
                                              'certificate does not have: %s' % (
                                                  item.file, display_text(', '.join(extra)))))
            else:
                checks.append(BundleCheck(BUNDLE_FAIL, 'csr', '%s was made for another key: the '
                                          'certificate %s was not issued from it (or was '
                                          're-keyed since)' % (item.file, leaf_name)))
        else:
            for key in keys:
                if key.key is not None and _key_problem(key) is None:
                    same = key.key.public_key is not None and key.key.public_key.ident == csr_key.ident
                    csr_with_key = True
                    checks.append(BundleCheck(BUNDLE_OK if same else BUNDLE_FAIL, 'csr', (
                        '%s was made with the private key %s' if same else
                        '%s was not made with the private key %s') % (item.file, key.file)))

    chain = []  # type: List[CertInfo]
    complete = False
    if leaf is None and not certs and csr_with_key:
        checks.append(BundleCheck(BUNDLE_SKIPPED, 'chain', 'no certificate in these files: only '
                                  'the private key and the CSR were compared'))
    elif leaf is None:
        checks.append(BundleCheck(BUNDLE_FAIL, 'chain', 'no server certificate in these files, '
                                  'only CA certificates (%s): add the certificate issued for '
                                  'your names' % ', '.join(_cert_label(cert) for cert in certs)
                                  if certs else 'no certificate in these files'))
    else:
        chain = [leaf]
        in_chain = {leaf.sha256}
        current = leaf
        while not current.self_signed:
            issuer = next((cert for cert in certs if cert.sha256 not in in_chain
                           and issued_by(current, cert)), None)
            if issuer is None:
                break
            chain.append(issuer)
            in_chain.add(issuer.sha256)
            current = issuer
        checks.extend(_chain_checks(leaf, chain, now))
        if leaf.is_ca:
            checks.append(BundleCheck(BUNDLE_WARN, 'chain', '%s is marked as a CA (basicConstraints '
                                      'CA:TRUE) but serves as the server certificate: Firefox '
                                      'refuses that (MOZILLA_PKIX_ERROR_CA_CERT_USED_AS_END_ENTITY)'
                                      '; make it again without CA:TRUE' % leaf_name))
        if not leaf.dns_names and not leaf.ip_addresses:
            hint = (' (openssl req: -addext "subjectAltName=DNS:%s")' % display_text(
                leaf.hostnames[0]) if leaf.hostnames else '')
            checks.append(BundleCheck(BUNDLE_WARN, 'names', '%s has no subjectAltName: browsers '
                                      'ignore the subject CN and refuse it for every name; make '
                                      'it again with its names in subjectAltName%s' % (
                                          leaf_name, hint)))
        complete = chain[-1].self_signed or len(chain) > 1
        checks.extend(_order_checks([cert for cert in chain if cert.sha256 not in unordered],
                                    where))
        for cert in certs:
            if cert.sha256 not in in_chain:
                checks.append(BundleCheck(BUNDLE_WARN, 'other', '%s (%s) is not part of the '
                                          'chain of %s: left out' % (
                                              _cert_label(cert), where[cert.sha256][0], leaf_name)))
    return BundleResult(list(items), leaf, chain, checks, matching, complete)


def _chain_checks(leaf: CertInfo, chain: Sequence[CertInfo], now: datetime) -> List[BundleCheck]:
    """Validity of each certificate, the chain as found, a missing intermediate, an extra root."""
    out = []  # type: List[BundleCheck]
    for cert in chain:
        if cert.not_after < now:
            out.append(BundleCheck(BUNDLE_FAIL if cert is leaf else BUNDLE_WARN, 'expiry',
                                   '%s expired on %s' % (_cert_label(cert),
                                                         cert.not_after.strftime('%Y-%m-%d'))))
        elif cert.not_before > now:
            out.append(BundleCheck(BUNDLE_WARN, 'expiry', '%s is not valid before %s' % (
                _cert_label(cert), cert.not_before.strftime('%Y-%m-%d'))))
    path = ' -> '.join(_cert_label(cert) + (' (root)' if cert.self_signed and cert is not leaf
                                            else '') for cert in chain)
    last = chain[-1]
    if leaf.self_signed:
        out.append(BundleCheck(BUNDLE_OK, 'chain', '%s is self-signed: there is no chain to send'
                               % _cert_label(leaf)))
    elif len(chain) == 1:
        hint = (' (the CA publishes it at %s)' % display_text(', '.join(leaf.ca_issuers))
                if leaf.ca_issuers else '')
        out.append(BundleCheck(BUNDLE_FAIL, 'chain', 'missing intermediate: no file holds %s, the '
                               'issuer of %s%s; servers must send it with the certificate - unless '
                               'it is a root your clients already trust (a private CA)' % (
                                   display_text(leaf.issuer_label()), _cert_label(leaf), hint)))
    elif last.self_signed:
        out.append(BundleCheck(BUNDLE_OK, 'chain', path))
        out.append(BundleCheck(BUNDLE_WARN, 'root', 'extra root: %s is a root certificate; servers '
                               'need not send it (clients use their own copy), so fullchain.pem '
                               'and chain.pem leave it out' % _cert_label(last)))
    else:
        out.append(BundleCheck(BUNDLE_OK, 'chain', '%s; %s is issued by %s, not in these files '
                               '(normal for a root the clients trust)' % (
                                   path, _cert_label(last), display_text(last.issuer_label()))))
    return out


def _order_checks(chain: Sequence[CertInfo], where: Dict[str, Tuple[str, int]]
                  ) -> List[BundleCheck]:
    """A file that lists chain certificates in another order than servers send them (the
    leaf first, then each certificate's issuer)."""
    out = []  # type: List[BundleCheck]
    by_file = {}  # type: Dict[str, List[Tuple[int, int, CertInfo]]]
    for rank, cert in enumerate(chain):
        file, position = where[cert.sha256]
        by_file.setdefault(file, []).append((position, rank, cert))
    for file, entries in by_file.items():
        entries.sort(key=lambda entry: entry[0])
        for (_pos, rank, cert), (_next_pos, next_rank, next_cert) in zip(entries, entries[1:]):
            if next_rank < rank:
                out.append(BundleCheck(BUNDLE_WARN, 'order', '%s lists %s before %s; servers send '
                                       'the leaf first, then each certificate\'s issuer '
                                       '(fullchain.pem has that order)' % (
                                           file, _cert_label(cert), _cert_label(next_cert))))
                break
    return out


def _write_secret(path: str, text: str) -> None:
    """Write ``path`` whole or not at all, readable by the owner only where the system has
    modes (a key goes in it)."""
    temp = _temp_path(path)
    try:
        handle = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, 'O_BINARY', 0),
                         0o600)
        with os.fdopen(handle, 'w', encoding='utf-8', newline='') as out:
            out.write(text)
        os.replace(temp, path)
    except OSError as exc:
        _remove_quietly(temp)
        raise UsageError('cannot write %s: %s' % (path, exc.strerror or exc))
    except BaseException:
        _remove_quietly(temp)
        raise


def bundle_outputs(result: BundleResult, haproxy: bool = False) -> List[Tuple[str, str, str]]:
    """``(file name, text, what it holds)`` to write: fullchain.pem (the leaf and its
    intermediates, leaf first), chain.pem (the intermediates, when there are any) and, with
    ``haproxy``, haproxy.pem (fullchain.pem and the private key). Empty when the chain is not
    complete (a missing intermediate) or there is no leaf."""
    if result.leaf is None or not result.complete:
        return []
    full = result.fullchain
    inter = result.intermediates
    what = 'the certificate%s' % (' + %s' % _count_text(len(inter), 'intermediate') if inter else '')
    out = [('fullchain.pem', ''.join(pem_encode(cert.der) for cert in full), what)]
    if inter:
        out.append(('chain.pem', ''.join(pem_encode(cert.der) for cert in inter),
                    _count_text(len(inter), 'intermediate')))
    if haproxy and result.key is not None and result.key.key is not None:
        out.append(('haproxy.pem', out[0][1] + result.key.key.pem,
                    what + ' + the private key'))
    return out


def _item_text(item: BundleItem, now: datetime, style: Style,
               leaf: Optional[CertInfo] = None) -> str:
    """One line about one item: what it is (never key material). A self-signed ``leaf`` is
    labelled so, not as a root, even when it is marked CA:TRUE."""
    if item.cert is not None:
        cert = item.cert
        if leaf is not None and cert.sha256 == leaf.sha256:
            role = 'self-signed' if cert.self_signed else ''
        else:
            role = 'root' if cert.self_signed and cert.is_ca else 'CA' if cert.is_ca else ''
        return 'certificate%s: %s' % (' (%s)' % role if role else '', cert_line(cert, now, style))
    if item.key is not None:
        key = item.key
        if key.encrypted:
            return 'private key: %s' % key.format
        what = key.public_key.label() if key.public_key is not None else key.algorithm
        return 'private key: %s, %s, unencrypted' % (what, key.format)
    if item.csr is not None:
        csr = item.csr
        text = 'CSR: %s' % (display_text(csr.subject_dn) or '(empty subject)')
        if csr.dns_names:
            text += ', names %s' % display_text(' '.join(csr.dns_names[:6])) + (
                ' (+%d)' % (len(csr.dns_names) - 6) if len(csr.dns_names) > 6 else '')
        if csr.public_key is not None:
            text += ', %s' % csr.public_key.label()
        return text
    if item.public_key is not None:
        return 'public key: %s' % item.public_key.label()
    if item.kind == 'pkcs12':
        return 'PKCS#12 bundle: not read here; extract it first: %s' % item.detail
    return 'not used: %s' % display_text(item.detail)


_BUNDLE_STYLES = {BUNDLE_OK: ('green', 'bold'), BUNDLE_WARN: ('yellow', 'bold'),
                  BUNDLE_FAIL: ('red', 'bold'), BUNDLE_SKIPPED: ('dim',)}
BUNDLE_FILE_COLUMN = 32  # file names up to this long share a column with their items


def render_bundle(result: BundleResult, written: Sequence[Tuple[str, str]] = (),
                  color: bool = False, width: int = 100, now: Optional[datetime] = None,
                  notes: Sequence[str] = ()) -> str:
    """The bundle-check report: each file's items, the checks, what was written.

    File names and check texts go through :func:`display_text` (a path or a certificate's
    URL could hold terminal escapes). A file name longer than :data:`BUNDLE_FILE_COLUMN`
    gets a line of its own with its items indented under it."""
    style = Style(color)
    now = now or _utcnow()
    files = list(dict.fromkeys(item.file for item in result.items))
    lines = [style.paint('Bundle check: %s' % _count_text(len(files), 'file'), 'bold')]
    labels = {file: display_text(file) for file in files}
    pad = max((len(label) for label in labels.values() if len(label) <= BUNDLE_FILE_COLUMN),
              default=0)
    for file in files:
        label = labels[file]
        own_line = len(label) > BUNDLE_FILE_COLUMN
        if own_line:
            lines.append('  ' + label)
        for index, item in enumerate(item for item in result.items if item.file == file):
            prefix = ('    ' if own_line else
                      '  %s  ' % (label.ljust(pad) if index == 0 else ' ' * pad))
            lines.extend(_wrap(prefix, len(prefix), _item_text(item, now, style, result.leaf),
                               width))
    lines.append('')
    lines.append(style.paint('Checks', 'bold'))
    label_width = max(len(status) for status in BUNDLE_STATUSES)
    for check in result.checks:
        prefix = '  %s  ' % style.paint(check.status.ljust(label_width),
                                        *_BUNDLE_STYLES[check.status])
        lines.extend(_wrap(prefix, 4 + label_width, display_text(check.text), width))
    for note in notes:
        lines.extend(_wrap('  ', 2, display_text(note), width))
    if written:
        lines.append('')
        lines.append('Written:')
        for path, what in written:
            lines.extend(_wrap('  ', 2, display_text('%s (%s)' % (path, what)), width))
    return '\n'.join(lines) + '\n'


BUNDLE_DESCRIPTION = """\
Check a certificate, its chain, private key and CSR together before installing them - in
any order and format (PEM, DER, P7B; PKCS#1, PKCS#8 and SEC1 keys) - and write the chain
in the order servers send it. Nothing is sent anywhere; nothing secret is printed."""

BUNDLE_EPILOG = """\
checks:
  key      the private key belongs to the certificate (public key compared: RSA modulus
           and exponent, EC point); an encrypted key is skipped (no password is asked),
           an EC key file without its public key is named and skipped
  csr      the CSR holds the certificate's public key (and asks for no other names);
           without a certificate: the CSR was made with the private key (the chain is
           then SKIPPED - a key and CSR checked before ordering the certificate)
  chain    the leaf, then each issuer (subject / issuer names and key identifiers, as
           servers are expected to send them; signatures are not verified): a leaf
           that nothing in the files issued is a missing intermediate (FAIL), CA
           certificates without the server certificate a FAIL, a root in the files an
           extra root (WARN), a file in another order a WARN (not a .p7b, which keeps
           no order), a certificate of another chain is left out
  names    a server certificate without subjectAltName (WARN: browsers refuse it)
  expiry   an expired certificate (the leaf: FAIL) or one not valid yet

bundle-check comes first: python3 ssl_origin_scan.py bundle-check [options] FILE...

output (--out-dir DIR): fullchain.pem (leaf + intermediates, leaf first, no root) and
  chain.pem (the intermediates), written only when the chain is complete; with
  --write-haproxy also haproxy.pem (fullchain.pem + the private key, owner-only on
  Linux / macOS - HAProxy's crt file). Existing files of these names are replaced.

exit codes: 0 every check passed, 1 a check failed (FAIL, or haproxy.pem could not be
            made), 2 usage error, 3 a file could not be written

examples:
  python3 ssl_origin_scan.py bundle-check www.example.com.crt ca-bundle.crt private.key
  python3 ssl_origin_scan.py bundle-check cert.pem chain.pem key.pem request.csr -o out/
  python3 ssl_origin_scan.py bundle-check cert.pem chain.pem key.pem -o /etc/haproxy/certs \\
    --write-haproxy

Türkçe: sertifikayı, zincirini, özel anahtarı ve CSR'ı birlikte denetler (anahtar
sertifikaya ait mi, CSR bu anahtarla mı yapıldı, zincir sırası, eksik ara sertifika,
fazladan kök) ve -o DİZİN ile fullchain.pem ile chain.pem'i doğru sırayla yazar;
--write-haproxy anahtarı da içeren haproxy.pem'i yazar. Hiçbir şey gönderilmez, gizli
hiçbir şey ekrana yazılmaz.
"""


def build_bundle_parser() -> argparse.ArgumentParser:
    """The ``bundle-check`` subcommand's parser (exposed for tests and documentation)."""
    parser = argparse.ArgumentParser(
        prog='%s bundle-check' % PROG, description=BUNDLE_DESCRIPTION, epilog=BUNDLE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('files', metavar='FILE', nargs='+',
                        help='certificate, chain, private key and CSR files (PEM or DER; one '
                             'file may hold several)')
    parser.add_argument('-o', '--out-dir', metavar='DIR',
                        help='write fullchain.pem and chain.pem there (the directory must exist)')
    parser.add_argument('--write-haproxy', action='store_true',
                        help='also write haproxy.pem: fullchain.pem + the private key (needs '
                             '--out-dir; the file holds the key - keep it private)')
    parser.add_argument('--no-color', action='store_true',
                        help='disable colours (also: NO_COLOR environment variable)')
    return parser


def _run_bundle(args: argparse.Namespace) -> int:
    err = sys.stderr
    if args.write_haproxy and not args.out_dir:
        raise UsageError('--write-haproxy needs --out-dir DIR')
    if args.out_dir and not os.path.isdir(args.out_dir):
        raise UsageError('--out-dir: directory does not exist: %s' % args.out_dir)
    items = []  # type: List[BundleItem]
    notes = []  # type: List[str]
    seen = set()  # type: Set[str]
    for path in args.files:
        same = os.path.normcase(os.path.realpath(path))
        if same in seen:
            notes.append('%s was given twice: read once.' % path)
            continue
        seen.add(same)
        try:
            with open(path, 'rb') as handle:
                data = handle.read(CERT_FILE_MAX_BYTES + 1)
        except OSError as exc:
            raise UsageError('cannot read %s: %s' % (path, exc.strerror or exc))
        if len(data) > CERT_FILE_MAX_BYTES:
            raise UsageError('%s is larger than %d MB: not a certificate or key file'
                             % (path, CERT_FILE_MAX_BYTES >> 20))
        items.extend(bundle_items(data, path))
    now = _utcnow()
    result = check_bundle(items, now)
    written, failed = [], []  # type: List[Tuple[str, str]], List[str]
    exit_code = EXIT_NEEDS_UPDATE if result.failed else EXIT_OK
    if args.write_haproxy and result.key is None:
        result.checks.append(BundleCheck(BUNDLE_FAIL, 'haproxy', 'haproxy.pem not written: no '
                                         'unencrypted private key in these files belongs to the '
                                         'certificate'))
        exit_code = EXIT_NEEDS_UPDATE
    if args.out_dir:
        outputs = bundle_outputs(result, haproxy=args.write_haproxy)
        if not outputs:
            notes.append('Nothing written to %s: %s.' % (
                args.out_dir, 'the chain is incomplete (a missing intermediate)'
                if result.leaf is not None else 'no server certificate'
                if any(item.cert is not None for item in result.items) else 'no certificate'))
        for name, text, what in outputs:
            path = os.path.join(args.out_dir, name)
            try:
                if name == 'haproxy.pem':
                    _write_secret(path, text)
                else:
                    _replace_file(path, text)
                written.append((path, what))
            except UsageError as exc:
                print('%s: error: %s' % (PROG, exc), file=err)
                failed.append(path)
        if any(os.path.basename(path) == 'haproxy.pem' for path, _what in written):
            notes.append('haproxy.pem holds the private key: %s; keep it out of backups, tickets '
                         'and repositories.' % ('readable by its owner only (mode 600)'
                                                if os.name != 'nt' else
                                                'restrict who can read it'))
    width = max(60, min(160, shutil.get_terminal_size((100, 24)).columns))
    _write_stdout(render_bundle(result, written, color=use_color(args.no_color, sys.stdout),
                                width=width, now=now, notes=notes))
    if failed:
        return EXIT_OUTPUT_ERROR
    return exit_code


def bundle_main(argv: Sequence[str]) -> int:
    """``ssl_origin_scan.py bundle-check FILE...``; returns the exit code (0, 1, 2 or 3)."""
    parser = build_bundle_parser()
    try:
        args = parser.parse_args(list(argv))
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else EXIT_USAGE
    try:
        return _run_bundle(args)
    except UsageError as exc:
        print('%s bundle-check: error: %s' % (PROG, exc), file=sys.stderr)
        return EXIT_USAGE


# =====================================================================================
# Old versus new server (--compare)
# =====================================================================================

COMPARE_BODY_LIMIT = 1024 * 1024     # body bytes read and hashed per side
COMPARE_EXPIRY_WARN_DAYS = 14        # a new certificate expiring sooner is a warning
COMPARE_FIELDS = ('reach', 'status', 'location', 'content_type', 'title', 'body', 'hsts', 'server',
                  'cert_subject', 'cert_covers', 'cert_trusted', 'cert_issuer', 'cert_expires', 'cert_sha256')
COMPARE_LABELS = {
    'reach': 'reached', 'status': 'HTTP status', 'location': 'Location', 'content_type': 'Content-Type',
    'title': '<title>', 'body': 'body SHA-256', 'hsts': 'HSTS', 'server': 'Server',
    'cert_subject': 'cert names', 'cert_covers': 'cert covers name', 'cert_trusted': 'cert trusted',
    'cert_issuer': 'cert issuer', 'cert_expires': 'cert expires', 'cert_sha256': 'cert SHA-256',
}
COMPARE_CERT_NAMES = 3               # names of a certificate shown before "+N"
COMPARE_NOTES = {
    'new-unreachable': 'the new server did not answer',
    'old-unreachable': 'the old server did not answer: nothing to compare with',
    'both-unreachable': 'neither server answered',
    'new-error-status': 'the new server answers with an error status',
    'dynamic-body': 'a page with a token or a time in it differs on every request',
    'body-cut': 'only the first %d bytes are compared' % COMPARE_BODY_LIMIT,
    'hsts-lost': 'visitors that never saw the header lose HTTPS-only',
    'hsts-off': 'max-age=0: browsers that kept the old header forget it and allow plain HTTP again',
    'hsts-invalid': 'not a valid header (no single usable max-age, or a directive twice): browsers ignore it',
    'hsts-weaker': 'a weaker policy than the old one: a shorter max-age, or includeSubDomains or preload dropped',
    'hsts-new': 'the new server adds HSTS',
    'cert-name': 'the certificate does not cover the name',
    'cert-untrusted': 'not trusted by this machine',
    'cert-untrusted-other': 'not trusted either, but for another reason or from another issuer than the old one: '
                            'a CDN or client that trusts the old certificate may refuse this one',
    'cert-expiring': 'expires within %d days' % COMPARE_EXPIRY_WARN_DAYS,
    'new-cert': 'another certificate (usual on a new server)',
    'same-cert': 'the same certificate',
}
# Certificate problems both servers can share: no difference, so said apart from the verdict.
COMPARE_SHARED = {
    'cert-untrusted': 'Both servers serve a certificate this machine does not trust (the same one, or one from '
                      'the same issuer): no difference between them (an origin CA certificate behind a CDN is '
                      'trusted by the CDN only; --private-ca names your own CA), but a client that reaches '
                      'either server directly refuses it.',
    'cert-name': 'Neither server\'s certificate covers the name: no difference between them (a CDN that '
                 'does not check the name hides it), but a client that reaches either server directly '
                 'refuses it.',
    'cert-expiring': 'Both servers serve a certificate that expires within %d days: no difference between '
                     'them, but renew it on both.' % COMPARE_EXPIRY_WARN_DAYS,
}
_SEVERITY_RANK = {'ok': 0, 'info': 1, 'warn': 2, 'error': 3}
_TITLE_RE = re.compile(rb'<title\b[^>]*>(.*?)</title\s*>', re.I | re.S)


@dataclass
class CompareSide:
    """What one address answered for the name (``--compare``)."""
    ip: str
    port: int
    failure: Optional[str] = None       # TIMEOUT / CLOSED / TLS_ERROR / HTTP_ERROR
    detail: str = ''
    cert: Optional[CertInfo] = None
    covers: Optional[bool] = None
    trusted: Optional[bool] = None
    trust_detail: str = ''
    tls_version: Optional[str] = None
    status: Optional[int] = None
    location: Optional[str] = None
    content_type: Optional[str] = None
    server: Optional[str] = None
    hsts: Optional[str] = None
    body_sha256: Optional[str] = None
    body_bytes: int = 0
    body_truncated: bool = False
    title: Optional[str] = None
    chain_length: Optional[int] = None  # the certificates the server sent (Python 3.10+), else None

    @property
    def ok(self) -> bool:
        """The server gave an HTTP answer."""
        return self.status is not None

    def to_dict(self, now: Optional[datetime] = None) -> Dict[str, Any]:
        """JSON-friendly (camelCase keys, the certificate as in the scan reports)."""
        return {
            'ip': self.ip, 'port': self.port, 'failure': self.failure, 'detail': self.detail,
            'status': self.status, 'location': self.location, 'contentType': self.content_type,
            'server': self.server, 'hsts': self.hsts, 'title': self.title,
            'body': ({'sha256': self.body_sha256, 'bytes': self.body_bytes, 'truncated': self.body_truncated}
                     if self.body_sha256 else None),
            'tlsVersion': self.tls_version,
            'certificate': self.cert.to_dict(now) if self.cert else None,
            'certCovers': self.covers, 'certTrusted': self.trusted, 'trustDetail': self.trust_detail,
            'chainLength': self.chain_length,
        }


def page_title(body: bytes, charset: Optional[str] = None) -> Optional[str]:
    """The first ``<title>`` of an HTML body: whitespace collapsed, the common entities
    decoded, at most 200 characters (the web app's pageTitle)."""
    match = _TITLE_RE.search(body)
    if not match:
        return None
    try:
        text = match.group(1).decode(charset or 'utf-8', 'replace')
    except LookupError:
        text = match.group(1).decode('utf-8', 'replace')

    def numeric(m: 're.Match[str]', base: int) -> str:
        value = int(m.group(1), base)
        if 0xD800 <= value <= 0xDFFF:
            return '�'   # a UTF-16 surrogate, as HTML reads it: never written as UTF-8
        return chr(value) if 0 < value < 0x110000 else m.group(0)

    text = re.sub(r'&#(\d{1,6});', lambda m: numeric(m, 10), text)
    text = re.sub(r'&#x([0-9a-fA-F]{1,6});', lambda m: numeric(m, 16), text)
    for entity, char in (('&quot;', '"'), ('&#39;', "'"), ('&apos;', "'"), ('&lt;', '<'), ('&gt;', '>'),
                         ('&nbsp;', ' '), ('&amp;', '&')):
        text = text.replace(entity, char)
    text = ' '.join(text.split())
    return text[:200] or None


def cert_names_text(cert: CertInfo, limit: int = COMPARE_CERT_NAMES) -> str:
    """The names a certificate carries, for a side-by-side line: the subject CN first, then the
    SAN host names not already listed (case-insensitive), the first ``limit`` and ``+N`` for the
    rest (the web app's certNames)."""
    names = []  # type: List[str]
    seen = set()
    for name in [cert.subject_cn or ''] + list(cert.hostnames):
        name = name.strip().rstrip('.')
        if name and name.lower() not in seen:
            seen.add(name.lower())
            names.append(name)
    if not names:
        return cert.short_label()
    more = len(names) - limit
    return ', '.join(names[:limit]) + (' +%d' % more if more > 0 else '')


def _charset(content_type: Optional[str]) -> Optional[str]:
    match = re.search(r'charset="?([A-Za-z0-9._-]+)', content_type or '')
    return match.group(1) if match else None


def fetch_side(ip: str, port: int, name: str, path: str, timeout: float,
               private_cas: Sequence[CertInfo] = ()) -> CompareSide:
    """One TLS connection to ``ip:port`` with SNI ``name`` (whatever certificate is served:
    :func:`make_client_context`), one ``GET path`` over it with ``Host: name`` (http.client on
    that socket), then one verifying handshake (the system's trust store and the host name;
    a certificate issued by a ``--private-ca`` counts as trusted)."""
    side = CompareSide(ip, port)
    address = _connect_address(ip)
    sock = None  # type: Optional[socket.socket]
    connected = False
    try:
        sock = socket.create_connection((address, port), timeout=timeout)
        connected = True
        tls = make_client_context().wrap_socket(sock, server_hostname=name, do_handshake_on_connect=False)
        sock = tls
        tls.settimeout(timeout)
        tls.do_handshake()
        der = tls.getpeercert(binary_form=True)
        side.tls_version = tls.version()
        # The certificates the server sent: public on Python 3.13+, on the private _sslobj since 3.10.
        unverified = (getattr(tls, 'get_unverified_chain', None)
                      or getattr(getattr(tls, '_sslobj', None), 'get_unverified_chain', None))
        if unverified is not None:
            try:
                sent = unverified()
                side.chain_length = len(sent) if sent else None
            except (ssl.SSLError, ValueError, TypeError):
                side.chain_length = None
        if der:
            try:
                side.cert = parse_certificate(der)
                side.covers = side.cert.covers(name)[0]
            except _CERT_PARSE_ERRORS:
                side.detail = 'the certificate could not be read'
        conn = http.client.HTTPConnection(name, port, timeout=timeout)
        conn.sock = tls  # the request goes over this TLS connection, never a new one
        host = name if port == 443 else '%s:%d' % (name, port)
        conn.request('GET', path, headers={'Host': host, 'User-Agent': _USER_AGENT, 'Accept': '*/*',
                                           'Accept-Encoding': 'identity', 'Connection': 'close'})
        response = conn.getresponse()
        body = response.read(COMPARE_BODY_LIMIT + 1)
        side.status = response.status
        side.location = response.getheader('Location')
        side.content_type = response.getheader('Content-Type')
        side.server = response.getheader('Server')
        side.hsts = response.getheader('Strict-Transport-Security')
        side.body_truncated = len(body) > COMPARE_BODY_LIMIT
        body = body[:COMPARE_BODY_LIMIT]
        side.body_bytes = len(body)
        side.body_sha256 = hashlib.sha256(body).hexdigest()
        side.title = page_title(body, _charset(side.content_type))
    except http.client.HTTPException as exc:
        side.failure, side.detail = 'HTTP_ERROR', 'no HTTP answer: %s' % (type(exc).__name__)
    except Exception as exc:  # noqa: BLE001 - every failure becomes a status
        classify = classify_exception if connected else classify_connect_exception
        side.failure, side.detail = classify(exc)
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if side.cert is not None:
        side.trusted, side.trust_detail = _verify_side(address, port, name, timeout, side.cert, private_cas)
    return side


def _verify_side(address: str, port: int, name: str, timeout: float, cert: CertInfo,
                 private_cas: Sequence[CertInfo]) -> Tuple[Optional[bool], str]:
    """``(trusted, detail)`` from a verifying handshake; None when it could not be made."""
    context = ssl.create_default_context()
    try:
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=name):
                return True, ''
    except ssl.SSLCertVerificationError as exc:
        detail = getattr(exc, 'verify_message', '') or _clean_ssl_message(exc)
        if cert.covers(name)[0] and any(issued_by(cert, ca) for ca in private_cas):
            # OpenSSL names only the unknown issuer: the dates are checked here, as for a public one
            now = _utcnow()
            if cert.not_after < now:
                return False, 'certificate has expired'
            if cert.not_before > now:
                return False, 'certificate is not yet valid'
            return True, 'issued by a --private-ca'
        return False, detail
    except (OSError, ssl.SSLError) as exc:
        return None, _clean_ssl_message(exc)


_HSTS_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_HSTS_VALUE = re.compile(r"""^(?:[!#$%&'*+.^_`|~0-9A-Za-z-]+|"[^"]*")$""")


def hsts_policy(value: Optional[str]) -> Optional[Tuple[Optional[int], bool, bool, bool]]:
    """A Strict-Transport-Security header as a browser reads it (RFC 6797 6.1, 8.1):
    ``(max-age, includeSubDomains, preload, valid)``, or None without one (the web app's
    parseHsts). Several header fields joined with ',' count as the first one alone. The header
    is valid only with exactly one max-age of digits (quoted or not), no directive twice, a
    valueless includeSubDomains and every directive a token (its value a token or a quoted
    string): a browser ignores any other header, so max-age is then None. ``preload`` is the
    bare directive (the preload list's rule)."""
    if not value or not value.strip():
        return None
    valid, age, include, preload = True, None, False, False  # type: bool, Optional[int], bool, bool
    seen = set()
    for part in value.strip().split(',')[0].split(';'):
        directive = part.strip()
        if not directive:
            continue
        match = re.match(r'^([^=\s]+)\s*(?:=\s*(.*))?$', directive)
        name = match.group(1).lower() if match else ''
        val = match.group(2).strip() if match and match.group(2) is not None else None
        if (not match or not _HSTS_TOKEN.match(name) or name in seen
                or (val is not None and not _HSTS_VALUE.match(val))):
            valid = False
            continue
        seen.add(name)
        if name == 'max-age':
            number = re.match(r'^(?:(\d+)|"(\d+)")$', val) if val is not None else None
            if number:
                age = int(number.group(1) or number.group(2))
            else:
                valid = False
        elif name == 'includesubdomains':
            if val is None:
                include = True
            else:
                valid = False
        elif name == 'preload':
            preload = val is None
    if age is None:
        valid = False
    return (age if valid else None), include, preload, valid


def _compare_field(key: str, old: Any, new: Any, severity: str, note: Optional[str] = None,
                   shared: Optional[bool] = None, same: Optional[bool] = None) -> Dict[str, Any]:
    """One compared field: 'ok' when both agree, unless its note is a certificate problem both
    servers share (``shared``: a 'warn' the verdict leaves out; the caller can say it itself, and
    ``same``: two untrusted certificates from different issuers do not agree)."""
    if same is None:
        same = old == new
    if shared is None:
        shared = same and note in COMPARE_SHARED
    return {'key': key, 'old': old, 'new': new, 'same': same,
            'severity': 'warn' if shared else 'ok' if same else severity, 'note': note, 'shared': shared}


def _shared_untrust(a: CompareSide, b: CompareSide, now: datetime) -> bool:
    """Whatever trusts one of two untrusted certificates also trusts the other (the web app's
    sharedUntrust): the same certificate; or, when the new one is valid by now, the same failure
    (this machine's verify message; a new leaf sent alone where the old server sent its chain,
    which Python 3.10+ reports, fails otherwise) from the same issuer when neither is self-signed - both Cloudflare Origin CA certificates (Cloudflare
    trusts its RSA and ECC origin CAs alike), else the same issuer DN as issued_by compares it
    and, when both carry one, the same authority key id (a re-created CA of the same name is
    another CA)."""
    ca, cb = a.cert, b.cert
    if ca is None or cb is None:
        return False
    if ca.sha256 == cb.sha256:
        return True
    if cb.not_before > now >= ca.not_before:
        return False
    if a.trust_detail != b.trust_detail or ca.self_signed or cb.self_signed:
        return False
    # Python stops at the first verify error, so a leaf sent without its intermediate reads like
    # the old chain; the certificates each server sent (Python 3.10+) tell them apart.
    if b.chain_length == 1 and (a.chain_length or 0) > 1:
        return False
    if is_origin_ca_certificate(ca) and is_origin_ca_certificate(cb):
        return True
    if not _dn_key(ca.issuer_dn) or _dn_key(ca.issuer_dn) != _dn_key(cb.issuer_dn):
        return False
    return not (ca.authority_key_id and cb.authority_key_id and ca.authority_key_id != cb.authority_key_id)


def compare_sides(a: CompareSide, b: CompareSide, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Field by field, with the web app's rules (lib/origincompare.js compareSides): the new
    server not answering, answering 4xx / 5xx where the old one did not, or a certificate
    that does not cover the name or is not trusted (while the old one was) is an error;
    another status, redirect, content type or title, a lost HSTS header (none, one browsers
    ignore, max-age=0, a shorter max-age, or without the old one's includeSubDomains or
    preload: :func:`hsts_policy`) or a certificate expiring within 14 days a warning; another
    body, Server header or certificate (its names, issuer, expiry, fingerprint) is
    information. A certificate problem both servers share (an untrusted certificate, the same
    one or failing alike from the same issuer: :func:`_shared_untrust`; neither covering the
    name; both expiring soon with the new one no sooner) is no difference: the field is
    ``shared``, its note is listed in ``shared`` and the verdict leaves it out; any other
    untrusted certificate after an untrusted one is a warning (``cert-untrusted-other``).
    Verdict: unreachable (neither server answered: this machine's network may be the cause as
    much as the servers), broken, incomplete (the old server did not answer), differs, same."""
    now = now or _utcnow()
    fields = []  # type: List[Dict[str, Any]]
    note, severity = None, 'ok'  # type: Optional[str], str
    if not b.ok and a.ok:
        note, severity = 'new-unreachable', 'error'
    elif not b.ok and not a.ok:
        note, severity = 'both-unreachable', 'warn'
    elif b.ok and not a.ok:
        note, severity = 'old-unreachable', 'info'
    fields.append({'key': 'reach', 'old': 'yes' if a.ok else (a.failure or 'no'),
                   'new': 'yes' if b.ok else (b.failure or 'no'), 'same': a.ok == b.ok,
                   'severity': severity, 'note': note})
    # The HTTP fields only when the new server answered (a failure says it all); without an
    # answer from the old one there is nothing to compare with: differences are information.
    if b.ok:
        warn = 'warn' if a.ok else 'info'

        def bad(status: Optional[int]) -> bool:
            return status is not None and status >= 400
        status_sev = 'error' if bad(b.status) and not (a.ok and bad(a.status)) else warn
        fields.append(_compare_field('status', a.status, b.status, status_sev,
                                     'new-error-status' if status_sev == 'error' and a.status != b.status else None))
        fields.append(_compare_field('location', a.location, b.location, warn))
        fields.append(_compare_field('content_type', a.content_type, b.content_type, warn))
        fields.append(_compare_field('title', a.title, b.title, warn))
        cut = a.body_truncated or b.body_truncated
        same_body = a.body_sha256 == b.body_sha256
        fields.append(_compare_field('body', a.body_sha256, b.body_sha256, 'info',
                                     ('body-cut' if cut else None) if same_body else 'dynamic-body'))
        hsts_note, hsts_sev = None, 'info'  # type: Optional[str], str
        old_hsts, new_hsts = hsts_policy(a.hsts), hsts_policy(b.hsts)

        def on(policy: Optional[Tuple[Optional[int], bool, bool, bool]]) -> bool:
            # One valid max-age above 0 (max-age=0 tells a browser to forget the policy; an
            # invalid header is ignored): no HSTS to keep, or to lose, otherwise.
            return policy is not None and policy[3] and (policy[0] or 0) > 0
        if on(old_hsts):
            if new_hsts is None:
                hsts_note, hsts_sev = 'hsts-lost', warn
            elif not new_hsts[3]:
                hsts_note, hsts_sev = 'hsts-invalid', warn
            elif new_hsts[0] == 0:
                hsts_note, hsts_sev = 'hsts-off', warn
            elif ((old_hsts[1] and not new_hsts[1]) or (old_hsts[2] and not new_hsts[2])
                  or (new_hsts[0] or 0) < (old_hsts[0] or 0)):
                hsts_note, hsts_sev = 'hsts-weaker', warn
        elif on(new_hsts):
            hsts_note = 'hsts-new'
        fields.append(_compare_field('hsts', a.hsts, b.hsts, hsts_sev, hsts_note))
        fields.append(_compare_field('server', a.server, b.server, 'info'))
    ca, cb = a.cert, b.cert
    if cb is not None:  # the certificate fields come with a certificate from the new server
        fields.append(_compare_field('cert_subject', cert_names_text(ca) if ca else None, cert_names_text(cb), 'info'))
        wrong_name = not b.covers
        fields.append(_compare_field('cert_covers', a.covers, b.covers, 'error' if wrong_name else 'info',
                                     'cert-name' if wrong_name else None))
        untrusted = b.trusted is False
        if untrusted and ca is not None and a.trusted is False and not _shared_untrust(a, b, now):
            # Both untrusted, but for another reason or from another issuer: whatever trusts the
            # old one (a CDN that knows its origin CA, clients that know an internal CA) may
            # refuse the new one.
            fields.append(_compare_field('cert_trusted', a.trusted, b.trusted, 'warn', 'cert-untrusted-other',
                                         same=False))
        else:
            fields.append(_compare_field('cert_trusted', a.trusted, b.trusted,
                                         ('error' if a.trusted else 'warn') if untrusted else 'info',
                                         'cert-untrusted' if untrusted else None))
        fields.append(_compare_field('cert_issuer', ca.issuer_label() if ca else None,
                                     cb.issuer_label() if cb else None, 'info'))
        soon = cb.days_left(now) < COMPARE_EXPIRY_WARN_DAYS
        old_day = ca.not_after.strftime('%Y-%m-%d') if ca else None
        new_day = cb.not_after.strftime('%Y-%m-%d')
        # Both expire soon, the new one no sooner: renew both, but the move changes nothing there.
        both_soon = soon and ca is not None and (old_day == new_day or (
            ca.days_left(now) < COMPARE_EXPIRY_WARN_DAYS and cb.not_after >= ca.not_after))
        fields.append(_compare_field('cert_expires', old_day, new_day, 'warn' if soon else 'info',
                                     'cert-expiring' if soon else None, both_soon))
        same_cert = bool(ca and cb and ca.sha256 == cb.sha256)
        fields.append(_compare_field('cert_sha256', ca.sha256 if ca else None, cb.sha256 if cb else None, 'info',
                                     'same-cert' if same_cert else ('new-cert' if ca and cb else None)))
    worst = 'ok'  # of the fields that count: a problem both servers share is said apart
    for item in fields:
        if not item.get('shared') and _SEVERITY_RANK[item['severity']] > _SEVERITY_RANK[worst]:
            worst = item['severity']
    if not a.ok and not b.ok:
        verdict = 'unreachable'
    elif worst == 'error':
        verdict = 'broken'
    elif not a.ok:
        verdict = 'incomplete'
    elif worst == 'warn':
        verdict = 'differs'
    else:
        verdict = 'same'
    return {'verdict': verdict, 'worst': worst, 'fields': fields,
            'differences': sum(1 for item in fields if not item['same']),
            'shared': [item['note'] for item in fields if item.get('shared')]}


def _compare_value(key: str, value: Any, side: CompareSide, now: datetime) -> str:
    if key == 'cert_trusted' and value is False:
        return 'no: %s' % (side.trust_detail or 'not trusted')
    if value is None:
        return '-'
    if key == 'body':
        return '%s... (%d bytes%s)' % (str(value)[:16], side.body_bytes, ', cut' if side.body_truncated else '')
    if key == 'cert_sha256':
        return '%s...' % str(value)[:16]
    if key == 'cert_expires' and side.cert:
        return '%s (%d days)' % (value, side.cert.days_left(now))
    if isinstance(value, bool):
        return 'yes' if value else 'no'
    if key == 'reach' and value != 'yes' and side.detail:
        return '%s: %s' % (value, side.detail)
    return str(value)


def render_compare(name: str, path: str, a: CompareSide, b: CompareSide, result: Dict[str, Any],
                   color: bool = False, width: int = 100, now: Optional[datetime] = None) -> str:
    """The side-by-side table: one line per field, the differences marked."""
    now = now or _utcnow()
    style = Style(color)
    col = max(16, (width - 32) // 2)

    def fit(text: str) -> str:
        return text if len(text) <= col else text[:col - 3] + '...'

    lines = ['Comparing %s on %s (old) and %s (new), port %d, GET %s' % (
        display_text(name), a.ip, b.ip, a.port, display_text(path)), '']
    lines.append('  %-18s %s %s' % ('', fit('old ' + a.ip).ljust(col), fit('new ' + b.ip)))
    # A difference is ERROR, DIFFERS (warning) or differs (information); a problem both servers
    # share (the same untrusted certificate, one expiring soon on both) or neither answering is
    # WARNING: no difference.
    marks = {('error', False): ('ERROR', ('red', 'bold')), ('error', True): ('ERROR', ('red', 'bold')),
             ('warn', False): ('DIFFERS', ('yellow', 'bold')), ('warn', True): ('WARNING', ('yellow', 'bold')),
             ('info', False): ('differs', ('gray',))}
    for item in result['fields']:
        old = fit(display_text(_compare_value(item['key'], item['old'], a, now)))
        new = fit(display_text(_compare_value(item['key'], item['new'], b, now)))
        mark = ''
        key = (item['severity'], bool(item['same'] or item.get('shared')))
        if key in marks:
            label, styles = marks[key]
            mark = style.paint(label, *styles)
        lines.append(('  %-18s %s %s  %s' % (COMPARE_LABELS[item['key']], old.ljust(col), new.ljust(col), mark)).rstrip())
        if item['note'] and item['note'] not in ('same-cert', 'body-cut'):
            lines.append('  %-18s %s' % ('', style.paint('^ ' + COMPARE_NOTES[item['note']], 'dim')))
    verdict = result['verdict']
    text = {
        'same': 'The new server answers like the old one (only informational differences).',
        'differs': 'The new server answers differently: check the fields marked DIFFERS before you move the name.',
        'broken': 'The new server is not ready: fix the fields marked ERROR before you move the name.',
        'incomplete': 'The old server did not answer, so there is nothing to compare with; the new one is shown.',
        'unreachable': 'Neither server answered: this machine\'s network (a firewall, a VPN, a route) may be the '
                       'cause as much as the servers. Check the addresses and the port, then compare again.',
    }[verdict]
    verdict_style = {'same': ('green', 'bold'), 'differs': ('yellow', 'bold'), 'broken': ('red', 'bold'),
                     'unreachable': ('yellow', 'bold')}.get(verdict, ('bold',))
    lines.append('')
    lines.append('%s: %s' % (style.paint(verdict.upper(), *verdict_style), text))
    for note in result.get('shared', []):
        lines.append('%s: %s' % (style.paint('WARNING', 'yellow', 'bold'), COMPARE_SHARED[note]))
    return '\n'.join(lines) + '\n'


def compare_to_dict(name: str, path: str, a: CompareSide, b: CompareSide, result: Dict[str, Any],
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """The ``--compare --json`` report (schema ``domainscope.compare/1``)."""
    return {
        'schema': 'domainscope.compare/1', 'tool': {'name': PROG, 'version': __version__},
        'generatedAt': iso_utc(now or _utcnow()), 'name': name, 'path': path,
        'old': a.to_dict(now), 'new': b.to_dict(now), 'verdict': result['verdict'],
        'shared': result.get('shared', []), 'fields': result['fields'],
    }


def _run_compare(args: argparse.Namespace) -> int:
    """``--compare OLD NEW -n NAME``: the same GET against both addresses, side by side."""
    unsupported = [flag for flag, used in (
        ('-t/--targets', args.targets), ('--exclude', args.exclude), ('--cert', args.cert), ('--csv', args.csv),
        ('--baseline', args.baseline), ('--warn-days', args.warn_days is not None), ('--notify', args.notify),
        ('--strict-public', args.strict_public), ('--fail-on-needs-update', args.fail_on_needs_update),
        ('--estate', args.estate), ('--include-backends', args.include_backends),
        ('--profile', args.profile), ('--ari', args.ari), ('--revocation', args.revocation)) if used]
    if unsupported:
        raise UsageError('--compare does not take %s' % ', '.join(unsupported))
    ips = []
    for value in args.compare:
        ip = normalize_ip(value.strip().strip('[]'))
        if ip is None:
            raise UsageError('--compare takes two IP addresses, not %r' % value)
        ips.append(ip)
    if ips[0] == ips[1]:
        raise UsageError('--compare: the old and the new address are the same')
    names, _warnings = load_names(args.names)
    if len(names) != 1 or names[0].startswith('*'):
        raise UsageError('--compare needs exactly one host name: -n www.example.com')
    ports = parse_ports(args.ports if args.ports is not None else DEFAULT_PORTS)
    if len(ports) != 1:
        raise UsageError('--compare takes one port (-p 443)')
    if port_protocols(ports).get(ports[0], PROTO_TLS) != PROTO_TLS:
        raise UsageError('--compare sends an HTTPS request: -p takes a port without a STARTTLS '
                         'protocol')
    path = args.path or '/'
    if not re.match(r'^/[\x21-\x7e]*$', path):
        raise UsageError('--path must start with "/" and hold printable ASCII only')
    if not (args.timeout > 0 and args.timeout <= MAX_TIMEOUT):
        raise UsageError('--timeout must be > 0 and <= %d seconds' % MAX_TIMEOUT)
    _check_output_path(args.json, '--json')
    private_cas, ca_messages = load_private_cas(args.private_ca)
    if not args.quiet:
        for message in ca_messages:
            print('warning: %s' % display_text(message), file=sys.stderr)
        print('Comparing %s on %s and %s ...' % (names[0], ips[0], ips[1]), file=sys.stderr)
    now = _utcnow()
    old = fetch_side(ips[0], ports[0], names[0], path, args.timeout, private_cas)
    new = fetch_side(ips[1], ports[0], names[0], path, args.timeout, private_cas)
    result = compare_sides(old, new, now)
    failed = False
    if args.json:
        text = json.dumps(compare_to_dict(names[0], path, old, new, result, now), indent=2,
                          ensure_ascii=args.json == '-' and not _stream_is_utf8(sys.stdout)) + '\n'
        try:
            _write_output(args.json, text)
        except UsageError as exc:
            print('%s: error: %s' % (PROG, exc), file=sys.stderr)
            failed = True
    if args.json != '-':
        width = max(60, min(160, shutil.get_terminal_size((100, 24)).columns))
        _write_output('-', render_compare(names[0], path, old, new, result,
                                          color=use_color(args.no_color, sys.stdout), width=width, now=now))
    if failed:
        return EXIT_OUTPUT_ERROR
    if args.fail_on_change and result['verdict'] in ('differs', 'broken', 'unreachable'):
        return EXIT_CHANGED
    return EXIT_OK


# =====================================================================================
# Command line
# =====================================================================================

DESCRIPTION = """\
Find which of your servers serve a TLS certificate for given hostnames - and which of
them still need the new (renewed) certificate - by connecting to every server IP
directly and asking for each hostname via SNI. Because it talks to your servers' own
IPs it sees through Cloudflare / CDN proxies. Run it from a machine inside your network
(e.g. a jump host). Python 3.8+, standard library only."""

EPILOG = """\
examples:
  Renewal day - which servers still serve the old certificate?
    python3 ssl_origin_scan.py -t servers.txt --cert new-cert.pem

  Names exported from the web app, on ports 443 and 8443:
    python3 ssl_origin_scan.py -t targets.txt -n names.txt --cert new-cert.pem -p 443,8443

  Machine-readable reports (JSON for scripts, CSV with BOM for Excel):
    python3 ssl_origin_scan.py -t targets.txt --cert new.pem --json report.json --csv report.csv

  A subnet and two names, no certificate (just "who hosts these?"):
    python3 ssl_origin_scan.py -t 10.0.0.0/24 -n www.example.com api.example.com

  The same sweep, leaving one address and a /28 alone (never connected to):
    python3 ssl_origin_scan.py -t 10.0.0.0/24 --exclude 10.0.0.5 10.0.0.64/28 -n www.example.com

  CI / cron - exit code 1 while any server still needs the new certificate:
    python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --fail-on-needs-update --no-color

  Renewal week - an RSA + ECDSA pair and another certificate, checked in one run:
    python3 ssl_origin_scan.py -t hosts.ini --cert a-rsa.pem --cert a-ecdsa.pem --cert b.pem

  Internal hosts signed by your own CA are PRIVATE_CERT, not NEEDS_UPDATE:
    python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --private-ca internal-ca.pem

  Every certificate your servers serve (no --cert needed), as a CSV inventory:
    python3 ssl_origin_scan.py -t hosts.ini -n names.txt --estate --csv estate.csv

  Mail and database servers: SMTP on 25 and 587 with STARTTLS, IMAPS on 993, PostgreSQL
  on 5432 and SMTP on 2525 too (the protocol follows the port; PORT/PROTOCOL names it):
    python3 ssl_origin_scan.py -t mail.txt --cert new.pem -p 25,587,993,5432,2525/smtp

  A TLS audit: TLS 1.0 / 1.1 still accepted, weak cipher suites, RSA + ECDSA pairs, broken
  chains, a server of a pool still serving last year's certificate:
    python3 ssl_origin_scan.py -t hosts.ini -n names.txt --tls-audit --json audit.json

  Every port a mail server uses (25, 587, 465, 143, 993, 110, 995), or every port the scan
  supports (web, mail, FTP, LDAP, XMPP, PostgreSQL, RDP), with the audit:
    python3 ssl_origin_scan.py -t mail.txt --cert new.pem --profile mail
    python3 ssl_origin_scan.py -t hosts.ini -n names.txt --profile all --tls-audit

  What the CAs say about every certificate your servers serve: the renewal window
  (ARI) and the revocation list, compared with last night's run:
    python3 ssl_origin_scan.py -t hosts.ini -n names.txt --estate --ari --revocation \\
      --baseline estate.json --json estate.json

  Before installing - the certificate, its chain, key and CSR checked together, and
  fullchain.pem / chain.pem written in the order servers send them:
    python3 ssl_origin_scan.py bundle-check cert.pem ca-bundle.crt private.key -o out/
    (python3 ssl_origin_scan.py bundle-check --help for every check)

  Cron - compare every run with the previous one, warn 21 days before a served
  certificate expires, post to a chat webhook only when there is something to say
  (the summary goes to a file, so cron mails only errors):
    export DOMAINSCOPE_NOTIFY_URL='https://hooks.slack.com/services/...'
    python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --baseline last.json \\
      --json last.json --warn-days 21 -q > last.txt

  Before DNS moves a name to a new server: does the new one answer like the old one?
    python3 ssl_origin_scan.py --compare 10.0.0.5 10.0.0.6 -n www.example.com --path /healthz

targets (-t, repeatable):
  an IP, hostname, CIDR (10.0.0.0/24), range (10.0.0.10-10.0.0.50 or 10.0.0.10-50),
  NAME=IP, "-" for stdin, or a file (format auto-detected):
    "name ip [ip...]" / "ip name" lines, /etc/hosts, CSV/TSV with a header row
    (name/hostname/server + ip/public_ip/private_ip/ipv4/ipv6/address columns, Turkish
    headers too; gateway, DNS, NTP, iLO/iDRAC/IPMI/BMC, MAC and e-mail columns are not
    server addresses),
    Ansible INI (web01 ansible_host=10.0.0.5, [groups]), simple Ansible YAML, JSON.
  Entries without an IP are resolved with the system resolver (IPv4 and IPv6).
  An address or hostname written with a port - 10.0.0.5:8443, [2001:db8::5]:8443,
  web01.example.com:8443, "web01 10.0.0.5:8443" in a file - is scanned on that port
  instead of -p; -p applies to every target written without one (list a target twice,
  with and without the port, to get both). IPv6 needs the brackets. A port that is not
  1-65535 is an error on the command line and a warning in a file; a CIDR or range
  takes no port. Next to an address on the same line, a hostname with a port is a
  warning, not a target: write the address with the port.
  In an Ansible INI inventory (a line under a [group] header or with ansible_* variables)
  a port on the host at the start of the line - 10.0.0.5:2222, [2001:db8::5]:2222,
  web01.example.com:2222 - is Ansible's SSH port (ansible_port), not a TLS port: that
  host is scanned on -p, with a warning. Leave the SSH port there; give TLS ports in -p.
  CIDRs/ranges larger than a /16 need --allow-large.
  Numeric "hostnames" such as 2026092401, 127.1 or 0x7f.0x1 are refused (usage error
  on the command line, skipped in files): the system resolver would read them as an
  IPv4 address. IPv4 parts with a leading zero (010.0.0.1, octal) are refused too.
  0.0.0.0/8, multicast and broadcast addresses are never scanned.

starttls (the protocol follows the port): SMTP on 25 and 587 (EHLO, STARTTLS), IMAP 143
  (STARTTLS), POP3 110 (STLS), FTP 21 (AUTH TLS), LDAP 389 (the StartTLS extended
  operation), XMPP 5222 (a client stream to the name asked for, then <starttls/>),
  PostgreSQL 5432 (the SSLRequest) and RDP 3389 (the X.224 connection request asking for
  TLS or CredSSP); every other port - 443, and the implicit-TLS 465, 993, 995, 636, 990 and
  5223 - speaks TLS from the first byte. PORT/PROTOCOL names it for another number: -p
  2525/smtp (port 2525 throughout the scan, an inventory's ports=2525 too), a target
  10.0.0.5:2525/smtp (that endpoint only), 25/tls (TLS from the first byte on 25).
  Protocols: tls, smtp, imap, pop3, ftp, ldap, xmpp, postgres, rdp. Inventory files keep
  plain port numbers (the web app reads them too). The statuses apply unchanged: a mail
  server serving the old certificate is NEEDS_UPDATE, one that offers no STARTTLS is a
  TLS_ERROR that says so (an RDP server on the RDP Security Layer alone too). The JSON
  names the protocol of such an endpoint (endpoints[].protocol) and what -p named
  (options.portProtocols).

profiles (--profile, repeatable): the ports of a kind of server instead of 443 - web: 443,
  8443; mail: 25, 587, 465, 143, 993, 110, 995; all: those and FTP 21 / 990, LDAP 389 /
  636, XMPP 5222 / 5223, PostgreSQL 5432 and RDP 3389. -p adds its own ports (a port in
  both is scanned once, with the protocol -p writes), and an inventory's ports= still
  replaces them for its server. The JSON says which (options.profiles).

tls audit (--tls-audit): after the scan, every endpoint where a handshake completed is
  checked one handshake at a time (after STARTTLS where the port speaks it), asked for the
  first name it hosts: the TLS versions it accepts (1.0, 1.1, 1.2, 1.3, each offered
  alone), weak cipher suites (NULL, anonymous, export, RC4, DES, 3DES, family by family
  with TLS 1.2 at most) and the key types it serves (RSA and ECDSA, by offering only the
  suites one key type signs; a TLS 1.3-only server cannot be asked). What this Python's
  OpenSSL / LibreSSL cannot offer is listed as not tested, never as refused. Then the chain
  it sends: one handshake verifying it against this machine's trust store for the name (one
  more reading what it sends when that fails), and the chain read in order (Python 3.10+):
  expired, not valid yet, another name, self-signed, a missing intermediate (also one this
  machine had but the server did not send), a root this machine does not trust (a private
  CA - --private-ca trusts it - or, on Windows, a public root Windows has not fetched yet),
  an expired intermediate; and, as warnings, an expired cross-signed copy of a root this
  machine trusts (only old clients fail), a chain out of order, a root sent along,
  certificates no part of it. Last the fleet: one name served with different certificates
  of one key type and kind (an RSA + ECDSA pair or an Origin CA certificate next to a public
  one is none, unless no endpoint serves both key types: then the renewal changed the key
  type) on different endpoints - the scan's certificates and the audit's RSA / ECDSA
  handshakes - newest first, the older one marked OLDER, with the load balancer
  (backends=) or VIP each endpoint sits behind: the pool member a renewal missed.
  The summary lists the endpoints still accepting TLS 1.0 / 1.1, accepting weak suites,
  serving half of an RSA + ECDSA pair (a name another endpoint serves with both, or that an
  RSA and an ECDSA --cert cover), with a broken chain, and the names served with different
  certificates; the JSON gets a "tlsAudit" section (tlsAudit.summary for the fleet -
  chainProblems, serialMismatches too -, tlsAudit.endpoints for every check and its chain).

renewal windows and revocation (--ari, --revocation; with a scan or --estate): every
  certificate the scan found served is asked of its CA once. --ari reads the CA's ACME
  Renewal Information (RFC 9773) window - Let's Encrypt, Google Trust Services, ZeroSSL,
  Sectigo, SSL.com (by key type) - sending the CertID (the issuer's key identifier and the
  serial number, both public); a 404 means the CA does not know the certificate. A CA is
  not asked again before the Retry-After of its last answer (the --baseline report's): the
  last answer is carried, as of its time. --revocation downloads the CRL the certificate
  names (at most 20 MB; OCSP is never asked) and says revoked with the reason and the time,
  good, or unknown with why (another CA's CRL, a CRL for other certificates, a stale one, no
  CRL named ...); this Python cannot check the CRL's signature: "CRL signature not
  verified" (the web app's headless runner, tools/ds.mjs tls --revocation, checks it). The
  summary lists them revoked first, the JSON gives each certificate "ari" {ca, certId,
  start, end, explanationURL, checkedAt, retryAfter, status, error} and "revocation"
  {status, reason, reasonCode, time, crl, checkedAt, thisUpdate, nextUpdate, signature,
  error}, the CSV (the scan's and --estate's) adds ari_start, ari_end, ari_explanation,
  ari_error and revocation, revoked_at, revocation_reason, revocation_error. With
  --baseline these count as changes: RENEW-NOW (the window opened, or ended, since the
  last run), MOVED-UP (it starts more than a day earlier than before: CAs do that before a
  mass revocation), CA-NOTICE (an explanation URL the last run's answers did not carry)
  and REVOKED (a certificate still served is on its CRL).

topology (keys on a server's line in an inventory file, or CSV columns, Ansible host
  variables, JSON keys; the web app's Servers view reads the same): where TLS terminates.
    ports=443,8443         the server's TLS ports, in place of -p for its addresses written
                           without a port (an address written with its own port keeps it);
                           in JSON and YAML the key is tls_ports (a ports key there usually
                           lists every open port, so it is not read); a port that usually
                           carries no TLS (22, 80 ...) is a warning
    terminates_tls=yes|no  no: a backend that never gets the certificate (plain HTTP behind
                           a load balancer) - not scanned unless --include-backends; a load
                           balancer passing TLS through to such backends only is scanned all
                           the same (TLS would end nowhere: the inventory is wrong somewhere)
    vip=203.0.113.50       an address several servers share (an HA pair): the certificate
                           goes on every one of them
    backends=web01,web02   this server is a load balancer forwarding to those servers
    nat=203.0.113.10       the public address this server is reachable at
  e.g. "lb01 203.0.113.2 vip=203.0.113.50 backends=web01,web02" and "web01 10.0.0.21
  terminates_tls=no". The summary then groups the servers by load balancer, and the JSON
  gets servers[].topology and skippedBackends. A VIP or NAT address is not scanned itself:
  each server is scanned on its own addresses (add the VIP with -t to see what the active
  node serves). A malformed value is a TOPOLOGY warning; Ansible group variables
  ([web:vars]) are not read for the topology - set the keys on each host.

exclude (--exclude, repeatable): addresses that must never be probed, e.g. a mail
  server or a host you may not test inside a swept range. IPs, CIDRs (IPv4/IPv6) or
  ranges, separated by spaces or commas, "-" for stdin, or a file with one or more
  per line (# comments). Hostnames are refused (exit code 2). Applied after names
  are resolved and before any connection. Reported in the summary, in the JSON
  ("excluded", summary.excludedAddresses, options.exclude) and in the CSV (one row
  per address, status EXCLUDED). A rule that matches no target is a warning.

names (-n, repeatable): hostnames or files with names (one per line, # comments).
  "*.example.com" probes example.com plus a synthetic name under the wildcard (quote
  it on the command line, '*.example.com', so the shell does not expand the *).
  --cert FILE adds the certificate's SAN names and lets servers that already serve
  it be reported as UPDATED (compared by SHA-256 fingerprint). The private key is
  never needed; if the file contains one it is ignored. --cert may be repeated (an
  RSA + ECDSA pair, or several certificates renewed together): every file's names
  are probed, a server serving any of them is UPDATED, and the summary ("matches
  FILE"), the JSON (newCertFile, newCertificates[].file) and the CSV (a last column
  new_cert) name the one it serves. With one --cert the reports are unchanged. A
  --cert whose names are all in a newer --cert with the same key type (last year's
  certificate next to its renewal) gets a warning: a server still serving it would
  be UPDATED, so leave it out if it is the certificate being replaced.

statuses (per server, port and name):
  UPDATED       serves the new certificate (--cert) for the name
  NEEDS_UPDATE  serves a certificate covering the name, but not the new one
  ORIGIN_CERT   ... a Cloudflare Origin CA certificate: trusted only by Cloudflare, right
                for an origin behind Cloudflare Full (strict) while the name is proxied
  PRIVATE_CERT  ... a self-signed certificate, or one issued by a --private-ca: usual on
                internal hosts
  NOT_HOSTED    the certificate served does not cover the name (default cert), or
                the server refused this name while other names work on that port
                (a closed or reset connection is retried once first)
  TLS_ERROR     the TLS handshake failed (also: its connection was refused after
                the port check found the port open)
  TIMEOUT       no answer within --timeout
  CLOSED        port closed or host unreachable (the port check before any handshake)
  A server "needs the new certificate" when it serves a name the new certificate
  covers (or, without SNI, a default certificate covering such a name) with another
  certificate. Names outside the new certificate are shown but do not count.
  ORIGIN_CERT and PRIVATE_CERT servers are listed apart and do not count either, unless
  --strict-public makes them NEEDS_UPDATE. When the new certificate is itself an Origin
  CA, self-signed or --private-ca certificate, older ones of that kind (and any from the
  new certificate's issuer) stay NEEDS_UPDATE. --private-ca matches the issuer DN and,
  when both certificates carry one, the key identifier; list the CA that signs the server
  certificates (the intermediate, if there is one) - a bundle file is fine.

estate (--estate): an inventory of every certificate the servers serve. Each ip:port is
  asked without SNI and for every -n name and every host name among the targets (a
  server named web01.example.com, a target given by host name); no --cert is needed. The
  summary lists, most urgent first: one name served with different certificates on
  different endpoints (OLDER: the one a renewal left behind - same key type and kind,
  issued before another), one public key on several hosts (addresses) or in several
  certificates (NEEDS A LOOK: in several certificates, or on 5 or more addresses),
  weak keys or signatures (RSA under 2048 bits, SHA-1, MD5), certificates covering none of
  the names asked, then every certificate by expiry (expired, < 7, < 30, < 90 days,
  later) with its kind (Cloudflare Origin CA, self-signed, --private-ca, other), key,
  SPKI SHA-256 and where it is served. The JSON gets an "estate" section (the result rows
  stay as they are), and --csv writes one row per certificate, endpoint and server
  instead of the result rows. The web app's Certificate estate view opens these JSON
  reports - several at once - with filters and a CSV export.

bundle-check FILE...: a subcommand - the certificate, its chain, private key and CSR
  checked together (key and CSR against the certificate by their public key, the chain
  order, a missing intermediate, an extra root; nothing secret is printed), and with
  -o DIR fullchain.pem and chain.pem written in the order servers send them
  (--write-haproxy: haproxy.pem with the key too). See bundle-check --help.

monitoring (--baseline, --warn-days, --notify; for cron and scheduled tasks):
  --baseline FILE compares the scan with a previous --json report, per IP, port and
  name: another certificate served for a name (SHA-256 fingerprint; the fallback
  certificate of a name a server does not host is left out), a status that moved
  (UPDATED -> NEEDS_UPDATE, hosted -> NOT_HOSTED, a new TLS_ERROR / TIMEOUT / CLOSED,
  recovered), endpoints and names that are new or gone. Listed under "Changes since
  the baseline" and in the JSON ("baseline", "changes"). A move from one failure
  state to another (CLOSED -> TIMEOUT, TLS_ERROR -> TIMEOUT: FAILING) is listed but
  not counted by --fail-on-change and --notify. Give the same file to
  --baseline and --json to compare each run with the one before: it is read before
  the scan and replaced after it (through a temporary file in the same directory,
  which must be writable), and while it does not exist (the first run) there is
  nothing to compare. A file that is not a --json report of this tool is a usage
  error.
  --warn-days N lists served certificates that expire within N days or have expired
  (only certificates that cover a probed name), in the summary and the JSON
  ("expiring", options.warnDays).
  --notify URL posts a short summary when something changed or expires (after every
  run with --notify-always). The payload follows the URL: Slack incoming webhooks
  (also Discord's .../slack endpoint), Microsoft Teams incoming webhooks and Power
  Automate / Logic Apps workflows (an Adaptive Card), Discord webhooks, Telegram
  (https://api.telegram.org/bot<token>/sendMessage?chat_id=<chat id>), Google Chat
  space webhooks, PagerDuty's Events API v2
  (https://events.pagerduty.com/v2/enqueue?routing_key=<integration key>: an incident
  per bad change - FAILED, REGRESSED, UNHOSTED, GONE - and per expiring certificate,
  resolved on the run its problem is over; the JSON keeps the keys still open in
  "notify", at most 50 events a run), ntfy (https://ntfy.sh/<topic>: plain text, priority
  4 when something is bad; DOMAINSCOPE_NTFY_TOKEN as a bearer token), and JSON with the
  changes for any other URL, signed when DOMAINSCOPE_NOTIFY_SECRET is set
  (X-DomainScope-Timestamp, and X-DomainScope-Signature: sha256= and the hex HMAC-SHA256
  of the timestamp, a dot and the body); --notify-format overrides the choice (e.g.
  slack for a Slack-compatible Mattermost, ntfy for a self-hosted ntfy server). A Slack
  Workflow Builder webhook (hooks.slack.com/triggers/...) gets the message in the
  variable "text": add it to the workflow. Set the URL in DOMAINSCOPE_NOTIFY_URL rather
  than on the command line, where it ends up in the shell history: whoever has it can
  post. It is never printed - only its host; user:password@ in it is sent as Basic
  authentication. One retry, 10 s timeout, no redirects, the system proxy settings
  apply. A notification that fails is reported on stderr and changes the exit code
  only with --fail-on-notify-error. When the --json file is also the baseline and a
  message with changes was not delivered, the file keeps the previous report, so the
  next run reports those changes again (expiring certificates are listed on every
  run anyway).
  Cron mails what a job prints: -q and the summary in a file (> last.txt) leave only
  errors, such as a notification that failed.

old versus new server (--compare OLD_IP NEW_IP -n NAME, instead of a scan):
  Opens one TLS connection to each address with SNI = NAME (whatever certificate is
  served), sends one GET of --path over it (Host: NAME, Accept-Encoding: identity) and
  reads up to 1 MiB of the body; then one verifying handshake per address (this machine's
  trust store and the name; a certificate issued by a --private-ca counts as trusted).
  Prints both answers side by side - reached, HTTP status, Location, Content-Type,
  <title>, body SHA-256, HSTS, Server, and the certificate: its names (subject CN and SANs),
  covers the name, trusted, issuer, expiry, SHA-256 fingerprint - with ERROR (the new server
  does not answer, answers 4xx / 5xx where the old one did not, or its certificate does not
  cover the name or is not trusted while the old one was), DIFFERS (another status, redirect,
  type or title, a lost HSTS header - none, one browsers ignore (no single valid max-age, a
  directive twice; joined headers count as the first), max-age=0, a shorter max-age, or
  without the old includeSubDomains or preload -, a new certificate expiring within 14
  days, an untrusted certificate that fails otherwise than the old untrusted one (another
  verify error, not valid yet, its leaf sent alone where the old server sent its chain:
  Python 3.10+ tells) or comes from another issuer) and differs (information:
  another body, Server header or certificate; a page with a token or a time in it differs
  on every request). A certificate problem both servers share - an untrusted certificate,
  the same one or failing alike from the same issuer (the issuer DN and authority key id;
  Cloudflare's RSA and ECC origin CAs count as one; a self-signed certificate is its own
  issuer), neither covering the name, both expiring within 14 days - is WARNING and no
  difference: two identical servers are SAME, with a WARNING line under
  the verdict. When neither server answers, the verdict is UNREACHABLE: this machine's
  network may be the cause as much as the servers. Private addresses are fine:
  this is the counterpart of the web app's check from the internet (Retire an IP > Compare
  the old and the new server). --json FILE writes both answers (schema
  domainscope.compare/1, the shared problems in "shared"); --fail-on-change exits with
  code 4 on BROKEN, DIFFERS or UNREACHABLE, never for a problem both servers share.

exit codes: 0 done, 1 NEEDS_UPDATE found (only with --fail-on-needs-update; ORIGIN_CERT
            and PRIVATE_CERT only with --strict-public),
            2 usage error (report files that cannot be written are refused before
            the scan), 3 a report file could not be written after the scan (the
            summary and the other report are still written), 4 something changed
            since --baseline (only with --fail-on-change), 5 the --notify message
            was not delivered (only with --fail-on-notify-error), 130 interrupted
            (Ctrl-C). When several apply: 3, then 5, then 4, then 1.

output encoding: follows the reader - the console code page when piped on Windows
  (cmd, PowerShell), UTF-8 for files, Git Bash and other systems. PYTHONIOENCODING=utf-8
  forces UTF-8 (e.g. for PowerShell 7 "> file"); --json/--csv FILE are always UTF-8.

Türkçe: yeni sertifikanın hangi sunuculara yüklenmesi gerektiğini bulur, örnek:
  python3 ssl_origin_scan.py -t sunucular.txt --cert yeni-sertifika.pem
  Birden çok sertifika (RSA + ECDSA ikilisi ya da aynı hafta yenilenenler) için --cert
  tekrarlanır: herhangi birini sunan sunucu UPDATED olur, raporlar hangisi olduğunu
  yazar ("matches DOSYA", JSON'da newCertFile, CSV'de new_cert sütunu). Adlarının
  tümü aynı anahtar türündeki daha yeni bir --cert içinde de olan bir --cert için
  (geçen yılın sertifikası) uyarı verilir: değiştirilen sertifikaysa onu çıkarın.
  Dokunulmaması gereken adresleri --exclude ile çıkarın: IP, CIDR ya da aralık,
  boşlukla ayrılmış ya da satır başına bir adres içeren bir dosya. Bu adreslere
  hiç bağlanılmaz; alan adı kabul edilmez. Örnek:
  python3 ssl_origin_scan.py -t 10.0.0.0/24 --exclude 10.0.0.5 10.0.0.64/28 -n www.example.com
  2026092401 ya da 0x7f.0x1 gibi sayısal "alan adları" reddedilir: sistem çözümleyicisi
  bunları IPv4 adresi olarak okur.
  Portu yazılmış bir hedef (10.0.0.5:8443, [2001:db8::5]:8443) yalnızca o porttan
  taranır; -p portu olmayan hedefler içindir.
  Topoloji anahtarları TLS'in nerede sonlandığını söyler (envanter satırında, CSV sütunu,
  Ansible host değişkeni ya da JSON anahtarı olarak): ports=443,8443 sunucunun TLS
  portlarıdır (-p yerine); terminates_tls=no sertifikayı hiç almayan düz HTTP arka uç
  sunucusudur ve --include-backends verilmedikçe taranmaz (TLS'i yalnızca böyle sunuculara
  ileten bir yük dengeleyici yine taranır: TLS hiçbir yerde sonlanmaz, envanter bir yerde
  yanlıştır); vip= bir HA çiftinin paylaştığı
  adrestir (sertifika ikisine de kurulur); backends=web01,web02 yük dengeleyicinin
  arkasındaki sunuculardır; nat= sunucunun genel adresidir. Özet sunucuları yük
  dengeleyiciye göre gruplar. Ansible INI envanterinde satırın başındaki
  adresin ya da host adının portu (10.0.0.5:2222) Ansible'ın SSH portudur: o sunucu -p
  portlarından taranır.
  Cloudflare Origin CA sertifikası sunan sunucular ORIGIN_CERT, kendinden imzalı ya da
  --private-ca ile verdiğiniz iç CA'nın imzaladığı sertifikayı sunanlar PRIVATE_CERT
  olarak ayrı listelenir ve "yeni sertifika gerekiyor" sayılmaz; --strict-public
  bunları da NEEDS_UPDATE sayar.
  Cron ile izleme: --baseline önceki --json raporuyla karşılaştırıp değişenleri
  (sunulan sertifika, durum, yeni ya da kaybolan satırlar) listeler; --warn-days N,
  süresi N gün içinde dolan sertifikaları gösterir; --notify (ya da
  DOMAINSCOPE_NOTIFY_URL) değişiklik ya da uyarı olunca Slack, Teams, Discord,
  Telegram, Google Chat, ntfy veya PagerDuty'ye kısa bir özet gönderir. PagerDuty'de
  her sorun için bir olay açılır, sorun giderildiğinde olay kapatılır. Başka bir
  adrese JSON gider; DOMAINSCOPE_NOTIFY_SECRET tanımlıysa ileti HMAC-SHA256 ile
  imzalanır (X-DomainScope-Signature). Aynı dosya hem --baseline
  hem --json ise ve bildirim gönderilemezse önceki rapor korunur; değişiklikler
  bir sonraki çalıştırmada yeniden bildirilir. Özet dosyaya yazılırsa cron
  yalnızca hataları e-postayla gönderir. Örnek:
  python3 ssl_origin_scan.py -t sunucular.txt --cert yeni.pem --baseline son.json \\
    --json son.json --warn-days 21 -q > son.txt
  --estate sunucuların sunduğu her sertifikanın envanterini çıkarır (--cert gerekmez):
  süre dolumu, türü, anahtarı, farklı uç noktalarda farklı sertifikayla sunulan adlar
  (yenilemede unutulan sunucu), birden çok sunucudaki aynı anahtar, zayıf anahtar ya da
  imzalar ve sorulan adların hiçbirini kapsamayan sertifikalar. JSON'a "estate" bölümü
  eklenir, --csv envanteri yazar; web uygulamasının Sertifika envanteri görünümü bu
  raporları açar.
  bundle-check alt komutu sertifikayı, zincirini, özel anahtarı ve CSR'ı birlikte
  denetler, -o DİZİN ile fullchain.pem ve chain.pem'i doğru sırayla yazar:
  python3 ssl_origin_scan.py bundle-check sertifika.pem ca-bundle.crt ozel.key -o cikti/
  Bir adı yeni sunucuya taşımadan önce eski ve yeni sunucuyu karşılaştırın (durum kodu,
  yönlendirme, başlık, gövde özeti, HSTS, sertifika yan yana):
  python3 ssl_origin_scan.py --compare 10.0.0.5 10.0.0.6 -n www.example.com
  Posta, dizin ve veritabanı portlarında TLS, STARTTLS ile başlar; protokol porta göre
  seçilir: SMTP 25 ve 587, IMAP 143, POP3 110, FTP 21, LDAP 389, XMPP 5222, PostgreSQL
  5432, RDP 3389. 465, 993, 995, 636, 990, 5223 ve diğer portlar doğrudan TLS'tir. Başka
  bir port için PORT/PROTOKOL yazın: -p 2525/smtp ya da 10.0.0.5:2525/smtp.
  --tls-audit her uç noktanın kabul ettiği TLS sürümlerini (1.0-1.3), zayıf şifre
  takımlarını ve sunduğu anahtar türlerini (RSA, ECDSA) denetler; bu Python'un
  sunamadığı sürüm ve takımlar "denenmedi" olarak yazılır. Sunulan sertifika zincirine de
  bakar: bu makine zincire o ad için güveniyor mu, eksik ara sertifika, güvenilmeyen kök,
  süresi dolmuş çapraz imza, sırası bozuk ya da gereksiz sertifika var mı. Aynı adı farklı
  sertifikalarla sunan uç noktaları (yenilemede unutulan havuz üyesi) yük dengeleyicisiyle
  birlikte yazar; bir RSA + ECDSA ikilisi buna girmez, ama hiçbir uç nokta ikisini birden
  sunmuyorsa anahtar türü değişmiş sayılır:
  python3 ssl_origin_scan.py -t sunucular.txt -n adlar.txt --tls-audit --json denetim.json
  --profile bir sunucu türünün portlarını 443 yerine tarar: web (443, 8443), mail (25, 587,
  465, 143, 993, 110, 995) ya da all (bunlar ve FTP, LDAP, XMPP, PostgreSQL, RDP 3389):
  python3 ssl_origin_scan.py -t posta.txt --cert yeni.pem --profile mail
"""


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser (exposed for tests and documentation)."""
    parser = argparse.ArgumentParser(
        prog=PROG, description=DESCRIPTION, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    what = parser.add_argument_group('what to scan')
    what.add_argument('-t', '--targets', metavar='TARGET', action='extend', nargs='+',
                      default=[],
                      help='inventory file, IP, CIDR, range, hostname or NAME=IP (repeatable; '
                           'required unless --compare)')
    what.add_argument('--exclude', metavar='ADDR', action='extend', nargs='+', default=[],
                      help='IP, CIDR or range that must never be probed, or a file of them '
                           '(repeatable; hostnames are refused)')
    what.add_argument('-n', '--names', metavar='NAME', action='extend', nargs='+', default=[],
                      help='hostname(s) or a file with one name per line (repeatable)')
    what.add_argument('--cert', metavar='FILE', action='append', default=[],
                      help='the new certificate (PEM/DER/P7B, chain OK): adds its names and '
                           'enables UPDATED detection (repeatable, e.g. RSA + ECDSA or several '
                           'certificates renewed together: serving any of them is UPDATED, and '
                           'the reports name which)')
    what.add_argument('--private-ca', metavar='FILE', action='append', default=[],
                      help='CA certificate(s) of your internal PKI (PEM/DER/P7B): what they '
                           'issued is PRIVATE_CERT, not NEEDS_UPDATE (repeatable)')
    what.add_argument('--strict-public', action='store_true',
                      help='count Cloudflare Origin CA, self-signed and private-CA '
                           'certificates as NEEDS_UPDATE too')
    what.add_argument('--estate', action='store_true',
                      help='inventory of every certificate the servers serve (no --cert '
                           'needed): asks each ip:port without SNI and for every -n name and '
                           'every host name among the targets; the summary, the JSON '
                           '("estate") and the CSV list each certificate by expiry, kind and '
                           'key, and one name served with different certificates, keys on '
                           'several hosts, weak keys and certificates covering none of the '
                           'names')
    scan = parser.add_argument_group('scan options')
    scan.add_argument('-p', '--ports', default=None, metavar='LIST',
                      help='TLS ports, comma separated, ranges allowed (default: 443, or the '
                           '--profile ports); a target written with its own port '
                           '(10.0.0.5:8443) keeps that one. STARTTLS follows the port: SMTP on 25 '
                           'and 587, IMAP 143, POP3 110, FTP 21, LDAP 389, XMPP 5222, PostgreSQL '
                           '5432, RDP 3389; name it for another number with PORT/PROTOCOL '
                           '(2525/smtp, also 10.0.0.5:2525/smtp; 25/tls for TLS from the first '
                           'byte)')
    scan.add_argument('--profile', action='append', default=[], choices=PROFILE_NAMES,
                      help='the ports of a kind of server instead of 443 (repeatable; -p adds '
                           'more): web 443, 8443; mail 25, 587, 465, 143, 993, 110, 995; all of '
                           'those and FTP 21 / 990, LDAP 389 / 636, XMPP 5222 / 5223, PostgreSQL '
                           '5432, RDP 3389')
    scan.add_argument('--tls-audit', action='store_true',
                      help='also audit every endpoint that answered TLS: the versions it '
                           'accepts (TLS 1.0 to 1.3, as far as this Python can offer them), '
                           'weak cipher suites (NULL, anonymous, export, RC4, DES, 3DES), the '
                           'key types it serves (RSA, ECDSA) and its certificate chain (trusted '
                           'by this machine for the name, complete, in order); the summary and '
                           'the JSON ("tlsAudit") list the fleet\'s legacy versions, weak suites, '
                           'RSA + ECDSA pairs served by halves, broken chains, and one name '
                           'served with different certificates across the endpoints (a pool '
                           'member the renewal missed)')
    scan.add_argument('--ari', action='store_true',
                      help='ask the issuing CA of every certificate served for its renewal window '
                           '(ACME Renewal Information, RFC 9773: Let\'s Encrypt, Google Trust '
                           'Services, ZeroSSL, Sectigo, SSL.com); sends each certificate\'s CertID '
                           '(the issuer\'s key identifier and the serial number), never again '
                           'before the Retry-After of its last answer (--baseline)')
    scan.add_argument('--revocation', action='store_true',
                      help='read the CRL every certificate served names (at most %d MB each; '
                           'no OCSP): revoked, with the reason and the time; this Python cannot '
                           'check the CRL\'s signature and says so' % (CRL_MAX_BYTES >> 20))
    scan.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                      help='parallel connections (default: %%(default)s; at most %d at a '
                           'time to one ip:port)' % MAX_PER_ENDPOINT)
    scan.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                      help='per-connection timeout in seconds (default: %(default)s)')
    scan.add_argument('--allow-large', action='store_true',
                      help='allow CIDRs/ranges larger than a /16 (up to a /12)')
    scan.add_argument('--no-wildcard-probe', action='store_true',
                      help='for *.domain names only probe the base domain')
    scan.add_argument('--include-backends', action='store_true',
                      help='also scan servers the inventory marks terminates_tls=no (plain-HTTP '
                           'backends that never get the certificate; left out by default)')
    out = parser.add_argument_group('output')
    out.add_argument('--json', metavar='FILE', help='write a JSON report ("-" = stdout)')
    out.add_argument('--csv', metavar='FILE', help='write a CSV report ("-" = stdout)')
    out.add_argument('--show-all', action='store_true',
                     help='also list servers that do not host the names or are unreachable')
    out.add_argument('--no-color', action='store_true',
                     help='disable colours (also: NO_COLOR environment variable)')
    out.add_argument('-q', '--quiet', action='store_true',
                     help='no progress line, no warnings on stderr')
    out.add_argument('--fail-on-needs-update', action='store_true',
                     help='exit with code 1 when any server needs the new certificate '
                          '(ORIGIN_CERT / PRIVATE_CERT servers only with --strict-public)')
    mon = parser.add_argument_group('monitoring (cron)')
    mon.add_argument('--baseline', metavar='FILE',
                     help='a previous --json report: list what changed since (served '
                          'certificate, status, new or gone rows)')
    mon.add_argument('--fail-on-change', action='store_true',
                     help='exit with code 4 when anything changed since --baseline')
    mon.add_argument('--warn-days', type=int, metavar='N',
                     help='list served certificates that expire within N days (off by '
                          'default)')
    mon.add_argument('--notify', metavar='URL',
                     help='POST a short summary to a Slack, Teams / Power Automate, Discord, '
                          'Telegram or Google Chat webhook (JSON for any other URL) when '
                          'something changed or expires (default: $%s)' % NOTIFY_ENV)
    mon.add_argument('--notify-format', choices=NOTIFY_FORMATS, default='auto',
                     help='payload format (default: auto, from the URL)')
    mon.add_argument('--notify-always', action='store_true',
                     help='notify after every run, even with nothing to report')
    mon.add_argument('--fail-on-notify-error', action='store_true',
                     help='exit with code 5 when the notification was not delivered')
    cmp = parser.add_argument_group('old versus new server (instead of a scan)')
    cmp.add_argument('--compare', metavar=('OLD_IP', 'NEW_IP'), nargs=2,
                     help='before DNS moves a name: GET --path over TLS (SNI and Host = the one -n '
                          'name) from both addresses and show the answers side by side (status, '
                          'Location, title, body SHA-256, HSTS, certificate); with -p (one port), '
                          '--timeout, --json, --private-ca, --fail-on-change (exit 4 when they differ '
                          'or neither answers)')
    cmp.add_argument('--path', default='/', help='the path --compare requests (default: /)')
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    return parser


def parse_ports(text: str) -> List[int]:
    """``'443,8443,9440-9442'`` -> ``[443, 8443, 9440, 9441, 9442]``; UsageError if invalid.

    A port or range may name its protocol (``2525/smtp``, ``25/tls``): it is then a
    :class:`ProtocolPort`, and that number speaks the protocol throughout the scan."""
    ports = []  # type: List[int]
    for token in (t for t in re.split(r'[\s,]+', text or '') if t):
        match = re.match(r'^(\d{1,5})(?:-(\d{1,5}))?(?:/([A-Za-z][A-Za-z0-9-]*))?$', token)
        if not match:
            raise UsageError('invalid port %r' % token)
        protocol = parse_protocol(match.group(3), token) if match.group(3) else None
        first = int(match.group(1))
        last = int(match.group(2) or first)
        if not (1 <= first <= 65535 and 1 <= last <= 65535) or last < first:
            raise UsageError('invalid port %r (1-65535)' % token)
        if last - first >= 1024:
            raise UsageError('port range %r is too large (max 1024 ports)' % token)
        for port in range(first, last + 1):
            value = ProtocolPort(port, protocol) if protocol else port
            if port not in ports:
                ports.append(value)
            elif protocol:  # 2525,2525/smtp: the protocol written wins
                ports[ports.index(port)] = value
    if not ports:
        raise UsageError('no ports given')
    return ports


def resolve_ports(text: Optional[str], profiles: Sequence[str] = ()) -> List[int]:
    """The ports of a scan: each ``--profile``'s (:data:`PORT_PROFILES`), then ``-p``'s; a port
    named twice is scanned once (the protocol -p writes with it wins); without either, -p's
    default (443). UsageError for an unknown profile or a bad -p."""
    parts = []  # type: List[str]
    for name in profiles:
        if name not in PORT_PROFILES:
            raise UsageError('unknown --profile %r (one of %s)' % (name, ', '.join(PROFILE_NAMES)))
        parts.append(','.join(str(port) for port in PORT_PROFILES[name]))
    if text is not None:
        parts.append(text)
    return parse_ports(','.join(parts) if parts else DEFAULT_PORTS)


def port_protocols(ports: Sequence[int]) -> Dict[int, str]:
    """The protocols -p names (``2525/smtp`` -> ``{2525: 'smtp'}``), by port number."""
    return {int(port): port.protocol for port in ports if isinstance(port, ProtocolPort)}


def load_new_certificate(path: str, now: Optional[datetime] = None
                         ) -> Tuple[CertInfo, List[str]]:
    """Read ``--cert FILE`` -> ``(leaf certificate, warning messages)``; UsageError if unusable."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except OSError as exc:
        raise UsageError('cannot read certificate %s: %s' % (path, exc.strerror or exc))
    certs, cert_warnings = load_certificates(data)
    codes = {code for code, _ in cert_warnings}
    if not certs:
        if 'PKCS12_UNSUPPORTED' in codes:
            raise UsageError('%s is a PKCS#12 (.pfx/.p12) bundle; extract the certificate '
                             'first:\n  openssl pkcs12 -in %s -nokeys -clcerts -out new-cert.pem'
                             % (path, path))
        if 'CSR_NOT_CERT' in codes:
            raise UsageError('%s is a certificate signing request (CSR), not a certificate'
                             % path)
        details = '; '.join(detail for code, detail in cert_warnings if code == 'PARSE_ERROR')
        suffix = ' (%s)' % details if details else ''
        raise UsageError('no certificate found in %s%s' % (path, suffix))
    messages = []
    if 'PRIVATE_KEY_PRESENT' in codes:
        messages.append('%s also contains a PRIVATE KEY - ignored (never needed; keep it '
                        'secret)' % path)
    leaf = select_leaf(certs)
    assert leaf is not None
    if leaf.precert:
        raise UsageError('%s is a CT precertificate (it carries the CT poison extension), which no '
                         'server serves: give the issued certificate of serial %s instead (from your '
                         'CA or ACME client, such as cert.pem or fullchain.pem)' % (path, leaf.serial_hex))
    if len(certs) > 1:
        messages.append('%s holds %d certificates; using the leaf %s' % (path, len(certs),
                                                                         leaf.short_label()))
    if leaf.is_ca and not (leaf.dns_names or leaf.ip_addresses):
        messages.append('the new certificate %s is a CA certificate that names no host, which no '
                        'server serves as its own: check that %s holds the server certificate'
                        % (leaf.short_label(), path))
    now = now or _utcnow()
    if leaf.not_after < now:
        messages.append('the new certificate %s EXPIRED on %s' % (
            leaf.short_label(), leaf.not_after.strftime('%Y-%m-%d')))
    elif leaf.not_before > now:
        messages.append('the new certificate %s is not valid before %s' % (
            leaf.short_label(), leaf.not_before.strftime('%Y-%m-%d')))
    return leaf, messages


def _issued_later(a: CertInfo, b: CertInfo) -> int:
    """1 when ``a`` was issued after ``b`` (a later notBefore, else a later notAfter), -1 when
    ``b`` was, 0 when the dates do not tell them apart."""
    for x, y in ((a.not_before, b.not_before), (a.not_after, b.not_after)):
        if x != y:
            return 1 if x > y else -1
    return 0


def replaced_new_certs(certs: Sequence[Tuple[CertInfo, str]]) -> List[str]:
    """Warnings for a ``--cert`` that another ``--cert`` probably replaces, as
    ``replacedLeaves`` in assets/js/lib/certsets.js: the same key algorithm, every name of it
    among the other's, and the other issued later (of two with the same names and dates, the
    one given later is flagged). Last year's certificate passed next to its renewal (a folder of
    certificates) would make a server still serving it UPDATED. ``certs`` are ``(certificate,
    --cert FILE)`` in command-line order."""
    out = []  # type: List[str]
    for i, (cert, path) in enumerate(certs):
        names = cert.hostnames
        if not names:
            continue
        newest = None  # type: Optional[Tuple[CertInfo, str]]
        for j, (other, other_path) in enumerate(certs):
            if j == i or other.key_algorithm != cert.key_algorithm:
                continue
            other_names = other.hostnames
            if not all(name in other_names for name in names):
                continue
            later = _issued_later(other, cert)
            twin = later == 0 and j < i and len(other_names) == len(names)
            if (later > 0 or twin) and (newest is None or _issued_later(other, newest[0]) > 0):
                newest = (other, other_path)
        if newest is not None:
            out.append('--cert %s is probably replaced by the newer --cert %s (the same key type '
                       'and all of its names): a server still serving it is reported UPDATED - '
                       'leave it out if it is the old certificate' % (path, newest[1]))
    return out


def _write_output(path: str, text: str, encoding: str = 'utf-8') -> None:
    if path == '-':
        _write_stdout(text)
        return
    try:
        with open(path, 'w', encoding=encoding, newline='') as handle:
            handle.write(text)
    except OSError as exc:
        raise UsageError('cannot write %s: %s' % (path, exc.strerror or exc))


def _write_stdout(text: str) -> None:
    """Write ``text`` to stdout. A reader that went away (``... | head``, ``| grep -q``)
    is not an error: the rest goes to the null device, so what comes after the output -
    the notification, the baseline - still happens. Any other failure (a full disk
    behind ``> file``) is a :class:`UsageError`."""
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except BrokenPipeError:
        _discard_stdout()
    except OSError as exc:
        raise UsageError('cannot write to stdout: %s' % (exc.strerror or exc))


def _discard_stdout() -> None:
    """Point stdout's file descriptor at the null device after a broken pipe, so the
    output still buffered is dropped quietly instead of failing again at exit."""
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)
    except (OSError, ValueError, AttributeError):
        pass  # not a real file (a test's StringIO): nothing is left to fail


def _temp_path(path: str) -> str:
    return '%s.%d.tmp' % (path, os.getpid())


def _replace_file(path: str, text: str, encoding: str = 'utf-8') -> None:
    """Write ``path`` whole or not at all: a temporary file next to it, renamed over it.
    An interrupted run (a full disk, Ctrl-C) leaves the previous file as it was - for a
    ``--json`` report that is also the next run's ``--baseline``."""
    temp = _temp_path(path)
    try:
        with open(temp, 'x', encoding=encoding, newline='') as handle:
            handle.write(text)
        if os.path.isfile(path):
            try:
                shutil.copymode(path, temp)
            except OSError:
                pass  # keep the default mode rather than fail the report
        os.replace(temp, path)
    except OSError as exc:
        _remove_quietly(temp)
        raise UsageError('cannot write %s: %s' % (path, exc.strerror or exc))
    except BaseException:
        _remove_quietly(temp)
        raise


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _check_output_path(path: Optional[str], option: str, replace: bool = False) -> None:
    """Refuse a report file that cannot be written before the scan, not after it: a
    missing directory, a directory, a read-only file or one another program holds open
    (a CSV still open in Excel on Windows). Nothing is truncated or left behind.

    With ``replace`` (a report written by :func:`_replace_file`) the directory must take
    a new file too: a writable file in a directory the user cannot write to would pass,
    and every run would then fail after the scan without advancing the baseline.
    """
    if not path or path == '-':
        return
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise UsageError('%s: directory does not exist: %s' % (option, directory))
    if os.path.isdir(path):
        raise UsageError('%s: %s is a directory' % (option, path))
    try:
        if os.path.isfile(path):
            with open(path, 'r+b'):  # open for writing, without truncating
                pass
        elif not os.path.exists(path):
            with open(path, 'xb'):
                pass
            os.remove(path)
    except OSError as exc:
        raise UsageError('%s: cannot write %s: %s' % (option, path, exc.strerror or exc))
    if replace:
        temp = _temp_path(path)
        try:
            with open(temp, 'xb'):
                pass
            os.remove(temp)
        except OSError as exc:
            raise UsageError('%s: cannot create a file in %s (the report replaces the '
                             'baseline through a temporary file there): %s'
                             % (option, directory, exc.strerror or exc))


def _isatty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


# --- stdout / stderr encoding ---------------------------------------------------------
# Python writes pipes and files in the ANSI code page on Windows (cp1252 / cp1254 ...),
# but console programs reading a pipe (cmd `| more`, `| findstr`, PowerShell, which
# decodes native output with [Console]::OutputEncoding) use the console's OEM code page
# (cp437 / cp857 ...), and Git Bash's mintty expects UTF-8 - hence mojibake like
# "T³rkþe" for "Türkçe". _configure_streams() picks the encoding the reader will use.

_IS_WINDOWS = os.name == 'nt'
_TRANSLIT_ERRORS = 'ssl_origin_scan.translit'
# Characters without a usable NFKD decomposition (the rest: 'ş' -> 's', 'ü' -> 'u' ...).
_ASCII_LOOKALIKES = {
    'ı': 'i', '‘': "'", '’': "'", '‚': "'", '“': '"', '”': '"',
    '„': '"', '–': '-', '—': '-', '…': '...', '→': '->',
    '←': '<-', '✓': 'v', '✗': 'x', '×': 'x', '\xa0': ' ', '•': '*',
}


def _translit_errors(exc: UnicodeError) -> Tuple[str, int]:
    """Codec error handler: an ASCII look-alike ('ş' -> 's', 'ı' -> 'i') or '?', never an error."""
    if not isinstance(exc, UnicodeEncodeError):
        raise exc
    out = []
    for char in exc.object[exc.start:exc.end]:
        rep = _ASCII_LOOKALIKES.get(char)
        if rep is None:
            rep = ''.join(c for c in unicodedata.normalize('NFKD', char)
                          if not unicodedata.combining(c))
        out.append(rep if rep and rep.isascii() else '?')
    return ''.join(out), exc.end


def _codec_name(encoding: Optional[str]) -> str:
    try:
        return codecs.lookup(encoding or '').name
    except (LookupError, TypeError):
        return ''


def _choose_stream_encoding(current: Optional[str], kind: str,
                            env: Optional[Dict[str, str]] = None, console_cp: int = 0,
                            windows: Optional[bool] = None,
                            utf8_mode: Optional[bool] = None) -> Optional[str]:
    """The encoding a standard stream should switch to, or None to keep ``current``.

    ``kind``: 'console' (terminal), 'file' (redirected to a regular file), 'pipe' or 'other'.
    An explicit PYTHONIOENCODING or Python UTF-8 mode always wins. Then:

    * already UTF-8 -> keep (includes the Windows console, which Python writes as UTF-16);
    * Windows pipe read by a console program (cmd ``| more``, ``| findstr``; PowerShell
      pipes and captures) -> the console output code page, e.g. cp857 / cp437;
    * Windows pipe under Git Bash / MSYS2 / Cygwin (UTF-8 terminals), console code page
      65001, no console at all, a redirect to a file, anything else -> UTF-8;
    * POSIX with an ASCII (C / POSIX) locale -> UTF-8; other locales are kept.
    """
    env = os.environ if env is None else env
    windows = _IS_WINDOWS if windows is None else windows
    utf8_mode = bool(getattr(sys.flags, 'utf8_mode', 0)) if utf8_mode is None else utf8_mode
    if env.get('PYTHONIOENCODING') or utf8_mode:
        return None
    current_codec = _codec_name(current)
    if current_codec == 'utf-8':
        return None
    if not windows:
        return 'utf-8' if current_codec in ('ascii', '') else None
    if kind == 'console':
        return None
    term = env.get('TERM', '')
    msys = bool(env.get('MSYSTEM')) or term.startswith(('xterm', 'cygwin', 'mintty'))
    if kind == 'pipe' and not msys and console_cp and console_cp != 65001:
        target = _codec_name('cp%d' % console_cp)
        if target:
            return None if target == current_codec else target
    return 'utf-8'


def _stream_kind(stream: TextIO) -> str:
    try:
        if stream.isatty():
            return 'console'
        mode = os.fstat(stream.fileno()).st_mode
    except (AttributeError, ValueError, OSError, io.UnsupportedOperation):
        return 'other'
    if stat.S_ISREG(mode):
        return 'file'
    if stat.S_ISFIFO(mode):
        return 'pipe'
    return 'other'


def _console_output_cp() -> int:
    """GetConsoleOutputCP() on Windows (0 without a console or elsewhere)."""
    if not _IS_WINDOWS:
        return 0
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetConsoleOutputCP())  # type: ignore[attr-defined]
    except (AttributeError, ImportError, OSError, ValueError):
        return 0


def _stream_is_utf8(stream: TextIO) -> bool:
    return _codec_name(getattr(stream, 'encoding', None)) == 'utf-8'


def _configure_streams() -> None:
    """Give stdout / stderr the encoding their reader expects (see
    :func:`_choose_stream_encoding`); characters it cannot represent become ASCII
    look-alikes or '?' - never a crash on a hostname / CN, never mojibake."""
    codecs.register_error(_TRANSLIT_ERRORS, _translit_errors)
    console_cp = None  # type: Optional[int]
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, 'reconfigure', None)
        if reconfigure is None:  # StringIO in tests, custom wrappers
            continue
        if console_cp is None:
            console_cp = _console_output_cp()
        target = _choose_stream_encoding(getattr(stream, 'encoding', None), _stream_kind(stream),
                                         console_cp=console_cp)
        try:
            if target:
                reconfigure(encoding=target, errors=_TRANSLIT_ERRORS)
            else:
                reconfigure(errors=_TRANSLIT_ERRORS)
        except (AttributeError, ValueError, LookupError, io.UnsupportedOperation):
            try:
                reconfigure(errors='replace')
            except (AttributeError, ValueError, LookupError, io.UnsupportedOperation):
                pass


def _run(args: argparse.Namespace) -> int:
    if args.compare:
        return _run_compare(args)
    err = sys.stderr
    quiet = args.quiet

    def warn(message: str) -> None:
        if not quiet:  # messages echo certificate labels and inventory lines
            print('warning: %s' % display_text(message), file=err)

    def warn_many(messages: Sequence[str]) -> None:
        for message in messages[:MAX_PRINTED_WARNINGS]:
            warn(message)
        if len(messages) > MAX_PRINTED_WARNINGS:
            warn('... and %d more warnings' % (len(messages) - MAX_PRINTED_WARNINGS))

    ports = resolve_ports(args.ports, args.profile)
    if not 1 <= args.workers <= MAX_WORKERS:
        raise UsageError('--workers must be between 1 and %d' % MAX_WORKERS)
    if not (args.timeout > 0 and args.timeout <= MAX_TIMEOUT):
        raise UsageError('--timeout must be > 0 and <= %d seconds' % MAX_TIMEOUT)
    if args.json == '-' and args.csv == '-':
        raise UsageError('--json - and --csv - cannot both write to stdout')
    if sum(list(values).count('-') for values in (args.targets, args.names, args.exclude)) > 1:
        raise UsageError('stdin ("-") can be used only once')
    json_is_baseline = _same_path(args.baseline, args.json)
    if _same_path(args.baseline, args.csv):
        raise UsageError('--csv would overwrite the --baseline file %s, and a CSV cannot be '
                         'compared: give that file to --json' % args.csv)
    _check_output_path(args.json, '--json', replace=json_is_baseline)
    _check_output_path(args.csv, '--csv')
    exclude_rules = load_excludes(args.exclude)  # strict: bad input stops before any lookup

    all_warnings = []  # type: List[str]
    if args.warn_days is not None and not 0 <= args.warn_days <= MAX_WARN_DAYS:
        raise UsageError('--warn-days must be between 0 and %d' % MAX_WARN_DAYS)
    if args.fail_on_change and not args.baseline:
        raise UsageError('--fail-on-change needs --baseline FILE')
    if args.baseline == '-':
        raise UsageError('--baseline reads a file, not stdin ("-")')
    # Read now, before the scan: with --json FILE the same file is replaced after it.
    baseline = load_baseline(args.baseline, allow_missing=json_is_baseline
                             ) if args.baseline else None
    notify_url, notify_format = _notify_settings(args, all_warnings)

    new_certs = []  # type: List[CertInfo]
    new_cert_files = {}  # type: Dict[str, str]
    for path in args.cert:
        leaf, messages = load_new_certificate(path)
        if all(leaf.sha256 != cert.sha256 for cert in new_certs):
            new_certs.append(leaf)
            new_cert_files[leaf.sha256] = path
        all_warnings.extend(messages)
    all_warnings.extend(replaced_new_certs([(cert, new_cert_files[cert.sha256])
                                            for cert in new_certs]))

    private_cas, ca_messages = load_private_cas(args.private_ca)
    all_warnings.extend(ca_messages)

    names, name_warnings = load_names(args.names)
    all_warnings.extend(name_warnings)
    cert_names = [host for cert in new_certs for host in cert.hostnames]
    probes = build_probe_names(names + cert_names, wildcard_probe=not args.no_wildcard_probe)
    if not probes and not args.estate:  # --estate asks every server without SNI anyway
        raise UsageError('nothing to probe: give hostnames with -n NAME|FILE and/or the new '
                         'certificate with --cert FILE (or --estate for every certificate '
                         'the servers serve)')
    if new_certs:
        uncovered = [p.name for p in probes if not p.wildcard and p.name in names
                     and not any(cert.covers(p.sni)[0] for cert in new_certs)]
        if uncovered:
            all_warnings.append('%d name(s) are not covered by the new certificate: %s'
                                % (len(uncovered), ', '.join(uncovered[:10])
                                   + (' ...' if len(uncovered) > 10 else '')))
    warn_many(all_warnings)

    servers, target_warnings = load_targets(args.targets, allow_large=args.allow_large,
                                            workers=min(args.workers, 32))
    target_messages = [str(w) for w in target_warnings]
    warn_many(target_messages)
    all_warnings.extend(target_messages)
    if not servers:
        raise UsageError('no scannable targets (no IP addresses found or resolved)')
    kept, excluded = apply_excludes(servers, exclude_rules)
    unused = ['--exclude %s matched no target address' % label
              for label in unused_excludes(exclude_rules, excluded)]
    warn_many(unused)
    all_warnings.extend(unused)
    if not kept:
        raise UsageError('no scannable targets: all %d target address(es) are excluded by '
                         '--exclude' % excluded_address_count(excluded))
    # terminates_tls=no (a plain-HTTP backend): never given the certificate, not scanned unless
    # --include-backends (run_scan sets them aside itself; this is for the messages)
    backends = [] if args.include_backends else servers_set_aside(kept)
    aside = {id(server) for server in backends}
    kept = [s for s in kept if id(s) not in aside]
    if not kept:
        raise UsageError('no scannable targets: every server left has terminates_tls=no (a '
                         'plain-HTTP backend that never gets the certificate); '
                         '--include-backends scans them')
    if args.estate:  # every server is asked for the host names among the targets too
        probes = build_probe_names(names + cert_names + inventory_names(kept),
                                   wildcard_probe=not args.no_wildcard_probe)

    ip_count = len({ip for server in kept for ip in server.ips})
    if not quiet:
        skipped = (' (%d excluded address(es) left out)' % excluded_address_count(excluded)
                   if excluded else '')
        if backends:
            skipped += (' (%d server(s) with terminates_tls=no left out; --include-backends '
                        'scans them)' % len(backends))
        if any(server.ports or server.tls_ports for server in kept):  # 203.0.113.10:8443, ports=
            endpoint_count = len({(ip, port) for server in kept for ip in server.ips
                                  for port in server.ports_for(ip, ports)})
            where = '%d IP(s), %d ip:port endpoint(s)' % (ip_count, endpoint_count)
        else:
            where = '%d IP(s) x %d port(s)' % (ip_count, len(ports))
        print('Scanning %d server(s) / %s for %d name(s) with %d workers, timeout %gs%s%s ...'
              % (len(kept), where, len(probes), args.workers, args.timeout, skipped,
                 ', then a TLS audit' if args.tls_audit else ''), file=err)
    progress = ProgressPrinter(err, enabled=not quiet and _isatty(err))
    try:
        # run_scan applies the same exclusion itself, so it is enforced where connections start.
        report = run_scan(servers, probes, ports, new_certs=new_certs, timeout=args.timeout,
                          workers=args.workers, progress=progress.update,
                          warnings=all_warnings, exclude=exclude_rules,
                          private_cas=private_cas, strict_public=args.strict_public,
                          new_cert_files=new_cert_files, include_backends=args.include_backends)
        report.profiles = [name for i, name in enumerate(args.profile)
                           if name not in args.profile[:i]]
        if args.tls_audit:
            report.audit = run_tls_audit(report, timeout=args.timeout, workers=args.workers,
                                         progress=progress.update)
    finally:
        progress.finish()
    if args.ari or args.revocation:
        served = len({row.cert.sha256 for row in report.results if row.cert is not None})
        if not quiet:
            print('Asking the CAs about %d certificate(s) served: %s ...' % (served, ' and '.join(
                what for what, on in (('the renewal window (ARI)', args.ari),
                                      ('the revocation list (CRL)', args.revocation)) if on)),
                  file=err)
        report.ari, report.revocation = bool(args.ari), bool(args.revocation)
        report.cert_status = check_certificate_status(report, ari=args.ari,
                                                      revocation=args.revocation,
                                                      baseline=baseline)
    monitor = None  # type: Optional[MonitorResult]
    if args.baseline or args.warn_days is not None:
        monitor = build_monitor(report, baseline, args.baseline, args.warn_days)
    pd_plan = None  # type: Optional[Dict[str, Any]]
    if monitor is not None:
        if notify_url and notify_format == 'pagerduty':
            pd_plan = pagerduty_plan(monitor, baseline, iso_utc(report.finished_at),
                                     doc=report_to_dict(report))
            monitor.notify_open = pd_plan['open']
        else:  # carried while no PagerDuty URL is set
            monitor.notify_open = open_keys_of(baseline)

    failed, held_back = [], []  # type: List[str], List[str]

    def write_report(path: str, text: str, encoding: str = 'utf-8', atomic: bool = False
                     ) -> None:
        # The scan is done: a report that cannot be written (disk full, a lock taken since
        # the check) is reported, and the other report and the summary still come out.
        try:
            if atomic:
                _replace_file(path, text, encoding)
            else:
                _write_output(path, text, encoding)
        except UsageError as exc:
            print('%s: error: %s' % (PROG, exc), file=err)
            failed.append(path)

    estate = estate_from_report(report_to_dict(report), report.finished_at) \
        if args.estate else None
    if args.csv:
        # BOM so Excel opens UTF-8 (Turkish characters) correctly; none on stdout. --estate
        # writes its inventory instead of the result rows (those stay in the JSON).
        if args.csv == '-':
            write_report('-', render_estate_csv(estate, lineterminator='\n', terminal=True)
                         if estate is not None else
                         render_csv(report, lineterminator='\n', terminal=True))
        else:
            write_report(args.csv, render_estate_csv(estate) if estate is not None
                         else render_csv(report), encoding='utf-8-sig')
    if args.json != '-' and args.csv != '-':
        width = max(60, min(160, shutil.get_terminal_size((100, 24)).columns))
        color = use_color(args.no_color, sys.stdout)
        text = render_estate(report, estate, color=color, show_all=args.show_all, width=width,
                             monitor=monitor) if estate is not None else \
            render_summary(report, color=color, show_all=args.show_all, width=width,
                           monitor=monitor)
        if report.audit is not None:
            text += '\n' + render_tls_audit(report.audit, color=color, show_all=args.show_all)
        write_report('-', text)

    notify_failed = interrupted = pd_failed = False
    posts = []  # type: List[Tuple[str, Any, Optional[bytes], Dict[str, str]]]
    secrets = []  # type: List[str]
    if notify_url and notify_format == 'pagerduty':
        # PagerDuty: a trigger per bad change or expiring certificate, a resolve once it is over
        if pd_plan is not None:
            post_url, events = pagerduty_events(notify_url, pd_plan)
            posts = [(post_url, event, None, {}) for event in events]
            # the URL posted to has no routing key: it is in each event
            secrets = [_pagerduty_routing_key(urllib.parse.urlsplit(notify_url).query) or '']
            if pd_plan['cut'] and not quiet:
                print('%s: warning: PagerDuty: %d more bad change(s) not sent (at most %d events '
                      'a run)' % (PROG, pd_plan['cut'], NOTIFY_MAX_EVENTS), file=err)
    elif notify_url and notify_format and should_notify(monitor, args.notify_always):
        post_url, data, extra = notify_request(notify_format, notify_url,
                                               report_to_dict(report, monitor), monitor)
        posts = [(post_url, None, data, extra)]
        secrets = [(os.environ.get(name) or '').strip()
                   for name in (NTFY_TOKEN_ENV, NOTIFY_SECRET_ENV)]
        if notify_format == 'ntfy':  # the topic: whoever knows it reads the messages
            secrets.extend(segment for segment in urllib.parse.unquote(
                urllib.parse.urlsplit(notify_url).path).split('/') if len(segment) >= 4)
    if posts:
        host = notify_host(notify_url)
        problem = None  # type: Optional[str]
        sent = 0
        try:
            for post_url, payload, data, extra in posts:
                problem = send_notification(post_url, payload, timeout=NOTIFY_TIMEOUT,
                                            retry_delay=NOTIFY_RETRY_DELAY, data=data,
                                            headers=extra, secrets=secrets)
                if problem:
                    break
                sent += 1
        except KeyboardInterrupt:
            interrupted = True
            print('\n%s: error: notification (%s, %s) interrupted' % (PROG, notify_format, host),
                  file=err)
        else:
            if problem:
                print('%s: error: notification failed (%s, %s): %s%s' % (
                    PROG, notify_format, host, redact_url(problem, notify_url, secrets),
                    ' (%d of %d events sent)' % (sent, len(posts)) if sent else ''), file=err)
            elif not quiet:
                print('Notification sent (%s, %s)%s' % (
                    notify_format, host, ': %d triggered, %d resolved' % (
                        len(pd_plan['triggers']), len(pd_plan['resolves']))
                    if notify_format == 'pagerduty' and pd_plan else ''), file=err)
        notify_failed = interrupted or bool(problem)
        pd_failed = notify_failed and notify_format == 'pagerduty'
        if pd_plan is not None and monitor is not None:
            # the keys open as PagerDuty got them: the events before the first that failed
            delivered = [event for _, event, _, _ in posts[:sent]]
            monitor.notify_open = pagerduty_open_after(
                pd_plan, {e['dedup_key'] for e in delivered if e['event_action'] == 'trigger'},
                {e['dedup_key'] for e in delivered if e['event_action'] == 'resolve'})

    if args.json:
        # After the notification: the report keeps the PagerDuty keys as delivered. Escape
        # non-ASCII when stdout is not UTF-8 so any consumer parses it correctly.
        json_text = render_json(
            report, ensure_ascii=args.json == '-' and not _stream_is_utf8(sys.stdout),
            monitor=monitor, estate=args.estate)
        undelivered = len(notable_changes(monitor.changes)) if notify_failed and monitor else 0
        if not json_is_baseline:
            write_report(args.json, json_text)
        elif undelivered or pd_failed:
            # This run's report would be the next baseline: the next run would compare
            # with it, find nothing and never send these changes. Keep the previous one -
            # with the PagerDuty incidents this run opened or resolved noted in it.
            held_back.append(args.json)
            noted = (pd_plan is not None and baseline is not None and monitor is not None
                     and monitor.notify_open != open_keys_of(baseline))
            print('%s: kept the previous baseline in %s (this report is not written there%s): %s'
                  % (PROG, args.json,
                     '; the PagerDuty incidents still open are noted in it' if noted else '',
                     'the %d change%s will be reported again on the next run'
                     % (undelivered, '' if undelivered == 1 else 's') if undelivered else
                     'the next run sends again what was not delivered'), file=err)
            if noted:
                write_report(args.json, json.dumps(
                    _with_open_keys(baseline, monitor.notify_open), indent=2,
                    ensure_ascii=False) + '\n', atomic=True)
        else:
            # Replaced whole or not at all: a half-written baseline would stop every
            # later run with a usage error.
            write_report(args.json, json_text, atomic=True)
    if not quiet:
        for path, label in ((args.json, 'JSON'), (args.csv, 'CSV')):
            if path and path != '-' and path not in failed and path not in held_back:
                print('%s report written to %s' % (label, path), file=err)

    if interrupted:
        return EXIT_INTERRUPTED
    if failed:
        return EXIT_OUTPUT_ERROR
    if notify_failed and args.fail_on_notify_error:
        return EXIT_NOTIFY_ERROR
    if args.fail_on_change and monitor is not None and notable_changes(monitor.changes):
        return EXIT_CHANGED
    if args.fail_on_needs_update and report.needs_update():
        return EXIT_NEEDS_UPDATE
    return EXIT_OK


def _same_path(first: Optional[str], second: Optional[str]) -> bool:
    """True when two command-line paths name the same file (never for ``-``)."""
    if not first or not second or '-' in (first, second):
        return False
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def _notify_settings(args: argparse.Namespace, warnings: List[str]
                     ) -> Tuple[Optional[str], Optional[str]]:
    """``(URL, format)`` from ``--notify`` or :data:`NOTIFY_ENV`, checked before the scan;
    ``(None, None)`` without one. Problems that do not stop the scan go to ``warnings``."""
    url, source = args.notify, '--notify'
    if not url:
        url, source = os.environ.get(NOTIFY_ENV, '').strip(), NOTIFY_ENV
    if not url:
        if args.notify_always or args.fail_on_notify_error or args.notify_format != 'auto':
            raise UsageError('--notify-always, --notify-format and --fail-on-notify-error need '
                             '--notify URL or %s' % NOTIFY_ENV)
        return None, None
    fmt = check_notify_url(url, args.notify_format, source)
    url = ascii_url(url)  # checked above; http.client would refuse it after the scan
    if notify_is_plaintext(url):
        warnings.append('%s uses http:// to another host: the webhook URL, which works as '
                        'a password, travels unencrypted' % source)
    if (source == '--notify' and not args.notify_always and not args.baseline
            and args.warn_days is None):
        warnings.append('--notify sends a message only with --baseline (changes), --warn-days '
                        '(expiring certificates) or --notify-always')
    return url, fmt


# Options of bundle-check that take no value and may come before the word (an alias such as
# `ssl_origin_scan.py --no-color`): moved after it. Any other option before it is a scan's.
BUNDLE_LEADING_FLAGS = ('--no-color', '--write-haproxy')


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point; returns the exit code (0, 1, 2, 3, 4, 5 or 130).

    ``bundle-check FILE...`` as the first argument - or after
    :data:`BUNDLE_LEADING_FLAGS` only - runs :func:`bundle_main` instead (the scan always
    starts with an option, so the word cannot be anything else). A scan usage error with the
    word elsewhere says that it must come first."""
    _configure_streams()
    args_list = list(sys.argv[1:] if argv is None else argv)
    if 'bundle-check' in args_list:
        at = args_list.index('bundle-check')
        if all(token in BUNDLE_LEADING_FLAGS for token in args_list[:at]):
            return bundle_main(args_list[:at] + args_list[at + 1:])
    parser = build_parser()
    try:
        args = parser.parse_args(args_list)
        if not args.targets and not args.compare:
            parser.error('the following arguments are required: -t/--targets')
    except SystemExit as exc:  # --help / --version (0) or usage errors (2)
        code = exc.code
        if code == EXIT_USAGE and 'bundle-check' in args_list:
            print('%s: bundle-check must be the first argument: %s bundle-check [options] '
                  'FILE...' % (PROG, PROG), file=sys.stderr)
        return code if isinstance(code, int) else EXIT_USAGE
    try:
        return _run(args)
    except UsageError as exc:
        print('%s: error: %s' % (PROG, exc), file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print('\ninterrupted - no report written', file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == '__main__':
    try:
        _code = main()
    except BrokenPipeError:  # e.g. `... --help | head`
        _discard_stdout()
        _code = EXIT_OK
    if _code == EXIT_INTERRUPTED:
        # Do not wait for in-flight connections to time out: leave immediately.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(_code)
    sys.exit(_code)
