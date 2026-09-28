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
  7. monitor  -> changes since a --baseline report, --warn-days expiry, --notify webhook

The module is importable: parse_certificate(), load_certificates(),
parse_inventory(), load_targets(), load_excludes(), apply_excludes(),
is_numeric_host(), build_probe_names(), run_scan(), report_to_dict(), render_csv(),
render_summary(), load_baseline(), compare_reports(), expiring_certificates(),
build_monitor(), build_notification(), send_notification() and main() are the
public API.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bisect
import codecs
import csv
import hashlib
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


class UsageError(Exception):
    """Bad command line or input files; reported as ``error: ...`` with exit code 2."""


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
    '1.2.840.113549.1.1.4': 'md5WithRSAEncryption',
    '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
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
_OID_SKI = '2.5.29.14'
_OID_AKI = '2.5.29.35'
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
            elif ext_oid == _OID_SKI:
                key_id = _expect(_read_tlv(buf, value[2], value[3]), 0x04, 'SubjectKeyIdentifier')
                subject_key_id = _content(buf, key_id).hex()
            elif ext_oid == _OID_AKI:
                aki = _expect(_read_tlv(buf, value[2], value[3]), 0x30, 'AuthorityKeyIdentifier')
                for item in _children(buf, aki[2], aki[3]):
                    if item[0] == 0x80:  # [0] keyIdentifier
                        authority_key_id = _content(buf, item).hex()

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

    @property
    def id(self) -> str:
        """Stable identifier: the name, else the first IP."""
        return self.name or (self.ips[0] if self.ips else '')

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

    def port_spec(self, key: str) -> List[Optional[int]]:
        """The ports of address or host name ``key`` (None = the -p ports)."""
        return list(self.ports.get(key, [None]))

    def ports_for(self, ip: str, default: Sequence[int]) -> List[int]:
        """The ports address ``ip`` is scanned on, with ``default`` as the -p ports."""
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
    code: str  # NO_IP | INVALID_IP | DUPLICATE_IP | PARSE | RESOLVE
    text: str
    source: str = ''

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

    def warn(self, line: int, code: str, text: str) -> None:
        """Record an :class:`InventoryWarning` for ``line``."""
        self.warnings.append(InventoryWarning(line, code, text, self.source))

    def add(self, name: Optional[str], ips: Sequence[TargetItem], line: int,
            groups: Sequence[str] = (), hostnames: Sequence[TargetItem] = ()) -> None:
        """Add (or merge into) server ``name``; unscannable IPs become warnings.

        An address or host name may come with its own port as an ``(target, port)`` pair.
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
                return
            self.warn(line, 'NO_IP', name or '')
            return
        name = (name or '').strip() or (usable[0][0] if usable else hosts[0][0])
        key = name.lower()
        server = self.servers.get(key)
        if server is None:
            server = Server(name=name, line=line, source=self.source)
            self.servers[key] = server
        for ip, port in usable:
            server.add_ip(ip, port)
        for group in groups:
            if group and group not in server.groups:
                server.groups.append(group)
        for host, port in hosts:
            server.add_hostname(host, port)

    def add_hostname(self, name: str, line: int, groups: Sequence[str] = (),
                     fallback: Optional[str] = None) -> None:
        """Add a server known only by ``name`` (resolved later), or warn why it cannot be.

        A numeric name (``2026092401``, ``127.1``) is an INVALID_IP, never resolved;
        anything else that is not a hostname is NO_IP (text: ``fallback`` or the name).
        ``web01.example.net:8443`` or ``203.0.113.10:8443`` keeps its port.
        """
        try:
            endpoint = split_endpoint(name)
        except ValueError as exc:
            self.warn(line, 'INVALID_IP', '%s (%s)' % (name, exc))
            return
        if endpoint is not None:
            self.add_token_values(None, [name], line, groups)
            return
        if _malformed_ip_block(name):  # 10.0.0.5-300: a typo'd range, not a host to resolve
            self.warn(line, 'INVALID_IP', name)
            return
        host = normalize_hostname(name)
        if host:
            self.add(name, [], line, groups, [host])
        elif is_numeric_host(name):
            self.warn(line, 'INVALID_IP', numeric_host_note(name))
        else:
            self.warn(line, 'NO_IP', name if fallback is None else fallback)

    def add_token_values(self, name: Optional[str], values: Sequence[str], line: int,
                         groups: Sequence[str] = ()) -> None:
        """Add ``name`` with IPs / hostnames / CIDRs taken from free-form ``values``.

        An address or host name written with a port (``203.0.113.10:8443``,
        ``[2001:db8::1]:8443``, ``web01.example.net:8443``) keeps it; one whose port or
        address cannot be read is an INVALID_IP warning, never dropped silently. Host names
        are resolved only when the entry has no address; there, one without a port is a
        hosts-file alias, but one with a port (``web01 203.0.113.10 db.example.net:5432``)
        was meant as a target, so it is a PARSE warning, as lib/inventory.js has it.
        """
        ips, hosts = [], []  # type: List[TargetItem], List[TargetItem]
        ported = []  # type: List[str]
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
                    self.add(block_ip, [block_ip], line, list(groups) + ([name] if name else []))
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
            self.add(name, ips, line, groups, [] if ips else hosts)

    def result(self, line_count: int) -> Inventory:
        """Finish: flag endpoints shared by several servers and compute stats.

        An endpoint is an address on its own port, or bare (the -p ports): one address on
        different ports (``web01 203.0.113.10:8443``, ``web02 203.0.113.10:9443``, a NAT
        forwarding each port to another machine) is no duplicate, as in lib/inventory.js.
        """
        servers = list(self.servers.values())
        seen = {}  # type: Dict[str, str]
        for server in servers:
            warned = set()  # type: Set[str]
            for ip in server.ips:
                for port in server.port_spec(ip):
                    endpoint = format_endpoint(ip, port)
                    owner = seen.setdefault(endpoint, server.name)
                    if owner != server.name and ip not in warned:
                        warned.add(ip)
                        self.warn(server.line, 'DUPLICATE_IP', '%s is listed for %s and %s'
                                  % (endpoint, owner, server.name))
        stats = {'lines': line_count, 'servers': len(servers),
                 'ips': len({ip for server in servers for ip in server.ips})}
        return Inventory(servers, self.warnings, stats)


def parse_inventory(text: str, source: str = '', allow_large: bool = False) -> Inventory:
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
            return builder.result(len(lines))
    first = next((line for line in lines if line.strip() and not _is_comment(line)), '')
    delimiter = _detect_csv_delimiter(first)
    if delimiter:
        _parse_csv(lines, delimiter, builder)
    elif first.strip() == '---' or any(
            re.match(r'^\s*(?:(?:ansible_host|ansible_ssh_host)\s*:\s*\S|hosts\s*:\s*$)', line)
            for line in lines):
        _parse_yaml(lines, builder)
    else:
        _parse_lines(lines, builder)
    return builder.result(len(lines))


def _detect_csv_delimiter(line: str) -> Optional[str]:
    for delimiter in ('\t', ',', ';'):
        if delimiter not in line:
            continue
        cells = [cell.strip().strip('"') for cell in line.split(delimiter)]
        if any(normalize_ip(cell) for cell in cells):
            return None  # a data line, not a header
        headers = [_normalize_header(cell) for cell in cells]
        if any(h in _NAME_RANK or _is_ip_header(h) for h in headers):
            return delimiter
    return None


def _parse_csv(lines: List[str], delimiter: str, builder: _InventoryBuilder) -> None:
    content = [(number, line) for number, line in enumerate(lines, 1)
               if line.strip() and not _is_comment(line)]
    if not content:
        return
    header = [_normalize_header(cell) for cell in
              next(csv.reader([content[0][1]], delimiter=delimiter))]
    name_idx = min((i for i, h in enumerate(header) if h in _NAME_RANK),
                   key=lambda i: _NAME_RANK[header[i]], default=None)
    ip_idx = [i for i, h in enumerate(header) if _is_ip_header(h) and i != name_idx]
    group_idx = [i for i, h in enumerate(header) if h in _GROUP_HEADERS]
    rows = csv.reader([line for _, line in content[1:]], delimiter=delimiter)
    for (number, _line), row in zip(content[1:], rows):
        cells = [cell.strip() for cell in row]
        name = cells[name_idx] if name_idx is not None and name_idx < len(cells) else ''
        columns = ip_idx or [i for i in range(len(cells)) if i != name_idx]
        values = []  # type: List[str]
        for i in columns:
            if i < len(cells) and cells[i]:
                values.extend(v for v in re.split(r'[\s,;|]+', cells[i]) if v)
        values = [v for v in values if ip_idx or _address_token(v) or is_ip_block(v)]
        groups = [cells[i] for i in group_idx if i < len(cells) and cells[i]]
        name_ip = _address_token(name) if name else None
        if name_ip:
            values.insert(0, name_ip)
            if name_ip != normalize_ip(name):  # an address with a port names the address
                name = (split_endpoint(name) or (name_ip, None))[0]
        if not values:
            if name:
                builder.add_hostname(name, number, groups, ','.join(cells))
            else:
                builder.warn(number, 'NO_IP', ','.join(cells))
            continue
        builder.add_token_values(name or None, values, number, groups)


def _parse_yaml(lines: List[str], builder: _InventoryBuilder) -> None:
    """Very small subset of YAML: nested ``key:`` mappings with ``ansible_host`` leaves."""
    kv_re = re.compile(r'^(\s*)(?:-\s+)?([^\s:#][^:#]*?)\s*:(?:\s+(.*?))?\s*$')
    stack = []  # type: List[Tuple[int, str]]
    pending = {}  # type: Dict[str, Tuple[int, List[str]]]

    def groups_of(path: List[Tuple[int, str]]) -> List[str]:
        keys = [key for _, key in path]
        return [keys[i - 1] for i, key in enumerate(keys)
                if key == 'hosts' and i > 0 and keys[i - 1] not in ('all', 'children')]

    for number, raw in enumerate(lines, 1):
        if not raw.strip() or _is_comment(raw) or raw.strip() in ('---', '...'):
            continue
        match = kv_re.match(raw.split(' #', 1)[0])
        if not match:
            continue
        indent = len(match.group(1))
        key = match.group(2).strip().strip('\'"')
        value = (match.group(3) or '').strip().strip('\'"')
        while stack and stack[-1][0] >= indent:
            stack.pop()
        parent = stack[-1][1] if stack else None
        if key in ('ansible_host', 'ansible_ssh_host'):
            if parent:
                pending.pop(parent, None)
                builder.add_token_values(parent, [value], number, groups_of(stack[:-1]))
            else:
                builder.add_token_values(None, [value], number)
            continue
        if value in ('', 'null', '~', '{}'):
            stack.append((indent, key))
            if parent == 'hosts':
                pending[key] = (number, groups_of(stack[:-1]))
    for key, (number, groups) in pending.items():
        builder.add_token_values(key, [key], number, groups)


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
    for number, raw in enumerate(lines, 1):
        line = _strip_comment(raw)
        if not line:
            continue
        section = re.match(r'^\[([^\]]+)\]$', line)
        if section and normalize_ip(section.group(1)) is None:
            name = section.group(1).strip()
            group, _, kind = name.partition(':')
            skip_section = kind in ('vars', 'children')
            continue
        if skip_section:
            continue
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
            builder.add_token_values(name, values, number, groups)
        elif had_invalid:
            continue  # "web01 10.0.0.300": a typo, do not silently resolve "web01" instead
        elif _is_header_like(tokens):
            continue  # "hostname   ip": a column heading, not a server called "hostname"
        elif name is not None:
            # A zone file's "2026092401 ; serial" line must never be resolved (glibc -> IP).
            builder.add_hostname(name, number, groups, line)


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
    if name is not None or _json_has_ip_field(data) or _json_host_values(data):
        ips, invalid = [], []  # type: List[str], List[str]
        _json_ips(data, ips, invalid=invalid)
        values = ips or _json_host_values(data)
        for token in invalid:
            builder.warn(0, 'INVALID_IP', '%s (%s)' % (token, _bad_port(token)))
        if values:
            builder.add_token_values(name or key_hint, values, 0)
        elif name and not invalid:
            # "web01" with a mistyped port is a warning, never the name resolved instead
            builder.add_hostname(name, 0)
        return
    for child_key, child in data.items():
        if child_key == '_meta' and isinstance(child, dict):
            _parse_json(child.get('hostvars', {}), builder)
            continue
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


def _add_endpoint_token(builder: _InventoryBuilder, token: str) -> bool:
    """A ``-t`` token with its own port (``203.0.113.10:8443``, ``[2001:db8::1]:8443``,
    ``web01.example.net:8443``) -> one server; False when ``token`` has no port."""
    try:
        endpoint = split_endpoint(token)
    except ValueError as exc:
        raise UsageError('invalid target %r: %s' % (token, exc))
    if endpoint is None:
        return False
    target, port = endpoint
    ip = normalize_ip(target)
    if ip:
        builder.add(ip, [(ip, port)], 0)
        return True
    if is_numeric_host(target):
        raise UsageError('invalid target %r: %s; write addresses as a.b.c.d'
                         % (token, numeric_host_note(target)))
    host = normalize_hostname(target)
    if host is None:
        raise UsageError('invalid target %r (expected an IP address or hostname before the '
                         'port)' % token)
    builder.add(target, [], 0, (), [(host, port)])
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
            inventory = parse_inventory((stdin or sys.stdin).read(), '<stdin>', allow_large)
        elif os.path.isfile(value):
            try:
                text = read_text_file(value)
            except OSError as exc:
                raise UsageError('cannot read %s: %s' % (value, exc.strerror or exc))
            inventory = parse_inventory(text, value, allow_large)
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
    servers, resolve_warnings = resolve_servers(list(merged.values()), resolver, workers, cancel)
    return servers, warnings + resolve_warnings


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
        return [ServerSummary(server, server_status(grouped.get(server.name, [])),
                              grouped.get(server.name, []))
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


class TlsProber:
    """Phase 2: TLS handshake with optional SNI, returning the peer certificate (DER)."""

    def __init__(self, context: Optional[ssl.SSLContext] = None) -> None:
        self.context = context or make_client_context()

    def __call__(self, ip: str, port: int, sni: Optional[str], timeout: float) -> TlsResult:
        started = time.monotonic()
        sock = None
        try:
            sock = socket.create_connection((_connect_address(ip), port), timeout=timeout)
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
            result = TlsResult(status=status, error=message, refused=is_refusal(exc),
                               transient=is_transient(exc))
        finally:
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
             new_cert_files: Optional[Dict[str, str]] = None) -> ScanReport:
    """Probe every ``server IP x port`` for every name and classify the results.

    A served certificate that is any of ``new_certs`` is UPDATED; ``new_cert_files``
    (sha256 -> the --cert FILE) lets the reports name which one when there are several.

    ``ports`` apply to every address except those with ports of their own
    (:attr:`Server.ports`). A certificate that covers a name but is not the new one is
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

    endpoints = {}  # type: Dict[Tuple[str, int], Endpoint]
    for server in servers:
        for ip in server.ips:
            for port in server.ports_for(ip, ports):
                endpoints.setdefault((ip, port), Endpoint(ip, port))

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
                      new_cert_files=dict(new_cert_files or {}))


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


def report_to_dict(report: ScanReport, monitor: Optional[MonitorResult] = None
                   ) -> Dict[str, Any]:
    """The ``--json`` document (see the module docstring / README for field meanings).

    With ``monitor`` (:func:`build_monitor`) the document also carries ``baseline`` and
    ``changes`` (with ``--baseline``), ``expiring`` and ``options.warnDays`` (with
    ``--warn-days``); without it, it is exactly the plain scan report.
    """
    now = report.finished_at
    new_fps = {cert.sha256 for cert in report.new_certs}
    summaries = report.server_summaries()
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
    certificates = {}
    for sha, cert in report.certificates.items():
        entry = cert.to_dict(now)
        entry['isNewCert'] = sha in new_fps
        kind, ca = report.cert_kind(cert)
        entry['kind'] = kind  # origin-ca | self-signed | private-ca | other
        entry['privateCa'] = ca.subject_dn if ca is not None else None
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
        'endpoints': [{'ip': e.ip, 'port': e.port, 'state': e.state, 'error': e.error,
                       'connectMs': e.connect_ms} for e in report.endpoints],
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
    return doc


def render_json(report: ScanReport, ensure_ascii: bool = False,
                monitor: Optional[MonitorResult] = None) -> str:
    """Pretty-printed JSON text of :func:`report_to_dict` (UTF-8, 2-space indent).

    ``ensure_ascii=True`` escapes non-ASCII characters (``\\u00fc``) - used when stdout is
    not UTF-8, so every consumer decodes the JSON correctly whatever the code page.
    """
    return json.dumps(report_to_dict(report, monitor), indent=2,
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
    columns = CSV_COLUMNS + ((NEW_CERT_CSV_COLUMN,) if several else ())
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
                   note: Optional[Callable[[str, CertInfo], str]] = None) -> List[str]:
    """Lines for one server: per endpoint, names grouped by (status, served certificate).

    ``note(status, cert)`` may add why a group has its status (``self-signed``).
    """
    server = summary.server
    head = '  ' + style.paint(display_text(server.name), 'bold')
    extra_ips = [ip for ip in server.ips if ip != server.name]
    if extra_ips:
        head += '  ' + style.paint(', '.join(extra_ips), 'dim')
    if server.groups:
        head += '  ' + style.paint(display_text('[%s]' % ', '.join(server.groups)), 'dim')
    out = [head]
    by_endpoint = {}  # type: Dict[Tuple[str, int], List[ProbeResult]]
    for row in summary.rows:
        by_endpoint.setdefault((row.ip, row.port), []).append(row)
    label_width = max(len(s) for s in STATUSES)
    indent = 8 + label_width
    for (ip, port), rows in by_endpoint.items():
        label = _endpoint_label(ip, port)
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
             explain: Sequence[str] = ()) -> None:
    lines.append(style.paint('%s: %d' % (title, len(summaries)), *colors))
    for text in explain:
        lines.extend(style.paint(line, 'dim') for line in _wrap('  ', 2, text, width))
    for summary in summaries:
        lines.extend(_render_server(summary, style, show_all, width, now, has_new, note))
    lines.append('')


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
    unreachable ones (otherwise counted).
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
             note)
    if has_new:
        _section(lines, 'Already serving the new certificate', buckets.get(UPDATED, []), style,
                 ('green', 'bold'), show_all, width, now, has_new, note)
    if buckets.get(ORIGIN_CERT):
        _section(lines, 'Serving a Cloudflare Origin CA certificate', buckets[ORIGIN_CERT],
                 style, ('cyan', 'bold'), show_all, width, now, has_new, note,
                 (_ORIGIN_NOTE, _NOT_COUNTED_NOTE) if has_new else (_ORIGIN_NOTE,))
    if buckets.get(PRIVATE_CERT):
        _section(lines, 'Serving a self-signed or private-CA certificate', buckets[PRIVATE_CERT],
                 style, ('blue', 'bold'), show_all, width, now, has_new, note,
                 (_PRIVATE_NOTE, _NOT_COUNTED_NOTE) if has_new else (_PRIVATE_NOTE,))

    errors = [s for s in buckets.get(TLS_ERROR, []) + buckets.get(TIMEOUT, [])
              if any(r.probe != PROBE_CONNECT for r in s.rows)]
    if errors:
        _section(lines, 'Handshake errors', errors, style, ('magenta', 'bold'), show_all, width,
                 now, has_new)

    not_hosted = buckets.get(NOT_HOSTED, [])
    other_cert = [s for s in not_hosted if any(r.status in HOSTED_STATUSES and not is_relevant(r)
                                               for r in s.rows)]
    not_hosted = [s for s in not_hosted if s not in other_cert]
    if other_cert:
        _section(lines, 'Hosting only names the new certificate does not cover', other_cert,
                 style, ('bold',), show_all, width, now, has_new, note)
    unreachable = [s for s in summaries if s.status in (CLOSED, TIMEOUT)
                   and all(r.probe == PROBE_CONNECT for r in s.rows)]
    if show_all:
        if not_hosted:
            _section(lines, 'Not hosting any of the names', not_hosted, style, ('bold',), True,
                     width, now, has_new)
        if unreachable:
            _section(lines, 'Unreachable (no open port)', unreachable, style, ('bold',), True,
                     width, now, has_new)
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
               'retry': 'Retrying reset handshakes'}

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
    without ``--warn-days``; the JSON keys follow the same rule.
    """

    baseline: Optional[Dict[str, Any]] = None
    changes: Optional[List[Dict[str, Any]]] = None
    warn_days: Optional[int] = None
    expiring: Optional[List[Dict[str, Any]]] = None


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
    return change.get('transition') != 'failing'


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
      a change), or a row only one report has.

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
    keys = list(new_endpoints) + [key for key in old_endpoints if key not in new_endpoints]
    for key in keys:
        old, new = old_endpoints.get(key), new_endpoints.get(key)
        ip, port = key
        if old is None or new is None or old['status'] != new['status']:
            before_view = _endpoint_view(old) if old else None
            after_view = _endpoint_view(new) if new else None
            if new is None and ip in excluded:
                after_view = {'status': EXCLUDED, 'excludedBy': excluded[ip]}
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

_CHANGE_TAGS = {'appeared': 'NEW', 'disappeared': 'GONE', 'cert': 'CERT'}
_TAG_STYLES = {'FAILED': ('red', 'bold'), 'REGRESSED': ('red', 'bold'), 'UNHOSTED': ('red',),
               'GONE': ('red',), 'RECOVERED': ('green',), 'UPDATED': ('green', 'bold'),
               'HOSTED': ('green',), 'NEW': ('cyan',), 'CERT': ('yellow',),
               'CHANGED': ('yellow',), 'FAILING': ('dim',)}
_BAD_TAGS = ('FAILED', 'REGRESSED', 'UNHOSTED', 'GONE')
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
    quiet = len(changes) - len(notable_changes(changes))
    if quiet:
        lines.append(style.paint(
            '  FAILING: %d moved from one failure state to another (TLS_ERROR, TIMEOUT, '
            'CLOSED) - nothing served either way, so not counted by --notify or '
            '--fail-on-change.' % quiet, 'dim'))
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

NOTIFY_FORMATS = ('auto', 'slack', 'teams', 'discord', 'telegram', 'googlechat', 'json')
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
_DISCORD_HOSTS = ('discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com')
_TEAMS_HOSTS = ('outlook.office.com', 'outlook.office365.com')
# Teams incoming webhooks, Power Automate / Logic Apps workflow triggers
_TEAMS_HOST_SUFFIXES = ('.webhook.office.com', '.logic.azure.com', '.api.powerplatform.com')
_TELEGRAM_PATH_RE = re.compile(r'^/bot[^/]+/sendMessage$')
_DISCORD_PATH_RE = re.compile(r'^/api/(?:v\d{1,2}/)?webhooks/')   # also /api/v10/webhooks/
# Path words of the webhook services above: not secrets, kept in error texts.
_NOTIFY_PATH_WORDS = frozenset((
    'api', 'automations', 'direct', 'hook', 'hooks', 'incomingwebhook', 'invoke', 'manual',
    'messages', 'paths', 'powerautomate', 'sendmessage', 'services', 'slack', 'spaces',
    'triggers', 'webhook', 'webhookb2', 'webhooks', 'workflows'))
_API_VERSION_RE = re.compile(r'^v\d{1,2}$')   # /api/v10/, /v1/spaces/: not a token either
_USER_AGENT = 'ssl_origin_scan/%s (+https://github.com/halilibrahimd27/domainscope)' % __version__


def detect_notify_format(url: str) -> str:
    """The payload a webhook URL expects: ``slack`` (hooks.slack.com, and Discord's
    Slack-compatible ``.../slack`` endpoint), ``discord`` (``/api/webhooks/``, also with
    an API version: ``/api/v10/webhooks/``), ``telegram`` (api.telegram.org), ``teams``
    (Teams incoming webhooks, Power Automate / Logic Apps workflows), ``googlechat``
    (chat.googleapis.com) or ``json`` for anything else."""
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
    return 'json'


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


def redact_url(text: str, url: str) -> str:
    """``text`` (an error message, a response body) without the secret parts of ``url``:
    the URL (also without its user info), its path, query and fragment, the query
    values, the path segments that may be tokens (:func:`_secret_segment`, in the forms
    of :func:`_segment_forms`), the user name and password, and the Basic
    authentication header made of them (:func:`split_credentials`). Webhook URLs are
    credentials - whoever has one can post."""
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
    found = {secret for secret in secrets if len(secret) >= 4} | {s for s in always if s}
    for secret in sorted(found, key=len, reverse=True):
        text = text.replace(secret, '***')
    return text


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
               limit: int) -> List[str]:
    """``items`` then ``footer``, as many items as fit in ``limit`` characters with
    the title; the rest are counted in a last "... and N more" line. Every line is cut
    at :data:`_NOTIFY_LINE_LIMIT` characters, the footer's too."""
    footer = [_clip(line) for line in footer]
    budget = limit - len(title) - sum(len(line) + 1 for line in footer) - 60
    out = []  # type: List[str]
    for index, line in enumerate(items):
        line = _clip(line)
        if len(line) + 1 > budget:
            out.append('- ... and %d more line(s) - see the --json report'
                       % (len(items) - index))
            break
        out.append(line)
        budget -= len(line) + 1
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


def _response_detail(raw: bytes) -> str:
    """The reason in a webhook's error answer: Telegram's ``description``, Discord's
    ``message``, Power Automate's ``error.message``, or the body itself (200 chars)."""
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
    return ' '.join(text.split())[:200]


def _network_error_text(reason: Any) -> str:
    if isinstance(reason, (socket.timeout, TimeoutError)):
        return 'timed out'
    if isinstance(reason, ssl.SSLError):
        return 'TLS: %s' % _clean_ssl_message(reason)
    if isinstance(reason, OSError) and reason.strerror:
        return reason.strerror
    return str(reason) or type(reason).__name__


def _post_once(opener: urllib.request.OpenerDirector, url: str, body: bytes,
               timeout: float, auth: Optional[str] = None
               ) -> Tuple[Optional[str], bool, Optional[float]]:
    """One POST -> ``(error or None, worth a retry, Retry-After seconds)``."""
    headers = {'Content-Type': 'application/json; charset=utf-8', 'User-Agent': _USER_AGENT}
    if auth:
        headers['Authorization'] = auth
    request = urllib.request.Request(url, data=body, method='POST', headers=headers)
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(65536)
        return None, False, None
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read(512) or b''
        except (OSError, http.client.HTTPException, ValueError):
            raw = b''
        finally:
            exc.close()
        text = 'HTTP %d %s' % (exc.code, exc.reason or '')
        if 300 <= exc.code < 400:
            text += ' (a redirect; not followed)'
        detail = _response_detail(raw)
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


def send_notification(url: str, payload: Dict[str, Any], timeout: float = NOTIFY_TIMEOUT,
                      retries: int = 1, retry_delay: float = NOTIFY_RETRY_DELAY,
                      sleep: Callable[[float], None] = time.sleep) -> Optional[str]:
    """POST ``payload`` as JSON to ``url`` -> None when delivered, else what went wrong.

    Certificate-verified HTTPS (the system proxy settings apply), no redirects,
    ``timeout`` seconds per attempt, ``retries`` more attempts after ``retry_delay``
    seconds (a 429's Retry-After, up to 10 s) for network errors, 5xx and 429 - a 4xx
    is the webhook's answer. A ``user:password@`` in the URL is sent as Basic
    authentication. The message never contains the URL (:func:`redact_url`).
    """
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect)
    target, auth = split_credentials(url)
    problem = None  # type: Optional[str]
    for attempt in range(1 + max(0, retries)):
        problem, retry, retry_after = _post_once(opener, target, body, timeout, auth)
        if problem is None:
            return None
        if not retry or attempt >= retries:
            break
        sleep(min(10.0, max(retry_delay, retry_after or 0.0)))
    return display_text(redact_url(problem or 'failed', url))


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
  Cron - compare every run with the previous one, warn 21 days before a served
  certificate expires, post to a chat webhook only when there is something to say
  (the summary goes to a file, so cron mails only errors):
    export DOMAINSCOPE_NOTIFY_URL='https://hooks.slack.com/services/...'
    python3 ssl_origin_scan.py -t hosts.ini --cert new.pem --baseline last.json \\
      --json last.json --warn-days 21 -q > last.txt

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
  space webhooks, and JSON with the changes for any other URL; --notify-format
  overrides the choice (e.g. slack for a Slack-compatible Mattermost). A Slack
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
  taranır; -p portu olmayan hedefler içindir. Ansible INI envanterinde satırın başındaki
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
  Telegram veya Google Chat'e kısa bir özet gönderir. Aynı dosya hem --baseline
  hem --json ise ve bildirim gönderilemezse önceki rapor korunur; değişiklikler
  bir sonraki çalıştırmada yeniden bildirilir. Özet dosyaya yazılırsa cron
  yalnızca hataları e-postayla gönderir. Örnek:
  python3 ssl_origin_scan.py -t sunucular.txt --cert yeni.pem --baseline son.json \\
    --json son.json --warn-days 21 -q > son.txt
"""


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser (exposed for tests and documentation)."""
    parser = argparse.ArgumentParser(
        prog=PROG, description=DESCRIPTION, epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    what = parser.add_argument_group('what to scan')
    what.add_argument('-t', '--targets', metavar='TARGET', action='extend', nargs='+',
                      required=True,
                      help='inventory file, IP, CIDR, range, hostname or NAME=IP (repeatable)')
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
    scan = parser.add_argument_group('scan options')
    scan.add_argument('-p', '--ports', default=DEFAULT_PORTS, metavar='LIST',
                      help='TLS ports, comma separated, ranges allowed (default: 443); a '
                           'target written with its own port (10.0.0.5:8443) keeps that one')
    scan.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                      help='parallel connections (default: %%(default)s; at most %d at a '
                           'time to one ip:port)' % MAX_PER_ENDPOINT)
    scan.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                      help='per-connection timeout in seconds (default: %(default)s)')
    scan.add_argument('--allow-large', action='store_true',
                      help='allow CIDRs/ranges larger than a /16 (up to a /12)')
    scan.add_argument('--no-wildcard-probe', action='store_true',
                      help='for *.domain names only probe the base domain')
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
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    return parser


def parse_ports(text: str) -> List[int]:
    """``'443,8443,9440-9442'`` -> ``[443, 8443, 9440, 9441, 9442]``; UsageError if invalid."""
    ports = []  # type: List[int]
    for token in (t for t in re.split(r'[\s,]+', text or '') if t):
        match = re.match(r'^(\d{1,5})(?:-(\d{1,5}))?$', token)
        if not match:
            raise UsageError('invalid port %r' % token)
        first = int(match.group(1))
        last = int(match.group(2) or first)
        if not (1 <= first <= 65535 and 1 <= last <= 65535) or last < first:
            raise UsageError('invalid port %r (1-65535)' % token)
        if last - first >= 1024:
            raise UsageError('port range %r is too large (max 1024 ports)' % token)
        for port in range(first, last + 1):
            if port not in ports:
                ports.append(port)
    if not ports:
        raise UsageError('no ports given')
    return ports


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
    if len(certs) > 1:
        messages.append('%s holds %d certificates; using the leaf %s' % (path, len(certs),
                                                                         leaf.short_label()))
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

    ports = parse_ports(args.ports)
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
    if not probes:
        raise UsageError('nothing to probe: give hostnames with -n NAME|FILE and/or the new '
                         'certificate with --cert FILE')
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

    ip_count = len({ip for server in kept for ip in server.ips})
    if not quiet:
        skipped = (' (%d excluded address(es) left out)' % excluded_address_count(excluded)
                   if excluded else '')
        if any(server.ports for server in kept):  # 203.0.113.10:8443 in the targets
            endpoint_count = len({(ip, port) for server in kept for ip in server.ips
                                  for port in server.ports_for(ip, ports)})
            where = '%d IP(s), %d ip:port endpoint(s)' % (ip_count, endpoint_count)
        else:
            where = '%d IP(s) x %d port(s)' % (ip_count, len(ports))
        print('Scanning %d server(s) / %s for %d name(s) with %d workers, timeout %gs%s ...'
              % (len(kept), where, len(probes), args.workers, args.timeout, skipped), file=err)
    progress = ProgressPrinter(err, enabled=not quiet and _isatty(err))
    try:
        # run_scan applies the same exclusion itself, so it is enforced where connections start.
        report = run_scan(servers, probes, ports, new_certs=new_certs, timeout=args.timeout,
                          workers=args.workers, progress=progress.update,
                          warnings=all_warnings, exclude=exclude_rules,
                          private_cas=private_cas, strict_public=args.strict_public,
                          new_cert_files=new_cert_files)
    finally:
        progress.finish()
    monitor = None  # type: Optional[MonitorResult]
    if args.baseline or args.warn_days is not None:
        monitor = build_monitor(report, baseline, args.baseline, args.warn_days)

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

    json_text = None  # type: Optional[str]
    if args.json:
        # Escape non-ASCII when stdout is not UTF-8 so any consumer parses it correctly.
        json_text = render_json(
            report, ensure_ascii=args.json == '-' and not _stream_is_utf8(sys.stdout),
            monitor=monitor)
        if not json_is_baseline:  # the baseline is replaced after the notification
            write_report(args.json, json_text)
    if args.csv:
        # BOM so Excel opens UTF-8 (Turkish characters) correctly; none on stdout.
        if args.csv == '-':
            write_report('-', render_csv(report, lineterminator='\n', terminal=True))
        else:
            write_report(args.csv, render_csv(report), encoding='utf-8-sig')
    if args.json != '-' and args.csv != '-':
        width = max(60, min(160, shutil.get_terminal_size((100, 24)).columns))
        write_report('-', render_summary(report, color=use_color(args.no_color, sys.stdout),
                                         show_all=args.show_all, width=width, monitor=monitor))

    notify_failed = interrupted = False
    if notify_url and notify_format and should_notify(monitor, args.notify_always):
        post_url, payload = build_notification(notify_format, notify_url,
                                               report_to_dict(report, monitor), monitor)
        host = notify_host(notify_url)
        problem = None  # type: Optional[str]
        try:
            problem = send_notification(post_url, payload, timeout=NOTIFY_TIMEOUT,
                                        retry_delay=NOTIFY_RETRY_DELAY)
        except KeyboardInterrupt:
            interrupted = True
            print('\n%s: error: notification (%s, %s) interrupted' % (PROG, notify_format, host),
                  file=err)
        else:
            if problem:
                print('%s: error: notification failed (%s, %s): %s' % (
                    PROG, notify_format, host, redact_url(problem, notify_url)), file=err)
            elif not quiet:
                print('Notification sent (%s, %s)' % (notify_format, host), file=err)
        notify_failed = interrupted or bool(problem)

    if json_text is not None and json_is_baseline:
        undelivered = len(notable_changes(monitor.changes)) if notify_failed and monitor else 0
        if undelivered:
            # This run's report would be the next baseline: the next run would compare
            # with it, find nothing and never send these changes. Keep the previous one.
            held_back.append(args.json)
            print('%s: kept the previous baseline in %s (this report is not written there): '
                  'the %d change%s will be reported again on the next run' % (
                      PROG, args.json, undelivered, '' if undelivered == 1 else 's'), file=err)
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


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point; returns the exit code (0, 1, 2, 3, 4, 5 or 130)."""
    _configure_streams()
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # --help / --version (0) or usage errors (2)
        code = exc.code
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
