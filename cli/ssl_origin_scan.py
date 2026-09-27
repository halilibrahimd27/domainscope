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
  6. verdict  -> UPDATED / NEEDS_UPDATE / NOT_HOSTED / TLS_ERROR / TIMEOUT / CLOSED

The module is importable: parse_certificate(), load_certificates(),
parse_inventory(), load_targets(), load_excludes(), apply_excludes(),
is_numeric_host(), build_probe_names(), run_scan(), report_to_dict(), render_csv(),
render_summary() and main() are the public API.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import bisect
import codecs
import csv
import hashlib
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
NOT_HOSTED = 'NOT_HOSTED'      # served cert does not cover the name (default cert)
TLS_ERROR = 'TLS_ERROR'        # handshake failed (or refused after the port check)
TIMEOUT = 'TIMEOUT'            # no answer within --timeout
CLOSED = 'CLOSED'              # port closed / host unreachable (phase-1 port check)
STATUSES = (UPDATED, NEEDS_UPDATE, NOT_HOSTED, TLS_ERROR, TIMEOUT, CLOSED)

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
        # Self-issued: identical encoded subject and issuer Names.
        self_signed=buf[issuer_tlv[1]:issuer_tlv[3]] == buf[subject_tlv[1]:subject_tlv[3]],
        sha256=hashlib.sha256(cert_der).hexdigest(),
        sha1=hashlib.sha1(cert_der).hexdigest(),
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


def load_certificates(data: Union[bytes, str]) -> Tuple[List[CertInfo], List[CertWarning]]:
    """Parse every certificate in ``data``; never raises for bad input.

    Accepts PEM (one or many blocks, CRLF, surrounding text such as an e-mail), raw DER,
    bare base64 DER and PKCS#7 (.p7b, PEM or DER). Detects PKCS#12 and CSRs. Private
    keys are never decoded - their presence only produces a PRIVATE_KEY_PRESENT warning.
    Returns ``(certificates in input order, [(code, detail), ...])``.
    """
    certs = []  # type: List[CertInfo]
    warnings = []  # type: List[CertWarning]
    raw = data.encode('latin-1', 'replace') if isinstance(data, str) else bytes(data)
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
_IDN_DEVIATION_RE = re.compile('([ßς‌‍])')
_VIRAMA = 9  # canonical combining class of a virama (RFC 5892 CONTEXTJ for ZWJ / ZWNJ)


def _idna_label(label: str) -> Optional[str]:
    """One non-ASCII label -> ``xn--`` form, as the web app (``new URL``, UTS #46
    non-transitional) computes it; ``None`` if invalid.

    Python's ``idna`` codec is IDNA 2003: ``straße`` would become ``strasse``, another
    registrable name. A deviation character is kept as it is (ZWJ / ZWNJ only right after
    a virama); the text around it gets the codec's nameprep mapping.
    """
    label = label.replace('ẞ', 'ß')  # capital sharp s
    try:
        if not _IDN_DEVIATION_RE.search(label):
            return label.encode('idna').decode('ascii').lower()
        out = ''
        for part in _IDN_DEVIATION_RE.split(label):
            if part in ('‌', '‍'):
                if not out or unicodedata.combining(out[-1]) != _VIRAMA:
                    return None
                out += part
            elif part in ('ß', 'ς'):
                out += part
            elif part:
                out += _idna_codec.nameprep(part)
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

    @property
    def id(self) -> str:
        """Stable identifier: the name, else the first IP."""
        return self.name or (self.ips[0] if self.ips else '')


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


def _is_header_like(tokens: Sequence[str]) -> bool:
    """A plain line that is a column heading (``hostname   ip``), as lib/inventory.js skips."""
    keys = [_normalize_header(token) for token in tokens]
    if len(keys) == 1:
        return _is_ip_header(keys[0]) or keys[0] in _NAME_RANK
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

    def add(self, name: Optional[str], ips: Sequence[str], line: int,
            groups: Sequence[str] = (), hostnames: Sequence[str] = ()) -> None:
        """Add (or merge into) server ``name``; unscannable IPs become warnings."""
        usable = []
        for ip in ips:
            reason = _unscannable_reason(ip)
            if reason is None:
                usable.append(ip)
            else:
                self.warn(line, 'INVALID_IP', '%s is not scannable (%s)' % (ip, reason))
        if not usable and not hostnames:
            if ips:
                return
            self.warn(line, 'NO_IP', name or '')
            return
        name = (name or '').strip() or (usable[0] if usable else hostnames[0])
        key = name.lower()
        server = self.servers.get(key)
        if server is None:
            server = Server(name=name, line=line, source=self.source)
            self.servers[key] = server
        for ip in usable:
            if ip not in server.ips:
                server.ips.append(ip)
        for group in groups:
            if group and group not in server.groups:
                server.groups.append(group)
        for host in hostnames:
            if host not in server.hostnames:
                server.hostnames.append(host)

    def add_hostname(self, name: str, line: int, groups: Sequence[str] = (),
                     fallback: Optional[str] = None) -> None:
        """Add a server known only by ``name`` (resolved later), or warn why it cannot be.

        A numeric name (``2026092401``, ``127.1``) is an INVALID_IP, never resolved;
        anything else that is not a hostname is NO_IP (text: ``fallback`` or the name).
        """
        host = normalize_hostname(name)
        if host:
            self.add(name, [], line, groups, [host])
        elif is_numeric_host(name):
            self.warn(line, 'INVALID_IP', numeric_host_note(name))
        else:
            self.warn(line, 'NO_IP', name if fallback is None else fallback)

    def add_token_values(self, name: Optional[str], values: Sequence[str], line: int,
                         groups: Sequence[str] = ()) -> None:
        """Add ``name`` with IPs / hostnames / CIDRs taken from free-form ``values``."""
        ips, hosts = [], []  # type: List[str], List[str]
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
            if _looks_like_ip(value):
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
        if ips or hosts:
            self.add(name, ips, line, groups, [] if ips else hosts)

    def result(self, line_count: int) -> Inventory:
        """Finish: flag IPs shared by several servers and compute stats."""
        servers = list(self.servers.values())
        seen = {}  # type: Dict[str, str]
        for server in servers:
            for ip in server.ips:
                if ip in seen and seen[ip] != server.name:
                    self.warn(server.line, 'DUPLICATE_IP',
                              '%s is listed for %s and %s' % (ip, seen[ip], server.name))
                else:
                    seen.setdefault(ip, server.name)
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
        values = [v for v in values if ip_idx or normalize_ip(v) or is_ip_block(v)]
        groups = [cells[i] for i in group_idx if i < len(cells) and cells[i]]
        name_ip = normalize_ip(name) if name else None
        if name_ip:
            values.insert(0, name_ip)
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
        for token in re.split(r'[\s,;]+', line):
            if not token:
                continue
            if '=' in token:
                key, _, value = token.partition('=')
                if key.lower() in _IP_KEYS:
                    values.append(value)
                continue  # other Ansible variables (ansible_user=...) are irrelevant
            if normalize_ip(token) or is_ip_block(token):
                values.append(token)
            elif _looks_like_ip(token):
                builder.warn(number, 'INVALID_IP', token)
                had_invalid = True
            elif name is None:
                name = token  # first word = name; later words (hosts-file aliases) ignored
        if values:
            builder.add_token_values(name, values, number, groups)
        elif had_invalid:
            continue  # "web01 10.0.0.300": a typo, do not silently resolve "web01" instead
        elif _is_header_like([t for t in re.split(r'[\s,;]+', line) if t]):
            continue  # "hostname   ip": a column heading, not a server called "hostname"
        elif name is not None:
            # A zone file's "2026092401 ; serial" line must never be resolved (glibc -> IP).
            builder.add_hostname(name, number, groups, line)


def _json_name(obj: Dict[str, Any]) -> Optional[str]:
    for key in _JSON_NAME_KEYS:
        value = obj.get(key)
        if isinstance(value, str) and value.strip() and normalize_ip(value) is None:
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


def _json_ips(node: Any, out: List[str], key: str = '') -> None:
    """Collect IP strings anywhere below ``node`` (skipping netmask/gateway/dns-like keys)."""
    if key and _JSON_SKIP_KEY_RE.search(key):
        return
    if isinstance(node, str):
        ip = normalize_ip(node)
        if ip and ip not in out:
            out.append(ip)
    elif isinstance(node, list):
        for item in node:
            _json_ips(item, out, key)
    elif isinstance(node, dict):
        for child_key, child in node.items():
            _json_ips(child, out, str(child_key))


def _json_host_values(obj: Dict[str, Any]) -> List[str]:
    """ansible_host-like values that are hostnames rather than IPs."""
    out = []
    for key in ('ansible_host', 'ansible_ssh_host'):
        value = obj.get(key)
        if isinstance(value, str) and normalize_ip(value) is None:
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
        if any(isinstance(item, str) and normalize_ip(item) for item in items):
            return True
    return False


def _json_target_tokens(text: str) -> List[str]:
    """Tokens of a JSON string that can be targets: IPs, CIDRs/ranges, dotted hostnames."""
    out = []
    for token in (t for t in re.split(r'[\s,;]+', text) if t):
        if normalize_ip(token) or is_ip_block(token):
            out.append(token)
        elif '.' in token and normalize_hostname(token) and not _looks_like_ip(token):
            out.append(token)
    return out


def _parse_json(data: Any, builder: _InventoryBuilder, key_hint: Optional[str] = None) -> None:
    """Walk JSON: server objects (name and/or IP fields), name->IP maps, lists, hostvars."""
    if isinstance(data, str):
        tokens = [t for t in re.split(r'[\s,;]+', data) if t]
        targets = _json_target_tokens(data)
        if not targets:
            return
        if key_hint is not None or len(tokens) == 1:
            builder.add_token_values(key_hint, targets, 0)       # {"web01": "10.0.0.5"}
        elif any(normalize_ip(t) for t in tokens):
            first_ip = normalize_ip(tokens[0])                    # "ip name" / "name ip"
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
        ips = []  # type: List[str]
        _json_ips(data, ips)
        values = ips or _json_host_values(data)
        if values:
            builder.add_token_values(name or key_hint, values, 0)
        elif name:
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

    Unlike inventory lines, every token is its own server. Raises :class:`UsageError`
    for tokens that are none of these, including numeric "hostnames" the system
    resolver would read as an IPv4 address (``2026092401``, ``127.1``, ``0x7f.0x1``).
    """
    builder = _InventoryBuilder('argument', allow_large)
    for token in (t for t in re.split(r'[\s,]+', value) if t):
        if '=' in token:
            name, _, target = token.partition('=')
            if not name or not target:
                raise UsageError('invalid target %r (expected NAME=IP)' % token)
            if is_numeric_host(target):
                raise UsageError('invalid target %r: %s; write addresses as a.b.c.d'
                                 % (token, numeric_host_note(target)))
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
        # 010.0.0.1, and the address part of 010.0.0.0/24 or 010.0.0.1-5
        if _has_ambiguous_ipv4_part(token) and _looks_like_ip(re.split(r'[/-]', token)[0]):
            legacy = _legacy_ipv4(token)
            raise UsageError('invalid target %r: an IPv4 part with a leading zero is ambiguous '
                             '(the system resolver reads it as octal%s)'
                             % (token, ': ' + legacy if legacy else ''))
        if is_numeric_host(token) and not _looks_like_ip(token):
            raise UsageError('invalid target %r: %s; write addresses as a.b.c.d'
                             % (token, numeric_host_note(token)))
        if _looks_like_path(token):
            raise UsageError('target file not found: %s' % value)
        host = normalize_hostname(token)
        if host is None or _looks_like_ip(token):
            raise UsageError('invalid target %r (expected a file, IP, CIDR, range or hostname)'
                             % token)
        builder.add(token, [], 0, (), [host])
    return builder.result(0)


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
                    if ip not in server.ips:
                        server.ips.append(ip)
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
                if ip not in existing.ips:
                    existing.ips.append(ip)
            for group in server.groups:
                if group not in existing.groups:
                    existing.groups.append(group)
            for host in server.hostnames:
                if host not in existing.hostnames:
                    existing.hostnames.append(host)
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
                                hostnames=list(server.hostnames)))
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
        """True when at least one server has status NEEDS_UPDATE."""
        return any(s.status == NEEDS_UPDATE for s in self.server_summaries())


def is_relevant(row: ProbeResult) -> bool:
    """False for a name the new certificate does not cover (installing it would not help)."""
    return row.new_cert_covers is not False


def server_status(rows: Sequence[ProbeResult]) -> str:
    """Overall status of a server from its rows.

    NEEDS_UPDATE (any name the new cert covers, or its no-SNI default cert) > UPDATED >
    TLS_ERROR > TIMEOUT (handshake) > NOT_HOSTED (some port open) > TIMEOUT (connect) >
    CLOSED. A NEEDS_UPDATE row for a name the new certificate does not cover counts as
    NOT_HOSTED here: the server hosts that name with another certificate, and installing
    the new one would not change that.
    """
    named = set()  # type: Set[str]
    for row in rows:
        if row.probe in (PROBE_SNI, PROBE_WILDCARD):
            relevant = row.status != NEEDS_UPDATE or is_relevant(row)
            named.add(row.status if relevant else NOT_HOSTED)
    default = {row.status for row in rows if row.probe == PROBE_DEFAULT}
    connect = {row.status for row in rows if row.probe == PROBE_CONNECT}
    if NEEDS_UPDATE in named or NEEDS_UPDATE in default:
        return NEEDS_UPDATE
    if UPDATED in named or UPDATED in default:
        return UPDATED
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
        if isinstance(exc, ssl.SSLEOFError):
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
    if isinstance(exc, ssl.SSLEOFError):
        return True
    if isinstance(exc, ssl.SSLError):
        return 'ALERT' in str(getattr(exc, 'reason', '') or '')
    return isinstance(exc, (ConnectionResetError, ConnectionAbortedError))


def is_transient(exc: BaseException) -> bool:
    """The connection was closed, reset or refused without a TLS alert.

    A server that does not host a name says so with an alert or a close, but a per-client
    connection limiter (nginx stream ``limit_conn``, HAProxy ``src_conn_cur``, a WAF)
    also closes or resets - so these failures are worth one retry.
    """
    return isinstance(exc, (ssl.SSLEOFError, ConnectionError))


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


def _parallel(func: Callable[[Any], Any], items: Sequence[Any], workers: int,
              on_result: Callable[[Any, Any], None], cancel: threading.Event,
              poll: float = 0.2) -> None:
    """Run ``func`` over ``items`` on a thread pool, calling ``on_result`` in this thread.

    At most ``2 * workers`` tasks are in flight, so huge CIDRs do not create millions of
    futures. Waits in short slices so Ctrl-C (KeyboardInterrupt) is delivered promptly;
    on any exception pending work is cancelled and the pool is abandoned (not joined).
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
             exclude: Iterable[Union[str, ExcludeRule]] = ()) -> ScanReport:
    """Probe every ``server IP x port`` for every name and classify the results.

    Addresses matching ``exclude`` (:class:`ExcludeRule` objects or IP / CIDR / range
    strings) are removed first - never connected to - and listed in
    :attr:`ScanReport.excluded`. Phase 1 TCP-connects each unique ip:port
    (``connect_fn``); phase 2 runs one TLS handshake per open endpoint and unique SNI
    plus one without SNI (``tls_fn``), at most :data:`MAX_PER_ENDPOINT` at a time per
    endpoint, and retries a closed / reset / refused handshake (:func:`is_transient`)
    once where others completed. Both functions are injectable for tests.
    ``progress(phase, done, total, info)`` is called from this thread with phase
    ``connect``, ``tls`` or ``retry``. KeyboardInterrupt propagates.
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
            for port in ports:
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
    # connection limits, and the resets would read as "server refused this name".
    snis = [None] if default_probe else []  # type: List[Optional[str]]
    seen_snis = set()  # type: Set[str]
    for probe in probes:
        if probe.sni not in seen_snis:
            seen_snis.add(probe.sni)
            snis.append(probe.sni)
    open_endpoints = [endpoint for endpoint in endpoints.values() if endpoint.state == OPEN]
    jobs = [(endpoint, sni) for sni in snis for endpoint in open_endpoints]
    slots = {(endpoint.ip, endpoint.port): threading.BoundedSemaphore(MAX_PER_ENDPOINT)
             for endpoint in open_endpoints}
    handshakes = {}  # type: Dict[Tuple[str, int, Optional[str]], TlsResult]
    tls_done = [0]

    def do_tls(job: Tuple[Endpoint, Optional[str]]) -> TlsResult:
        endpoint, sni = job
        with slots[(endpoint.ip, endpoint.port)]:  # waiting here is not handshake time
            if cancel.is_set():
                return TlsResult(status=TLS_ERROR, error='not probed')
            try:
                return tls_fn(endpoint.ip, endpoint.port, sni, timeout)
            except Exception as exc:  # noqa: BLE001 - injected/unknown failures
                status, message = classify_exception(exc)
                return TlsResult(status=status, error=message, refused=is_refusal(exc),
                                 transient=is_transient(exc))

    def on_tls(job: Tuple[Endpoint, Optional[str]], result: TlsResult) -> None:
        handshakes[(job[0].ip, job[0].port, job[1])] = result
        tls_done[0] += 1
        if progress:
            progress('tls', tls_done[0], len(jobs), {})

    _parallel(do_tls, jobs, workers, on_tls, cancel)

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
            for port in ports:
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
                                            relevant_probes, None, works=works))
                for probe in probes:
                    results.append(_verdict(server.name, endpoint, probe.name, probe.sni,
                                            handshakes.get((ip, port, probe.sni)), cert_of,
                                            new_fps, probes, new_covers(probe.sni),
                                            PROBE_WILDCARD if probe.wildcard else PROBE_SNI,
                                            works=works))
    return ScanReport(servers=list(servers), probes=list(probes), ports=ports,
                      new_certs=list(new_certs), endpoints=list(endpoints.values()),
                      results=results, certificates=certificates, started_at=started,
                      finished_at=_utcnow(), timeout=timeout, workers=workers,
                      warnings=list(warnings or []),
                      exclude=[rule.label for rule in exclude_rules], excluded=excluded)


def _verdict(server: str, endpoint: Endpoint, name: Optional[str], sni: Optional[str],
             result: Optional[TlsResult], cert_of: Callable[[TlsResult], Union[CertInfo, str]],
             new_fps: Set[str], probes: Sequence[ProbeName], new_cert_covers: Optional[bool],
             kind: str = PROBE_DEFAULT, works: bool = False) -> ProbeResult:
    """Classify one handshake result into a :class:`ProbeResult` row.

    ``works`` tells whether any other handshake on the same ip:port completed.
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
                row.status, row.covered_by = NEEDS_UPDATE, by
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
        row.status = NEEDS_UPDATE
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


def report_to_dict(report: ScanReport) -> Dict[str, Any]:
    """The ``--json`` document (see the module docstring / README for field meanings)."""
    now = report.finished_at
    new_fps = {cert.sha256 for cert in report.new_certs}
    summaries = report.server_summaries()
    servers = []
    for summary in summaries:
        by_status = {}  # type: Dict[str, List[str]]
        for row in summary.rows:
            if row.probe in (PROBE_SNI, PROBE_WILDCARD) and row.name:
                key = 'OTHER' if row.status == NEEDS_UPDATE and not is_relevant(row) \
                    else row.status
                names = by_status.setdefault(key, [])
                if row.name not in names:
                    names.append(row.name)
        default_rows = [row for row in summary.rows if row.probe == PROBE_DEFAULT]
        servers.append({
            'name': summary.server.name,
            'ips': list(summary.server.ips),
            'groups': list(summary.server.groups),
            'status': summary.status,
            'needsUpdate': by_status.get(NEEDS_UPDATE, []),
            'updated': by_status.get(UPDATED, []),
            'errors': by_status.get(TLS_ERROR, []) + by_status.get(TIMEOUT, []),
            # hosted with another certificate that the new one does not cover
            'hostedNotInNewCert': by_status.get('OTHER', []),
            'defaultCertNeedsUpdate': any(r.status == NEEDS_UPDATE for r in default_rows),
        })
    certificates = {}
    for sha, cert in report.certificates.items():
        entry = cert.to_dict(now)
        entry['isNewCert'] = sha in new_fps
        certificates[sha] = entry
    return {
        'tool': 'ssl_origin_scan',
        'version': __version__,
        'startedAt': iso_utc(report.started_at),
        'finishedAt': iso_utc(report.finished_at),
        'elapsedSeconds': round((report.finished_at - report.started_at).total_seconds(), 3),
        'options': {'ports': list(report.ports), 'timeoutSeconds': report.timeout,
                    'workers': report.workers, 'exclude': list(report.exclude)},
        'newCertificates': [cert.to_dict(now) for cert in report.new_certs],
        'names': [{'name': p.name, 'sni': p.sni, 'wildcard': p.wildcard} for p in report.probes],
        'summary': {
            'servers': len(report.servers),
            'endpoints': len(report.endpoints),
            'openEndpoints': sum(1 for e in report.endpoints if e.state == OPEN),
            'serversNeedingUpdate': sum(1 for s in summaries if s.status == NEEDS_UPDATE),
            'serversUpdated': sum(1 for s in summaries if s.status == UPDATED),
            'statusCounts': report.status_counts(),
            'excludedAddresses': report.excluded_count(),
        },
        'servers': servers,
        'endpoints': [{'ip': e.ip, 'port': e.port, 'state': e.state, 'error': e.error,
                       'connectMs': e.connect_ms} for e in report.endpoints],
        'results': [_row_dict(row, now) for row in report.results],
        # target addresses --exclude removed before the scan (never connected to)
        'excluded': [{'server': e.server, 'ip': e.ip, 'excludedBy': e.rule}
                     for e in report.excluded],
        'certificates': certificates,
        'warnings': list(report.warnings),
    }


def render_json(report: ScanReport, ensure_ascii: bool = False) -> str:
    """Pretty-printed JSON text of :func:`report_to_dict` (UTF-8, 2-space indent).

    ``ensure_ascii=True`` escapes non-ASCII characters (``\\u00fc``) - used when stdout is
    not UTF-8, so every consumer decodes the JSON correctly whatever the code page.
    """
    return json.dumps(report_to_dict(report), indent=2, ensure_ascii=ensure_ascii) + '\n'


CSV_COLUMNS = ('server', 'ip', 'port', 'probe', 'name', 'sni', 'status', 'covered_by',
               'new_cert_covers', 'cert_subject_cn', 'cert_issuer', 'cert_serial',
               'cert_not_after', 'cert_days_left', 'cert_sha256', 'tls_version', 'error')

# Leading characters that make a spreadsheet evaluate a cell (CSV injection); the same set
# as FORMULA_START in assets/js/lib/export.js.
_CSV_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')


def _csv_cell(value: Any) -> Any:
    """A spreadsheet-safe cell: text starting with ``= + - @`` TAB or CR gets a leading
    apostrophe, like the web app's ``toCsv``, and control characters are escaped
    (:func:`display_text`, for ``--csv -`` on a terminal). Numbers are left untouched."""
    if not isinstance(value, str):
        return value
    if value.startswith(_CSV_FORMULA_START):
        value = "'" + value
    return display_text(value)


def render_csv(report: ScanReport, lineterminator: str = '\r\n') -> str:
    """One CSV row per result (RFC 4180 quoting); columns are :data:`CSV_COLUMNS`.

    With ``--exclude``, one more row per excluded target address follows the results:
    probe ``excluded``, status ``EXCLUDED``, empty port, the matching rule in ``error``.
    Certificate fields come from whatever server answered, so every text cell goes
    through :func:`_csv_cell` (a certificate CN ``=HYPERLINK(...)`` stays text in Excel);
    the JSON report keeps the exact values.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator=lineterminator)
    writer.writerow(CSV_COLUMNS)
    for row in report.results:
        data = _row_dict(row, report.finished_at)
        covers = data['newCertCovers']
        writer.writerow([_csv_cell(value) for value in (
            data['server'], data['ip'], data['port'], data['probe'], data['name'] or '',
            data['sni'] or '', data['status'], data['coveredBy'] or '',
            '' if covers is None else ('yes' if covers else 'no'),
            data['certSubjectCN'] or '', data['certIssuer'] or '', data['certSerial'] or '',
            data['certNotAfter'] or '',
            '' if data['certDaysLeft'] is None else data['certDaysLeft'],
            data['certSha256'] or '', data['tlsVersion'] or '', data['error'] or '',
        )])
    for entry in report.excluded:
        row = dict.fromkeys(CSV_COLUMNS, '')  # type: Dict[str, Any]
        row.update(server=entry.server, ip=entry.ip, probe=PROBE_EXCLUDED, status=EXCLUDED,
                   error='excluded by --exclude %s (never probed)' % entry.rule)
        writer.writerow([_csv_cell(row[column]) for column in CSV_COLUMNS])
    return buffer.getvalue()


class Style:
    """ANSI styling that degrades to plain text when disabled."""

    _CODES = {'bold': '1', 'dim': '2', 'red': '31', 'green': '32', 'yellow': '33',
              'blue': '34', 'magenta': '35', 'cyan': '36', 'gray': '90'}
    _STATUS = {NEEDS_UPDATE: ('red', 'bold'), UPDATED: ('green', 'bold'), NOT_HOSTED: ('gray',),
               TLS_ERROR: ('magenta',), TIMEOUT: ('yellow',), CLOSED: ('gray',)}

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
    out = []
    for char in text:
        if unicodedata.category(char) in ('Cc', 'Cf', 'Zl', 'Zp'):
            code = ord(char)
            out.append('\\x%02x' % code if code < 0x100 else
                       '\\u%04x' % code if code < 0x10000 else '\\U%08x' % code)
        else:
            out.append(char)
    return ''.join(out)


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
    order = [(NEEDS_UPDATE, True), (UPDATED, True), (UPDATED, False), (NEEDS_UPDATE, False),
             (TLS_ERROR, True), (TLS_ERROR, False), (TIMEOUT, True), (TIMEOUT, False),
             (NOT_HOSTED, True), (NOT_HOSTED, False)]
    key = (status, relevant)
    return order.index(key) if key in order else len(order)


def _render_server(summary: ServerSummary, style: Style, show_all: bool, width: int,
                   now: datetime, has_new_cert: bool) -> List[str]:
    """Lines for one server: per endpoint, names grouped by (status, served certificate)."""
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
            show_all or default.status in (NEEDS_UPDATE, UPDATED))
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
            if has_new_cert and not relevant and status in (NEEDS_UPDATE, UPDATED):
                text += '  (not covered by the new certificate)'
            out.extend(_wrap(prefix, indent, text, width))
            cert = group[0].cert
            if status in (NEEDS_UPDATE, NOT_HOSTED) and cert is not None:
                out.append(' ' * indent + 'current: ' + cert_line(cert, now, style))
                out.append(' ' * (indent + 9) + style.paint(cert_ids(cert), 'dim'))
            elif error:  # handshake failures, names the server refused
                out.append(' ' * indent + style.paint(display_text(error), 'dim'))
        if show_default and default is not None:
            text = '      default certificate (no SNI): %s' % style.status(default.status)
            if default.cert is not None:
                text += '  ' + cert_line(default.cert, now, style)
            elif default.error:
                text += '  ' + style.paint(display_text(default.error), 'dim')
            out.append(text)
    return out


def _section(lines: List[str], title: str, summaries: Sequence[ServerSummary], style: Style,
             colors: Sequence[str], show_all: bool, width: int, now: datetime,
             has_new: bool) -> None:
    lines.append(style.paint('%s: %d' % (title, len(summaries)), *colors))
    for summary in summaries:
        lines.extend(_render_server(summary, style, show_all, width, now, has_new))
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
                   width: int = 100) -> str:
    """Human-readable report, most actionable first.

    Sections: servers that need the new certificate (with the certificate they serve now,
    its expiry, days left and issuer), servers already serving it, handshake errors,
    servers that host only names the new certificate does not cover, and - only with
    ``show_all`` - servers not hosting any name and unreachable ones (otherwise counted).
    """
    style = Style(color)
    now = report.finished_at
    summaries = report.server_summaries()
    has_new = bool(report.new_certs)
    elapsed = (report.finished_at - report.started_at).total_seconds()
    open_count = sum(1 for e in report.endpoints if e.state == OPEN)
    header = 'SSL origin scan: %d server(s), %d endpoint(s) (%d open), %d name(s), ' \
        'ports %s, %.1fs' % (len(report.servers), len(report.endpoints), open_count,
                             len(report.probes), ','.join(str(p) for p in report.ports), elapsed)
    lines = [style.paint(header, 'bold')]
    if report.exclude:
        lines.append(_excluded_line(report, style))
    for cert in report.new_certs:
        lines.append('New certificate: %s | %s' % (cert_line(cert, now, style), cert_ids(cert)))
    if not has_new:
        lines.append(style.paint('No --cert given: every server whose certificate covers a name '
                                 'is listed (status NEEDS_UPDATE).', 'dim'))
    lines.append('')

    buckets = {}  # type: Dict[str, List[ServerSummary]]
    for summary in summaries:
        buckets.setdefault(summary.status, []).append(summary)
    needs = buckets.get(NEEDS_UPDATE, [])
    _section(lines, 'Servers that need the new certificate' if has_new
             else 'Servers hosting the names', needs, style,
             ('red', 'bold') if needs else ('green', 'bold'), show_all, width, now, has_new)
    if has_new:
        _section(lines, 'Already serving the new certificate', buckets.get(UPDATED, []), style,
                 ('green', 'bold'), show_all, width, now, has_new)

    errors = [s for s in buckets.get(TLS_ERROR, []) + buckets.get(TIMEOUT, [])
              if any(r.probe != PROBE_CONNECT for r in s.rows)]
    if errors:
        _section(lines, 'Handshake errors', errors, style, ('magenta', 'bold'), show_all, width,
                 now, has_new)

    not_hosted = buckets.get(NOT_HOSTED, [])
    other_cert = [s for s in not_hosted if any(r.status == NEEDS_UPDATE and not is_relevant(r)
                                               for r in s.rows)]
    not_hosted = [s for s in not_hosted if s not in other_cert]
    if other_cert:
        _section(lines, 'Hosting only names the new certificate does not cover', other_cert,
                 style, ('bold',), show_all, width, now, has_new)
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
    totals = ', '.join('%s %d' % (style.status(status), counts.get(status, 0))
                       for status in (NEEDS_UPDATE, UPDATED, NOT_HOSTED, TLS_ERROR, TIMEOUT,
                                      CLOSED))
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

targets (-t, repeatable):
  an IP, hostname, CIDR (10.0.0.0/24), range (10.0.0.10-10.0.0.50 or 10.0.0.10-50),
  NAME=IP, "-" for stdin, or a file (format auto-detected):
    "name ip [ip...]" / "ip name" lines, /etc/hosts, CSV/TSV with a header row
    (name/hostname/server + ip/public_ip/private_ip/ipv4/ipv6/address columns, Turkish
    headers too; gateway, DNS, NTP, iLO/iDRAC/IPMI/BMC, MAC and e-mail columns are not
    server addresses),
    Ansible INI (web01 ansible_host=10.0.0.5, [groups]), simple Ansible YAML, JSON.
  Entries without an IP are resolved with the system resolver (IPv4 and IPv6).
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
  never needed; if the file contains one it is ignored.

statuses (per server, port and name):
  UPDATED       serves the new certificate (--cert) for the name
  NEEDS_UPDATE  serves a certificate covering the name, but not the new one
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

exit codes: 0 done, 1 NEEDS_UPDATE found (only with --fail-on-needs-update),
            2 usage error, 130 interrupted (Ctrl-C)

output encoding: follows the reader - the console code page when piped on Windows
  (cmd, PowerShell), UTF-8 for files, Git Bash and other systems. PYTHONIOENCODING=utf-8
  forces UTF-8 (e.g. for PowerShell 7 "> file"); --json/--csv FILE are always UTF-8.

Türkçe: yeni sertifikanın hangi sunuculara yüklenmesi gerektiğini bulur, örnek:
  python3 ssl_origin_scan.py -t sunucular.txt --cert yeni-sertifika.pem
  Dokunulmaması gereken adresleri --exclude ile çıkarın: IP, CIDR ya da aralık,
  boşlukla ayrılmış ya da satır başına bir adres içeren bir dosya. Bu adreslere
  hiç bağlanılmaz; alan adı kabul edilmez. Örnek:
  python3 ssl_origin_scan.py -t 10.0.0.0/24 --exclude 10.0.0.5 10.0.0.64/28 -n www.example.com
  2026092401 ya da 0x7f.0x1 gibi sayısal "alan adları" reddedilir: sistem çözümleyicisi
  bunları IPv4 adresi olarak okur.
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
                           'enables UPDATED detection (repeatable, e.g. RSA + ECDSA)')
    scan = parser.add_argument_group('scan options')
    scan.add_argument('-p', '--ports', default=DEFAULT_PORTS, metavar='LIST',
                      help='TLS ports, comma separated, ranges allowed (default: 443)')
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
                     help='exit with code 1 when any server needs the new certificate')
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


def _write_output(path: str, text: str, encoding: str = 'utf-8') -> None:
    if path == '-':
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    try:
        with open(path, 'w', encoding=encoding, newline='') as handle:
            handle.write(text)
    except OSError as exc:
        raise UsageError('cannot write %s: %s' % (path, exc.strerror or exc))


def _check_output_path(path: Optional[str], option: str) -> None:
    if not path or path == '-':
        return
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise UsageError('%s: directory does not exist: %s' % (option, directory))
    if os.path.isdir(path):
        raise UsageError('%s: %s is a directory' % (option, path))


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
    '←': '<-', '✓': 'v', '✗': 'x', '×': 'x', ' ': ' ', '•': '*',
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
    _check_output_path(args.json, '--json')
    _check_output_path(args.csv, '--csv')
    exclude_rules = load_excludes(args.exclude)  # strict: bad input stops before any lookup

    all_warnings = []  # type: List[str]
    new_certs = []  # type: List[CertInfo]
    for path in args.cert:
        leaf, messages = load_new_certificate(path)
        if all(leaf.sha256 != cert.sha256 for cert in new_certs):
            new_certs.append(leaf)
        all_warnings.extend(messages)

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
        print('Scanning %d server(s) / %d IP(s) x %d port(s) for %d name(s) with %d workers, '
              'timeout %gs%s ...' % (len(kept), ip_count, len(ports), len(probes),
                                     args.workers, args.timeout, skipped), file=err)
    progress = ProgressPrinter(err, enabled=not quiet and _isatty(err))
    try:
        # run_scan applies the same exclusion itself, so it is enforced where connections start.
        report = run_scan(servers, probes, ports, new_certs=new_certs, timeout=args.timeout,
                          workers=args.workers, progress=progress.update,
                          warnings=all_warnings, exclude=exclude_rules)
    finally:
        progress.finish()

    if args.json:
        # Escape non-ASCII when stdout is not UTF-8 so any consumer parses it correctly.
        _write_output(args.json, render_json(
            report, ensure_ascii=args.json == '-' and not _stream_is_utf8(sys.stdout)))
    if args.csv:
        # BOM so Excel opens UTF-8 (Turkish characters) correctly; none on stdout.
        if args.csv == '-':
            _write_output('-', render_csv(report, lineterminator='\n'))
        else:
            _write_output(args.csv, render_csv(report), encoding='utf-8-sig')
    if args.json != '-' and args.csv != '-':
        width = max(60, min(160, shutil.get_terminal_size((100, 24)).columns))
        sys.stdout.write(render_summary(report, color=use_color(args.no_color, sys.stdout),
                                        show_all=args.show_all, width=width))
        sys.stdout.flush()
    if not quiet:
        for path, label in ((args.json, 'JSON'), (args.csv, 'CSV')):
            if path and path != '-':
                print('%s report written to %s' % (label, path), file=err)
    if args.fail_on_needs_update and report.needs_update():
        return EXIT_NEEDS_UPDATE
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point; returns the exit code (0, 1, 2 or 130)."""
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
    except BrokenPipeError:  # e.g. `... | head`
        try:
            _devnull = os.open(os.devnull, os.O_WRONLY)
            os.dup2(_devnull, sys.stdout.fileno())
        except OSError:
            pass
        _code = EXIT_OK
    if _code == EXIT_INTERRUPTED:
        # Do not wait for in-flight connections to time out: leave immediately.
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(_code)
    sys.exit(_code)
