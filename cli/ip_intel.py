#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ip_intel.py - the names an IP address serves, or served, seen from inside your network.

Companion CLI of the "DomainScope - SSL & DNS Toolkit" web app
(https://github.com/halilibrahimd27/domainscope). The web app's reverse-IP lookups run in a
browser: they reach only the services that send CORS headers, and a private address never
leaves the page. This script runs the lookup from your own machine, for one address, a CIDR
range or a file of them, and adds what a browser cannot do:

  1. TLS: the certificate each address serves on --ports (443) without SNI, then again with
     the SNI of the names found (the certificates' own names first) - what the server says it
     hosts, also for addresses only your network reaches;
  2. PTR, through the system resolver;
  3. free passive sources (unless --no-passive): HackerTarget reverse IP, AlienVault OTX
     passive DNS, Robtex passive DNS, Shodan InternetDB and mnemonic passive DNS (which sends
     no CORS headers, so no browser can ask it);
  4. sources that need a key of yours, read from environment variables only: SecurityTrails,
     VirusTotal, Shodan, Censys, ViewDNS, WhoisXML API and Netlas.

A private or reserved address never goes to a third party: it gets TLS and PTR only. Every
name is merged with its sources and first / last seen dates, then checked with the system
resolver: HERE (it resolves to the address now), MOVED (to other addresses only) or
NO_ADDRESS. A source that fails is a status of its address (RATE_LIMITED, REFUSED, TIMEOUT,
ERROR), never a silent gap. Keys are never printed, logged or written to a report.

Python 3.8+, standard library only, single file - copy it anywhere.

The module is importable: parse_targets(), normalize_name(), parse_certificate(), the
parse_<source>() parsers, ask_source(), run_domains(), render_text(), report_to_dict(),
render_csv() and main() are the public API.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

__version__ = '1.0.0'
PROG = 'ip_intel.py'
SCHEMA = 'domainscope.ip-intel/1'
USER_AGENT = 'ip_intel/%s (+https://github.com/halilibrahimd27/domainscope)' % __version__

# --- name statuses: what the system resolver says about a name now ---------------------
HERE = 'HERE'                  # the name resolves to the address
MOVED = 'MOVED'                # it resolves, to other addresses only
NO_ADDRESS = 'NO_ADDRESS'      # it does not resolve (NXDOMAIN, or no A / AAAA)
WILDCARD = 'WILDCARD'          # a certificate's *.name: it covers names, it is not one
LOOKUP_ERROR = 'LOOKUP_ERROR'  # the resolver gave no answer (timeout, SERVFAIL)
UNCHECKED = 'UNCHECKED'        # not checked (--no-verify)
STATUSES = (HERE, MOVED, NO_ADDRESS, WILDCARD, LOOKUP_ERROR, UNCHECKED)
# The CSV row of an address without a single name (not a name status).
NO_NAMES = 'NO_NAMES'

# --- source statuses, per address ----------------------------------------------------------
OK = 'OK'
SKIPPED = 'SKIPPED'            # not asked: a private address, IPv6 at an IPv4-only source
RATE_LIMITED = 'RATE_LIMITED'  # its quota or rate limit (HTTP 429 / 402, or its own text)
REFUSED = 'REFUSED'            # HTTP 401 / 403: the key was refused, or this client
TIMEOUT = 'TIMEOUT'            # no answer in --timeout seconds
ERROR = 'ERROR'                # a network or HTTP error, or an answer that could not be read
SOURCE_STATUSES = (OK, SKIPPED, RATE_LIMITED, REFUSED, TIMEOUT, ERROR)
FAILED = (RATE_LIMITED, REFUSED, TIMEOUT, ERROR)

# --- a TLS port, asked without SNI -------------------------------------------------------
PORT_OK = 'OK'                 # a certificate
PORT_CLOSED = 'CLOSED'         # connection refused
PORT_TIMEOUT = 'TIMEOUT'
PORT_TLS_ERROR = 'TLS_ERROR'   # connected, no handshake (often: the server wants an SNI)
PORT_ERROR = 'ERROR'           # unreachable, or another socket error
PORT_STATES = (PORT_OK, PORT_CLOSED, PORT_TIMEOUT, PORT_TLS_ERROR, PORT_ERROR)

# --- how the address's TLS shows a name ------------------------------------------------
TLS_SNI = 'SNI'    # asked with the name as SNI, the address served a certificate that covers it
TLS_CERT = 'CERT'  # the name is in a certificate the address serves

EXIT_OK = 0
EXIT_SOURCE_ERRORS = 1   # only with --fail-on-error
EXIT_USAGE = 2
EXIT_OUTPUT_ERROR = 3    # a --json / --csv file could not be written after the run
EXIT_INTERRUPTED = 130

DEFAULT_PORTS = (443,)
DEFAULT_TIMEOUT = 10.0
DEFAULT_WORKERS = 8
MAX_WORKERS = 64
DEFAULT_MAX_ADDRESSES = 1024   # an IPv4 /22
MAX_ADDRESSES = 65536
DEFAULT_SNI_MAX = 16           # SNI handshakes per address and port
MAX_PORTS = 16
MAX_BODY = 8 * 1024 * 1024
MAX_TARGET_FILE = 20 * 1024 * 1024
MNEMONIC_LIMIT = 1000          # records asked of mnemonic per address (one page)


class UsageError(Exception):
    """Bad command line or input; reported as ``error: ...`` with exit code 2."""


class HttpFailure(Exception):
    """A request without an HTTP answer."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind  # 'timeout' | 'network'


class LookupFailure(Exception):
    """A system-resolver question without an answer (not: a name without an address)."""


# ---------------------------------------------------------------------------------------
# Names and addresses
# ---------------------------------------------------------------------------------------

_LABEL_RE = re.compile(r'^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$')


def normalize_name(value: Any) -> Optional[str]:
    """A host name as reported: lowercase, no trailing dot, IDNA (``xn--``) for a non-ASCII
    name; a leading ``*.`` is kept (a certificate's wildcard). None for anything else: an
    address, a single label, an empty or over-long label, a character no host name holds."""
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if text.endswith('.'):
        text = text[:-1]
    wildcard = text.startswith('*.')
    body = text[2:] if wildcard else text
    if not body or len(body) > 253:
        return None
    if any(ord(char) > 0x7f for char in body):
        try:
            body = body.encode('idna').decode('ascii')
        except (UnicodeError, ValueError):
            return None
    labels = body.split('.')
    if len(labels) < 2 or not all(_LABEL_RE.match(label) for label in labels):
        return None
    if labels[-1].isdigit() or labels[-1] == 'arpa':
        return None  # an IPv4 address, a name no resolver serves, a reverse-DNS name
    return '*.' + body if wildcard else body


def name_covers(pattern: str, host: str) -> bool:
    """Whether a certificate name covers ``host``: the same name, or ``*.base`` for exactly
    one label in front of ``base``."""
    if pattern == host:
        return True
    if pattern.startswith('*.'):
        head, _, rest = host.partition('.')
        return bool(head) and rest == pattern[2:]
    return False


def canonical_ip(value: str) -> Optional[str]:
    """An address in its canonical text (IPv4-mapped IPv6 as IPv4), or None."""
    try:
        addr = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return str(addr)


def is_public(ip: str) -> bool:
    """True for an address a third party may hear about: global unicast. Private, loopback,
    link-local, shared (CGNAT), documentation, multicast and reserved ranges are False."""
    addr = ipaddress.ip_address(ip)
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return bool(addr.is_global) and not (addr.is_private or addr.is_multicast or addr.is_reserved
                                         or addr.is_loopback or addr.is_link_local
                                         or addr.is_unspecified)


def _network_addresses(net: Any) -> Iterable[Any]:
    # An IPv4 network without its network and broadcast addresses (a /31 or /32: every one).
    if net.version == 4 and net.prefixlen < 31:
        return net.hosts()
    return iter(net)


def _read_text(path: str, stdin: Optional[Any] = None) -> str:
    if path == '-':
        return (stdin or sys.stdin).read()
    try:
        if os.path.getsize(path) > MAX_TARGET_FILE:
            raise UsageError('%s is larger than %d MB' % (path, MAX_TARGET_FILE // (1024 * 1024)))
        with open(path, 'rb') as handle:
            raw = handle.read()
    except OSError as exc:
        raise UsageError('cannot read %s: %s' % (path, exc.strerror or exc))
    for encoding in ('utf-8-sig', 'utf-16'):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if encoding == 'utf-8-sig' or raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
            return text
    return raw.decode('latin-1')


def parse_targets(values: Sequence[str], max_addresses: int = DEFAULT_MAX_ADDRESSES,
                  stdin: Optional[Any] = None) -> Tuple[List[str], List[str]]:
    """The addresses of ``values`` - addresses, CIDR ranges, files of them ('-' = stdin; one
    or more a line, ``#`` comments) - in order without repeats, and a warning per file token
    that is neither. Raises :class:`UsageError` for a value that is none of them, and for more
    than ``max_addresses`` addresses (a range is checked before it is expanded)."""
    addresses = []  # type: List[str]
    seen = set()  # type: Set[str]
    warnings = []  # type: List[str]

    def add(ip: str) -> None:
        if ip in seen:
            return
        if len(addresses) >= max_addresses:
            raise UsageError('more than --max %d addresses: give fewer or raise --max' % max_addresses)
        seen.add(ip)
        addresses.append(ip)

    def add_token(token: str) -> bool:
        ip = canonical_ip(token)
        if ip:
            add(ip)
            return True
        if '/' not in token:
            return False
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            return False
        if net.num_addresses > max_addresses:
            raise UsageError('%s holds %d addresses, more than --max %d: give a smaller range or '
                             'raise --max' % (token, net.num_addresses, max_addresses))
        for addr in _network_addresses(net):
            add(canonical_ip(str(addr)) or str(addr))
        return True

    for value in values:
        token = value.strip()
        if token and add_token(token):
            continue
        if token == '-' or (token and os.path.isfile(token)):
            label = 'stdin' if token == '-' else token
            for number, line in enumerate(_read_text(token, stdin).splitlines(), 1):
                for item in re.split(r'[\s,;]+', line.split('#', 1)[0]):
                    if item and not add_token(item):
                        warnings.append('%s line %d: %s is not an address or a CIDR range; skipped'
                                        % (label, number, _plain(item[:80])))
            continue
        raise UsageError('%s is not an address, a CIDR range or a file' % _plain(token or '""'))
    return addresses, warnings


# ---------------------------------------------------------------------------------------
# Certificates: a minimal DER reader for the names, the issuer and the expiry
# ---------------------------------------------------------------------------------------

class DerError(ValueError):
    """Malformed DER, or not an X.509 certificate."""


Tlv = Tuple[int, int, int, int]  # tag, header start, content start, content end

_OID_CN = '2.5.4.3'
_OID_O = '2.5.4.10'
_OID_SAN = '2.5.29.17'


def _read_tlv(buf: bytes, pos: int, end: int) -> Tlv:
    start = pos
    if pos + 2 > end:
        raise DerError('unexpected end of data')
    tag = buf[pos]
    if tag & 0x1F == 0x1F:
        raise DerError('high tag numbers are not used in a certificate')
    first = buf[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DerError('indefinite length')
    else:
        count = first & 0x7F
        if count > 4 or pos + count > end:
            raise DerError('bad length')
        length = int.from_bytes(buf[pos:pos + count], 'big')
        pos += count
    if length > end - pos:
        raise DerError('length exceeds the data')
    return tag, start, pos, pos + length


def _children(buf: bytes, start: int, end: int) -> List[Tlv]:
    out = []  # type: List[Tlv]
    while start < end:
        tlv = _read_tlv(buf, start, end)
        out.append(tlv)
        start = tlv[3]
    return out


def _expect(tlv: Tlv, tag: int, what: str) -> Tlv:
    if tlv[0] != tag:
        raise DerError('expected %s' % what)
    return tlv


def _decode_oid(data: bytes) -> str:
    if not data or data[-1] & 0x80 or len(data) > 64:
        raise DerError('bad OBJECT IDENTIFIER')
    arcs = []  # type: List[int]
    value = 0
    for octet in data:
        value = (value << 7) | (octet & 0x7F)
        if not octet & 0x80:
            arcs.append(value)
            value = 0
    first = arcs[0]
    head = [0, first] if first < 40 else [1, first - 40] if first < 80 else [2, first - 80]
    return '.'.join(str(arc) for arc in head + arcs[1:])


def _decode_string(tag: int, data: bytes) -> Optional[str]:
    if tag == 0x0C:                          # UTF8String
        return data.decode('utf-8', 'replace')
    if tag in (0x12, 0x13, 0x14, 0x16, 0x1A):  # Numeric, Printable, Teletex, IA5, Visible
        return data.decode('latin-1')
    if tag == 0x1E:                          # BMPString
        return data.decode('utf-16-be', 'replace')
    if tag == 0x1C:                          # UniversalString
        return data.decode('utf-32-be', 'replace')
    return None


def _name_attrs(buf: bytes, tlv: Tlv) -> Dict[str, str]:
    """The first CN and O of an X.501 Name."""
    found = {}  # type: Dict[str, str]
    for rdn in _children(buf, tlv[2], tlv[3]):
        for atv in _children(buf, rdn[2], rdn[3]):
            parts = _children(buf, atv[2], atv[3])
            if len(parts) != 2 or parts[0][0] != 0x06:
                continue
            oid = _decode_oid(buf[parts[0][2]:parts[0][3]])
            text = _decode_string(parts[1][0], buf[parts[1][2]:parts[1][3]])
            key = 'CN' if oid == _OID_CN else 'O' if oid == _OID_O else None
            if key and text is not None and key not in found:
                found[key] = text
    return found


def _day_of_time(tag: int, data: bytes) -> Optional[str]:
    try:
        text = data.decode('ascii')
        if tag == 0x17:   # UTCTime, RFC 5280 50-year pivot
            yy = int(text[:2])
            year, rest = (1900 + yy if yy >= 50 else 2000 + yy), text[2:]
        elif tag == 0x18:  # GeneralizedTime
            year, rest = int(text[:4]), text[4:]
        else:
            return None
        return datetime(year, int(rest[:2]), int(rest[2:4])).strftime('%Y-%m-%d')
    except (UnicodeDecodeError, ValueError):
        return None


@dataclass
class CertFacts:
    """What one certificate says about the names it is for."""
    subject_cn: Optional[str]
    issuer: Optional[str]       # the issuer's CN, else its O
    not_after: Optional[str]    # YYYY-MM-DD (UTC)
    dns_names: List[str]        # the SAN dNSNames as written
    sha256: str

    def names(self) -> List[str]:
        """The host names it is for: its SAN names, else its CN when that is a host name."""
        raw = self.dns_names or ([self.subject_cn] if self.subject_cn else [])
        out = []  # type: List[str]
        for value in raw:
            name = normalize_name(value)
            if name and name not in out:
                out.append(name)
        return out


def parse_certificate(der: bytes) -> CertFacts:
    """The subject CN, issuer, expiry, SAN names and SHA-256 of one DER certificate. Raises
    :class:`DerError` (a ValueError) for anything that is not one."""
    buf = bytes(der)
    cert = _expect(_read_tlv(buf, 0, len(buf)), 0x30, 'a Certificate')
    top = _children(buf, cert[2], cert[3])
    if len(top) < 3:
        raise DerError('a Certificate has 3 parts')
    tbs = _expect(top[0], 0x30, 'TBSCertificate')
    fields = _children(buf, tbs[2], tbs[3])
    index = 1 if fields and fields[0][0] == 0xA0 else 0
    if len(fields) < index + 6:
        raise DerError('TBSCertificate is missing fields')
    issuer_tlv = _expect(fields[index + 2], 0x30, 'the issuer')
    validity = _expect(fields[index + 3], 0x30, 'Validity')
    subject_tlv = _expect(fields[index + 4], 0x30, 'the subject')
    times = _children(buf, validity[2], validity[3])
    not_after = _day_of_time(times[1][0], buf[times[1][2]:times[1][3]]) if len(times) == 2 else None
    issuer = _name_attrs(buf, issuer_tlv)
    subject = _name_attrs(buf, subject_tlv)
    dns_names = []  # type: List[str]
    for extra in fields[index + 6:]:
        if extra[0] != 0xA3:
            continue
        for wrapper in _children(buf, extra[2], extra[3]):
            for ext in _children(buf, wrapper[2], wrapper[3]):
                parts = _children(buf, ext[2], ext[3])
                if len(parts) < 2 or parts[0][0] != 0x06:
                    continue
                if _decode_oid(buf[parts[0][2]:parts[0][3]]) != _OID_SAN:
                    continue
                value = _expect(parts[-1], 0x04, 'extnValue')
                names = _expect(_read_tlv(buf, value[2], value[3]), 0x30, 'GeneralNames')
                for general in _children(buf, names[2], names[3]):
                    if general[0] == 0x82:  # [2] dNSName
                        dns_names.append(buf[general[2]:general[3]].decode('ascii', 'replace'))
    return CertFacts(subject.get('CN'), issuer.get('CN') or issuer.get('O'), not_after, dns_names,
                     hashlib.sha256(buf[cert[1]:cert[3]]).hexdigest())


# ---------------------------------------------------------------------------------------
# TLS, PTR and forward lookups (from this machine: nothing here is a third party)
# ---------------------------------------------------------------------------------------

def make_tls_context() -> ssl.SSLContext:
    """A deliberately permissive client: the point is whatever certificate is served, so
    nothing is verified, and old protocol versions and ciphers are allowed."""
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


def _clean_ssl_message(exc: BaseException) -> str:
    text = re.sub(r'\s*\(_ssl\.c:\d+\)', '', str(exc))
    return text or type(exc).__name__


def tls_handshake(ip: str, port: int, sni: Optional[str], timeout: float,
                  context: Optional[ssl.SSLContext] = None) -> Tuple[str, Optional[bytes], str]:
    """One handshake with ``ip:port`` (``sni`` as server name, None for none) ->
    ``(port state, the DER certificate or None, detail)``."""
    sock = None  # type: Any
    try:
        try:
            sock = socket.create_connection((ip, port), timeout=timeout)
        except ConnectionRefusedError:
            return PORT_CLOSED, None, 'connection refused'
        except (socket.timeout, TimeoutError):
            return PORT_TIMEOUT, None, 'no answer in %g s' % timeout
        except OSError as exc:
            return PORT_ERROR, None, exc.strerror or str(exc) or type(exc).__name__
        try:
            tls = (context or make_tls_context()).wrap_socket(sock, server_hostname=sni,
                                                              do_handshake_on_connect=False)
            sock = tls
            tls.settimeout(timeout)
            tls.do_handshake()
            der = tls.getpeercert(binary_form=True)
        except (socket.timeout, TimeoutError):
            return PORT_TIMEOUT, None, 'no handshake in %g s' % timeout
        except ssl.SSLError as exc:
            return PORT_TLS_ERROR, None, _clean_ssl_message(exc)
        except (OSError, ValueError) as exc:
            return PORT_TLS_ERROR, None, str(exc) or type(exc).__name__
        if not der:
            return PORT_TLS_ERROR, None, 'no certificate'
        return PORT_OK, der, ''
    finally:
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass


def _no_address_codes() -> Set[int]:
    codes = {11001, 11004}  # WSAHOST_NOT_FOUND, WSANO_DATA (Windows)
    for attr in ('EAI_NONAME', 'EAI_NODATA', 'EAI_ADDRFAMILY'):
        value = getattr(socket, attr, None)
        if isinstance(value, int):
            codes.add(value)
    return codes


_NO_PTR_ERRNOS = {1, 4, 11001, 11004}  # HOST_NOT_FOUND, NO_DATA (and the Windows codes)


def system_ptr(ip: str) -> List[str]:
    """The PTR names of ``ip`` from the system resolver ([] for none); raises
    :class:`LookupFailure` when the resolver gives no answer."""
    try:
        host, aliases, _ = socket.gethostbyaddr(ip)
    except socket.herror as exc:
        if exc.errno in _NO_PTR_ERRNOS:
            return []
        raise LookupFailure(exc.strerror or str(exc))
    except socket.gaierror as exc:
        if exc.errno in _no_address_codes():
            return []
        raise LookupFailure(exc.strerror or str(exc))
    except (OSError, UnicodeError) as exc:
        raise LookupFailure(str(exc) or type(exc).__name__)
    out = []  # type: List[str]
    for value in [host] + list(aliases):
        name = normalize_name(value)
        if name and not name.startswith('*.') and name not in out:
            out.append(name)
    return out


def system_forward(name: str) -> List[str]:
    """The addresses ``name`` resolves to with the system resolver ([] for none); raises
    :class:`LookupFailure` when the resolver gives no answer."""
    try:
        infos = socket.getaddrinfo(name, None, 0, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        if exc.errno in _no_address_codes():
            return []
        raise LookupFailure(exc.strerror or str(exc))
    except (OSError, UnicodeError, ValueError) as exc:
        raise LookupFailure(str(exc) or type(exc).__name__)
    out = []  # type: List[str]
    for info in infos:
        ip = canonical_ip(str(info[4][0]).split('%')[0])
        if ip and ip not in out:
            out.append(ip)
    return out


# ---------------------------------------------------------------------------------------
# HTTP (certificate-verified HTTPS, no redirects, a size cap)
# ---------------------------------------------------------------------------------------

@dataclass
class HttpResponse:
    status: int
    body: bytes
    headers: Dict[str, str] = field(default_factory=dict)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect is an answer, never followed: it would carry a key header to another host."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> None:
        return None


_OPENER = None  # type: Optional[urllib.request.OpenerDirector]
_OPENER_LOCK = threading.Lock()


def _opener() -> urllib.request.OpenerDirector:
    global _OPENER
    with _OPENER_LOCK:
        if _OPENER is None:
            _OPENER = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=ssl.create_default_context()), _NoRedirect)
        return _OPENER


def _reason_text(reason: Any) -> str:
    if isinstance(reason, ssl.SSLError):
        text = 'TLS: %s' % _clean_ssl_message(reason)
        if 'CERTIFICATE_VERIFY_FAILED' in text:
            text += ' (this Python may lack CA certificates; on macOS run "Install Certificates.command")'
        return text
    if isinstance(reason, OSError) and reason.strerror:
        return reason.strerror
    return str(reason) or type(reason).__name__


def http_request(url: str, headers: Optional[Mapping[str, str]] = None, data: Optional[bytes] = None,
                 timeout: float = DEFAULT_TIMEOUT) -> HttpResponse:
    """GET ``url`` (POST with ``data``) -> every HTTP answer, 4xx and 5xx included. Raises
    :class:`HttpFailure` without one. The message never holds the URL (a key can be in it)."""
    request = urllib.request.Request(url, data=data, method='POST' if data is not None else 'GET')
    request.add_header('User-Agent', USER_AGENT)
    request.add_header('Accept', 'application/json, text/plain;q=0.9, */*;q=0.1')
    for key, value in (headers or {}).items():
        request.add_header(key, value)
    try:
        with _opener().open(request, timeout=timeout) as response:
            body = response.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                raise HttpFailure('network', 'an answer larger than %d MB' % (MAX_BODY // (1024 * 1024)))
            return HttpResponse(response.status, body, {k.lower(): v for k, v in response.headers.items()})
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(65536) or b''
        except (OSError, ValueError):
            body = b''
        finally:
            exc.close()
        return HttpResponse(exc.code, body, {k.lower(): v for k, v in (exc.headers or {}).items()})
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise HttpFailure('timeout', 'no answer in %g s' % timeout)
        raise HttpFailure('network', _reason_text(exc.reason))
    except (socket.timeout, TimeoutError):
        raise HttpFailure('timeout', 'no answer in %g s' % timeout)
    except (OSError, ValueError) as exc:
        raise HttpFailure('network', _reason_text(exc))


# ---------------------------------------------------------------------------------------
# Sources: what each one answers (verified live against 1.1.1.1 on 2026-10-08, see SPEC 7.2)
# ---------------------------------------------------------------------------------------

@dataclass
class Hit:
    name: str
    first: Optional[str] = None   # YYYY-MM-DD (UTC)
    last: Optional[str] = None


@dataclass
class SourceResult:
    """One source's answer for one address."""
    source: str
    status: str
    hits: List[Hit] = field(default_factory=list)
    detail: str = ''
    total: Optional[int] = None   # the names it says it has, when it says
    truncated: bool = False       # it has more than it sent
    intel: Dict[str, Any] = field(default_factory=dict)
    asked: bool = True            # a request was made


_ISO_DAY = re.compile(r'^(\d{4})-(\d{2})-(\d{2})')


def _day(value: Any) -> Optional[str]:
    """A source's date as YYYY-MM-DD (UTC): ISO text, epoch seconds or epoch milliseconds."""
    if value is None or isinstance(value, bool) or value == '':
        return None
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e11:
            seconds /= 1000.0
        if not 0 < seconds < 4102444800:  # before 2100
            return None
        return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%d')
    text = str(value).strip()
    if text.isdigit():
        return _day(int(text))
    match = _ISO_DAY.match(text)
    return '%s-%s-%s' % match.groups() if match else None


def _earlier(a: Optional[str], b: Optional[str]) -> Optional[str]:
    return min(a, b) if a and b else a or b


def _later(a: Optional[str], b: Optional[str]) -> Optional[str]:
    return max(a, b) if a and b else a or b


def _hits(rows: Iterable[Tuple[Any, Any, Any]]) -> Tuple[List[Hit], int]:
    """Hits from ``(name, first seen, last seen)`` rows, merged per name (the earliest first,
    the latest last), and the number of values that are no host name."""
    by_name = {}  # type: Dict[str, Hit]
    bad = 0
    for raw, first, last in rows:
        name = normalize_name(raw)
        if not name:
            bad += 1
            continue
        hit = by_name.get(name)
        if hit is None:
            by_name[name] = Hit(name, _day(first), _day(last))
        else:
            hit.first = _earlier(hit.first, _day(first))
            hit.last = _later(hit.last, _day(last))
    return sorted(by_name.values(), key=lambda h: h.name), bad


def _json(body: bytes) -> Any:
    return json.loads(body.decode('utf-8-sig'))


def _int(value: Any) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def _first_line(text: str, size: int = 160) -> str:
    line = ' '.join((text.strip().splitlines() or [''])[0].split())
    return line[:size] + ('...' if len(line) > size else '')


def _rows(doc: Any, key: str) -> List[Any]:
    value = doc.get(key) if isinstance(doc, dict) else None
    if not isinstance(value, list):
        raise ValueError('no %s list' % key)
    return value


def parse_hackertarget(body: bytes) -> SourceResult:
    """HackerTarget reverseiplookup: text, a host name a line; its errors and its quota are
    HTTP 200 text too ("API count exceeded", "error check your search parameter")."""
    text = body.decode('utf-8', 'replace').lstrip('\ufeff').strip()
    if re.search(r'api count exceeded|increase quota|rate limit|too many requests', text, flags=re.I):
        return SourceResult('hackertarget', RATE_LIMITED, detail=_first_line(text))
    if re.match(r'error\b', text, flags=re.I):
        return SourceResult('hackertarget', ERROR, detail=_first_line(text))
    if not text or re.match(r'no (dns )?(a )?records? found|no records', text, flags=re.I):
        return SourceResult('hackertarget', OK)
    hits, bad = _hits((line.split(',')[0], None, None) for line in text.splitlines() if line.strip())
    if not hits and bad:
        return SourceResult('hackertarget', ERROR, detail='unexpected answer: ' + _first_line(text))
    return SourceResult('hackertarget', OK, hits)


def parse_otx(body: bytes) -> SourceResult:
    """AlienVault OTX ``indicators/IPv4|IPv6/{ip}/passive_dns``: ``{passive_dns: [{hostname,
    first, last, record_type, address}], count}``."""
    doc = _json(body)
    rows = _rows(doc, 'passive_dns')
    hits, _ = _hits((r.get('hostname'), r.get('first'), r.get('last')) for r in rows if isinstance(r, dict))
    total = _int(doc.get('count'))
    return SourceResult('otx', OK, hits, total=total, truncated=total is not None and total > len(rows))


def parse_robtex(body: bytes) -> SourceResult:
    """Robtex ``pdns/reverse/{ip}``: NDJSON, one ``{rrname, rrdata, rrtype, time_first,
    time_last, count}`` a line (epoch seconds)."""
    text = body.decode('utf-8', 'replace').strip()
    rows = []  # type: List[Dict[str, Any]]
    bad = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if isinstance(row, dict):
            if str(row.get('status', '')).lower() in ('ratelimited', 'rate limited'):
                return SourceResult('robtex', RATE_LIMITED, detail='rate limited')
            rows.append(row)
    if not rows and bad:
        raise ValueError('not NDJSON: %s' % _first_line(text, 80))
    hits, _ = _hits((r.get('rrname'), r.get('time_first'), r.get('time_last')) for r in rows)
    return SourceResult('robtex', OK, hits)


def parse_internetdb(body: bytes) -> SourceResult:
    """Shodan InternetDB ``/{ip}``: ``{hostnames, ports, tags, vulns, cpes, ip}`` (an HTTP 404
    ``{detail: "No information available"}`` for an address it knows nothing about)."""
    doc = _json(body)
    if not isinstance(doc, dict):
        raise ValueError('not an object')
    names = doc.get('hostnames') or []
    if not isinstance(names, list):
        raise ValueError('hostnames is not a list')
    hits, _ = _hits((n, None, None) for n in names)
    intel = {}  # type: Dict[str, Any]
    for key in ('ports', 'tags', 'vulns', 'cpes'):
        value = doc.get(key)
        if isinstance(value, list):
            intel[key] = [v for v in value if isinstance(v, (str, int)) and not isinstance(v, bool)]
    return SourceResult('internetdb', OK, hits, intel=intel)


def parse_mnemonic(body: bytes) -> SourceResult:
    """mnemonic ``pdns/v3/{ip}``: ``{responseCode, count, data: [{query, answer, rrtype,
    firstSeenTimestamp, lastSeenTimestamp}]}`` (epoch milliseconds). For an address the name
    is the ``query`` of an A / AAAA record and the ``answer`` of a PTR record."""
    doc = _json(body)
    rows = _rows(doc, 'data')
    code = _int(doc.get('responseCode'))
    if code is not None and code != 200:
        messages = doc.get('messages') if isinstance(doc.get('messages'), list) else []
        text = '; '.join(str(m.get('message') if isinstance(m, dict) else m) for m in messages[:2])
        return SourceResult('mnemonic', ERROR, detail='responseCode %d%s' % (code, ': ' + text if text else ''))
    picked = []  # type: List[Tuple[Any, Any, Any]]
    for row in rows:
        if not isinstance(row, dict):
            continue
        rtype = str(row.get('rrtype') or '').lower()
        if rtype not in ('a', 'aaaa', 'ptr'):
            continue
        name = row.get('answer') if rtype == 'ptr' else row.get('query')
        picked.append((name, row.get('firstSeenTimestamp'), row.get('lastSeenTimestamp')))
    hits, _ = _hits(picked)
    total = _int(doc.get('count'))
    # Its count stops at the page size (1000 for 1.1.1.1, live 2026-10-08): a full page may hide more.
    return SourceResult('mnemonic', OK, hits, total=total,
                        truncated=len(rows) >= MNEMONIC_LIMIT or (total is not None and total > len(rows)))


def parse_securitytrails(body: bytes) -> SourceResult:
    """SecurityTrails ``POST /v1/domains/list`` with an ``ipv4`` / ``ipv6`` filter:
    ``{records: [{hostname}], record_count}``."""
    doc = _json(body)
    rows = _rows(doc, 'records')
    hits, _ = _hits((r.get('hostname'), None, None) for r in rows if isinstance(r, dict))
    total = _int(doc.get('record_count'))
    return SourceResult('securitytrails', OK, hits, total=total,
                        truncated=total is not None and total > len(rows))


def parse_virustotal(body: bytes) -> SourceResult:
    """VirusTotal ``/api/v3/ip_addresses/{ip}/resolutions``: ``{data: [{attributes: {host_name,
    date}}], links: {next}, meta: {count}}`` (``date``: the last resolution, epoch seconds)."""
    doc = _json(body)
    rows = _rows(doc, 'data')
    picked = []  # type: List[Tuple[Any, Any, Any]]
    for row in rows:
        attrs = row.get('attributes') if isinstance(row, dict) else None
        if isinstance(attrs, dict):
            picked.append((attrs.get('host_name'), None, attrs.get('date')))
    hits, _ = _hits(picked)
    links = doc.get('links') if isinstance(doc.get('links'), dict) else {}
    meta = doc.get('meta') if isinstance(doc.get('meta'), dict) else {}
    return SourceResult('virustotal', OK, hits, total=_int(meta.get('count')), truncated=bool(links.get('next')))


def parse_shodan(body: bytes) -> SourceResult:
    """Shodan ``/shodan/host/{ip}``: ``{hostnames, domains, last_update, ports}`` (an HTTP 404
    for an address it knows nothing about)."""
    doc = _json(body)
    if not isinstance(doc, dict):
        raise ValueError('not an object')
    names = doc.get('hostnames') or []
    if not isinstance(names, list):
        raise ValueError('hostnames is not a list')
    if not names and doc.get('error'):
        return SourceResult('shodan', ERROR, detail=_first_line(str(doc.get('error'))))
    hits, _ = _hits((n, None, doc.get('last_update')) for n in names)
    return SourceResult('shodan', OK, hits)


def parse_censys(body: bytes) -> SourceResult:
    """Censys Search v2 ``/hosts/{ip}/names``: ``{result: {names, links: {next}}}``."""
    doc = _json(body)
    result = doc.get('result') if isinstance(doc, dict) else None
    names = _rows(result, 'names')
    hits, _ = _hits((n, None, None) for n in names)
    links = result.get('links') if isinstance(result.get('links'), dict) else {}
    return SourceResult('censys', OK, hits, truncated=bool(links.get('next')))


def parse_viewdns(body: bytes) -> SourceResult:
    """ViewDNS ``reverseip``: ``{response: {domain_count, total_pages, domains: [{name,
    last_resolved}]}}``; an error is ``{success: false, error: {message}}``."""
    doc = _json(body)
    if not isinstance(doc, dict):
        raise ValueError('not an object')
    if doc.get('success') is False or isinstance(doc.get('error'), (dict, str)):
        error = doc.get('error')
        message = error.get('message') if isinstance(error, dict) else error
        return SourceResult('viewdns', ERROR, detail=_first_line(str(message or 'error')))
    holder = next((doc[k] for k in ('response', 'data', 'result') if isinstance(doc.get(k), dict)), doc)
    if isinstance(holder.get('error'), str):
        return SourceResult('viewdns', ERROR, detail=_first_line(holder['error']))
    rows = _rows(holder, 'domains')
    picked = []  # type: List[Tuple[Any, Any, Any]]
    for row in rows:
        if isinstance(row, str):
            picked.append((row, None, None))
        elif isinstance(row, dict):
            picked.append((row.get('name') or row.get('domain'), None, row.get('last_resolved')))
    hits, _ = _hits(picked)
    pages = _int(holder.get('total_pages'))
    return SourceResult('viewdns', OK, hits, total=_int(holder.get('domain_count')),
                        truncated=pages is not None and pages > 1)


WHOISXML_PAGE = 300


def parse_whoisxml(body: bytes) -> SourceResult:
    """WhoisXML API Reverse IP ``/api/v1``: ``{current_page, size, result: [{name, first_seen,
    last_visit}]}`` (epoch seconds, at most 300 a page)."""
    doc = _json(body)
    if isinstance(doc, dict) and not isinstance(doc.get('result'), list) and doc.get('messages'):
        return SourceResult('whoisxml', ERROR, detail=_first_line(str(doc.get('messages'))))
    rows = _rows(doc, 'result')
    hits, _ = _hits((r.get('name'), r.get('first_seen'), r.get('last_visit')) for r in rows if isinstance(r, dict))
    return SourceResult('whoisxml', OK, hits, truncated=len(rows) >= WHOISXML_PAGE)


NETLAS_PAGE = 20


def parse_netlas(body: bytes) -> SourceResult:
    """Netlas ``/api/domains/?q=a:{ip}``: ``{items: [{data: {domain, a, '@timestamp'}}]}``,
    20 a page."""
    doc = _json(body)
    rows = _rows(doc, 'items')
    picked = []  # type: List[Tuple[Any, Any, Any]]
    for row in rows:
        data = row.get('data') if isinstance(row, dict) else None
        if isinstance(data, dict):
            picked.append((data.get('domain'), None, data.get('@timestamp') or data.get('last_updated')))
    hits, _ = _hits(picked)
    return SourceResult('netlas', OK, hits, truncated=len(rows) >= NETLAS_PAGE)


def _q(value: str, safe: str = ':') -> str:
    return urllib.parse.quote(value, safe=safe)


RequestParts = Tuple[str, Dict[str, str], Optional[bytes]]


def _req_hackertarget(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return 'https://api.hackertarget.com/reverseiplookup/?q=' + _q(ip), {}, None


def _req_otx(ip: str, keys: Mapping[str, str]) -> RequestParts:
    kind = 'IPv6' if ':' in ip else 'IPv4'
    return 'https://otx.alienvault.com/api/v1/indicators/%s/%s/passive_dns' % (kind, _q(ip)), {}, None


def _req_robtex(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return 'https://freeapi.robtex.com/pdns/reverse/' + _q(ip), {}, None


def _req_internetdb(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return 'https://internetdb.shodan.io/' + _q(ip), {}, None


def _req_mnemonic(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return 'https://api.mnemonic.no/pdns/v3/%s?limit=%d' % (_q(ip), MNEMONIC_LIMIT), {}, None


def _req_securitytrails(ip: str, keys: Mapping[str, str]) -> RequestParts:
    body = json.dumps({'filter': {'ipv6' if ':' in ip else 'ipv4': ip}}).encode('utf-8')
    return ('https://api.securitytrails.com/v1/domains/list?page=1',
            {'APIKEY': keys['SECURITYTRAILS_API_KEY'], 'Content-Type': 'application/json'}, body)


def _req_virustotal(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return ('https://www.virustotal.com/api/v3/ip_addresses/%s/resolutions?limit=40' % _q(ip),
            {'x-apikey': keys['VT_API_KEY']}, None)


def _req_shodan(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return ('https://api.shodan.io/shodan/host/%s?minify=true&key=%s'
            % (_q(ip), _q(keys['SHODAN_API_KEY'], '')), {}, None)


def _req_censys(ip: str, keys: Mapping[str, str]) -> RequestParts:
    pair = '%s:%s' % (keys['CENSYS_API_ID'], keys['CENSYS_API_SECRET'])
    token = base64.b64encode(pair.encode('utf-8')).decode('ascii')
    return ('https://search.censys.io/api/v2/hosts/%s/names?per_page=100' % _q(ip),
            {'Authorization': 'Basic ' + token}, None)


def _req_viewdns(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return ('https://api.viewdns.info/reverseip/?host=%s&apikey=%s&output=json'
            % (_q(ip), _q(keys['VIEWDNS_API_KEY'], '')), {}, None)


def _req_whoisxml(ip: str, keys: Mapping[str, str]) -> RequestParts:
    return ('https://reverse-ip.whoisxmlapi.com/api/v1?apiKey=%s&ip=%s'
            % (_q(keys['WHOISXML_API_KEY'], ''), _q(ip)), {}, None)


def _req_netlas(ip: str, keys: Mapping[str, str]) -> RequestParts:
    query = 'aaaa:"%s"' % ip if ':' in ip else 'a:%s' % ip
    return ('https://app.netlas.io/api/domains/?q=%s&start=0' % _q(query, ''),
            {'X-API-Key': keys['NETLAS_API_KEY']}, None)


@dataclass(frozen=True)
class Source:
    """A third-party source of names for an address."""
    id: str
    name: str
    keys: Tuple[str, ...]      # the environment variables of its key (none: a free source)
    ipv6: bool                 # whether it is asked for an IPv6 address
    interval: float            # seconds between two of its requests in one run
    request: Callable[[str, Mapping[str, str]], RequestParts]
    parse: Callable[[bytes], SourceResult]
    empty_404: bool = False    # an HTTP 404 means: nothing known about the address


SOURCES = (
    Source('hackertarget', 'HackerTarget reverse IP', (), False, 1.0, _req_hackertarget, parse_hackertarget),
    Source('otx', 'AlienVault OTX passive DNS', (), True, 0.5, _req_otx, parse_otx),
    Source('robtex', 'Robtex passive DNS', (), True, 1.0, _req_robtex, parse_robtex),
    Source('internetdb', 'Shodan InternetDB', (), True, 0.2, _req_internetdb, parse_internetdb, True),
    Source('mnemonic', 'mnemonic passive DNS', (), True, 0.5, _req_mnemonic, parse_mnemonic),
    Source('securitytrails', 'SecurityTrails', ('SECURITYTRAILS_API_KEY',), True, 1.0,
           _req_securitytrails, parse_securitytrails),
    Source('virustotal', 'VirusTotal', ('VT_API_KEY',), True, 15.0, _req_virustotal, parse_virustotal),
    Source('shodan', 'Shodan', ('SHODAN_API_KEY',), True, 1.0, _req_shodan, parse_shodan, True),
    Source('censys', 'Censys Search', ('CENSYS_API_ID', 'CENSYS_API_SECRET'), True, 2.5,
           _req_censys, parse_censys),
    Source('viewdns', 'ViewDNS reverse IP', ('VIEWDNS_API_KEY',), False, 1.0, _req_viewdns, parse_viewdns),
    Source('whoisxml', 'WhoisXML API reverse IP', ('WHOISXML_API_KEY',), False, 0.5,
           _req_whoisxml, parse_whoisxml),
    Source('netlas', 'Netlas', ('NETLAS_API_KEY',), True, 1.0, _req_netlas, parse_netlas),
)
SOURCE_IDS = tuple(s.id for s in SOURCES)
KEY_VARIABLES = tuple(var for s in SOURCES for var in s.keys)
LOCAL_SOURCES = ('tls', 'ptr')  # from this machine


def load_keys(environ: Mapping[str, str]) -> Dict[str, str]:
    """The key variables that are set (and not blank) in ``environ``."""
    return {var: environ[var].strip() for var in KEY_VARIABLES if environ.get(var, '').strip()}


def has_key(source: Source, keys: Mapping[str, str]) -> bool:
    return bool(source.keys) and all(keys.get(var) for var in source.keys)


def select_sources(names: Optional[str], passive: bool = True, keys: Optional[Mapping[str, str]] = None
                   ) -> List[Source]:
    """The third-party sources of a run: the ones ``names`` lists (comma-separated), else the
    free ones (unless not ``passive``) and every key source whose key is set."""
    keys = keys or {}
    if names is not None:
        wanted = [n.lower() for n in re.split(r'[\s,]+', names) if n]
        unknown = [n for n in wanted if n not in SOURCE_IDS]
        if unknown:
            raise UsageError('unknown source %s; the sources: %s' % (', '.join(unknown), ', '.join(SOURCE_IDS)))
        chosen = [s for s in SOURCES if s.id in wanted]
        for source in chosen:
            if source.keys and not has_key(source, keys):
                raise UsageError('%s needs %s in the environment' % (source.id, ' and '.join(source.keys)))
        return chosen
    return [s for s in SOURCES if (passive and not s.keys) or has_key(s, keys)]


def _body_message(body: bytes) -> str:
    """A short reason from an error answer: its JSON message / error / detail, else its first
    line."""
    text = body[:4096].decode('utf-8', 'replace').strip()
    try:
        doc = json.loads(text)
    except ValueError:
        doc = None

    def pick(value: Any, depth: int = 0) -> str:
        if isinstance(value, str):
            return value
        if isinstance(value, dict) and depth < 3:
            for key in ('message', 'messages', 'error', 'detail', 'status'):
                found = pick(value.get(key), depth + 1)
                if found:
                    return found
        if isinstance(value, list) and value and depth < 3:
            return pick(value[0], depth + 1)
        return ''

    if doc is not None:
        return _first_line(pick(doc))
    if text.startswith('<'):
        return ''  # an HTML error page
    return _first_line(text)


def redact(text: str, secrets: Iterable[str]) -> str:
    """``text`` without any of ``secrets`` (as given or URL-encoded): a key never reaches a
    status, the terminal or a report, even when a service echoes it."""
    for secret in secrets:
        if not secret or len(secret) < 4:
            continue
        for form in {secret, urllib.parse.quote(secret, safe=''), urllib.parse.quote_plus(secret)}:
            text = text.replace(form, '[key]')
    return text


def ask_source(source: Source, ip: str, keys: Optional[Mapping[str, str]] = None,
               http: Optional[Callable[..., HttpResponse]] = None,
               timeout: float = DEFAULT_TIMEOUT) -> SourceResult:
    """Ask one source about one (public) address -> its result; never raises for a failure of
    the source (it becomes the status)."""
    keys = keys or {}
    secrets = [keys[var] for var in source.keys if keys.get(var)]
    try:
        url, headers, data = source.request(ip, keys)
        response = (http or http_request)(url, headers=headers, data=data, timeout=timeout)
    except HttpFailure as exc:
        return SourceResult(source.id, TIMEOUT if exc.kind == 'timeout' else ERROR,
                            detail=redact(str(exc), secrets))
    if response.status == 404 and source.empty_404:
        return SourceResult(source.id, OK)
    if response.status != 200:
        status = (RATE_LIMITED if response.status in (402, 429) else
                  REFUSED if response.status in (401, 403) else ERROR)
        text = 'HTTP %d' % response.status
        if 300 <= response.status < 400:
            text += ' (a redirect; not followed)'
        message = _body_message(response.body)
        if message:
            text += ': ' + message
        return SourceResult(source.id, status, detail=redact(text, secrets))
    try:
        result = source.parse(response.body)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        return SourceResult(source.id, ERROR, detail=redact('an answer that could not be read (%s)'
                                                            % _first_line(str(exc), 80), secrets))
    result.source = source.id
    result.detail = redact(result.detail, secrets)
    return result


class _Gate:
    """One source's pace and breaker for a run: one request per ``interval`` seconds across
    the workers, and none after it answered RATE_LIMITED or REFUSED."""

    def __init__(self, interval: float, stop: threading.Event,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.interval = interval
        self.stop = stop
        self.clock = clock
        self.lock = threading.Lock()
        self.next_at = 0.0
        self.tripped = None  # type: Optional[Tuple[str, SourceResult]]

    def wait(self) -> None:
        with self.lock:
            now = self.clock()
            start = max(now, self.next_at)
            self.next_at = start + self.interval
        if start > now:
            self.stop.wait(start - now)

    def trip(self, ip: str, result: SourceResult) -> None:
        with self.lock:
            if self.tripped is None:
                self.tripped = (ip, result)

    def not_asked(self, source: str) -> Optional[SourceResult]:
        if self.tripped is None:
            return None
        ip, first = self.tripped
        return SourceResult(source, first.status, asked=False,
                            detail='not asked: it answered %s for %s (%s)' % (first.status, ip, first.detail))


# ---------------------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------------------

@dataclass
class CertSeen:
    """A certificate the address serves on a port, and the SNI names it was served for."""
    port: int
    facts: CertFacts
    snis: List[str] = field(default_factory=list)    # '' = asked without SNI
    covers: List[str] = field(default_factory=list)  # the SNI names it covers


@dataclass
class PortState:
    port: int
    state: str
    detail: str = ''


@dataclass
class NameRow:
    name: str
    sources: List[str]
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    tls: Optional[str] = None            # TLS_SNI | TLS_CERT
    status: str = UNCHECKED
    resolves_to: List[str] = field(default_factory=list)
    detail: str = ''


@dataclass
class AddressReport:
    ip: str
    public: bool
    ports: List[PortState] = field(default_factory=list)
    certificates: List[CertSeen] = field(default_factory=list)
    sources: List[SourceResult] = field(default_factory=list)
    names: List[NameRow] = field(default_factory=list)
    intel: Dict[str, Any] = field(default_factory=dict)
    sni_tried: int = 0
    sni_failed: Dict[str, int] = field(default_factory=dict)  # port state -> handshakes

    def failed(self) -> List[SourceResult]:
        return [s for s in self.sources if s.status in FAILED]


@dataclass
class IntelReport:
    addresses: List[AddressReport]
    generated: datetime
    sources: List[str]          # the third-party sources of the run
    options: Dict[str, Any]
    warnings: List[str] = field(default_factory=list)

    def failures(self) -> List[Tuple[str, SourceResult]]:
        return [(a.ip, s) for a in self.addresses for s in a.failed()]


def _parallel(jobs: Sequence[Callable[[], Any]], workers: int, stop: threading.Event,
              tick: Optional[Callable[[], None]] = None) -> List[Any]:
    """Run ``jobs`` on ``workers`` threads -> their results in order. On an interrupt the
    jobs not started yet return at once (Python 3.8 has no cancel_futures)."""
    results = [None] * len(jobs)  # type: List[Any]
    if not jobs:
        return results

    def run(index: int) -> None:
        if stop.is_set():
            return
        results[index] = jobs[index]()
        if tick:
            tick()

    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(jobs))))
    try:
        for future in [pool.submit(run, i) for i in range(len(jobs))]:
            future.result()
    except BaseException:
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True)
    return results


def _add_certificate(rep: AddressReport, port: int, der: bytes, sni: str) -> Optional[CertSeen]:
    try:
        facts = parse_certificate(der)
    except (ValueError, IndexError, OverflowError):
        return None
    for seen in rep.certificates:
        if seen.port == port and seen.facts.sha256 == facts.sha256:
            break
    else:
        seen = CertSeen(port, facts)
        rep.certificates.append(seen)
    if sni not in seen.snis:
        seen.snis.append(sni)
    if sni and any(name_covers(pattern, sni) for pattern in facts.names()) and sni not in seen.covers:
        seen.covers.append(sni)
    return seen


def _tls_result(rep: AddressReport) -> SourceResult:
    names = []  # type: List[str]
    for seen in rep.certificates:
        for name in seen.facts.names() + seen.covers:
            if name not in names:
                names.append(name)
    states = [p.state for p in rep.ports]
    parts = []  # type: List[str]
    for port in rep.ports:
        count = sum(1 for c in rep.certificates if c.port == port.port)
        if count:
            parts.append('%d: %d certificate%s' % (port.port, count, '' if count == 1 else 's'))
        else:
            parts.append('%d: %s%s' % (port.port, port.state.lower().replace('_', ' '),
                                       ' (%s)' % port.detail if port.detail and port.state != PORT_CLOSED else ''))
    if rep.sni_failed:
        failed = sum(rep.sni_failed.values())
        parts.append('%d of %d SNI handshakes failed (%s)' % (
            failed, rep.sni_tried, ', '.join('%d %s' % (n, s.lower().replace('_', ' '))
                                              for s, n in sorted(rep.sni_failed.items()))))
    if rep.certificates:
        status = OK
    elif states and all(s == PORT_TIMEOUT for s in states):
        status = TIMEOUT
    elif any(s in (PORT_ERROR, PORT_TIMEOUT) for s in states):
        status = ERROR
    else:
        status = OK  # closed, or not TLS: an answer
    hits = [Hit(n) for n in names]
    return SourceResult('tls', status, hits, detail='; '.join(parts))


def _sni_candidates(rep: AddressReport, others: Sequence[SourceResult], limit: int) -> List[str]:
    """The names to ask the address for by SNI: its certificates' names first, then PTR, then
    the names of the most sources."""
    out = []  # type: List[str]

    def add(name: str) -> None:
        if len(out) < limit and not name.startswith('*.') and name not in out:
            out.append(name)

    for seen in rep.certificates:
        for name in seen.facts.names():
            add(name)
    counts = {}  # type: Dict[str, int]
    for result in others:
        if result.status != OK:
            continue
        for hit in result.hits:
            counts[hit.name] = counts.get(hit.name, 0) + (100 if result.source == 'ptr' else 1)
    for name in sorted(counts, key=lambda n: (-counts[n], n)):
        add(name)
    return out


_STATUS_RANK = {status: rank for rank, status in enumerate(STATUSES)}
_TLS_RANK = {TLS_SNI: 0, TLS_CERT: 1, None: 2}


def _merge(rep: AddressReport) -> None:
    rows = {}  # type: Dict[str, NameRow]
    for result in rep.sources:
        if result.status != OK:
            continue
        for hit in result.hits:
            row = rows.get(hit.name)
            if row is None:
                row = rows[hit.name] = NameRow(hit.name, [])
            if result.source not in row.sources:
                row.sources.append(result.source)
            row.first_seen = _earlier(row.first_seen, hit.first)
            row.last_seen = _later(row.last_seen, hit.last)
    for seen in rep.certificates:
        for name in seen.facts.names():
            if name in rows and rows[name].tls is None:
                rows[name].tls = TLS_CERT
        for name in seen.covers:
            if name in rows:
                rows[name].tls = TLS_SNI
    for row in rows.values():
        if row.name.startswith('*.'):
            row.status = WILDCARD
    rep.names = list(rows.values())


def _sort_names(rep: AddressReport) -> None:
    rep.names.sort(key=lambda r: (_STATUS_RANK.get(r.status, 99), _TLS_RANK.get(r.tls, 2),
                                  -len(r.sources), r.name))


def run_domains(addresses: Sequence[str], ports: Sequence[int] = DEFAULT_PORTS, tls: bool = True,
                ptr: bool = True, sources: Sequence[Source] = (),
                keys: Optional[Mapping[str, str]] = None, verify: bool = True,
                sni_max: int = DEFAULT_SNI_MAX, timeout: float = DEFAULT_TIMEOUT,
                workers: int = DEFAULT_WORKERS, http: Optional[Callable[..., HttpResponse]] = None,
                handshake: Optional[Callable[..., Tuple[str, Optional[bytes], str]]] = None,
                ptr_lookup: Optional[Callable[[str], List[str]]] = None,
                forward_lookup: Optional[Callable[[str], List[str]]] = None,
                public: Optional[Callable[[str], bool]] = None, pace: bool = True,
                progress: Optional[Callable[[str, int, int], None]] = None,
                stop: Optional[threading.Event] = None) -> IntelReport:
    """The names of every address: (1) TLS without SNI, PTR and the sources, at once; (2) SNI
    handshakes for the names found; (3) a forward lookup of every name. A private or
    reserved address (``public`` False) is asked of no source."""
    stop = stop or threading.Event()
    keys = dict(keys or {})
    shake = handshake or tls_handshake
    ptr_of = ptr_lookup or system_ptr
    forward = forward_lookup or system_forward
    is_pub = public or is_public
    context = make_tls_context() if tls else None
    reports = [AddressReport(ip, bool(is_pub(ip))) for ip in addresses]
    gates = {s.id: _Gate(s.interval if pace else 0.0, stop) for s in sources}
    lock = threading.Lock()

    def ticker(phase: str, total: int) -> Callable[[], None]:
        done = [0]

        def tick() -> None:
            with lock:
                done[0] += 1
                if progress:
                    progress(phase, done[0], total)
        return tick

    def handshake_job(ip: str, port: int, sni: Optional[str]) -> Callable[[], Any]:
        if handshake is None:
            return lambda: shake(ip, port, sni, timeout, context)
        return lambda: shake(ip, port, sni, timeout)

    def ptr_job(ip: str) -> Callable[[], SourceResult]:
        def job() -> SourceResult:
            try:
                names = ptr_of(ip)
            except LookupFailure as exc:
                return SourceResult('ptr', ERROR, detail=str(exc))
            return SourceResult('ptr', OK, [Hit(n) for n in names])
        return job

    def source_job(source: Source, rep: AddressReport) -> Callable[[], SourceResult]:
        def job() -> SourceResult:
            if not rep.public:
                return SourceResult(source.id, SKIPPED, asked=False,
                                    detail='a private or reserved address: not sent to a third party')
            if ':' in rep.ip and not source.ipv6:
                return SourceResult(source.id, SKIPPED, asked=False, detail='IPv4 only')
            gate = gates[source.id]
            early = gate.not_asked(source.id)
            if early is None:
                gate.wait()
                early = gate.not_asked(source.id)
            if early is not None:
                return early
            try:
                result = ask_source(source, rep.ip, keys, http, timeout)
            except Exception as exc:  # noqa: BLE001 - a bug in one parser must not end the run
                result = SourceResult(source.id, ERROR, detail='%s: %s' % (type(exc).__name__, exc))
            if result.status in (RATE_LIMITED, REFUSED):
                gate.trip(rep.ip, result)
            return result
        return job

    # 1. TLS without SNI, PTR and the sources
    jobs = []  # type: List[Callable[[], Any]]
    plan = []  # type: List[Tuple[AddressReport, str, Any]]
    for rep in reports:
        for port in (ports if tls else ()):
            plan.append((rep, 'tls', port))
            jobs.append(handshake_job(rep.ip, port, None))
        if ptr:
            plan.append((rep, 'ptr', None))
            jobs.append(ptr_job(rep.ip))
        for source in sources:
            plan.append((rep, 'source', source))
            jobs.append(source_job(source, rep))
    found = {}  # type: Dict[str, List[SourceResult]]
    for (rep, kind, item), result in zip(plan, _parallel(jobs, workers, stop, ticker('lookups', len(jobs)))):
        if kind == 'tls':
            state, der, detail = result
            rep.ports.append(PortState(item, state, detail))
            if der:
                _add_certificate(rep, item, der, '')
        else:
            found.setdefault(rep.ip, []).append(result)
            if result.source == 'internetdb' and result.status == OK and result.intel:
                rep.intel = dict(result.intel, source='internetdb')

    # 2. SNI handshakes for the names found
    if tls and sni_max > 0:
        sni_plan = []  # type: List[Tuple[AddressReport, int, str]]
        for rep in reports:
            open_ports = [p.port for p in rep.ports if p.state in (PORT_OK, PORT_TLS_ERROR)]
            names = _sni_candidates(rep, found.get(rep.ip, []), sni_max) if open_ports else []
            for port in open_ports:
                for name in names:
                    sni_plan.append((rep, port, name))
        sni_jobs = [handshake_job(rep.ip, port, name) for rep, port, name in sni_plan]
        for (rep, port, name), result in zip(sni_plan, _parallel(sni_jobs, workers, stop,
                                                                  ticker('SNI handshakes', len(sni_jobs)))):
            state, der, _detail = result
            rep.sni_tried += 1
            if der:
                _add_certificate(rep, port, der, name)
            else:
                rep.sni_failed[state] = rep.sni_failed.get(state, 0) + 1

    for rep in reports:
        others = found.get(rep.ip, [])
        ordered = []  # type: List[SourceResult]
        if tls:
            ordered.append(_tls_result(rep))
        ordered.extend(r for r in others if r.source == 'ptr')
        ordered.extend(r for s in sources for r in others if r.source == s.id)
        rep.sources = ordered
        _merge(rep)

    # 3. Where does each name point now?
    if verify:
        names = sorted({row.name for rep in reports for row in rep.names if row.status != WILDCARD})

        def lookup_job(name: str) -> Callable[[], Tuple[Optional[List[str]], str]]:
            def job() -> Tuple[Optional[List[str]], str]:
                try:
                    return forward(name), ''
                except LookupFailure as exc:
                    return None, str(exc) or 'no answer'
            return job

        answers = dict(zip(names, _parallel([lookup_job(n) for n in names], workers, stop,
                                            ticker('name checks', len(names)))))
        for rep in reports:
            for row in rep.names:
                if row.status == WILDCARD:
                    continue
                addrs, problem = answers.get(row.name) or (None, 'not asked')
                if addrs is None:
                    row.status, row.detail = LOOKUP_ERROR, problem
                    continue
                row.resolves_to = list(addrs)
                row.status = HERE if rep.ip in addrs else MOVED if addrs else NO_ADDRESS
    for rep in reports:
        _sort_names(rep)
    options = {'ports': list(ports) if tls else [], 'tls': tls, 'ptr': ptr, 'verify': verify,
               'sniMax': sni_max if tls else 0, 'timeout': timeout, 'workers': workers}
    return IntelReport(reports, datetime.now(timezone.utc), [s.id for s in sources], options)


# ---------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------

def _plain(text: str) -> str:
    """Printable ASCII for the terminal: anything else ``\\xNN`` (names come from servers)."""
    return ''.join(c if 0x20 <= ord(c) < 0x7f else '\\x%02x' % ord(c) if ord(c) < 0x100 else '\\u%04x' % ord(c)
                   for c in text)


def _seen_text(row: NameRow) -> str:
    if row.first_seen and row.last_seen and row.first_seen != row.last_seen:
        return '%s..%s' % (row.first_seen, row.last_seen)
    return row.last_seen or row.first_seen or ''


def _source_text(result: SourceResult) -> str:
    if result.status == OK:
        if result.source == 'tls':
            return 'tls OK (%s)' % result.detail if result.detail else 'tls OK'
        count = len(result.hits)
        text = '%d name%s' % (count, '' if count == 1 else 's')
        if result.truncated:
            text += ' of %d' % result.total if result.total and result.total > count else ', more at the source'
        return '%s OK (%s)' % (result.source, text)
    return '%s %s%s' % (result.source, result.status, ' (%s)' % result.detail if result.detail else '')


def _cert_line(seen: CertSeen) -> str:
    facts = seen.facts
    names = facts.names()
    head = facts.subject_cn or (names[0] if names else 'no subject CN')
    bits = ['issuer %s' % (facts.issuer or 'unknown')]
    if facts.not_after:
        bits.append('until %s' % facts.not_after)
    bits.append('%d name%s' % (len(names), '' if len(names) == 1 else 's'))
    asked = [s for s in seen.snis if s]
    if asked:
        bits.append('SNI %s%s' % (', '.join(asked[:3]), ' +%d' % (len(asked) - 3) if len(asked) > 3 else ''))
    elif '' in seen.snis:
        bits.append('no SNI')
    return '  TLS %d: %s (%s)' % (seen.port, head, ', '.join(bits))


def _counts(report: IntelReport) -> Dict[str, int]:
    counts = {s: 0 for s in STATUSES}
    for rep in report.addresses:
        for row in rep.names:
            counts[row.status] = counts.get(row.status, 0) + 1
    return counts


def render_text(report: IntelReport) -> str:
    """The readable report: per address its certificates, intel, names and source statuses."""
    lines = ['IP intel: %d address%s; sources: %s' % (
        len(report.addresses), '' if len(report.addresses) == 1 else 'es',
        ', '.join([s for s in LOCAL_SOURCES if report.options.get(s)] + report.sources) or 'none')]
    width = min(48, max([len(r.name) for a in report.addresses for r in a.names] or [12]))
    for rep in report.addresses:
        lines.append('')
        ptr_names = [h.name for s in rep.sources if s.source == 'ptr' for h in s.hits]
        title = rep.ip + ('  (PTR %s)' % ', '.join(ptr_names) if ptr_names else '')
        lines.append(_plain(title))
        if not rep.public:
            lines.append('  a private or reserved address: TLS and PTR only, nothing sent to a third party')
        for seen in rep.certificates:
            lines.append(_plain(_cert_line(seen)))
        if rep.intel:
            bits = []  # type: List[str]
            if rep.intel.get('ports'):
                bits.append('ports %s' % ', '.join(str(p) for p in rep.intel['ports']))
            if rep.intel.get('tags'):
                bits.append('tags %s' % ', '.join(str(t) for t in rep.intel['tags']))
            vulns = rep.intel.get('vulns') or []
            if vulns:
                bits.append('%d vuln%s (%s%s)' % (len(vulns), '' if len(vulns) == 1 else 's',
                                                  ', '.join(str(v) for v in vulns[:3]),
                                                  ', ...' if len(vulns) > 3 else ''))
            if bits:
                lines.append(_plain('  intel: %s (Shodan InternetDB)' % '; '.join(bits)))
        if rep.names:
            lines.append('  %s  %-12s  %-4s  %-22s  %s' % ('NAME'.ljust(width), 'NOW', 'TLS', 'SEEN', 'SOURCES'))
            for row in rep.names:
                text = '  %s  %-12s  %-4s  %-22s  %s' % (row.name.ljust(width), row.status, row.tls or '',
                                                        _seen_text(row), ', '.join(row.sources))
                if row.status == MOVED:
                    text += '  now %s' % ', '.join(row.resolves_to[:3])
                    if len(row.resolves_to) > 3:
                        text += ' +%d' % (len(row.resolves_to) - 3)
                elif row.status == LOOKUP_ERROR and row.detail:
                    text += '  (%s)' % row.detail
                lines.append(_plain(text.rstrip()))
        else:
            lines.append('  no names')
        shown = [s for s in rep.sources if rep.public or s.source in LOCAL_SOURCES]
        if shown:
            lines.append(_plain('  sources: %s' % '; '.join(_source_text(s) for s in shown)))
    lines.append('')
    counts = _counts(report)
    total = sum(counts.values())
    lines.append('%d name%s on %d address%s%s' % (
        total, '' if total == 1 else 's', len(report.addresses), '' if len(report.addresses) == 1 else 'es',
        ': ' + ', '.join('%d %s' % (counts[s], s) for s in STATUSES if counts[s]) if total else ''))
    failures = report.failures()
    if failures:
        by_source = {}  # type: Dict[str, int]
        for _ip, result in failures:
            by_source[result.source] = by_source.get(result.source, 0) + 1
        lines.append('Incomplete: %s failed (%s); run again later, or leave a source out with --sources.' % (
            'a source' if len(failures) == 1 else '%d source lookups' % len(failures),
            ', '.join('%s on %d address%s' % (s, n, '' if n == 1 else 'es') for s, n in sorted(by_source.items()))))
    lines.append('HERE: the name resolves to the address now. MOVED: elsewhere now (an old name, or a CDN '
                 'in front). NO_ADDRESS: it does not resolve. TLS SNI: the address serves a certificate '
                 'for it; CERT: the name is in a certificate it serves.')
    return '\n'.join(lines) + '\n'


def _source_dict(result: SourceResult) -> Dict[str, Any]:
    out = {'id': result.source, 'status': result.status, 'names': len(result.hits),
           'detail': result.detail or None, 'asked': result.asked}  # type: Dict[str, Any]
    if result.total is not None:
        out['total'] = result.total
    if result.truncated:
        out['truncated'] = True
    return out


def report_to_dict(report: IntelReport) -> Dict[str, Any]:
    """The JSON report (schema ``domainscope.ip-intel/1``). It never holds a key."""
    return {
        'schema': SCHEMA,
        'tool': {'name': PROG, 'version': __version__},
        'generatedAt': report.generated.strftime('%Y-%m-%dT%H:%M:%SZ'),
        'command': 'domains',
        'options': dict(report.options, sources=report.sources),
        'addresses': [{
            'ip': rep.ip,
            'public': rep.public,
            'ports': [{'port': p.port, 'state': p.state, 'detail': p.detail or None} for p in rep.ports],
            'certificates': [{'port': c.port, 'sha256': c.facts.sha256, 'subjectCn': c.facts.subject_cn,
                              'issuer': c.facts.issuer, 'notAfter': c.facts.not_after,
                              'names': c.facts.names(), 'sni': [s or None for s in c.snis],
                              'covers': c.covers} for c in rep.certificates],
            'sources': [_source_dict(s) for s in rep.sources],
            'intel': rep.intel or None,
            'names': [{'name': r.name, 'status': r.status, 'resolvesTo': r.resolves_to, 'tls': r.tls,
                       'sources': r.sources, 'firstSeen': r.first_seen, 'lastSeen': r.last_seen,
                       'detail': r.detail or None} for r in rep.names],
        } for rep in report.addresses],
        'summary': {'addresses': len(report.addresses), 'names': sum(len(a.names) for a in report.addresses),
                    'counts': _counts(report), 'sourceFailures': len(report.failures())},
        'warnings': report.warnings,
    }


CSV_COLUMNS = ('ip', 'name', 'status', 'resolves_to', 'tls', 'sources', 'first_seen', 'last_seen',
               'source_errors')
_CSV_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')
_CSV_ESCAPE_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]')


def csv_cell(value: Any) -> Any:
    """A spreadsheet-safe cell: text starting with ``= + - @`` TAB or CR gets a leading
    apostrophe (a spreadsheet would run it as a formula), control and bidi characters are
    written ``\\xNN`` / ``\\uNNNN``; numbers stay numbers."""
    if value is None:
        return ''
    if not isinstance(value, str):
        return value
    if value.startswith(_CSV_FORMULA_START):
        value = "'" + value
    return _CSV_ESCAPE_RE.sub(lambda m: '\\x%02x' % ord(m.group()) if ord(m.group()) < 0x100
                              else '\\u%04x' % ord(m.group()), value)


def render_csv(report: IntelReport, lineterminator: str = '\r\n') -> str:
    """One row per address and name; an address without names gets one NO_NAMES row. The
    ``source_errors`` column names the sources that failed for the address."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator=lineterminator)
    writer.writerow(CSV_COLUMNS)
    for rep in report.addresses:
        errors = ' '.join('%s:%s' % (s.source, s.status) for s in rep.failed())
        for row in rep.names:
            writer.writerow([csv_cell(v) for v in (
                rep.ip, row.name, row.status, ' '.join(row.resolves_to), row.tls or '', ' '.join(row.sources),
                row.first_seen, row.last_seen, errors)])
        if not rep.names:
            writer.writerow([csv_cell(v) for v in (rep.ip, '', NO_NAMES, '', '', '', '', '', errors)])
    return out.getvalue()


def render_sources(environ: Mapping[str, str]) -> str:
    """The ``sources`` command: every source, and whether its key is set (never the key)."""
    keys = load_keys(environ)
    lines = ['Sources of "%s domains" (a private or reserved address goes to none of them):' % PROG,
             '  %-15s %-28s %-5s %s' % ('ID', 'NAME', 'IPv6', 'KEY')]
    for source in SOURCES:
        if source.keys:
            state = 'set' if has_key(source, keys) else 'not set'
            key = '%s: %s' % (' + '.join(source.keys), state)
        else:
            key = 'free (--no-passive leaves it out)'
        lines.append('  %-15s %-28s %-5s %s' % (source.id, source.name, 'yes' if source.ipv6 else 'no', key))
    lines.append('Local, from this machine: tls (the certificates on --ports), ptr (the system resolver).')
    lines.append('Keys are read from these environment variables only; no report or message holds one.')
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------

EPILOG = """\
examples:
  One address: its certificates on 443, PTR and the free sources, then a check of every name:
    python3 ip_intel.py domains 203.0.113.10

  A range inside your network, TLS on two ports, nothing sent to a third party:
    python3 ip_intel.py domains 10.0.0.0/24 -p 443,8443 --no-passive --no-keys

  A file of addresses, with your own keys, reports for scripts:
    VT_API_KEY=... python3 ip_intel.py domains ips.txt --json names.json --csv names.csv

  The sources, and which keys are set:
    python3 ip_intel.py sources

sources (third parties; a private or reserved address goes to none of them):
  free  hackertarget, otx, robtex, internetdb, mnemonic (--no-passive leaves them out)
  key   securitytrails (SECURITYTRAILS_API_KEY), virustotal (VT_API_KEY), shodan
        (SHODAN_API_KEY), censys (CENSYS_API_ID + CENSYS_API_SECRET), viewdns
        (VIEWDNS_API_KEY), whoisxml (WHOISXML_API_KEY), netlas (NETLAS_API_KEY): asked when
        the variable is set (--no-keys leaves them out). Keys come from the environment only.
  A source that answers RATE_LIMITED or REFUSED is not asked again in the run.

name statuses (the system resolver, now):
  HERE          the name resolves to the address
  MOVED         it resolves to other addresses only (an old name, or a CDN in front)
  NO_ADDRESS    it does not resolve
  WILDCARD      a certificate's *.name: it covers names, it is not one
  LOOKUP_ERROR  the resolver gave no answer
  UNCHECKED     --no-verify
  TLS SNI: asked with the name, the address served a certificate for it. TLS CERT: the name
  is in a certificate the address serves.

source statuses (per address): OK, SKIPPED (not asked: a private address, or IPv6 at an
  IPv4-only source), RATE_LIMITED, REFUSED (HTTP 401 / 403: the key, or this client),
  TIMEOUT, ERROR.

exit codes: 0 done, 1 a source failed for an address (only with --fail-on-error), 2 usage
  error, 3 a report file could not be written, 130 interrupted.

Türkçe: Bir IP adresinin bugün sunduğu ya da geçmişte sunduğu alan adlarını kendi
  ağınızdan bulur: adresin sunduğu sertifikalar (SNI'li ve SNI'siz), PTR, ücretsiz pasif DNS
  kaynakları ve anahtarını ortam değişkeniyle verdiğiniz kaynaklar; her adın bugün nereye
  çözümlendiğini de kontrol eder. Özel adresler hiçbir üçüncü tarafa gönderilmez. Örnek:
    python3 ip_intel.py domains 203.0.113.10
"""


def _ports(values: Optional[Sequence[str]]) -> List[int]:
    if not values:
        return list(DEFAULT_PORTS)
    ports = []  # type: List[int]
    for value in values:
        for item in re.split(r'[\s,]+', value):
            if not item:
                continue
            if not item.isdigit() or not 1 <= int(item) <= 65535:
                raise UsageError('--ports takes port numbers 1-65535, not %s' % _plain(item))
            if int(item) not in ports:
                ports.append(int(item))
    if len(ports) > MAX_PORTS:
        raise UsageError('at most %d ports' % MAX_PORTS)
    return ports


def build_parser() -> argparse.ArgumentParser:
    description = ('The names an IP address serves, or served: its TLS certificates, PTR, free passive '
                   'DNS sources and the sources of your own keys, each name checked with the system '
                   'resolver. Python 3.8+, standard library only.')
    parser = argparse.ArgumentParser(prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=description, epilog=EPILOG)
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    commands = parser.add_subparsers(dest='command', metavar='COMMAND')
    commands.required = True
    domains = commands.add_parser('domains', help='the names of addresses, ranges or a file of them',
                                  formatter_class=argparse.RawDescriptionHelpFormatter,
                                  description=description, epilog=EPILOG)
    domains.add_argument('targets', nargs='+', metavar='TARGET',
                         help='an address, a CIDR range or a file of them, one or more a line '
                              '("-" = stdin)')
    what = domains.add_argument_group('what is asked')
    what.add_argument('-p', '--ports', action='append', metavar='LIST',
                      help='TLS ports, comma-separated (default: 443)')
    what.add_argument('--sni-max', type=int, default=DEFAULT_SNI_MAX, metavar='N',
                      help='SNI handshakes per address and port for the names found (default: %(default)s)')
    what.add_argument('--no-tls', action='store_true', help='no TLS handshakes')
    what.add_argument('--no-ptr', action='store_true', help='no PTR lookup')
    what.add_argument('--no-passive', action='store_true', help='leave the free passive sources out')
    what.add_argument('--no-keys', action='store_true', help='leave the key sources out, keys set or not')
    what.add_argument('--sources', metavar='LIST',
                      help='ask only these third-party sources, comma-separated (see "%s sources")' % PROG)
    what.add_argument('--no-verify', action='store_true',
                      help='do not look up where each name points now')
    limits = domains.add_argument_group('limits')
    limits.add_argument('--max', type=int, default=DEFAULT_MAX_ADDRESSES, metavar='N',
                        help='at most N addresses (default: %(default)s, an IPv4 /22)')
    limits.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                        help='per request, handshake and lookup (default: %(default)s)')
    limits.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                        help='lookups in flight (default: %(default)s); each source keeps its own pace')
    out = domains.add_argument_group('output')
    out.add_argument('--json', metavar='FILE', help='write a JSON report ("-" = stdout)')
    out.add_argument('--csv', metavar='FILE', help='write a CSV report ("-" = stdout)')
    out.add_argument('--fail-on-error', action='store_true',
                     help='exit with code 1 when a source failed for an address')
    out.add_argument('-q', '--quiet', action='store_true', help='no progress and no warnings on stderr')
    commands.add_parser('sources', help='list the sources and which keys are set (never the keys)',
                        description='List the sources and which keys are set (never the keys).')
    return parser


def _write(path: str, text: str, encoding: str = 'utf-8') -> None:
    if path == '-':
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    with open(path, 'w', encoding=encoding, newline='') as handle:
        handle.write(text)


def _run_domains(args: argparse.Namespace) -> int:
    err = sys.stderr
    if not 0 < args.timeout <= 120:
        raise UsageError('--timeout must be > 0 and <= 120 seconds')
    if not 1 <= args.workers <= MAX_WORKERS:
        raise UsageError('--workers must be between 1 and %d' % MAX_WORKERS)
    if not 1 <= args.max <= MAX_ADDRESSES:
        raise UsageError('--max must be between 1 and %d' % MAX_ADDRESSES)
    if not 0 <= args.sni_max <= 256:
        raise UsageError('--sni-max must be between 0 and 256')
    if args.json == '-' and args.csv == '-':
        raise UsageError('--json - and --csv - cannot both write to stdout')
    ports = _ports(args.ports)
    keys = {} if args.no_keys else load_keys(os.environ)
    sources = select_sources(args.sources, passive=not args.no_passive, keys=keys)
    addresses, warnings = parse_targets(args.targets, args.max)
    if not addresses:
        raise UsageError('no addresses in %s' % ', '.join(_plain(t) for t in args.targets))
    if not args.quiet:
        for warning in warnings[:25]:
            print('warning: %s' % warning, file=err)
        if len(warnings) > 25:
            print('warning: ... and %d more' % (len(warnings) - 25), file=err)
        if len(addresses) > 16 and sources:
            print('note: %d addresses: each source keeps its pace and the free ones have daily quotas; '
                  '--no-passive or --sources narrows the run' % len(addresses), file=err)
    tty = not args.quiet and hasattr(err, 'isatty') and err.isatty()

    def progress(phase: str, done: int, total: int) -> None:
        if tty and (done == total or done % 10 == 0):
            err.write('\r%s: %d / %d' % (phase, done, total))
            if done == total:
                err.write('\n')
            err.flush()

    report = run_domains(addresses, ports=ports, tls=not args.no_tls, ptr=not args.no_ptr, sources=sources,
                         keys=keys, verify=not args.no_verify, sni_max=args.sni_max, timeout=args.timeout,
                         workers=args.workers, progress=progress)
    report.warnings = warnings
    secrets = list(keys.values())
    failed = False
    for path, kind in ((args.json, 'json'), (args.csv, 'csv')):
        if not path:
            continue
        if kind == 'json':
            text = json.dumps(report_to_dict(report), indent=2) + '\n'
        else:
            text = render_csv(report, '\n' if path == '-' else '\r\n')
        try:
            _write(path, redact(text, secrets), 'utf-8' if kind == 'json' or path == '-' else 'utf-8-sig')
        except OSError as exc:
            print('%s: error: cannot write %s: %s' % (PROG, path, exc.strerror or exc), file=err)
            failed = True
    if args.json != '-' and args.csv != '-':
        sys.stdout.write(redact(render_text(report), secrets))
        sys.stdout.flush()
    if failed:
        return EXIT_OUTPUT_ERROR
    if args.fail_on_error and report.failures():
        return EXIT_SOURCE_ERRORS
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
        if args.command == 'sources':
            sys.stdout.write(render_sources(os.environ))
            return EXIT_OK
        return _run_domains(args)
    except UsageError as exc:
        print('%s: error: %s' % (PROG, exc), file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print('\ninterrupted', file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == '__main__':
    sys.exit(main())
