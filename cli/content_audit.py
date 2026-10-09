#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""content_audit.py - an authorized self-audit of your own web servers.

Companion CLI of the "DomainScope - SSL & DNS Toolkit" web app
(https://github.com/halilibrahimd27/domainscope). Audit web servers you own or are
authorised to test for forgotten paths and files that should not be public: an open
version-control directory (`.git`, `.svn`), environment and config files (`.env`,
`web.config`), backup and editor leftovers (`*.bak`, `index.php~`), and server-status or
debug panels. A browser page cannot do this - it cannot read a cross-origin response's
status code - so it lives in the CLI, run from a machine that can reach your servers.

This is a self-audit, not a scanner for the whole web:
  * targets come from you - host names, URLs, a file of them, or the host names a scan of
    yours already covered (`--from-scan`). It never discovers hosts on its own;
  * it asks a small, curated list of about forty well-known exposure paths, not a wordlist,
    and `paths` prints it. `--paths FILE` adds a few of your own (capped, not a wordlist);
  * two baseline requests per target first (random paths, new each run) learn how the server
    answers a path that is not there, so a site that answers 200 for everything does not
    drown you in false positives;
  * a per-host rate cap keeps the audit polite (default 5 requests a second per host, shared
    by every target on the host), and a host that answers 429 or 503 is backed off;
  * it only reads: a plain GET, the first 256 KB of each body, redirects followed only within
    the same origin (scheme, host and port). It never sends a payload, guesses a password or
    tries to exploit anything.

JSON (`--json`) and CSV (`--csv`) outputs carry every result; the text summary shows the
findings first and says which paths could not be checked. Exit code 0; 1 with
`--fail-on-finding` when anything is exposed, or with `--fail-on-error` when a target could not
be fully audited; 2 for a usage error, 3 when a report file could not be written, 130 when
interrupted.

Python 3.8+, standard library only, single file - copy it anywhere.

The module is importable: parse_targets(), Target, PROBES, Probe, http_get(), probe_baseline(),
classify(), HostPacer, audit_host(), run_audit(), render_text(), report_to_dict(), render_csv(),
render_paths() and main() are the public API.
"""

from __future__ import annotations

import argparse
import csv
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait as wait_futures
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Set, Tuple

__version__ = '1.0.0'
PROG = 'content_audit.py'
SCHEMA = 'domainscope.content-audit/1'
TOOL = 'content_audit'
USER_AGENT = 'content_audit/%s (+https://github.com/halilibrahimd27/domainscope)' % __version__

# --- verdicts, per (host, path) --------------------------------------------------------
EXPOSED = 'EXPOSED'        # the file or directory is readable (a finding)
LISTED = 'LISTED'          # a directory listing is served (a finding)
PROTECTED = 'PROTECTED'    # it exists but is behind auth (401 / 403) - informational
REDIRECT = 'REDIRECT'      # answered with a redirect to another origin (not followed)
BASELINE = 'BASELINE'      # indistinguishable from the server's answer for a missing path
NOT_FOUND = 'NOT_FOUND'    # 404 / 410, or a 200 whose content did not match the file
BLOCKED = 'BLOCKED'        # the server answered 429 / 503 (rate limited us) or we backed off
TIMEOUT = 'TIMEOUT'        # no answer in --timeout seconds
ERROR = 'ERROR'            # a network or protocol error
VERDICTS = (EXPOSED, LISTED, PROTECTED, REDIRECT, BASELINE, NOT_FOUND, BLOCKED, TIMEOUT, ERROR)
# The verdicts that count as a finding and, with --fail-on-finding, fail the run.
FINDING_VERDICTS = (EXPOSED, LISTED)
# Shown to the operator as "worth a look" (findings + the present-but-protected paths).
NOTABLE_VERDICTS = (EXPOSED, LISTED, PROTECTED)
# A path that was not checked: its target's audit is incomplete (--fail-on-error fails on it).
UNCHECKED_VERDICTS = (BLOCKED, TIMEOUT, ERROR)

# --- confidence of a finding -----------------------------------------------------------
CONFIRMED = 'confirmed'    # the body matched what the file looks like
LIKELY = 'likely'          # the status says it is there, no content signature to confirm
PRESENT = 'present'        # it is there but protected (401 / 403)

# --- what a host answers for a path that is not there (Baseline.kind) -----------------
HARD_404 = 'hard-404'          # 404 / 410: every answer means what it says
SOFT_404 = 'soft-404'          # the same 2xx catch-all page for anything
CATCH_REDIRECT = 'redirect'    # the same redirect for anything
DENIED = 'denied'              # 401 / 403 for anything: then a 401 / 403 says nothing about a path
STATUS_ONLY = 'status-only'    # another steady status: results are status-only
MIXED = 'mixed'                # the samples disagreed: results are status-only
RATE_LIMITED = 'rate-limited'  # 429 / 503: nothing else is asked of the host
NO_ANSWER = 'no-answer'        # no HTTP answer: the target is unreachable

# --- severity of a probe ---------------------------------------------------------------
HIGH = 'high'
MEDIUM = 'medium'
LOW = 'low'
SEVERITIES = (HIGH, MEDIUM, LOW)
_SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

EXIT_OK = 0
EXIT_FINDINGS = 1          # only with --fail-on-finding
EXIT_INCOMPLETE = 1        # only with --fail-on-error: a target unreachable or a path not checked
EXIT_USAGE = 2
EXIT_OUTPUT_ERROR = 3      # a --json / --csv file could not be written after the audit
EXIT_INTERRUPTED = 130

DEFAULT_SCHEME = 'https'
DEFAULT_RATE = 5.0         # requests a second, per host
MAX_RATE = 50.0
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 120.0
DEFAULT_WORKERS = 8        # targets audited in parallel; each host's requests stay paced
MAX_WORKERS = 64
DEFAULT_MAX_HOSTS = 256
MAX_HOSTS = 4096
MAX_REDIRECTS = 4          # followed only within the same origin
REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_BODY = 256 * 1024      # bytes read per response (enough to recognise a file)
MAX_CUSTOM_PATHS = 200     # --paths is for a few of your own, never a wordlist
MAX_TARGET_FILE = 20 * 1024 * 1024
BASELINE_SAMPLES = 2       # random, non-existent paths asked to learn the catch-all
_POLL_SECONDS = 0.1        # how often the main thread looks up from the workers (for Ctrl+C)


class UsageError(Exception):
    """Bad command line or input; reported as ``error: ...`` with exit code 2."""


class HttpFailure(Exception):
    """A request without an HTTP answer."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind  # 'timeout' | 'network'


# ---------------------------------------------------------------------------------------
# Text safety: server-controlled text reaches the terminal, so strip control / bidi codes
# ---------------------------------------------------------------------------------------

def _plain(text: str) -> str:
    """Printable ASCII for the terminal: anything else ``\\xNN`` / ``\\uNNNN`` (bodies, host
    names and redirect targets all come from the server)."""
    return ''.join(c if 0x20 <= ord(c) < 0x7f else '\\x%02x' % ord(c) if ord(c) < 0x100
                   else '\\u%04x' % ord(c) for c in text)


_CSV_FORMULA_START = ('=', '+', '-', '@', '\t', '\r')
_CSV_ESCAPE_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]')


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
# Targets: the servers to audit - host names, URLs, files of them, or a scan's JSON
# ---------------------------------------------------------------------------------------

_LABEL_RE = re.compile(r'^(?=.{1,63}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$')
# A name whose last label is a number (decimal, or 0x hex) is an IPv4 address to the system
# resolver, read the inet_aton way: 010 is octal 8, 127.1 is 127.0.0.1. One that ipaddress did
# not accept is no target: it would be audited somewhere else than the inventory meant.
_NUMERIC_TAIL_RE = re.compile(r'^(?:[0-9]+|0[xX][0-9a-fA-F]*)$')
# A command-line token with one of these endings is a file name, never a host (no such TLD).
_FILE_SUFFIXES = ('.txt', '.csv', '.tsv', '.json', '.lst', '.yml', '.yaml', '.xml', '.ini',
                  '.cfg', '.conf')
_BRACKET_HINT = '%s: write an IPv6 address in brackets, any port after them: [2001:db8::1]:8443'


@dataclass(frozen=True)
class Target:
    """One server to audit, as a normalised base URL."""
    scheme: str
    host: str          # a host name (lowercased, IDNA) or an IP literal, no brackets
    port: int
    base_path: str     # '/' or a path the probes are joined under, always ending in '/'

    @property
    def netloc(self) -> str:
        host = '[%s]' % self.host if ':' in self.host else self.host
        default = 443 if self.scheme == 'https' else 80
        return host if self.port == default else '%s:%d' % (host, self.port)

    @property
    def url(self) -> str:
        return '%s://%s%s' % (self.scheme, self.netloc, self.base_path)

    def path_url(self, rel: str) -> str:
        return '%s://%s%s%s' % (self.scheme, self.netloc, self.base_path, rel.lstrip('/'))


def _numeric_tail(host: str) -> bool:
    return bool(_NUMERIC_TAIL_RE.match(host.rstrip('.').rsplit('.', 1)[-1]))


def _idna_host(host: str) -> Optional[str]:
    """A host name lowercased and, if it has non-ASCII, IDNA-encoded; None if it is not a
    valid host name (an address-like name ending in a number included)."""
    host = host.strip().rstrip('.')
    if not host:
        return None
    try:
        host.encode('ascii')
        ascii_host = host.lower()
    except UnicodeEncodeError:
        try:
            ascii_host = host.encode('idna').decode('ascii').lower()
        except (UnicodeError, UnicodeDecodeError):
            return None
    labels = ascii_host.split('.')
    if not labels or any(not _LABEL_RE.match(lbl) for lbl in labels):
        return None
    if _numeric_tail(ascii_host):
        return None  # an address we did not accept above, or a bare number
    return ascii_host


def _canonical_ip(value: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(value)
    except ValueError:
        return None
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def parse_target(value: str) -> Target:
    """One token -> a :class:`Target`. Accepts ``https://host[:port][/path]``, ``host``,
    ``host:port``, ``[v6]:port`` and IP literals (a bare IPv6 address too). A bare host is
    https on 443; a bare ``host:80`` is http. A dotted number that is not an address
    (``010.0.0.1``, ``127.1``) is refused: the resolver would read it as another address.
    Raises :class:`UsageError` for anything else."""
    token = value.strip()
    if not token:
        raise UsageError('an empty target')
    if '://' not in token and token.count(':') >= 2 and not token.startswith('['):
        ip = _canonical_ip(token)  # a bare IPv6 address (it cannot carry a port)
        if ip is None:
            raise UsageError(_BRACKET_HINT % _plain(token))
        return Target(DEFAULT_SCHEME, ip, 443, '/')
    if '://' not in token:
        # Add a scheme so urlsplit reads the authority; pick it back off the port below.
        token_for_split = '//' + token
        had_scheme = False
    else:
        token_for_split = token
        had_scheme = True
    try:
        parts = urllib.parse.urlsplit(token_for_split, scheme='')
    except ValueError:
        raise UsageError('%s is not a URL or host' % _plain(token))
    scheme = (parts.scheme or '').lower()
    if had_scheme and scheme not in ('http', 'https'):
        raise UsageError('%s: only http and https are audited' % _plain(token))
    host = parts.hostname
    if not host:
        raise UsageError('%s has no host' % _plain(token))
    try:
        port = parts.port
    except ValueError:
        if parts.netloc.count(':') >= 2 and '[' not in parts.netloc:
            raise UsageError(_BRACKET_HINT % _plain(token))
        raise UsageError('%s has a bad port' % _plain(token))
    ip = _canonical_ip(host)
    if ip is not None:
        norm_host = ip
    elif _numeric_tail(host):
        raise UsageError('%s is not an address (leading zeros, or fewer than four numbers?)'
                         % _plain(host))
    else:
        norm_host = _idna_host(host)
        if norm_host is None:
            raise UsageError('%s is not a valid host name' % _plain(host))
    if not scheme:
        scheme = 'http' if port == 80 else DEFAULT_SCHEME
    if port is None:
        port = 443 if scheme == 'https' else 80
    if not 1 <= port <= 65535:
        raise UsageError('%s: port out of range' % _plain(token))
    base_path = parts.path or '/'
    if not base_path.startswith('/'):
        base_path = '/' + base_path
    if not base_path.endswith('/'):
        base_path += '/'
    return Target(scheme, norm_host, port, base_path)


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


# The host-name lists of an ssl_origin_scan report's servers[] entries. servers[].name is an
# inventory label (web01, origin), never a host name, so it is never read.
_SCAN_SERVER_LISTS = ('needsUpdate', 'updated', 'originCert', 'privateCert', 'hostedNotInNewCert')


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _hosts_from_scan(doc: Any) -> Tuple[List[str], int]:
    """Host names from a scan's JSON -> (names, skipped). Reads an ssl_origin_scan report
    (``names[].name`` and the host-name lists of ``servers[]``; never ``servers[].name``, an
    inventory label), an ip_intel report (``addresses[].names[].name`` where the status is
    ``HERE``; ``skipped`` counts the others: a MOVED name points at another server now), or a
    plain ``{"names"|"hosts"|"targets": [...]}`` / bare list of strings. Wildcards and
    addresses are dropped: a wildcard is no host (its base name counts only if the scan listed
    it as a name of its own)."""
    names = []  # type: List[str]
    here = set()  # type: Set[str]
    elsewhere = set()  # type: Set[str]

    def strings(value: Any) -> None:
        names.extend(v for v in _as_list(value) if isinstance(v, str))

    if isinstance(doc, list):
        strings(doc)
    elif isinstance(doc, dict):
        for key in ('names', 'hosts', 'targets'):
            strings(doc.get(key))
        for entry in _as_list(doc.get('names')):  # ssl_origin_scan: {name, sni, wildcard}
            if isinstance(entry, dict) and isinstance(entry.get('name'), str) \
                    and not entry.get('wildcard'):
                names.append(entry['name'])
        for server in _as_list(doc.get('servers')):
            if isinstance(server, dict):
                for key in _SCAN_SERVER_LISTS:
                    strings(server.get(key))
        for address in _as_list(doc.get('addresses')):  # ip_intel
            if not isinstance(address, dict):
                continue
            for row in _as_list(address.get('names')):
                if not isinstance(row, dict) or not isinstance(row.get('name'), str):
                    continue
                if row.get('status') == 'HERE':
                    names.append(row['name'])
                    here.add(row['name'].lower())
                elif '*' not in row['name']:
                    elsewhere.add(row['name'].lower())
    out, seen = [], set()  # type: List[str], Set[str]
    for name in names:
        name = name.strip().rstrip('.')
        if not name or '*' in name or _canonical_ip(name):
            continue
        host = _idna_host(name)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out, len(elsewhere - here)


def parse_targets(values: Sequence[str], from_scan: Sequence[str] = (),
                  scheme: str = DEFAULT_SCHEME, max_hosts: int = DEFAULT_MAX_HOSTS,
                  stdin: Optional[Any] = None,
                  files: Sequence[str] = ()) -> Tuple[List[Target], List[str]]:
    """The targets of ``values`` (hosts, URLs, or files of them; ``-`` = stdin), of each of
    ``files`` (always a file, ``-`` = stdin: one that cannot be read is an error, never a host
    name) and the host names of each ``from_scan`` JSON report, de-duplicated in order, and a
    warning per unreadable token. Raises :class:`UsageError` past ``max_hosts``, on a bad
    command-line target or on a file that cannot be read (a bad target inside a file is a
    warning)."""
    targets = []  # type: List[Target]
    seen = set()  # type: set
    warnings = []  # type: List[str]

    def add(target: Target) -> None:
        key = (target.scheme, target.host, target.port, target.base_path)
        if key in seen:
            return
        if len(targets) >= max_hosts:
            raise UsageError('more than --max-hosts %d targets: give fewer or raise --max-hosts'
                             % max_hosts)
        seen.add(key)
        targets.append(target)

    def add_host(host: str) -> None:
        add(parse_target('%s://%s' % (scheme, host)))

    def add_file(token: str) -> None:
        label = 'stdin' if token == '-' else token
        for number, line in enumerate(_read_text(token, stdin).splitlines(), 1):
            line = line.split('#', 1)[0].strip()
            if not line:
                continue
            for item in re.split(r'[\s,;]+', line):
                if not item:
                    continue
                try:
                    add(parse_target(item))
                except UsageError as exc:
                    warnings.append('%s line %d: %s' % (label, number, exc))

    for value in values:
        token = value.strip()
        if not token:
            continue
        if token == '-' or os.path.isfile(token):
            add_file(token)
        elif '://' not in token and token.lower().endswith(_FILE_SUFFIXES):
            raise UsageError('cannot read %s: no such file (a host name? give it as https://%s/)'
                             % (_plain(token), _plain(token)))
        else:
            add(parse_target(token))  # a command-line target: its errors stop the run
    for path in files:
        add_file(path)

    for path in from_scan:
        text = _read_text(path, stdin)
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            raise UsageError('%s is not JSON' % path)
        hosts, skipped = _hosts_from_scan(doc)
        if skipped:
            warnings.append('%s: %d name%s skipped: only the names that resolve to the address '
                            'now (HERE) are audited' % (path, skipped, '' if skipped == 1 else 's'))
        if not hosts:
            warnings.append('%s: no host names found in the scan' % path)
        for host in hosts:
            add_host(host)
    return targets, warnings


# ---------------------------------------------------------------------------------------
# The curated path list: about forty well-known exposure paths, each with a content check
# ---------------------------------------------------------------------------------------

# categories
VCS = 'vcs'              # version-control directories
SECRET = 'secret'        # credentials, keys, environment files
CONFIG = 'config'        # server / app configuration
BACKUP = 'backup'        # backups and editor leftovers
INFO = 'info'            # status pages, debug and metadata endpoints
LISTING = 'listing'      # directory listing probes


def _head(body: bytes, size: int = 8192) -> str:
    return body[:size].decode('latin-1', 'replace')


def _looks_html(body: bytes) -> bool:
    head = body[:1024].lower()
    return b'<!doctype html' in head or b'<html' in head or b'<head' in head


def contains(*needles: str) -> Callable[[bytes, str], bool]:
    """A matcher for a file that may itself be HTML (a status page): any needle in the body."""
    probes = [n.lower().encode('latin-1') for n in needles]
    def check(body: bytes, ctype: str) -> bool:
        low = body[:MAX_BODY].lower()
        return any(p in low for p in probes)
    return check


def text_contains(*needles: str) -> Callable[[bytes, str], bool]:
    """A matcher for a non-HTML text file: the body must not be an HTML page (a catch-all app
    page is) and must hold a needle. :func:`classify` strips the echoed request path first, so
    a 404 page that quotes the path cannot satisfy it."""
    inner = contains(*needles)
    def check(body: bytes, ctype: str) -> bool:
        return not _looks_html(body) and inner(body, ctype)
    return check


def starts(*prefixes: bytes) -> Callable[[bytes, str], bool]:
    def check(body: bytes, ctype: str) -> bool:
        return any(body.startswith(p) for p in prefixes)
    return check


def git_head(body: bytes, ctype: str) -> bool:
    if _looks_html(body):
        return False
    text = _head(body, 256).strip()
    first = text.splitlines()[0] if text else ''
    return first.startswith('ref:') or bool(re.match(r'^[0-9a-f]{40}$|^[0-9a-f]{64}$', first))


def git_index(body: bytes, ctype: str) -> bool:
    return body[:4] == b'DIRC'  # the git index signature


def git_reflog(body: bytes, ctype: str) -> bool:
    if _looks_html(body):
        return False
    return bool(re.match(r'^[0-9a-f]{40} [0-9a-f]{40} ', _head(body, 256)))


def svn_entries(body: bytes, ctype: str) -> bool:
    """Subversion's entries file: the format number on a line of its own, then an empty line
    and ``dir`` (the working copy root), or the old XML form with ``wc-entries``. A bare number
    is not enough (a catch-all "404" is one); the stub newer clients leave there is found by the
    ``.svn/wc.db`` probe instead."""
    if _looks_html(body):
        return False
    head = _head(body, 512)
    if head.lstrip().startswith('<?xml'):
        return 'wc-entries' in head.lower()
    lines = [line.strip() for line in head.splitlines()[:6]]
    return (len(lines) >= 3 and lines[0].isdigit() and len(lines[0]) <= 2
            and 'dir' in lines[1:])


def netrc(body: bytes, ctype: str) -> bool:
    """A .netrc: a ``machine NAME`` line and a ``login`` or ``password`` token."""
    if _looks_html(body):
        return False
    text = _head(body).lower()
    return (bool(re.search(r'(?m)^[ \t]*machine[ \t]+\S', text))
            and bool(re.search(r'(?:^|\s)(?:login|password)[ \t]+\S', text)))


def actuator_health(body: bytes, ctype: str) -> bool:
    """Spring Boot's health endpoint with its details shown (components, disk space, the
    database). A bare ``{"status":"UP"}`` is a normal health check and does not match."""
    if _looks_html(body):
        return False
    low = body[:MAX_BODY].lower()
    return b'"status"' in low and (b'"components"' in low or b'"details"' in low)


def dotenv(body: bytes, ctype: str) -> bool:
    if _looks_html(body):
        return False
    lines = [l for l in _head(body).splitlines() if l.strip() and not l.lstrip().startswith('#')]
    if not lines:
        return False
    assigns = sum(1 for l in lines[:60] if re.match(r'^\s*(export\s+)?[A-Za-z_][\w.]*\s*=', l))
    return assigns >= 1 and assigns >= len(lines[:60]) * 0.5


def listing(body: bytes, ctype: str) -> bool:
    low = body[:MAX_BODY].lower()
    return (b'index of /' in low or b'directory listing for' in low
            or b'<title>index of' in low or b'[to parent directory]' in low)


def sql_dump(body: bytes, ctype: str) -> bool:
    if _looks_html(body):
        return False
    return contains('CREATE TABLE', 'INSERT INTO', 'MySQL dump', 'PostgreSQL database dump',
                    'SQLite format 3')(body, ctype) or body.startswith(b'SQLite format 3\x00')


def php_source(body: bytes, ctype: str) -> bool:
    if _looks_html(body):
        return False
    return contains('<?php', 'DB_PASSWORD', "define('db_", 'mysqli_connect')(body, ctype)


@dataclass(frozen=True)
class Probe:
    path: str                                   # relative, joined under the target base path
    category: str
    severity: str
    note: str
    confirm: Optional[Callable[[bytes, str], bool]] = None  # a body signature to confirm it


# One curated list. Not a wordlist: each path is a well-known, high-signal exposure, and each
# carries a content check so a catch-all 200 page is not mistaken for the real file. Files that
# are public on purpose (security.txt, a bare health check) are not on it.
PROBES = (
    # Version control
    Probe('.git/HEAD', VCS, HIGH, 'an exposed Git repository leaks source and history', git_head),
    Probe('.git/config', VCS, HIGH, 'Git config (remote URLs, sometimes credentials)',
          text_contains('[core]', '[remote')),
    Probe('.git/index', VCS, HIGH, 'the Git index lists every tracked file', git_index),
    Probe('.git/logs/HEAD', VCS, HIGH, 'the Git reflog (commits, author e-mails)', git_reflog),
    Probe('.svn/wc.db', VCS, HIGH, 'a Subversion working copy database', starts(b'SQLite format 3\x00')),
    Probe('.svn/entries', VCS, MEDIUM, 'an older Subversion working copy', svn_entries),
    Probe('.hg/requires', VCS, MEDIUM, 'a Mercurial repository',
          text_contains('revlogv1', 'dotencode', 'fncache', 'generaldelta', 'sparserevlog')),
    Probe('.bzr/branch-format', VCS, LOW, 'a Bazaar branch', text_contains('Bazaar')),
    # Secrets and environment
    Probe('.env', SECRET, HIGH, 'environment file: credentials, API keys, database passwords', dotenv),
    Probe('.env.local', SECRET, HIGH, 'a local environment file', dotenv),
    Probe('.env.production', SECRET, HIGH, 'a production environment file', dotenv),
    Probe('.env.bak', BACKUP, HIGH, 'a backup of the environment file', dotenv),
    Probe('.aws/credentials', SECRET, HIGH, 'AWS access keys',
          text_contains('aws_access_key_id', 'aws_secret_access_key')),
    Probe('.ssh/id_rsa', SECRET, HIGH, 'a private SSH key', text_contains('PRIVATE KEY-----')),
    Probe('.npmrc', SECRET, MEDIUM, 'an npm config (registry auth tokens)',
          text_contains('_authtoken', '_auth=', '//registry')),
    Probe('.netrc', SECRET, HIGH, 'a .netrc with login credentials', netrc),
    # Configuration
    Probe('.htaccess', CONFIG, MEDIUM, 'an Apache .htaccess served as text',
          text_contains('rewriteengine', 'rewriterule', 'authtype', 'require ', 'deny from')),
    Probe('web.config', CONFIG, MEDIUM, 'an IIS web.config served as text',
          text_contains('<configuration', '<system.web', '<connectionstrings')),
    Probe('wp-config.php.bak', CONFIG, HIGH, 'a WordPress config backup (DB credentials, salts)', php_source),
    Probe('config.php.bak', CONFIG, HIGH, 'a PHP config backup', php_source),
    Probe('.vscode/sftp.json', CONFIG, MEDIUM, 'a VS Code SFTP config (host, user, password)',
          text_contains('"remotepath"')),
    Probe('docker-compose.yml', CONFIG, MEDIUM, 'a Compose file (service images, env, secrets)',
          text_contains('services:', 'image:')),
    Probe('.docker/config.json', SECRET, HIGH, 'a Docker registry auth config', text_contains('"auths"')),
    # Backups and editor leftovers
    Probe('backup.zip', BACKUP, HIGH, 'a site backup archive', starts(b'PK\x03\x04', b'PK\x05\x06')),
    Probe('backup.sql', BACKUP, HIGH, 'a database dump', sql_dump),
    Probe('database.sql', BACKUP, HIGH, 'a database dump', sql_dump),
    Probe('dump.sql', BACKUP, HIGH, 'a database dump', sql_dump),
    Probe('index.php.bak', BACKUP, MEDIUM, 'a source backup served as text', php_source),
    Probe('index.php~', BACKUP, MEDIUM, 'an editor leftover served as text', php_source),
    Probe('.index.php.swp', BACKUP, MEDIUM, 'a Vim swap file', starts(b'b0VIM')),
    Probe('.DS_Store', INFO, LOW, 'a macOS .DS_Store (leaks file names)', starts(b'\x00\x00\x00\x01Bud1')),
    # Status, debug and metadata endpoints
    Probe('server-status', INFO, MEDIUM, 'Apache mod_status (requests, client IPs)',
          contains('Apache Server Status')),
    Probe('server-info', INFO, MEDIUM, 'Apache mod_info (full server configuration)',
          contains('Apache Server Information')),
    Probe('phpinfo.php', INFO, MEDIUM, 'a phpinfo() page (environment, paths, modules)',
          contains('<title>phpinfo()', 'phpinfo()</title>', '>PHP Version <')),
    Probe('info.php', INFO, MEDIUM, 'a phpinfo() page',
          contains('<title>phpinfo()', 'phpinfo()</title>', '>PHP Version <')),
    Probe('actuator/env', INFO, HIGH, 'Spring Boot actuator env (config, sometimes secrets)',
          text_contains('"activeprofiles"', '"propertysources"')),
    Probe('actuator/health', INFO, LOW, 'Spring Boot actuator health with its details (components, '
          'disk, database)', actuator_health),
    Probe('package.json', INFO, LOW, 'package.json (dependency and script disclosure)',
          text_contains('"dependencies"', '"devdependencies"')),
    Probe('composer.json', INFO, LOW, 'composer.json (dependency disclosure)',
          text_contains('"require"', '"autoload"')),
    # Directory listings
    Probe('uploads/', LISTING, MEDIUM, 'an open uploads directory listing', listing),
    Probe('backups/', LISTING, MEDIUM, 'an open backups directory listing', listing),
    Probe('.git/', LISTING, HIGH, 'an open .git directory listing', listing),
)


def paths_for(categories: Optional[Sequence[str]], extra: Sequence[str] = ()) -> List[Probe]:
    """The curated probes (optionally only ``categories``) plus any custom ``extra`` paths."""
    chosen = [p for p in PROBES if not categories or p.category in categories]
    for raw in extra:
        rel = raw.strip().lstrip('/')
        if rel:
            chosen.append(Probe(rel, 'custom', MEDIUM, 'a path you added', None))
    return chosen


# ---------------------------------------------------------------------------------------
# HTTP: one GET, redirects followed only within the same origin, the first MAX_BODY bytes
# ---------------------------------------------------------------------------------------

@dataclass
class Response:
    status: int
    body: bytes
    content_type: str
    length: int                      # bytes read (may be less than Content-Length if capped)
    final_url: str
    redirects: List[str] = field(default_factory=list)   # each redirect's target origin, in order
    location: str = ''               # the answer is a redirect not followed: its target's origin


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib must not follow a redirect, nor even parse its Location (a broken one would be a
    failure, not the answer it is): every 3xx is raised as an HTTPError, and :func:`http_get`
    decides, by origin."""

    def http_error_302(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> None:
        return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


_OPENERS = {}  # type: Dict[Tuple[bool, Optional[str]], urllib.request.OpenerDirector]
_OPENER_LOCK = threading.Lock()


def _make_context(insecure: bool, cafile: Optional[str]) -> ssl.SSLContext:
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=cafile)


def _opener(insecure: bool, cafile: Optional[str]) -> urllib.request.OpenerDirector:
    """A cached opener per trust mode: ``--insecure``, the system store, or each ``--cafile``."""
    key = (True, None) if insecure else (False, cafile or None)
    with _OPENER_LOCK:
        opener = _OPENERS.get(key)
        if opener is None:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=_make_context(insecure, key[1])), _NoRedirect)
            _OPENERS[key] = opener
        return opener


def _reset_openers() -> None:
    """Tests build fresh openers between trust modes."""
    with _OPENER_LOCK:
        _OPENERS.clear()


def _ctype(headers: Any) -> str:
    return (headers.get('Content-Type') or headers.get('content-type') or '').split(';')[0].strip().lower()


def _origin(url: str) -> str:
    """``scheme://host[:port]`` of an http(s) URL (the default port left out), '' for anything
    else. Never the path: a redirect's path or query can carry a token."""
    try:
        parts = urllib.parse.urlsplit(url)
        port = parts.port
    except ValueError:
        return ''
    scheme = (parts.scheme or '').lower()
    host = parts.hostname
    if scheme not in ('http', 'https') or not host:
        return ''
    netloc = '[%s]' % host if ':' in host else host
    if port is not None and port != (443 if scheme == 'https' else 80):
        netloc += ':%d' % port
    return '%s://%s' % (scheme, netloc)


def _same_origin(a: str, b: str) -> bool:
    """True when ``a`` and ``b`` share scheme, host and port: the only redirects followed, so a
    ``--header`` never reaches another service (another port) or goes out in clear text."""
    origin = _origin(a)
    return bool(origin) and origin == _origin(b)


def _join(base: str, location: str) -> str:
    try:
        return urllib.parse.urljoin(base, location)
    except ValueError:  # an unusable Location (a broken IPv6 literal, ...)
        return ''


def http_get(url: str, headers: Optional[Mapping[str, str]] = None, timeout: float = DEFAULT_TIMEOUT,
             insecure: bool = False, cafile: Optional[str] = None,
             max_redirects: int = MAX_REDIRECTS) -> Response:
    """GET ``url`` -> every HTTP answer (4xx and 5xx included), following redirects only within
    the same origin (scheme, host and port). A redirect anywhere else is returned as the answer,
    with its target's origin in :attr:`Response.location`, so a request to a server you audit
    never carries your ``--header`` to another host, another port or plain http, and another
    service's file is never taken for the audited one. Raises :class:`HttpFailure` without an
    answer. The message never holds the URL."""
    current = url
    redirects = []  # type: List[str]
    opener = _opener(insecure, cafile)
    for _ in range(max_redirects + 1):
        request = urllib.request.Request(current, method='GET')
        request.add_header('User-Agent', USER_AGENT)
        request.add_header('Accept', '*/*')
        request.add_header('Accept-Encoding', 'identity')
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with opener.open(request, timeout=timeout) as response:
                body = response.read(MAX_BODY)
                return Response(response.status, body, _ctype(response.headers), len(body),
                                current, redirects)
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                body = exc.read(MAX_BODY) or b''
            except (OSError, ValueError):
                body = b''
            finally:
                exc.close()
            ctype = _ctype(exc.headers) if exc.headers else ''
            if status in REDIRECT_CODES:
                location = exc.headers.get('Location') if exc.headers else None
                target = _join(current, location) if location else ''
                origin = _origin(target) if target else ''
                redirects.append(origin)
                if origin and _same_origin(current, target):
                    current = target
                    continue
                # Another origin, or no usable Location: the redirect is the answer.
                return Response(status, body, ctype, len(body), current, redirects, origin)
            return Response(status, body, ctype, len(body), current, redirects)
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, (socket.timeout, TimeoutError)):
                raise HttpFailure('timeout', 'no answer in %g s' % timeout)
            raise HttpFailure('network', _reason_text(exc.reason))
        except (socket.timeout, TimeoutError):
            raise HttpFailure('timeout', 'no answer in %g s' % timeout)
        except (OSError, ValueError) as exc:
            raise HttpFailure('network', _reason_text(exc))
    raise HttpFailure('network', 'too many redirects (> %d)' % max_redirects)


def _reason_text(reason: Any) -> str:
    if isinstance(reason, ssl.SSLError):
        text = 'TLS: %s' % (getattr(reason, 'reason', None) or reason)
        if 'CERTIFICATE_VERIFY_FAILED' in str(reason):
            text += ' (use --cafile for a private CA, or --insecure for a self-signed host you trust)'
        return text
    if isinstance(reason, OSError) and reason.strerror:
        return reason.strerror
    return str(reason) or type(reason).__name__


# ---------------------------------------------------------------------------------------
# The baseline: what the server does for a path that is not there
# ---------------------------------------------------------------------------------------

@dataclass
class Baseline:
    """How a host answers a random, non-existent path (``kind``: one of the constants above)."""
    kind: str = ''                       # '' = not asked
    soft_404: bool = False               # a 2xx catch-all page, or a steady redirect, for anything
    status: Optional[int] = None         # the status of the first sample
    content_type: str = ''
    length: int = 0                      # the catch-all body length (path echo removed)
    redirect_to: Optional[str] = None    # a steady redirect's target origin, if any
    samples: int = 0
    note: str = ''
    body: bytes = field(default=b'', repr=False)  # the catch-all page (echo removed), while auditing


def _baseline_tokens() -> List[str]:
    """Path names nobody has: random, new for every target."""
    return ['ds-audit-baseline-%s' % secrets.token_hex(6) for _ in range(BASELINE_SAMPLES)]


def _strip_echo(body: bytes, path: str) -> bytes:
    """A 404 page often quotes the path it did not find; removing it keeps a content check (or
    a length comparison) from matching on the echo rather than on the file."""
    out = body
    for text in (path, '/' + path.lstrip('/')):
        token = text.encode('latin-1', 'replace')
        if token:
            out = out.replace(token, b'')
    return out


def _stable_length(body: bytes, token: str) -> int:
    """The body length with the requested token removed, so a 404 page that echoes the path
    does not look like a different length for every probe."""
    return len(body.replace(token.encode('latin-1', 'replace'), b''))


def _similar_length(a: int, b: int) -> bool:
    return abs(a - b) <= max(96, int(0.08 * max(a, b, 1)))


def probe_baseline(target: Target, fetch: Callable[[str], Response]) -> Baseline:
    """Ask :data:`BASELINE_SAMPLES` random paths through ``fetch`` (an already-paced GET that
    raises :class:`HttpFailure`) and say how the host answers a path that is not there:
    ``SOFT_404`` when they agree on a 2xx (status, content type and length: the catch-all page,
    kept in :attr:`Baseline.body` for :func:`classify`), ``CATCH_REDIRECT`` for a steady
    redirect, ``HARD_404``, ``DENIED`` (401 / 403 for anything), ``STATUS_ONLY`` (another steady
    status), ``MIXED`` (they disagreed), ``RATE_LIMITED`` (429 / 503: nothing more is asked) or
    ``NO_ANSWER`` (a request without an answer: the target is unreachable)."""
    base = Baseline()
    seen = []  # type: List[Tuple[int, str, int, Optional[str], bytes]]
    for token in _baseline_tokens():
        try:
            resp = fetch(target.path_url(token))
        except HttpFailure as exc:
            base.kind = NO_ANSWER
            base.note = 'baseline request failed: %s' % exc
            return base
        if resp.status in (429, 503):
            base.kind, base.status, base.samples = RATE_LIMITED, resp.status, len(seen) + 1
            base.note = ('the server answered %d (slow down) to a baseline request: nothing else '
                         'was asked' % resp.status)
            return base
        seen.append((resp.status, resp.content_type, _stable_length(resp.body, token),
                     resp.location or None, _strip_echo(resp.body, token)))
    base.samples = len(seen)
    first = seen[0]
    base.status, base.content_type, base.length, base.redirect_to = first[:4]
    status = first[0]
    same_status = all(s[0] == status for s in seen)
    agree = same_status and all(s[1] == first[1] and _similar_length(s[2], first[2])
                                and s[3] == first[3] for s in seen)
    if agree and 200 <= status < 300:
        base.kind, base.soft_404, base.body = SOFT_404, True, first[4]
        base.note = ('the server answers %d for unknown paths (a catch-all page): an answer like '
                     'it is not counted' % status)
    elif agree and status in REDIRECT_CODES and first[3]:
        base.kind, base.soft_404 = CATCH_REDIRECT, True
        base.note = 'the server redirects unknown paths to %s' % _plain(first[3])
    elif same_status and status in (404, 410):
        base.kind = HARD_404
        base.note = 'the server returns %d for unknown paths' % status
    elif same_status and status in (401, 403):
        base.kind = DENIED
        base.note = ('every unknown path answers %d, so a %d says nothing about a path here (the '
                     'whole host behind auth? -H "Name: value" for an authorised audit)'
                     % (status, status))
    elif agree:
        base.kind = STATUS_ONLY
        base.note = 'the server answers %d for unknown paths; results are status-only' % status
    elif same_status:
        base.kind = MIXED
        base.note = ('the server answered %d to unknown paths with different pages; results are '
                     'status-only' % status)
    else:
        base.kind = MIXED
        base.note = ('the server was inconsistent for unknown paths (%s); results are status-only'
                     % ', '.join(str(s[0]) for s in seen))
    return base


# ---------------------------------------------------------------------------------------
# Classifying one probe's answer against the baseline
# ---------------------------------------------------------------------------------------

@dataclass
class Result:
    path: str
    url: str
    category: str
    severity: str
    note: str
    status: Optional[int] = None
    content_type: str = ''
    length: int = 0
    verdict: str = NOT_FOUND
    confidence: str = ''
    location: str = ''     # a redirect's target origin, if any
    detail: str = ''       # why this verdict

    @property
    def finding(self) -> bool:
        return self.verdict in FINDING_VERDICTS


def _catchall_like(resp: Response, baseline: Baseline, path: str) -> bool:
    """A 2xx answer that is indistinguishable from the server's catch-all page."""
    if baseline.kind != SOFT_404:
        return False
    return (resp.content_type == baseline.content_type
            and _similar_length(_stable_length(resp.body, path), baseline.length))


def classify(probe: Probe, resp: Response, baseline: Baseline) -> Tuple[str, str, str]:
    """-> (verdict, confidence, detail). A 2xx is judged by the probe's content check, against
    the host's baseline: where the catch-all page passes the check too, the check proves
    nothing, so an answer like that page is BASELINE and another body only LIKELY. On a host
    that denies every unknown path, the same 401 / 403 says nothing about the path either."""
    status = resp.status

    if status in (401, 403):
        if baseline.kind == DENIED and baseline.status == status:
            return BASELINE, '', 'every unknown path answers %d too' % status
        return PROTECTED, PRESENT, 'the path exists but is protected (%d)' % status
    if status == 429 or status == 503:
        return BLOCKED, '', 'the server answered %d (slow down)' % status
    if status in (404, 410):
        return NOT_FOUND, '', 'not found (%d)' % status
    if status in REDIRECT_CODES:
        # A redirect to another origin (http_get follows the same-origin ones).
        where = _plain(resp.location) if resp.location else 'another location'
        return REDIRECT, '', 'redirects to %s' % where
    if not (200 <= status < 300):
        return NOT_FOUND, '', 'status %d' % status

    catchall = _catchall_like(resp, baseline, probe.path)
    if probe.confirm is not None:
        # The check runs on the body with the echoed request path removed, so a page that quotes
        # the path cannot satisfy it (and the text checks reject an HTML page).
        if not probe.confirm(_strip_echo(resp.body, probe.path), resp.content_type):
            return NOT_FOUND, '', '%d but the body did not match the expected file (likely the app page)' % status
        verdict = LISTED if probe.category == LISTING else EXPOSED
        if baseline.kind == SOFT_404 and probe.confirm(baseline.body, baseline.content_type):
            if catchall:
                return BASELINE, '', 'same as the catch-all page, which passes the content check too'
            return verdict, LIKELY, ('the content check matches, but it matches the catch-all page '
                                     'too; this body is unlike that page')
        return verdict, CONFIRMED, 'content matches the expected file'

    # No content check (a custom path): the baseline is all we have. A 2xx that is
    # indistinguishable from the catch-all page is not reported.
    if catchall:
        return BASELINE, '', 'same as the catch-all page'
    if baseline.soft_404:
        return EXPOSED, LIKELY, 'a %d answer unlike the catch-all page' % status
    return EXPOSED, LIKELY, 'a %d answer' % status


# ---------------------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------------------

@dataclass
class HostReport:
    target: Target
    reachable: bool = True
    error: str = ''
    baseline: Baseline = field(default_factory=Baseline)
    results: List[Result] = field(default_factory=list)

    def findings(self) -> List[Result]:
        return [r for r in self.results if r.finding]

    def notable(self) -> List[Result]:
        return [r for r in self.results if r.verdict in NOTABLE_VERDICTS]

    def unchecked(self) -> List[Result]:
        return [r for r in self.results if r.verdict in UNCHECKED_VERDICTS]


@dataclass
class AuditReport:
    hosts: List[HostReport] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    generated_at: str = ''
    options: Dict[str, Any] = field(default_factory=dict)

    def findings(self) -> List[Result]:
        return [r for host in self.hosts for r in host.findings()]

    def complete(self) -> bool:
        """Every target answered and every path was checked."""
        return all(h.reachable and not h.unchecked() for h in self.hosts)


def _sort_results(results: List[Result]) -> None:
    rank = {v: i for i, v in enumerate(
        (EXPOSED, LISTED, PROTECTED, REDIRECT, BLOCKED, TIMEOUT, ERROR, BASELINE, NOT_FOUND))}
    results.sort(key=lambda r: (rank.get(r.verdict, 99), _SEVERITY_ORDER.get(r.severity, 9), r.path))


class HostPacer:
    """The request pace of one host, shared by every target on it (both schemes, every port and
    base path), so ``--rate`` holds for the host as a whole. :attr:`blocked` is set once the host
    answers 429 / 503; after that no target on it asks anything more."""

    def __init__(self, rate: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Optional[Callable[[float], None]] = None) -> None:
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.blocked = threading.Event()
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_at = None  # type: Optional[float]

    def wait_turn(self, stop: threading.Event) -> None:
        """Wait for the host's next request slot (cut short when ``stop`` is set)."""
        with self._lock:
            now = self._clock()
            slot = now if self._next_at is None else max(now, self._next_at)
            self._next_at = slot + self.interval
        delay = slot - now
        if delay > 0:
            if self._sleep is not None:
                self._sleep(delay)
            else:
                stop.wait(delay)


class _Stopped(Exception):
    """The run was interrupted before a request went out."""


def audit_host(target: Target, probes: Sequence[Probe], rate: float = DEFAULT_RATE,
               timeout: float = DEFAULT_TIMEOUT, insecure: bool = False,
               cafile: Optional[str] = None, headers: Optional[Mapping[str, str]] = None,
               stop: Optional[threading.Event] = None,
               get: Optional[Callable[..., Response]] = None,
               clock: Callable[[], float] = time.monotonic,
               sleep: Optional[Callable[[float], None]] = None,
               pacer: Optional[HostPacer] = None) -> HostReport:
    """Audit one target: a baseline, then each probe, one request at a time, paced by ``pacer``
    (the host's, shared with its other targets; without it a new one at ``rate``). A 429 / 503
    backs the whole host off. Once ``stop`` is set (Ctrl+C) nothing more is asked. ``get``
    defaults to :func:`http_get`, looked up when called."""
    report = HostReport(target)
    stop = stop or threading.Event()
    pacer = pacer or HostPacer(rate, clock=clock, sleep=sleep)
    fetch = get or http_get

    def paced_get(url: str) -> Response:
        pacer.wait_turn(stop)
        if stop.is_set():
            raise _Stopped()
        return fetch(url, headers=headers, timeout=timeout, insecure=insecure, cafile=cafile)

    def not_asked(probe: Probe) -> Result:
        return Result(probe.path, target.path_url(probe.path), probe.category, probe.severity,
                      probe.note, verdict=BLOCKED,
                      detail='not asked: the host answered 429 / 503 earlier')

    if stop.is_set():
        return report
    if pacer.blocked.is_set():
        report.baseline = Baseline(kind=RATE_LIMITED,
                                   note='not asked: the host answered 429 / 503 to another target')
        report.results = [not_asked(p) for p in probes]
        _sort_results(report.results)
        return report
    try:
        report.baseline = probe_baseline(target, paced_get)
    except _Stopped:
        return report
    if report.baseline.kind == NO_ANSWER:
        report.reachable = False
        report.error = report.baseline.note
        return report
    if report.baseline.kind == RATE_LIMITED:
        pacer.blocked.set()

    for probe in probes:
        if stop.is_set():
            break
        if pacer.blocked.is_set():
            report.results.append(not_asked(probe))
            continue
        result = Result(probe.path, target.path_url(probe.path), probe.category, probe.severity,
                        probe.note)
        try:
            resp = paced_get(result.url)
        except _Stopped:
            break
        except HttpFailure as exc:
            result.verdict = TIMEOUT if exc.kind == 'timeout' else ERROR
            result.detail = str(exc)
            report.results.append(result)
            continue
        result.status = resp.status
        result.content_type = resp.content_type
        result.length = resp.length
        result.location = resp.location
        result.verdict, result.confidence, result.detail = classify(probe, resp, report.baseline)
        if result.verdict == BLOCKED:
            pacer.blocked.set()
        report.results.append(result)
    report.baseline.body = b''  # only needed while this target is audited
    _sort_results(report.results)
    return report


def run_audit(targets: Sequence[Target], probes: Sequence[Probe], rate: float = DEFAULT_RATE,
              timeout: float = DEFAULT_TIMEOUT, insecure: bool = False, cafile: Optional[str] = None,
              headers: Optional[Mapping[str, str]] = None, workers: int = DEFAULT_WORKERS,
              progress: Optional[Callable[[int, int], None]] = None,
              get: Optional[Callable[..., Response]] = None,
              clock: Callable[[], float] = time.monotonic,
              sleep: Optional[Callable[[float], None]] = None) -> AuditReport:
    """Audit every target, up to ``workers`` at a time. The targets on one host share a
    :class:`HostPacer`, so ``rate`` holds per host however many targets it has. A
    KeyboardInterrupt (Ctrl+C) stops every target before its next request, then propagates."""
    report = AuditReport(generated_at=_utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
    report.hosts = [HostReport(t) for t in targets]
    if not targets:
        return report
    stop = threading.Event()
    pacers = {}  # type: Dict[str, HostPacer]
    for target in targets:
        if target.host not in pacers:
            pacers[target.host] = HostPacer(rate, clock=clock, sleep=sleep)
    done = [0]
    lock = threading.Lock()

    def one(index: int) -> None:
        if stop.is_set():
            return
        target = targets[index]
        report.hosts[index] = audit_host(target, probes, timeout=timeout, insecure=insecure,
                                         cafile=cafile, headers=headers, stop=stop, get=get,
                                         pacer=pacers[target.host])
        if progress:
            with lock:
                done[0] += 1
                progress(done[0], len(targets))

    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets))))
    try:
        pending = {pool.submit(one, i) for i in range(len(targets))}
        while pending:
            # A short wait, so Ctrl+C reaches this thread at once (on Windows too) and the
            # workers are stopped before their next request; a worker's error ends it the same way.
            finished, pending = wait_futures(pending, timeout=_POLL_SECONDS,
                                             return_when=FIRST_EXCEPTION)
            for future in finished:
                future.result()
    except BaseException:
        stop.set()
        raise
    finally:
        pool.shutdown(wait=True)
    return report


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


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


_VERDICT_COLOR = {EXPOSED: 'red', LISTED: 'red', PROTECTED: 'yellow', REDIRECT: 'dim',
                  BLOCKED: 'yellow', TIMEOUT: 'yellow', ERROR: 'yellow'}


def _plural(count: int, word: str) -> str:
    return '%d %s%s' % (count, word, '' if count == 1 else 's')


def _result_line(result: Result, color: _Color) -> str:
    sev = result.severity.upper()
    tag = result.verdict
    paint = getattr(color, _VERDICT_COLOR.get(result.verdict, 'dim'))
    head = '  %-9s %-6s %s' % (paint(tag), sev if result.finding or result.verdict == PROTECTED else '',
                               _plain('/' + result.path.lstrip('/')))
    bits = []
    if result.status is not None:
        bits.append('%d' % result.status)
    if result.content_type:
        bits.append(_plain(result.content_type))
    if result.confidence:
        bits.append(result.confidence)
    if result.detail:
        bits.append(_plain(result.detail))
    return '%s  (%s)' % (head.rstrip(), '; '.join(bits)) if bits else head.rstrip()


def _unchecked_line(results: Sequence[Result]) -> str:
    """Why paths were not checked: never a clean result, and what to do about it."""
    count = {v: sum(1 for r in results if r.verdict == v) for v in UNCHECKED_VERDICTS}
    why = []
    if count[BLOCKED]:
        why.append('%d blocked, the server rate-limited the audit (rerun later or lower --rate)'
                   % count[BLOCKED])
    if count[TIMEOUT]:
        why.append('%d timed out (raise --timeout)' % count[TIMEOUT])
    if count[ERROR]:
        why.append('%d failed (--show-all says why)' % count[ERROR])
    return '%s not checked: %s' % (_plural(len(results), 'path'), '; '.join(why))


def render_text(report: AuditReport, color: Optional[_Color] = None, show_all: bool = False) -> str:
    color = color or _Color(False)
    lines = []  # type: List[str]
    total_findings = 0
    for host in report.hosts:
        lines.append(color.bold(_plain(host.target.url)))
        if not host.reachable:
            lines.append('  %s %s' % (color.yellow('unreachable'), _plain(host.error)))
            lines.append('')
            continue
        if host.baseline.note:
            lines.append('  %s' % color.dim('baseline: ' + _plain(host.baseline.note)))
        notable = host.notable()
        unchecked = host.unchecked()
        checked = len(host.results) - len(unchecked)
        total_findings += len(host.findings())
        partial = not notable and unchecked and checked
        if not notable:
            if not unchecked:
                lines.append('  %s' % color.green('nothing exposed'))
            elif checked:
                lines.append('  %s' % color.yellow('no finding in the %s checked%s' % (
                    _plural(checked, 'path'), '' if show_all else ' (--show-all to see them)')))
        for result in (host.results if show_all else notable):
            lines.append(_result_line(result, color))
        if not show_all and not partial:
            quiet = checked - len(notable)
            if quiet:
                lines.append('  %s' % color.dim('%d more path%s not exposed (--show-all to see them)'
                                                % (quiet, '' if quiet == 1 else 's')))
        if unchecked:
            lines.append('  %s' % color.yellow(_unchecked_line(unchecked)))
        lines.append('')
    counts = _counts(report)
    reachable = sum(1 for h in report.hosts if h.reachable)
    summary = ('%d target%s, %d reachable: %s exposed (%d high, %d medium, %d low), %d protected'
               % (len(report.hosts), '' if len(report.hosts) == 1 else 's', reachable,
                  color.red(str(total_findings)) if total_findings else '0',
                  counts['high'], counts['medium'], counts['low'], counts[PROTECTED]))
    lines.append(summary)
    unreachable = len(report.hosts) - reachable
    if unreachable or counts['unchecked']:
        gaps = []
        if unreachable:
            gaps.append('%s unreachable' % _plural(unreachable, 'target'))
        if counts['unchecked']:
            gaps.append('%s not checked' % _plural(counts['unchecked'], 'path'))
        lines.append(color.yellow('incomplete: %s (--fail-on-error exits 1 on this)' % ', '.join(gaps)))
    if report.warnings:
        lines.append('warnings: %d (see --json)' % len(report.warnings))
    return '\n'.join(lines) + '\n'


def _counts(report: AuditReport) -> Dict[str, int]:
    counts = {'high': 0, 'medium': 0, 'low': 0, PROTECTED: 0, 'unchecked': 0}
    for host in report.hosts:
        for result in host.results:
            if result.finding:
                counts[result.severity] = counts.get(result.severity, 0) + 1
            elif result.verdict == PROTECTED:
                counts[PROTECTED] += 1
            elif result.verdict in UNCHECKED_VERDICTS:
                counts['unchecked'] += 1
    return counts


def _result_dict(result: Result) -> Dict[str, Any]:
    return {'path': result.path, 'url': result.url, 'category': result.category,
            'severity': result.severity, 'status': result.status, 'contentType': result.content_type,
            'length': result.length, 'verdict': result.verdict, 'confidence': result.confidence,
            'finding': result.finding, 'location': result.location, 'note': result.note,
            'detail': result.detail}


def report_to_dict(report: AuditReport) -> Dict[str, Any]:
    counts = _counts(report)
    hosts = []
    for host in report.hosts:
        hosts.append({
            'target': host.target.url,
            'scheme': host.target.scheme, 'host': host.target.host, 'port': host.target.port,
            'basePath': host.target.base_path,
            'reachable': host.reachable, 'error': host.error or None,
            'baseline': {'kind': host.baseline.kind or None, 'soft404': host.baseline.soft_404,
                         'status': host.baseline.status, 'contentType': host.baseline.content_type,
                         'length': host.baseline.length, 'redirectTo': host.baseline.redirect_to,
                         'samples': host.baseline.samples, 'note': host.baseline.note},
            'findings': len(host.findings()),
            'unchecked': len(host.unchecked()),
            'results': [_result_dict(r) for r in host.results],
        })
    return {
        'tool': TOOL, 'schema': SCHEMA, 'version': __version__,
        'generatedAt': report.generated_at,
        'options': report.options,
        'summary': {'targets': len(report.hosts),
                    'reachable': sum(1 for h in report.hosts if h.reachable),
                    'findings': len(report.findings()),
                    'bySeverity': {'high': counts['high'], 'medium': counts['medium'], 'low': counts['low']},
                    'protected': counts[PROTECTED],
                    'unchecked': counts['unchecked'],
                    'complete': report.complete()},
        'hosts': hosts,
        'warnings': report.warnings,
    }


CSV_COLUMNS = ('target', 'host', 'port', 'path', 'url', 'status', 'contentType', 'length',
               'category', 'severity', 'verdict', 'confidence', 'finding', 'location', 'detail')


def render_csv(report: AuditReport, lineterminator: str = '\r\n') -> str:
    """One row per (target, path). An unreachable host gets one row with an empty path."""
    out = io.StringIO()
    writer = csv.writer(out, lineterminator=lineterminator)
    writer.writerow(CSV_COLUMNS)
    for host in report.hosts:
        t = host.target
        if not host.reachable:
            writer.writerow([csv_cell(v) for v in (t.url, t.host, t.port, '', '', '', '', '',
                                                    '', '', 'ERROR', '', False, '', host.error)])
            continue
        for r in host.results:
            writer.writerow([csv_cell(v) for v in (
                t.url, t.host, t.port, r.path, r.url, r.status if r.status is not None else '',
                r.content_type, r.length, r.category, r.severity, r.verdict, r.confidence,
                r.finding, r.location, r.detail)])
    return out.getvalue()


def render_paths() -> str:
    """The ``paths`` command: the curated list, by category."""
    lines = ['The curated exposure paths %s checks (%d), by category:' % (PROG, len(PROBES))]
    by_cat = {}  # type: Dict[str, List[Probe]]
    for probe in PROBES:
        by_cat.setdefault(probe.category, []).append(probe)
    for category in (VCS, SECRET, CONFIG, BACKUP, INFO, LISTING):
        probes = by_cat.get(category, [])
        if not probes:
            continue
        lines.append('')
        lines.append('%s:' % category)
        for probe in probes:
            lines.append('  %-5s /%-24s %s' % (probe.severity, probe.path, probe.note))
    lines.append('')
    lines.append('--paths FILE adds up to %d of your own; --only CATEGORY narrows the list.'
                 % MAX_CUSTOM_PATHS)
    return '\n'.join(lines) + '\n'


# ---------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------

def _parse_headers(values: Optional[Sequence[str]]) -> Dict[str, str]:
    headers = {}  # type: Dict[str, str]
    for raw in values or []:
        if ':' not in raw:
            raise UsageError('--header must be "Name: value", not %s' % _plain(raw))
        name, value = raw.split(':', 1)
        name = name.strip()
        if not name or any(c in name for c in ' \t'):
            raise UsageError('--header has a bad name: %s' % _plain(raw))
        headers[name] = value.strip()
    return headers


def _custom_paths(path: Optional[str], stdin: Optional[Any] = None) -> List[str]:
    if not path:
        return []
    paths = []  # type: List[str]
    for line in _read_text(path, stdin).splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            paths.append(line)
    if len(paths) > MAX_CUSTOM_PATHS:
        raise UsageError('--paths holds %d paths; at most %d (this is a self-audit, not a wordlist)'
                         % (len(paths), MAX_CUSTOM_PATHS))
    return paths


EPILOG = """\
examples:
  %(prog)s audit example.com www.example.com
  %(prog)s audit https://app.example.net:8443/ --rate 2 --json audit.json --csv audit.csv
  %(prog)s audit -t hosts.txt --from-scan scan.json --only vcs,secret
  %(prog)s audit -t hosts.txt --fail-on-finding --fail-on-error
  %(prog)s paths

Only audit servers you own or are authorised to test. Targets come from you; the path list is
curated, not a wordlist; requests are rate-capped per host and the tool only reads.
""" % {'prog': PROG}


def build_parser() -> argparse.ArgumentParser:
    description = ('An authorised self-audit of your own web servers for exposed paths: open '
                   'version-control directories, environment and config files, backups and '
                   'status / debug pages. A baseline request per target suppresses catch-all '
                   'pages; a per-host rate cap keeps it polite. Python 3.8+, stdlib only.')
    parser = argparse.ArgumentParser(prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=description, epilog=EPILOG)
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    commands = parser.add_subparsers(dest='command', metavar='COMMAND')
    commands.required = True

    audit = commands.add_parser('audit', help='audit your servers for exposed paths',
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                description=description, epilog=EPILOG)
    audit.add_argument('targets', nargs='*', metavar='TARGET',
                       help='a host, a URL, or a file of them ("-" = stdin). A bare host is https')
    src = audit.add_argument_group('targets')
    src.add_argument('-t', '--targets-file', action='append', default=[], metavar='FILE',
                     help='a file of targets, one or more a line ("-" = stdin); repeatable. '
                          'A file that cannot be read is an error')
    src.add_argument('--from-scan', action='append', default=[], metavar='FILE',
                     help='take host names from a scan JSON report (ssl_origin_scan: the names it '
                          'probed; ip_intel: the names found HERE); repeatable')
    what = audit.add_argument_group('what is checked')
    what.add_argument('--only', metavar='LIST',
                      help='only these categories, comma-separated: %s'
                           % ', '.join((VCS, SECRET, CONFIG, BACKUP, INFO, LISTING)))
    what.add_argument('--paths', metavar='FILE',
                      help='add up to %d of your own paths (one a line); not a wordlist' % MAX_CUSTOM_PATHS)
    net = audit.add_argument_group('how')
    net.add_argument('--rate', type=float, default=DEFAULT_RATE, metavar='N',
                     help='requests a second, per host, shared by all its targets (default: '
                          '%(default)s; max ' + ('%g' % MAX_RATE) + ')')
    net.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                     help='per request (default: %(default)s)')
    net.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                     help='targets audited in parallel (default: %(default)s); a host keeps its rate')
    net.add_argument('--max-hosts', type=int, default=DEFAULT_MAX_HOSTS, metavar='N',
                     help='at most N targets (default: %(default)s)')
    net.add_argument('-H', '--header', action='append', default=[], metavar='"Name: value"',
                     help='an extra request header (a cookie or token for an authorised audit); '
                          'repeatable. Sent only to the audited origin (scheme, host and port): a '
                          'redirect anywhere else is not followed')
    net.add_argument('--insecure', action='store_true',
                     help='do not verify TLS certificates (for a self-signed host you trust)')
    net.add_argument('--cafile', metavar='FILE', help='verify TLS against this CA bundle (a private CA)')
    out = audit.add_argument_group('output')
    out.add_argument('--json', metavar='FILE', help='write a JSON report ("-" = stdout)')
    out.add_argument('--csv', metavar='FILE', help='write a CSV report ("-" = stdout)')
    out.add_argument('--show-all', action='store_true', help='list every path, not only the findings')
    out.add_argument('--fail-on-finding', action='store_true',
                     help='exit with code 1 when anything is exposed (for CI)')
    out.add_argument('--fail-on-error', action='store_true',
                     help='exit with code 1 when a target could not be fully audited: unreachable, '
                          'or paths not checked (rate limited, timed out, failed)')
    out.add_argument('--no-color', action='store_true', help='no ANSI colors')
    out.add_argument('-q', '--quiet', action='store_true', help='no progress or warnings on stderr')

    commands.add_parser('paths', help='print the curated path list and exit',
                        description='Print the curated exposure paths the audit checks.')
    return parser


def _write(path: str, text: str, encoding: str = 'utf-8') -> None:
    if path == '-':
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    with open(path, 'w', encoding=encoding, newline='') as handle:
        handle.write(text)


def _run_audit(args: argparse.Namespace) -> int:
    err = sys.stderr
    if not 0 < args.timeout <= MAX_TIMEOUT:
        raise UsageError('--timeout must be > 0 and <= %g seconds' % MAX_TIMEOUT)
    if not 0 < args.rate <= MAX_RATE:
        raise UsageError('--rate must be > 0 and <= %g requests a second' % MAX_RATE)
    if not 1 <= args.workers <= MAX_WORKERS:
        raise UsageError('--workers must be between 1 and %d' % MAX_WORKERS)
    if not 1 <= args.max_hosts <= MAX_HOSTS:
        raise UsageError('--max-hosts must be between 1 and %d' % MAX_HOSTS)
    if args.json == '-' and args.csv == '-':
        raise UsageError('--json - and --csv - cannot both write to stdout')
    if args.cafile and args.insecure:
        raise UsageError('--cafile and --insecure cannot be combined')
    if args.cafile and not os.path.isfile(args.cafile):
        raise UsageError('--cafile %s is not a file' % _plain(args.cafile))

    categories = None
    if args.only:
        categories = [c.strip().lower() for c in re.split(r'[\s,]+', args.only) if c.strip()]
        known = {VCS, SECRET, CONFIG, BACKUP, INFO, LISTING}
        bad = [c for c in categories if c not in known]
        if bad:
            raise UsageError('--only: unknown categor%s %s (choose from %s)'
                             % ('y' if len(bad) == 1 else 'ies', ', '.join(_plain(b) for b in bad),
                                ', '.join(sorted(known))))
    headers = _parse_headers(args.header)
    extra = _custom_paths(args.paths)
    probes = paths_for(categories, extra)

    targets, warnings = parse_targets(args.targets, from_scan=args.from_scan,
                                      max_hosts=args.max_hosts, files=args.targets_file)
    if not targets:
        raise UsageError('no targets: give a host, a URL, -t FILE or --from-scan FILE')

    if not args.quiet:
        for warning in warnings[:25]:
            print('warning: %s' % warning, file=err)
        if len(warnings) > 25:
            print('warning: ... and %d more' % (len(warnings) - 25), file=err)
        print('note: auditing %s on an explicit, authorised target list; %s each, %g req/s per host'
              % (_plural(len(targets), 'target'), _plural(len(probes), 'path'), args.rate), file=err)
    tty = not args.quiet and hasattr(err, 'isatty') and err.isatty()

    def progress(done: int, total: int) -> None:
        if tty and (done == total or done % 5 == 0):
            err.write('\raudited: %d / %d targets' % (done, total))
            if done == total:
                err.write('\n')
            err.flush()

    report = run_audit(targets, probes, rate=args.rate, timeout=args.timeout, insecure=args.insecure,
                       cafile=args.cafile, headers=headers, workers=args.workers, progress=progress)
    report.warnings = warnings
    report.options = {'rate': args.rate, 'timeout': args.timeout, 'workers': args.workers,
                      'categories': categories, 'customPaths': len(extra), 'probes': len(probes),
                      'insecure': args.insecure, 'cafile': bool(args.cafile),
                      'headers': sorted(headers.keys())}

    failed = False
    for path, kind in ((args.json, 'json'), (args.csv, 'csv')):
        if not path:
            continue
        if kind == 'json':
            text = json.dumps(report_to_dict(report), indent=2) + '\n'
        else:
            text = render_csv(report, '\n' if path == '-' else '\r\n')
        try:
            _write(path, text, 'utf-8' if kind == 'json' or path == '-' else 'utf-8-sig')
        except OSError as exc:
            print('%s: error: cannot write %s: %s' % (PROG, path, exc.strerror or exc), file=err)
            failed = True

    if args.json != '-' and args.csv != '-':
        use_color = not args.no_color and not os.environ.get('NO_COLOR') \
            and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        sys.stdout.write(render_text(report, _Color(use_color), show_all=args.show_all))
        sys.stdout.flush()

    if failed:
        return EXIT_OUTPUT_ERROR
    if args.fail_on_finding and report.findings():
        return EXIT_FINDINGS
    if args.fail_on_error and not report.complete():
        return EXIT_INCOMPLETE
    return EXIT_OK


def main(argv: Optional[Sequence[str]] = None) -> int:
    """Command-line entry point; returns the exit code (0, 1, 2, 3 or 130)."""
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
        if args.command == 'paths':
            sys.stdout.write(render_paths())
            return EXIT_OK
        return _run_audit(args)
    except UsageError as exc:
        print('%s: error: %s' % (PROG, exc), file=sys.stderr)
        return EXIT_USAGE
    except KeyboardInterrupt:
        print('\ninterrupted', file=sys.stderr)
        return EXIT_INTERRUPTED


if __name__ == '__main__':
    sys.exit(main())
