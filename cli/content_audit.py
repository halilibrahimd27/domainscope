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
  * targets come from you - host names, URLs, a file of them, or the names a scan of yours
    already found (`--from-scan`). It never discovers hosts on its own;
  * it asks a small, curated list of about forty well-known exposure paths, not a wordlist,
    and `ds_paths` prints it. `--paths FILE` adds a few of your own (capped, not a wordlist);
  * one baseline request per host first (a random, non-existent path) learns the server's
    catch-all behaviour, so a site that answers 200 for everything does not drown you in
    false positives;
  * a per-host rate cap keeps the audit polite (default 5 requests a second per host), and the
    audit backs off a host that answers 429 or 503;
  * it only reads: a plain GET, the first 256 KB of each body, redirects followed only on the
    same host. It never sends a payload, guesses a password or tries to exploit anything.

JSON (`--json`) and CSV (`--csv`) outputs carry every result; the text summary shows the
findings first. Exit code 0, or 1 with `--fail-on-finding` when anything is exposed, 2 for a
usage error, 3 when a report file could not be written.

Python 3.8+, standard library only, single file - copy it anywhere.

The module is importable: parse_targets(), Target, PROBES, Probe, http_get(), probe_baseline(),
classify(), audit_host(), run_audit(), render_text(), report_to_dict(), render_csv(),
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
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

__version__ = '1.0.0'
PROG = 'content_audit.py'
SCHEMA = 'domainscope.content-audit/1'
TOOL = 'content_audit'
USER_AGENT = 'content_audit/%s (+https://github.com/halilibrahimd27/domainscope)' % __version__

# --- verdicts, per (host, path) --------------------------------------------------------
EXPOSED = 'EXPOSED'        # the file or directory is readable (a finding)
LISTED = 'LISTED'          # a directory listing is served (a finding)
PROTECTED = 'PROTECTED'    # it exists but is behind auth (401 / 403) - informational
REDIRECT = 'REDIRECT'      # answered with a redirect off the audited path
BASELINE = 'BASELINE'      # indistinguishable from the server's catch-all page
NOT_FOUND = 'NOT_FOUND'    # 404 / 410, or a 200 whose content did not match the file
BLOCKED = 'BLOCKED'        # the server answered 429 / 503 (rate limited us) or we backed off
TIMEOUT = 'TIMEOUT'        # no answer in --timeout seconds
ERROR = 'ERROR'            # a network or protocol error
VERDICTS = (EXPOSED, LISTED, PROTECTED, REDIRECT, BASELINE, NOT_FOUND, BLOCKED, TIMEOUT, ERROR)
# The verdicts that count as a finding and, with --fail-on-finding, fail the run.
FINDING_VERDICTS = (EXPOSED, LISTED)
# Shown to the operator as "worth a look" (findings + the present-but-protected paths).
NOTABLE_VERDICTS = (EXPOSED, LISTED, PROTECTED)

# --- confidence of a finding -----------------------------------------------------------
CONFIRMED = 'confirmed'    # the body matched what the file looks like
LIKELY = 'likely'          # the status says it is there, no content signature to confirm
PRESENT = 'present'        # it is there but protected (401 / 403)

# --- severity of a probe ---------------------------------------------------------------
HIGH = 'high'
MEDIUM = 'medium'
LOW = 'low'
SEVERITIES = (HIGH, MEDIUM, LOW)
_SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}

EXIT_OK = 0
EXIT_FINDINGS = 1          # only with --fail-on-finding
EXIT_USAGE = 2
EXIT_OUTPUT_ERROR = 3      # a --json / --csv file could not be written after the audit
EXIT_INTERRUPTED = 130

DEFAULT_SCHEME = 'https'
DEFAULT_RATE = 5.0         # requests a second, per host
MAX_RATE = 50.0
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 120.0
DEFAULT_WORKERS = 8        # hosts audited in parallel; each host's requests stay serial
MAX_WORKERS = 64
DEFAULT_MAX_HOSTS = 256
MAX_HOSTS = 4096
MAX_REDIRECTS = 4          # followed only on the same host
MAX_BODY = 256 * 1024      # bytes read per response (enough to recognise a file)
MAX_CUSTOM_PATHS = 200     # --paths is for a few of your own, never a wordlist
MAX_TARGET_FILE = 20 * 1024 * 1024
BASELINE_SAMPLES = 2       # random, non-existent paths asked to learn the catch-all


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
_NUMERIC_RE = re.compile(r'^[0-9.]+$')


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


def _idna_host(host: str) -> Optional[str]:
    """A host name lowercased and, if it has non-ASCII, IDNA-encoded; None if it is not a
    valid host name."""
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
    if len(labels) == 1 and _NUMERIC_RE.match(ascii_host):
        return None  # a bare number is not a host name (and not an IP we accepted above)
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
    ``host:port``, ``[v6]:port`` and IP literals. A bare host is https on 443; a bare
    ``host:80`` is http. Raises :class:`UsageError` for anything else."""
    token = value.strip()
    if not token:
        raise UsageError('an empty target')
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
        raise UsageError('%s has a bad port' % _plain(token))
    ip = _canonical_ip(host)
    if ip is not None:
        norm_host = ip
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


def _hosts_from_scan(doc: Any) -> List[str]:
    """Host names from a scan's JSON: an ssl_origin_scan / ip_intel report, or a plain
    ``{"names"|"hosts": [...]}`` or bare list of strings. Addresses and wildcards dropped."""
    names = []  # type: List[str]

    def take(value: Any) -> None:
        if isinstance(value, str):
            names.append(value)
        elif isinstance(value, list):
            for item in value:
                take(item)

    if isinstance(doc, list):
        take(doc)
    elif isinstance(doc, dict):
        for key in ('names', 'hosts', 'targets'):
            take(doc.get(key))
        for key in ('servers', 'addresses', 'rows'):
            rows = doc.get(key)
            if isinstance(rows, list):
                for row in rows:
                    if isinstance(row, dict):
                        take(row.get('names'))
                        take(row.get('name'))
        for cert in (doc.get('newCertificates') or []):
            if isinstance(cert, dict):
                take(cert.get('names'))
    out, seen = [], set()  # type: List[str], set
    for name in names:
        if not isinstance(name, str):
            continue
        name = name.strip().lstrip('*.').rstrip('.')
        if not name or _canonical_ip(name):
            continue
        host = _idna_host(name)
        if host and host not in seen:
            seen.add(host)
            out.append(host)
    return out


def parse_targets(values: Sequence[str], from_scan: Sequence[str] = (),
                  scheme: str = DEFAULT_SCHEME, max_hosts: int = DEFAULT_MAX_HOSTS,
                  stdin: Optional[Any] = None) -> Tuple[List[Target], List[str]]:
    """The targets of ``values`` (hosts, URLs, files of them, ``-`` = stdin) and the host
    names of each ``from_scan`` JSON report, de-duplicated in order, and a warning per
    unreadable token. Raises :class:`UsageError` past ``max_hosts`` or on a bad command-line
    target (a bad target inside a file is a warning)."""
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

    for value in values:
        token = value.strip()
        if not token:
            continue
        if token != '-' and not os.path.isfile(token):
            add(parse_target(token))  # a command-line target: its errors stop the run
            continue
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

    for path in from_scan:
        text = _read_text(path, stdin)
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            raise UsageError('%s is not JSON' % path)
        hosts = _hosts_from_scan(doc)
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
    if _looks_html(body):
        return False
    first = (_head(body, 64).splitlines() or [''])[0].strip()
    return first.isdigit() or first.startswith('<?xml')  # the format number, or the XML form


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


# One curated list. Not a wordlist: each path is a well-known, high-signal exposure, and most
# carry a content check so a catch-all 200 page is not mistaken for the real file.
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
    Probe('.netrc', SECRET, HIGH, 'a .netrc with login credentials',
          text_contains('machine ', 'login ', 'password ')),
    # Configuration
    Probe('.htaccess', CONFIG, MEDIUM, 'an Apache .htaccess served as text',
          text_contains('rewriteengine', 'rewriterule', 'authtype', 'require ', 'deny from')),
    Probe('web.config', CONFIG, MEDIUM, 'an IIS web.config served as text',
          text_contains('<configuration', '<system.web', '<connectionstrings')),
    Probe('wp-config.php.bak', CONFIG, HIGH, 'a WordPress config backup (DB credentials, salts)', php_source),
    Probe('config.php.bak', CONFIG, HIGH, 'a PHP config backup', php_source),
    Probe('.vscode/sftp.json', CONFIG, MEDIUM, 'a VS Code SFTP config (host, user, password)',
          text_contains('"host"', '"remotepath"', '"privatekeypath"')),
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
    Probe('actuator/health', INFO, LOW, 'a Spring Boot actuator endpoint',
          text_contains('{"status":"up"', '{"status":"down"', '{"status": "up"')),
    Probe('.well-known/security.txt', INFO, LOW, 'a security.txt (not a leak; noted for completeness)',
          text_contains('contact:', 'expires:')),
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
# HTTP: one GET, redirects followed only on the same host, the first MAX_BODY bytes
# ---------------------------------------------------------------------------------------

@dataclass
class Response:
    status: int
    body: bytes
    content_type: str
    length: int                      # bytes read (may be less than Content-Length if capped)
    final_url: str
    redirects: List[str] = field(default_factory=list)   # redirect target hosts, in order


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib must not follow redirects for us: we decide, by host, in :func:`http_get`."""

    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any,
                         newurl: str) -> None:
        return None


_OPENER_INSECURE = None  # type: Optional[urllib.request.OpenerDirector]
_OPENER_SECURE = None    # type: Optional[urllib.request.OpenerDirector]
_OPENER_LOCK = threading.Lock()


def _make_context(insecure: bool, cafile: Optional[str]) -> ssl.SSLContext:
    if insecure:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    return ssl.create_default_context(cafile=cafile)


def _opener(insecure: bool, cafile: Optional[str]) -> urllib.request.OpenerDirector:
    """A cached opener per trust mode. ``--cafile`` rebuilds it (one file for a whole run)."""
    global _OPENER_INSECURE, _OPENER_SECURE
    with _OPENER_LOCK:
        if insecure:
            if _OPENER_INSECURE is None:
                _OPENER_INSECURE = urllib.request.build_opener(
                    urllib.request.HTTPSHandler(context=_make_context(True, None)), _NoRedirect)
            return _OPENER_INSECURE
        if _OPENER_SECURE is None:
            _OPENER_SECURE = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=_make_context(False, cafile)), _NoRedirect)
        return _OPENER_SECURE


def _reset_openers() -> None:
    """Tests build fresh openers between trust modes."""
    global _OPENER_INSECURE, _OPENER_SECURE
    with _OPENER_LOCK:
        _OPENER_INSECURE = _OPENER_SECURE = None


def _ctype(headers: Any) -> str:
    return (headers.get('Content-Type') or headers.get('content-type') or '').split(';')[0].strip().lower()


def _same_host(a: str, b: str) -> bool:
    return (urllib.parse.urlsplit(a).hostname or '').lower() == (urllib.parse.urlsplit(b).hostname or '').lower()


def http_get(url: str, headers: Optional[Mapping[str, str]] = None, timeout: float = DEFAULT_TIMEOUT,
             insecure: bool = False, cafile: Optional[str] = None,
             max_redirects: int = MAX_REDIRECTS) -> Response:
    """GET ``url`` -> every HTTP answer (4xx and 5xx included), following redirects only to
    the same host (an off-host redirect is returned as-is, so a request to a server you audit
    never carries your ``--header`` to another host). Raises :class:`HttpFailure` without an
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
            if status in (301, 302, 303, 307, 308):
                location = exc.headers.get('Location') if exc.headers else None
                target = urllib.parse.urljoin(current, location) if location else None
                if target and target.split('://', 1)[0] in ('http', 'https') and _same_host(current, target):
                    redirects.append(urllib.parse.urlsplit(target).hostname or '')
                    current = target
                    continue
                # An off-host redirect, or a redirect without a usable Location: the answer.
                off = urllib.parse.urlsplit(urllib.parse.urljoin(current, location or '')).hostname
                redirects.append((off or '') if location else '')
            return Response(status, body, _ctype(exc.headers) if exc.headers else '',
                            len(body), current, redirects)
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
    """How a host answers a random, non-existent path."""
    soft_404: bool = False               # it answers 2xx (or a steady redirect) for anything
    status: Optional[int] = None         # the catch-all status
    content_type: str = ''
    length: int = 0                      # the catch-all body length (path echo removed)
    redirect_host: Optional[str] = None  # a steady off-host redirect target, if any
    samples: int = 0
    note: str = ''


_RANDOM_NAMES = ('ds-audit-baseline-7f3a9', 'ds-audit-baseline-c1e82')


def _stable_length(body: bytes, token: str) -> int:
    """The body length with the requested token removed, so a 404 page that echoes the path
    does not look like a different length for every probe."""
    return len(body.replace(token.encode('latin-1', 'replace'), b''))


def _similar_length(a: int, b: int) -> bool:
    return abs(a - b) <= max(96, int(0.08 * max(a, b, 1)))


def probe_baseline(target: Target, fetch: Callable[[str], Response]) -> Baseline:
    """Ask up to :data:`BASELINE_SAMPLES` random paths through ``fetch`` (an already-paced GET
    that raises :class:`HttpFailure`). If they agree on a 2xx answer (or a steady same-status
    redirect) the host has a catch-all and :attr:`Baseline.soft_404` is set with its signature;
    if they 404, the baseline is a hard 404."""
    base = Baseline()
    seen = []  # type: List[Tuple[int, str, int, Optional[str]]]
    for i, name in enumerate(_RANDOM_NAMES[:BASELINE_SAMPLES]):
        token = '%s%d' % (name, i)
        try:
            resp = fetch(target.path_url(token))
        except HttpFailure as exc:
            base.note = 'baseline request failed: %s' % exc
            return base
        redirect_host = resp.redirects[-1] if resp.redirects and resp.redirects[-1] else None
        seen.append((resp.status, resp.content_type, _stable_length(resp.body, token), redirect_host))
    base.samples = len(seen)
    if not seen:
        return base
    first = seen[0]
    agree = all(s[0] == first[0] and s[1] == first[1] and _similar_length(s[2], first[2])
                and s[3] == first[3] for s in seen)
    base.status, base.content_type, base.length, base.redirect_host = first
    if agree and (200 <= first[0] < 300 or (first[0] in (301, 302, 303, 307, 308) and first[3])):
        base.soft_404 = True
        base.note = ('the server answers %d for unknown paths%s' %
                     (first[0], ' (redirects to %s)' % _plain(first[3]) if first[3] else ''))
    elif agree and first[0] in (404, 410):
        base.note = 'the server returns %d for unknown paths' % first[0]
    else:
        base.note = 'the server was inconsistent for unknown paths; results are status-only'
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
    location: str = ''     # a redirect's target host, if any
    detail: str = ''       # why this verdict

    @property
    def finding(self) -> bool:
        return self.verdict in FINDING_VERDICTS


def _strip_echo(body: bytes, path: str) -> bytes:
    """A 404 page often quotes the path it did not find; removing it keeps a content check (or
    a length comparison) from matching on the echo rather than on the file."""
    out = body
    for text in (path, '/' + path.lstrip('/')):
        token = text.encode('latin-1', 'replace')
        if token:
            out = out.replace(token, b'')
    return out


def _catchall_like(resp: Response, baseline: Baseline, path: str) -> bool:
    """A 2xx answer that is indistinguishable from the server's catch-all page."""
    if not (baseline.soft_404 and baseline.status is not None and 200 <= baseline.status < 300):
        return False
    return (resp.content_type == baseline.content_type
            and _similar_length(_stable_length(resp.body, path), baseline.length))


def classify(probe: Probe, resp: Response, baseline: Baseline) -> Tuple[str, str, str]:
    """-> (verdict, confidence, detail). Uses the probe's content check and the host's
    baseline so a catch-all 200 page is not reported as a find."""
    status = resp.status

    if status in (401, 403):
        return PROTECTED, PRESENT, 'the path exists but is protected (%d)' % status
    if status == 429 or status == 503:
        return BLOCKED, '', 'the server answered %d (slow down)' % status
    if status in (404, 410):
        return NOT_FOUND, '', 'not found (%d)' % status
    if status in (301, 302, 303, 307, 308):
        # A redirect that did not stay on-host (http_get follows same-host ones).
        host = resp.redirects[-1] if resp.redirects else ''
        return REDIRECT, '', 'redirects to %s' % (_plain(host) if host else 'another location')
    if not (200 <= status < 300):
        return NOT_FOUND, '', 'status %d' % status

    # A 2xx answer. A content check runs on the body with the echoed request path removed, so
    # a catch-all page that quotes the path cannot satisfy it and the text checks reject HTML.
    if probe.confirm is not None:
        if probe.confirm(_strip_echo(resp.body, probe.path), resp.content_type):
            verdict = LISTED if probe.category == LISTING else EXPOSED
            return verdict, CONFIRMED, 'content matches the expected file'
        return NOT_FOUND, '', '200 but the body did not match the expected file (likely the app page)'

    # No content check (a custom path): the baseline is all we have. A 2xx that is
    # indistinguishable from the catch-all page is not reported.
    if _catchall_like(resp, baseline, probe.path):
        return BASELINE, '', 'same as the catch-all page'
    if baseline.soft_404:
        return EXPOSED, LIKELY, 'a 200 answer unlike the catch-all page'
    return EXPOSED, LIKELY, 'a 200 answer'


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


@dataclass
class AuditReport:
    hosts: List[HostReport] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    generated_at: str = ''
    options: Dict[str, Any] = field(default_factory=dict)

    def findings(self) -> List[Result]:
        return [r for host in self.hosts for r in host.findings()]


def _sort_results(results: List[Result]) -> None:
    rank = {v: i for i, v in enumerate(
        (EXPOSED, LISTED, PROTECTED, REDIRECT, BLOCKED, TIMEOUT, ERROR, BASELINE, NOT_FOUND))}
    results.sort(key=lambda r: (rank.get(r.verdict, 99), _SEVERITY_ORDER.get(r.severity, 9), r.path))


def audit_host(target: Target, probes: Sequence[Probe], rate: float = DEFAULT_RATE,
               timeout: float = DEFAULT_TIMEOUT, insecure: bool = False,
               cafile: Optional[str] = None, headers: Optional[Mapping[str, str]] = None,
               stop: Optional[threading.Event] = None,
               get: Callable[..., Response] = http_get,
               clock: Callable[[], float] = time.monotonic,
               sleep: Optional[Callable[[float], None]] = None) -> HostReport:
    """Audit one target: a baseline, then each probe, no faster than ``rate`` requests a
    second, backing off after a 429 / 503. Serial by design - the rate cap is per host."""
    report = HostReport(target)
    interval = 1.0 / rate if rate > 0 else 0.0
    stop = stop or threading.Event()

    def wait(seconds: float) -> None:
        if seconds > 0:
            stop.wait(seconds)

    sleeper = sleep or wait
    next_at = [clock()]

    def paced_get(url: str) -> Response:
        now = clock()
        if now < next_at[0]:
            sleeper(next_at[0] - now)
        next_at[0] = max(now, next_at[0]) + interval
        return get(url, headers=headers, timeout=timeout, insecure=insecure, cafile=cafile)

    report.baseline = probe_baseline(target, paced_get)
    if report.baseline.status is None and report.baseline.note.startswith('baseline request failed'):
        report.reachable = False
        report.error = report.baseline.note
        return report

    blocked = False
    for probe in probes:
        if stop.is_set():
            break
        result = Result(probe.path, target.path_url(probe.path), probe.category, probe.severity,
                        probe.note)
        if blocked:
            result.verdict = BLOCKED
            result.detail = 'not asked: the host answered 429 / 503 earlier'
            report.results.append(result)
            continue
        try:
            resp = paced_get(result.url)
        except HttpFailure as exc:
            result.verdict = TIMEOUT if exc.kind == 'timeout' else ERROR
            result.detail = str(exc)
            report.results.append(result)
            continue
        result.status = resp.status
        result.content_type = resp.content_type
        result.length = resp.length
        if resp.redirects and resp.redirects[-1]:
            result.location = resp.redirects[-1]
        result.verdict, result.confidence, result.detail = classify(probe, resp, report.baseline)
        if result.verdict == BLOCKED:
            blocked = True
        report.results.append(result)
    _sort_results(report.results)
    return report


def run_audit(targets: Sequence[Target], probes: Sequence[Probe], rate: float = DEFAULT_RATE,
              timeout: float = DEFAULT_TIMEOUT, insecure: bool = False, cafile: Optional[str] = None,
              headers: Optional[Mapping[str, str]] = None, workers: int = DEFAULT_WORKERS,
              progress: Optional[Callable[[int, int], None]] = None,
              get: Callable[..., Response] = http_get) -> AuditReport:
    """Audit every target, up to ``workers`` hosts at a time (each host serial and rate-capped)."""
    report = AuditReport(generated_at=_utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
    report.hosts = [HostReport(t) for t in targets]
    stop = threading.Event()
    done = [0]
    lock = threading.Lock()

    def one(index: int) -> None:
        report.hosts[index] = audit_host(targets[index], probes, rate=rate, timeout=timeout,
                                         insecure=insecure, cafile=cafile, headers=headers,
                                         stop=stop, get=get)
        if progress:
            with lock:
                done[0] += 1
                progress(done[0], len(targets))

    try:
        with ThreadPoolExecutor(max_workers=min(workers, max(1, len(targets)))) as pool:
            list(pool.map(one, range(len(targets))))
    except KeyboardInterrupt:
        stop.set()
        raise
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
        total_findings += len(host.findings())
        shown = host.results if show_all else notable
        if not shown:
            lines.append('  %s' % color.green('nothing exposed'))
        for result in shown:
            lines.append(_result_line(result, color))
        if not show_all:
            quiet = len(host.results) - len(notable)
            if quiet:
                lines.append('  %s' % color.dim('%d more path%s not exposed (--show-all to see them)'
                                                % (quiet, '' if quiet == 1 else 's')))
        lines.append('')
    counts = _counts(report)
    reachable = sum(1 for h in report.hosts if h.reachable)
    summary = ('%d target%s, %d reachable: %s exposed (%d high, %d medium, %d low), %d protected'
               % (len(report.hosts), '' if len(report.hosts) == 1 else 's', reachable,
                  color.red(str(total_findings)) if total_findings else '0',
                  counts['high'], counts['medium'], counts['low'], counts[PROTECTED]))
    lines.append(summary)
    if report.warnings:
        lines.append('warnings: %d (see --json)' % len(report.warnings))
    return '\n'.join(lines) + '\n'


def _counts(report: AuditReport) -> Dict[str, int]:
    counts = {'high': 0, 'medium': 0, 'low': 0, PROTECTED: 0}
    for host in report.hosts:
        for result in host.results:
            if result.finding:
                counts[result.severity] = counts.get(result.severity, 0) + 1
            elif result.verdict == PROTECTED:
                counts[PROTECTED] += 1
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
            'baseline': {'soft404': host.baseline.soft_404, 'status': host.baseline.status,
                         'contentType': host.baseline.content_type, 'length': host.baseline.length,
                         'redirectHost': host.baseline.redirect_host, 'samples': host.baseline.samples,
                         'note': host.baseline.note},
            'findings': len(host.findings()),
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
                    'protected': counts[PROTECTED]},
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
    """The ``ds_paths`` command: the curated list, by category."""
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
  %(prog)s ds_audit example.com www.example.com
  %(prog)s ds_audit https://app.example.net:8443/ --rate 2 --json audit.json --csv audit.csv
  %(prog)s ds_audit -t hosts.txt --from-scan scan.json --only vcs,secret
  %(prog)s ds_paths

Only audit servers you own or are authorised to test. Targets come from you; the path list is
curated, not a wordlist; requests are rate-capped per host and the tool only reads.
""" % {'prog': PROG}


def build_parser() -> argparse.ArgumentParser:
    description = ('An authorised self-audit of your own web servers for exposed paths: open '
                   'version-control directories, environment and config files, backups and '
                   'status / debug pages. A baseline request per host suppresses catch-all '
                   'pages; a per-host rate cap keeps it polite. Python 3.8+, stdlib only.')
    parser = argparse.ArgumentParser(prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=description, epilog=EPILOG)
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    commands = parser.add_subparsers(dest='command', metavar='COMMAND')
    commands.required = True

    audit = commands.add_parser('ds_audit', help='audit your servers for exposed paths',
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                description=description, epilog=EPILOG)
    audit.add_argument('targets', nargs='*', metavar='TARGET',
                       help='a host, a URL, or a file of them ("-" = stdin). A bare host is https')
    src = audit.add_argument_group('targets')
    src.add_argument('-t', '--targets-file', action='append', default=[], metavar='FILE',
                     help='a file of targets, one or more a line ("-" = stdin); repeatable')
    src.add_argument('--from-scan', action='append', default=[], metavar='FILE',
                     help='take host names from a scan JSON report (ssl_origin_scan / ip_intel); '
                          'repeatable')
    what = audit.add_argument_group('what is checked')
    what.add_argument('--only', metavar='LIST',
                      help='only these categories, comma-separated: %s'
                           % ', '.join((VCS, SECRET, CONFIG, BACKUP, INFO, LISTING)))
    what.add_argument('--paths', metavar='FILE',
                      help='add up to %d of your own paths (one a line); not a wordlist' % MAX_CUSTOM_PATHS)
    net = audit.add_argument_group('how')
    net.add_argument('--rate', type=float, default=DEFAULT_RATE, metavar='N',
                     help='requests a second, per host (default: %(default)s; max ' + ('%g' % MAX_RATE) + ')')
    net.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                     help='per request (default: %(default)s)')
    net.add_argument('-w', '--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                     help='hosts audited in parallel (default: %(default)s); each host stays serial')
    net.add_argument('--max-hosts', type=int, default=DEFAULT_MAX_HOSTS, metavar='N',
                     help='at most N targets (default: %(default)s)')
    net.add_argument('-H', '--header', action='append', default=[], metavar='"Name: value"',
                     help='an extra request header (a cookie or token for an authorised audit); '
                          'repeatable, sent only to the audited host, never across a redirect')
    net.add_argument('--insecure', action='store_true',
                     help='do not verify TLS certificates (for a self-signed host you trust)')
    net.add_argument('--cafile', metavar='FILE', help='verify TLS against this CA bundle (a private CA)')
    out = audit.add_argument_group('output')
    out.add_argument('--json', metavar='FILE', help='write a JSON report ("-" = stdout)')
    out.add_argument('--csv', metavar='FILE', help='write a CSV report ("-" = stdout)')
    out.add_argument('--show-all', action='store_true', help='list every path, not only the findings')
    out.add_argument('--fail-on-finding', action='store_true',
                     help='exit with code 1 when anything is exposed (for CI)')
    out.add_argument('--no-color', action='store_true', help='no ANSI colors')
    out.add_argument('-q', '--quiet', action='store_true', help='no progress or warnings on stderr')

    commands.add_parser('ds_paths', help='print the curated path list and exit',
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

    all_targets = list(args.targets) + list(args.targets_file)
    targets, warnings = parse_targets(all_targets, from_scan=args.from_scan,
                                      max_hosts=args.max_hosts)
    if not targets:
        raise UsageError('no targets: give a host, a URL, -t FILE or --from-scan FILE')

    if not args.quiet:
        for warning in warnings[:25]:
            print('warning: %s' % warning, file=err)
        if len(warnings) > 25:
            print('warning: ... and %d more' % (len(warnings) - 25), file=err)
        print('note: auditing %d host%s on an explicit, authorised target list; %d path%s each, '
              '%g req/s per host' % (len(targets), '' if len(targets) == 1 else 's', len(probes),
                                     '' if len(probes) == 1 else 's', args.rate), file=err)
    tty = not args.quiet and hasattr(err, 'isatty') and err.isatty()

    def progress(done: int, total: int) -> None:
        if tty and (done == total or done % 5 == 0):
            err.write('\raudited: %d / %d hosts' % (done, total))
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
        if args.command == 'ds_paths':
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
