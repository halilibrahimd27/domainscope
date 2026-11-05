#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""dir_scan.py - map the paths under a web host you own: directories and endpoints.

Companion CLI of the "DomainScope - SSL & DNS Toolkit" web app
(https://github.com/halilibrahimd27/domainscope). Given web hosts you own or are authorised to
test, it tries a list of common directory and endpoint names (`/api`, `/admin`, `/.well-known`,
`/dashboard`, `/graphql`, …) and reports which ones answer: what is there, what is behind
auth, what redirects. A browser page cannot do this - it cannot read a cross-origin response's
status code - so it lives in the CLI, run from a machine that can reach your hosts. The web
app's "Endpoint map" view reads its --json report and lists the paths found.

This is a map of your own site, not a scanner for the whole web:
  * targets come from you - host names, URLs, a file of them, or the host names a scan of
    yours already covered (`--from-scan`). It never discovers hosts on its own;
  * it tries a built-in list of about {builtin} common directory and endpoint names, and your
    own with `--wordlist FILE` (one a line; up to {maxwords}); `--extensions` also tries each
    name with an extension (`admin.php`, `backup.zip`);
  * two baseline requests per target first (random paths, new each run) learn how the server
    answers a path that is not there, so a site that answers 200 for everything is not a wall
    of false hits;
  * a per-host rate cap keeps the scan polite (default {rate} requests a second per host,
    shared by every target on the host), and a host that answers 429 or 503 is backed off;
  * it only reads: a plain GET, the first {maxbody} KB of each body, redirects followed only
    within the same origin (scheme, host and port). It never sends a payload or tries to
    exploit anything. A path that answers is a fact about your site, not a vulnerability.

JSON (`--json`) and CSV (`--csv`) outputs carry every result; the text summary lists the paths
that answer, grouped, and says which could not be checked. Exit code 0; 1 with `--fail-on-found`
when any path answers, or with `--fail-on-error` when a target could not be fully mapped; 2 for
a usage error, 3 when a report file could not be written, 70 for an internal error, 130 when
interrupted.

Python 3.9+, standard library only, single file - copy it anywhere.

The module is importable: parse_targets(), Target, built_in_words(), load_words(), http_get(),
probe_baseline(), classify(), HostPacer, map_host(), run_scan(), render_text(),
report_to_dict(), render_csv() and main() are the public API.
"""

from __future__ import annotations

import argparse
import csv
import http.client
import io
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import FIRST_EXCEPTION, ThreadPoolExecutor, wait as wait_futures
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

__version__ = '1.0.0'
PROG = 'dir_scan.py'
SCHEMA = 'domainscope.dir-scan/1'
TOOL = 'dir_scan'
USER_AGENT = 'dir_scan/%s (+https://github.com/halilibrahimd27/domainscope)' % __version__

# --- verdicts, per (host, path) --------------------------------------------------------
FOUND = 'FOUND'            # the path answers, unlike a random path (a real directory / endpoint)
LISTING = 'LISTING'        # a directory listing is served (its files are visible)
PROTECTED = 'PROTECTED'    # it exists but is behind auth (401 / 403)
REDIRECT = 'REDIRECT'      # it redirects elsewhere (another origin, or another path on the site)
NOT_FOUND = 'NOT_FOUND'    # 404 / 410, or indistinguishable from the server's catch-all page
BLOCKED = 'BLOCKED'        # the server answered 429 / 503 (rate limited us) or we backed off
TIMEOUT = 'TIMEOUT'        # no answer in --timeout seconds
ERROR = 'ERROR'            # a network or protocol error, or a 5xx (says nothing about the path)
VERDICTS = (FOUND, LISTING, PROTECTED, REDIRECT, NOT_FOUND, BLOCKED, TIMEOUT, ERROR)
# The verdicts that are a path on your site: with --fail-on-found these fail the run.
HIT_VERDICTS = (FOUND, LISTING)
# Shown to the operator as "answered" (what the map is): hits + protected + redirects.
NOTABLE_VERDICTS = (FOUND, LISTING, PROTECTED, REDIRECT)
# A path that was not checked: the target's map is incomplete (--fail-on-error fails on it).
UNCHECKED_VERDICTS = (BLOCKED, TIMEOUT, ERROR)

# --- what a host answers for a path that is not there (Baseline.kind) -----------------
HARD_404 = 'hard-404'          # 404 / 410: every answer means what it says
SOFT_404 = 'soft-404'          # the same 2xx catch-all page for anything
CATCH_REDIRECT = 'redirect'    # the same redirect for anything
DENIED = 'denied'              # 401 / 403 for anything: then a 401 / 403 says nothing about a path
STATUS_ONLY = 'status-only'    # another steady status: results are status-only
MIXED = 'mixed'                # the samples disagreed: results are status-only
RATE_LIMITED = 'rate-limited'  # 429 / 503: nothing else is asked of the host
NO_ANSWER = 'no-answer'        # no HTTP answer: the target is unreachable

EXIT_OK = 0
EXIT_FOUND = 1             # only with --fail-on-found: a path answered
EXIT_INCOMPLETE = 1        # only with --fail-on-error: a target unreachable or a path not checked
EXIT_USAGE = 2
EXIT_OUTPUT_ERROR = 3      # a --json / --csv file could not be written after the run
EXIT_INTERNAL_ERROR = 70   # a bug: an unexpected exception (the traceback goes to stderr)
EXIT_INTERRUPTED = 130

DEFAULT_SCHEME = 'https'
DEFAULT_RATE = 5.0         # requests a second, per host
MAX_RATE = 50.0
DEFAULT_TIMEOUT = 10.0
MAX_TIMEOUT = 120.0
DEFAULT_WORKERS = 8        # targets mapped in parallel; each host's requests stay paced
MAX_WORKERS = 64
DEFAULT_MAX_HOSTS = 256
MAX_HOSTS = 4096
MAX_WORDS = 20000          # the wordlist cap: a map of your site, not a brute-force run
MAX_EXTENSIONS = 16
MAX_TARGET_FILE = 20 * 1024 * 1024
MAX_WORDLIST_FILE = 8 * 1024 * 1024
MAX_REDIRECTS = 4          # followed only within the same origin
REDIRECT_CODES = (301, 302, 303, 307, 308)
MAX_BODY = 64 * 1024       # bytes read per response (enough to spot a directory listing)
BASELINE_SAMPLES = 2       # random, non-existent paths asked to learn the catch-all
_POLL_SECONDS = 0.1        # how often the main thread looks up from the workers (for Ctrl+C)


class UsageError(Exception):
    """Bad command line or input; reported as ``error: ...`` with exit code 2."""


class HttpFailure(Exception):
    """A request without an HTTP answer."""

    def __init__(self, kind: str, message: str) -> None:
        super().__init__(message)
        self.kind = kind  # 'timeout' | 'network' | 'protocol'


# ---------------------------------------------------------------------------------------
# Text safety: server-controlled text reaches the terminal, so strip control / bidi codes
# ---------------------------------------------------------------------------------------

def _plain(text: str) -> str:
    """Printable ASCII for the terminal: anything else ``\\xNN`` / ``\\uNNNN`` (paths, host
    names and redirect targets all come from the server or the user)."""
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
# Targets: the hosts to map - host names, URLs, files of them, or a scan's JSON
# ---------------------------------------------------------------------------------------

_LABEL_RE = re.compile(r'^(?=.{1,63}$)[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?$')
_NUMERIC_TAIL_RE = re.compile(r'^(?:[0-9]+|0[xX][0-9a-fA-F]*)$')
_FILE_SUFFIXES = ('.txt', '.csv', '.tsv', '.json', '.lst', '.yml', '.yaml', '.xml', '.ini',
                  '.cfg', '.conf')
_BRACKET_HINT = '%s: write an IPv6 address in brackets, any port after them: [2001:db8::1]:8443'


@dataclass(frozen=True)
class Target:
    """One host to map, as a normalised base URL."""
    scheme: str
    host: str          # a host name (lowercased, IDNA) or an IP literal, no brackets
    port: int
    base_path: str     # '/' or a path the names are joined under, always ending in '/'

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
        return None
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
    https on 443; a bare ``host:80`` is http. A dotted number that is not an address is
    refused. Raises :class:`UsageError` for anything else."""
    token = value.strip()
    if not token:
        raise UsageError('an empty target')
    if '://' not in token and token.count(':') >= 2 and not token.startswith('['):
        ip = _canonical_ip(token)
        if ip is None:
            raise UsageError(_BRACKET_HINT % _plain(token))
        return Target(DEFAULT_SCHEME, ip, 443, '/')
    if '://' not in token:
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
        raise UsageError('%s: only http and https are mapped' % _plain(token))
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


def _read_text(path: str, stdin: Optional[Any] = None, cap: int = MAX_TARGET_FILE) -> str:
    if path == '-':
        return (stdin or sys.stdin).read()
    try:
        if os.path.getsize(path) > cap:
            raise UsageError('%s is larger than %d MB' % (_plain(path), cap // (1024 * 1024)))
        with open(path, 'rb') as handle:
            raw = handle.read()
    except OSError as exc:
        raise UsageError('cannot read %s: %s' % (_plain(path), exc.strerror or exc))
    for encoding in ('utf-8-sig', 'utf-16'):
        try:
            text = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        if encoding == 'utf-8-sig' or raw[:2] in (b'\xff\xfe', b'\xfe\xff'):
            return text
    return raw.decode('latin-1')


def _as_list(value: Any) -> List[Any]:
    return value if isinstance(value, list) else []


def _hosts_from_scan(doc: Any) -> Tuple[List[str], int]:
    """Host names from a DomainScope scan report (ssl_origin_scan: the names it probed;
    ip_intel: the names found HERE; dir_scan / content_audit: the hosts mapped), de-duplicated,
    and how many were skipped as not-here."""
    if not isinstance(doc, dict):
        return [], 0
    out = []  # type: List[str]
    seen = set()  # type: set
    skipped = 0

    def take(name: Any) -> None:
        host = _idna_host(name) if isinstance(name, str) else None
        if host and host not in seen:
            seen.add(host)
            out.append(host)

    schema = doc.get('schema') if isinstance(doc.get('schema'), str) else ''
    if schema.startswith('domainscope.ip-intel'):
        for row in _as_list(doc.get('results')):
            if not isinstance(row, dict):
                continue
            for item in _as_list(row.get('names')):
                if isinstance(item, dict):
                    if item.get('here') is False:
                        skipped += 1
                        continue
                    take(item.get('name'))
    elif schema.startswith('domainscope.dir-scan') or schema.startswith('domainscope.content-audit'):
        for host in _as_list(doc.get('hosts')):
            if isinstance(host, dict) and isinstance(host.get('host'), str):
                take(host['host'])
    else:
        for name in _as_list(doc.get('names')):
            if isinstance(name, dict):
                if name.get('wildcard'):
                    base = name.get('name')
                    take(base[2:] if isinstance(base, str) and base.startswith('*.') else base)
                else:
                    take(name.get('name'))
        for server in _as_list(doc.get('servers')):
            if not isinstance(server, dict):
                continue
            for key in ('needsUpdate', 'updated', 'hostnames', 'names'):
                for item in _as_list(server.get(key)):
                    take(item if isinstance(item, str) else (item.get('name') if isinstance(item, dict) else None))
    return out, skipped


def parse_targets(values: Sequence[str], from_scan: Sequence[str] = (),
                  scheme: str = DEFAULT_SCHEME, max_hosts: int = DEFAULT_MAX_HOSTS,
                  stdin: Optional[Any] = None,
                  files: Sequence[str] = ()) -> Tuple[List[Target], List[str]]:
    """The targets of ``values`` (hosts, URLs, or files of them; ``-`` = stdin), of each of
    ``files`` (always a file) and the host names of each ``from_scan`` JSON report,
    de-duplicated in order, with a warning per unreadable token."""
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
            add(parse_target(token))
    for path in files:
        add_file(path)
    for path in from_scan:
        text = _read_text(path, stdin)
        try:
            doc = json.loads(text)
        except (ValueError, TypeError):
            raise UsageError('%s is not JSON' % _plain(path))
        hosts, skipped = _hosts_from_scan(doc)
        if skipped:
            warnings.append('%s: %d name%s skipped: only the names that resolve to the address '
                            'now (HERE) are mapped' % (_plain(path), skipped, '' if skipped == 1 else 's'))
        if not hosts:
            warnings.append('%s: no host names found in the scan' % _plain(path))
        for host in hosts:
            add_host(host)
    return targets, warnings


# ---------------------------------------------------------------------------------------
# The wordlist: common directory and endpoint names (your own with --wordlist)
# ---------------------------------------------------------------------------------------

# A map of a typical web host: the directories and endpoints that commonly exist, not a
# brute-force list. Grouped only for reading; the scan tries them all. Names a server would
# have are here (api, admin, static, uploads, health); secret files (.git, .env, backups) are
# cli/content_audit.py's job, which also judges whether each is really exposed.
_BUILTIN_WORDS = """
# API and application
api api/v1 api/v2 api/v3 graphql graphiql rest rpc soap grpc openapi swagger swagger-ui
swagger.json openapi.json api-docs apidocs docs redoc playground query webhook webhooks
callback oauth oauth2 auth authorize token sso saml openid .well-known/openid-configuration
# Auth and accounts
login logout signin signup register account accounts user users profile me session sessions
password reset forgot-password verify confirm 2fa mfa
# Admin and management
admin administrator admin/login wp-admin wp-login.php administrator/index.php manager console
dashboard panel cpanel controlpanel backend adminer phpmyadmin pma dbadmin management manage
# Content and app
app application home index main portal site web www blog news shop store cart checkout
search api/search product products category categories page pages post posts article articles
# Static and assets
static assets public media files uploads upload download downloads images img css js
javascript fonts dist build vendor node_modules .well-known .well-known/security.txt
# Config, status and ops
config configuration settings setup install installer env health healthz healthcheck ping
status stat info metrics prometheus actuator actuator/health actuator/info debug test tests
version ready live readiness liveness server-status server-info
# Data and storage
data db database backup backups dump dumps export exports import logs log tmp temp cache
storage private secret secrets internal
# Common framework paths
wp-content wp-includes wp-json .htaccess robots.txt sitemap.xml sitemap humans.txt crossdomain.xml
favicon.ico .git .svn .env web.config phpinfo.php info.php composer.json package.json
# Mail, monitoring, misc
mail webmail email contact support help faq about terms privacy legal error errors
maintenance staging dev development prod production demo beta old new backup2 bak archive
""".strip()


def built_in_words() -> List[str]:
    """The built-in directory / endpoint names, de-duplicated in order."""
    out = []  # type: List[str]
    seen = set()  # type: set
    for line in _BUILTIN_WORDS.splitlines():
        line = line.split('#', 1)[0].strip()
        for word in line.split():
            cleaned = _clean_word(word)
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                out.append(cleaned)
    return out


_WORD_BAD = re.compile(r'[\x00-\x1f\x7f-\x9f\s]')


def _clean_word(word: str) -> Optional[str]:
    """A wordlist entry -> a relative path, or None. Leading slashes are dropped (joined under
    the target), a scheme or '..' is refused (it would leave the host / base path), control and
    whitespace characters too."""
    word = word.strip().lstrip('/')
    if not word or '://' in word or _WORD_BAD.search(word):
        return None
    if word == '..' or word.startswith('../') or '/../' in word or word.endswith('/..'):
        return None
    return word


def load_words(path: Optional[str], extensions: Sequence[str] = (), use_builtin: bool = True,
               stdin: Optional[Any] = None, max_words: int = MAX_WORDS) -> List[str]:
    """The names to try: the built-in list (unless ``use_builtin`` is false), then ``path``
    (one a line, ``#`` comments, ``-`` = stdin), de-duplicated in order. With ``extensions``,
    each name that has no extension of its own is also tried with each (``admin`` -> ``admin``,
    ``admin.php``). Raises :class:`UsageError` past ``max_words`` or when nothing is left."""
    words = built_in_words() if use_builtin else []
    if path:
        text = _read_text(path, stdin, cap=MAX_WORDLIST_FILE)
        for line in text.splitlines():
            line = line.split('#', 1)[0].strip() if line.lstrip().startswith('#') else line.strip()
            cleaned = _clean_word(line)
            if cleaned:
                words.append(cleaned)
    exts = []  # type: List[str]
    for ext in extensions:
        ext = ext.strip().lstrip('.')
        if ext and ext not in exts and re.match(r'^[A-Za-z0-9._-]{1,16}$', ext):
            exts.append(ext)
    out = []  # type: List[str]
    seen = set()  # type: set
    for word in words:
        for candidate in [word] + ([
            '%s.%s' % (word, ext) for ext in exts
            if '.' not in word.rsplit('/', 1)[-1] and not word.endswith('/')
        ] if exts else []):
            if candidate not in seen:
                seen.add(candidate)
                out.append(candidate)
    if not out:
        raise UsageError('no names to try: the wordlist is empty')
    if len(out) > max_words:
        raise UsageError('%d names to try; at most %d (this maps a site, it is not a '
                         'brute-force run). Use --max-words to raise it, or a shorter list'
                         % (len(out), max_words))
    return out


# ---------------------------------------------------------------------------------------
# HTTP: one GET, redirects followed only within the same origin, the first MAX_BODY bytes
# (the request machinery is cli/content_audit.py's, reviewed and shared by copy)
# ---------------------------------------------------------------------------------------

@dataclass
class Response:
    status: int
    body: bytes
    content_type: str
    length: int
    final_url: str
    redirects: List[str] = field(default_factory=list)
    location: str = ''
    requested: str = ''


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib must not follow a redirect, nor parse its Location: every 3xx is raised as an
    HTTPError and :func:`http_get` decides by origin."""

    def http_error_302(self, req: Any, fp: Any, code: int, msg: str, headers: Any) -> None:
        return None

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


class _Deadline:
    """A watchdog for one request: every socket registered while it is current is shut down
    when ``seconds`` have passed, ending any blocked read at once."""

    def __init__(self, seconds: float) -> None:
        self.expired = False
        self._sockets = []  # type: List[socket.socket]
        self._lock = threading.Lock()
        self._timer = threading.Timer(max(0.0, seconds), self._fire)
        self._timer.daemon = True

    def __enter__(self) -> '_Deadline':
        _CURRENT.deadline = self
        self._timer.start()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._timer.cancel()
        _CURRENT.deadline = None

    def add(self, sock: socket.socket) -> None:
        with self._lock:
            if self.expired:
                _shutdown(sock)
            else:
                self._sockets.append(sock)

    def _fire(self) -> None:
        with self._lock:
            self.expired = True
            sockets, self._sockets = self._sockets, []
        for sock in sockets:
            _shutdown(sock)


_CURRENT = threading.local()


def _shutdown(sock: socket.socket) -> None:
    try:
        socket.socket.shutdown(sock, socket.SHUT_RDWR)
    except (OSError, ValueError):
        pass


def _watch(sock: socket.socket) -> None:
    deadline = getattr(_CURRENT, 'deadline', None)
    if deadline is not None:
        deadline.add(sock)


class _WatchedHTTPConnection(http.client.HTTPConnection):
    def connect(self) -> None:
        super().connect()
        _watch(self.sock)


class _WatchedHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req: Any) -> Any:
        return self.do_open(_WatchedHTTPConnection, req)


class _WatchedContext(ssl.SSLContext):
    def wrap_socket(self, sock: Any, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        handshake = kwargs.pop('do_handshake_on_connect', True)
        tls = super().wrap_socket(sock, *args, do_handshake_on_connect=False, **kwargs)
        _watch(tls)
        if handshake:
            tls.do_handshake()
        return tls


_OPENERS = {}  # type: Dict[Tuple[bool, Optional[str]], urllib.request.OpenerDirector]
_OPENER_LOCK = threading.Lock()


def _make_context(insecure: bool, cafile: Optional[str]) -> ssl.SSLContext:
    context = _WatchedContext(ssl.PROTOCOL_TLS_CLIENT)
    if insecure:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if cafile:
        context.load_verify_locations(cafile=cafile)
    else:
        context.load_default_certs(ssl.Purpose.SERVER_AUTH)
    return context


def _opener(insecure: bool, cafile: Optional[str]) -> urllib.request.OpenerDirector:
    key = (True, None) if insecure else (False, cafile or None)
    with _OPENER_LOCK:
        opener = _OPENERS.get(key)
        if opener is None:
            opener = urllib.request.build_opener(
                _WatchedHTTPHandler(),
                urllib.request.HTTPSHandler(context=_make_context(insecure, key[1])), _NoRedirect)
            _OPENERS[key] = opener
        return opener


def _reset_openers() -> None:
    with _OPENER_LOCK:
        _OPENERS.clear()


def _ctype(headers: Any) -> str:
    return (headers.get('Content-Type') or headers.get('content-type') or '').split(';')[0].strip().lower()


def _origin(url: str) -> str:
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
    origin = _origin(a)
    return bool(origin) and origin == _origin(b)


def _join(base: str, location: str) -> str:
    try:
        return urllib.parse.urljoin(base, location)
    except ValueError:
        return ''


def http_get(url: str, headers: Optional[Mapping[str, str]] = None, timeout: float = DEFAULT_TIMEOUT,
             insecure: bool = False, cafile: Optional[str] = None,
             max_redirects: int = MAX_REDIRECTS) -> Response:
    """GET ``url`` -> every HTTP answer, following redirects only within the same origin. A
    redirect anywhere else is the answer, its target origin in :attr:`Response.location`, so a
    ``--header`` never reaches another host. ``timeout`` bounds each request as a whole. Raises
    :class:`HttpFailure` without an answer; the message never holds the URL."""
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
        with _Deadline(timeout) as deadline:
            try:
                answer = _one_request(opener, request, timeout)
            except HttpFailure:
                if deadline.expired:
                    raise HttpFailure('timeout', 'no complete answer in %g s' % timeout)
                raise
            if deadline.expired:
                raise HttpFailure('timeout', 'no complete answer in %g s' % timeout)
        status, body, ctype, location = answer
        if status in REDIRECT_CODES and location is not None:
            target = _join(current, location) if location else ''
            origin = _origin(target) if target else ''
            redirects.append(origin)
            if origin and _same_origin(current, target):
                current = target
                continue
            return Response(status, body, ctype, len(body), current, redirects, origin, url)
        return Response(status, body, ctype, len(body), current, redirects, '', url)
    raise HttpFailure('network', 'too many redirects (> %d)' % max_redirects)


def _one_request(opener: urllib.request.OpenerDirector, request: urllib.request.Request,
                 timeout: float) -> Tuple[int, bytes, str, Optional[str]]:
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(MAX_BODY)
            return response.status, body, _ctype(response.headers), None
    except urllib.error.HTTPError as exc:
        status = exc.code
        try:
            body = exc.read(MAX_BODY) or b''
        except (OSError, ValueError, http.client.HTTPException):
            body = b''
        finally:
            exc.close()
        ctype = _ctype(exc.headers) if exc.headers else ''
        location = None  # type: Optional[str]
        if status in REDIRECT_CODES:
            location = (exc.headers.get('Location') if exc.headers else None) or ''
        return status, body, ctype, location
    except urllib.error.URLError as exc:
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            raise HttpFailure('timeout', 'no answer in %g s' % timeout)
        raise HttpFailure('network', _reason_text(exc.reason))
    except (socket.timeout, TimeoutError):
        raise HttpFailure('timeout', 'no answer in %g s' % timeout)
    except http.client.HTTPException as exc:
        raise HttpFailure('protocol', _http_error_text(exc))
    except (OSError, ValueError) as exc:
        raise HttpFailure('network', _reason_text(exc))


def _http_error_text(exc: Exception) -> str:
    if isinstance(exc, http.client.RemoteDisconnected):
        return 'the server closed the connection without an answer'
    if isinstance(exc, http.client.BadStatusLine):
        return 'not an HTTP answer (another protocol on this port?)'
    if isinstance(exc, http.client.IncompleteRead):
        return 'the answer was cut short'
    text = str(exc) or type(exc).__name__
    return 'not a valid HTTP answer: %s' % (text if len(text) <= 120 else text[:117] + '...')


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
    kind: str = ''
    soft_404: bool = False
    status: Optional[int] = None
    content_type: str = ''
    length: int = 0
    redirect_to: Optional[str] = None
    samples: int = 0
    note: str = ''


def _baseline_tokens() -> List[str]:
    return ['ds-dirscan-%s' % secrets.token_hex(6) for _ in range(BASELINE_SAMPLES)]


def _strip_echo(body: bytes, path: str) -> bytes:
    out = body
    for text in (path, '/' + path.lstrip('/')):
        token = text.encode('latin-1', 'replace')
        if token:
            out = out.replace(token, b'')
    return out


def _stable_length(body: bytes, token: str) -> int:
    return len(body.replace(token.encode('latin-1', 'replace'), b''))


def _similar_length(a: int, b: int) -> bool:
    return abs(a - b) <= max(96, int(0.08 * max(a, b, 1)))


def probe_baseline(target: Target, fetch: Callable[[str], Response]) -> Baseline:
    """Ask :data:`BASELINE_SAMPLES` random paths and say how the host answers a path that is not
    there (the ``Baseline.kind`` constants)."""
    base = Baseline()
    seen = []  # type: List[Tuple[int, str, int, Optional[str]]]
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
                     resp.location or None))
    base.samples = len(seen)
    first = seen[0]
    base.status, base.content_type, base.length, base.redirect_to = first
    status = first[0]
    same_status = all(s[0] == status for s in seen)
    agree = same_status and all(s[1] == first[1] and _similar_length(s[2], first[2])
                                and s[3] == first[3] for s in seen)
    if agree and 200 <= status < 300:
        base.kind, base.soft_404 = SOFT_404, True
        base.note = ('the server answers %d for unknown paths (a catch-all page): an answer like '
                     'it is not reported' % status)
    elif agree and status in REDIRECT_CODES and first[3]:
        base.kind, base.soft_404 = CATCH_REDIRECT, True
        base.note = 'the server redirects unknown paths to %s' % _plain(first[3])
    elif same_status and status in (404, 410):
        base.kind = HARD_404
        base.note = 'the server returns %d for unknown paths' % status
    elif same_status and status in (401, 403):
        base.kind = DENIED
        base.note = ('every unknown path answers %d, so a %d says nothing about a path here (the '
                     'whole host behind auth? -H "Name: value" for an authorised scan)'
                     % (status, status))
    elif agree and 500 <= status < 600:
        base.kind = STATUS_ONLY
        base.note = 'the server answers %d (a server error) for unknown paths' % status
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
# Classifying one answer against the baseline
# ---------------------------------------------------------------------------------------

@dataclass
class Result:
    path: str
    url: str
    verdict: str = NOT_FOUND
    status: Optional[int] = None
    content_type: str = ''
    length: int = 0
    location: str = ''     # a redirect's target origin, if any
    detail: str = ''

    @property
    def hit(self) -> bool:
        return self.verdict in HIT_VERDICTS


def _looks_listing(body: bytes) -> bool:
    low = body[:MAX_BODY].lower()
    return (b'index of /' in low or b'directory listing for' in low
            or b'<title>index of' in low or b'[to parent directory]' in low)


def _catchall_like(resp: Response, baseline: Baseline, path: str) -> bool:
    if baseline.kind != SOFT_404:
        return False
    return (resp.content_type == baseline.content_type
            and _similar_length(_stable_length(resp.body, path), baseline.length))


def _moved(resp: Response) -> bool:
    """A same-origin redirect led to another path (``/admin`` -> ``/login``). A trailing slash
    added or a query string is no move."""
    if not resp.redirects or not resp.requested or not resp.final_url:
        return False
    try:
        asked = urllib.parse.urlsplit(resp.requested).path or '/'
        got = urllib.parse.urlsplit(resp.final_url).path or '/'
    except ValueError:
        return True
    return asked.rstrip('/') != got.rstrip('/')


def classify(path: str, resp: Response, baseline: Baseline) -> Tuple[str, str]:
    """-> (verdict, detail). A 2xx answer unlike the server's catch-all page is a real path
    (``FOUND``, or ``LISTING`` when a directory listing is served); one like the catch-all, or
    one a same-origin redirect led to, is ``NOT_FOUND``. 401 / 403 is ``PROTECTED`` unless the
    host denies everything. A 5xx says nothing about the path (``ERROR``)."""
    status = resp.status
    if status in (401, 403):
        if baseline.kind == DENIED and baseline.status == status:
            return NOT_FOUND, 'every unknown path answers %d too' % status
        return PROTECTED, 'exists but is behind auth (%d)' % status
    if status in (429, 503):
        return BLOCKED, 'the server answered %d (slow down)' % status
    if status in (404, 410):
        return NOT_FOUND, 'not found (%d)' % status
    if status in REDIRECT_CODES:
        where = _plain(resp.location) if resp.location else 'another location'
        return REDIRECT, 'redirects to %s' % where
    if 500 <= status < 600:
        return ERROR, 'the server answered %d (a server error says nothing about the path)' % status
    if not (200 <= status < 300):
        return NOT_FOUND, 'status %d' % status
    if _catchall_like(resp, baseline, path):
        return NOT_FOUND, 'same as the catch-all page'
    if _moved(resp):
        return REDIRECT, 'redirects to another page on the site (a login or home page?)'
    if _looks_listing(resp.body):
        return LISTING, 'a directory listing is served (its files are visible)'
    extra = ' unlike the catch-all page' if baseline.soft_404 else ''
    return FOUND, 'a %d answer%s' % (status, extra)


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
    not_mapped: str = ''

    def hits(self) -> List[Result]:
        return [r for r in self.results if r.hit]

    def notable(self) -> List[Result]:
        return [r for r in self.results if r.verdict in NOTABLE_VERDICTS]

    def unchecked(self) -> List[Result]:
        return [r for r in self.results if r.verdict in UNCHECKED_VERDICTS]

    def complete(self) -> bool:
        return self.reachable and not self.not_mapped and not self.unchecked()


@dataclass
class ScanReport:
    hosts: List[HostReport] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    generated_at: str = ''
    options: Dict[str, Any] = field(default_factory=dict)

    def hits(self) -> List[Result]:
        return [r for host in self.hosts for r in host.hits()]

    def complete(self) -> bool:
        return all(h.complete() for h in self.hosts)


_VERDICT_RANK = {v: i for i, v in enumerate(
    (FOUND, LISTING, PROTECTED, REDIRECT, BLOCKED, TIMEOUT, ERROR, NOT_FOUND))}


def _sort_results(results: List[Result]) -> None:
    results.sort(key=lambda r: (_VERDICT_RANK.get(r.verdict, 99), r.path))


class HostPacer:
    """The request pace of one host, shared by every target on it, so ``--rate`` holds per
    host. :attr:`blocked` is set once the host answers 429 / 503."""

    def __init__(self, rate: float, clock: Callable[[], float] = time.monotonic,
                 sleep: Optional[Callable[[float], None]] = None) -> None:
        self.interval = 1.0 / rate if rate > 0 else 0.0
        self.blocked = threading.Event()
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._next_at = None  # type: Optional[float]

    def wait_turn(self, stop: threading.Event) -> None:
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


def map_host(target: Target, words: Sequence[str], rate: float = DEFAULT_RATE,
             timeout: float = DEFAULT_TIMEOUT, insecure: bool = False,
             cafile: Optional[str] = None, headers: Optional[Mapping[str, str]] = None,
             stop: Optional[threading.Event] = None,
             get: Optional[Callable[..., Response]] = None,
             clock: Callable[[], float] = time.monotonic,
             sleep: Optional[Callable[[float], None]] = None,
             pacer: Optional[HostPacer] = None) -> HostReport:
    """Map one target: a baseline, then each name, one request at a time, paced by ``pacer``. A
    429 / 503 backs the whole host off. Ctrl+C (``stop``) ends it."""
    report = HostReport(target)
    stop = stop or threading.Event()
    pacer = pacer or HostPacer(rate, clock=clock, sleep=sleep)
    fetch = get or http_get

    def paced_get(url: str) -> Response:
        pacer.wait_turn(stop)
        if stop.is_set():
            raise _Stopped()
        return fetch(url, headers=headers, timeout=timeout, insecure=insecure, cafile=cafile)

    def not_asked(path: str) -> Result:
        return Result(path, target.path_url(path), verdict=BLOCKED,
                      detail='not asked: the host answered 429 / 503 earlier')

    if stop.is_set():
        return report
    if pacer.blocked.is_set():
        report.baseline = Baseline(kind=RATE_LIMITED,
                                   note='not asked: the host answered 429 / 503 to another target')
        report.results = [not_asked(w) for w in words]
        _sort_results(report.results)
        return report
    try:
        report.baseline = probe_baseline(target, paced_get)
    except _Stopped:
        return report
    except Exception as exc:  # a bug must cost this target, never the run
        report.reachable = False
        report.error = 'internal error while learning the baseline: %s' % _exception_text(exc)
        return report
    if report.baseline.kind == NO_ANSWER:
        report.reachable = False
        report.error = report.baseline.note
        return report
    if report.baseline.kind == RATE_LIMITED:
        pacer.blocked.set()

    for word in words:
        if stop.is_set():
            break
        if pacer.blocked.is_set():
            report.results.append(not_asked(word))
            continue
        result = Result(word, target.path_url(word))
        try:
            resp = paced_get(result.url)
            result.status = resp.status
            result.content_type = resp.content_type
            result.length = resp.length
            result.location = resp.location
            result.verdict, result.detail = classify(word, resp, report.baseline)
        except _Stopped:
            break
        except HttpFailure as exc:
            result.verdict = TIMEOUT if exc.kind == 'timeout' else ERROR
            result.detail = str(exc)
        except Exception as exc:  # a bug must cost this path, never the run
            result.verdict = ERROR
            result.detail = 'internal error: %s' % _exception_text(exc)
        if result.verdict == BLOCKED:
            pacer.blocked.set()
        report.results.append(result)
    report.not_mapped = _not_mapped(report)
    _sort_results(report.results)
    return report


def _not_mapped(report: HostReport) -> str:
    if not report.results or any(r.verdict != REDIRECT or not r.status or r.status not in REDIRECT_CODES
                                 or not r.location for r in report.results):
        return ''
    targets = sorted({r.location for r in report.results})
    if len(targets) == 1 and targets[0]:
        return ('every path redirects to %s: nothing was mapped here (map that origin instead)'
                % targets[0])
    return 'every path redirects to another origin: nothing was mapped here'


def _exception_text(exc: BaseException) -> str:
    text = str(exc)
    if len(text) > 160:
        text = text[:157] + '...'
    return '%s: %s' % (type(exc).__name__, text) if text else type(exc).__name__


def run_scan(targets: Sequence[Target], words: Sequence[str], rate: float = DEFAULT_RATE,
             timeout: float = DEFAULT_TIMEOUT, insecure: bool = False, cafile: Optional[str] = None,
             headers: Optional[Mapping[str, str]] = None, workers: int = DEFAULT_WORKERS,
             progress: Optional[Callable[[int, int], None]] = None,
             get: Optional[Callable[..., Response]] = None,
             clock: Callable[[], float] = time.monotonic,
             sleep: Optional[Callable[[float], None]] = None) -> ScanReport:
    """Map every target, up to ``workers`` at a time; the targets on one host share a pacer, so
    ``rate`` holds per host. Ctrl+C stops every target before its next request, then propagates."""
    report = ScanReport(generated_at=_utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'))
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
        try:
            report.hosts[index] = map_host(target, words, timeout=timeout, insecure=insecure,
                                           cafile=cafile, headers=headers, stop=stop, get=get,
                                           pacer=pacers[target.host])
        except Exception as exc:  # a bug must cost this target, never the run
            report.hosts[index] = HostReport(target, reachable=False,
                                             error='internal error: %s' % _exception_text(exc))
        if progress:
            with lock:
                done[0] += 1
                progress(done[0], len(targets))

    pool = ThreadPoolExecutor(max_workers=max(1, min(workers, len(targets))))
    try:
        pending = {pool.submit(one, i) for i in range(len(targets))}
        while pending:
            finished, pending = wait_futures(pending, timeout=_POLL_SECONDS, return_when=FIRST_EXCEPTION)
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
    cyan = lambda self, t: self.paint('36', t)
    dim = lambda self, t: self.paint('2', t)
    bold = lambda self, t: self.paint('1', t)


_VERDICT_COLOR = {FOUND: 'green', LISTING: 'red', PROTECTED: 'yellow', REDIRECT: 'cyan',
                  BLOCKED: 'yellow', TIMEOUT: 'yellow', ERROR: 'yellow'}


def _plural(count: int, word: str, plural: Optional[str] = None) -> str:
    return '%d %s' % (count, word if count == 1 else (plural or word + 's'))


def _result_line(result: Result, color: _Color) -> str:
    paint = getattr(color, _VERDICT_COLOR.get(result.verdict, 'dim'))
    head = '  %s %s' % (paint('%-9s' % result.verdict), _plain('/' + result.path.lstrip('/')))
    bits = []
    if result.status is not None:
        bits.append(str(result.status))
    if result.verdict in (FOUND, LISTING) and result.length:
        bits.append('%d B' % result.length)
    if result.location:
        bits.append('\u2192 %s' % _plain(result.location))
    if result.verdict in (TIMEOUT, ERROR) and result.detail:
        bits.append(_plain(result.detail))
    return '%s%s' % (head, color.dim('  (%s)' % ' · '.join(bits)) if bits else '')


def _unchecked_line(results: Sequence[Result]) -> str:
    by = {}  # type: Dict[str, int]
    for r in results:
        if r.verdict in UNCHECKED_VERDICTS:
            by[r.verdict] = by.get(r.verdict, 0) + 1
    order = {BLOCKED: 0, TIMEOUT: 1, ERROR: 2}
    parts = ['%d %s' % (n, v.lower()) for v, n in sorted(by.items(), key=lambda kv: order.get(kv[0], 9))]
    return ', '.join(parts)


def render_text(report: ScanReport, color: Optional[_Color] = None, show_all: bool = False) -> str:
    color = color or _Color(False)
    out = io.StringIO()
    total_hits = 0
    for host in report.hosts:
        title = host.target.url
        if not host.reachable:
            out.write('%s  %s\n' % (color.bold(title), color.yellow('unreachable: %s' % _plain(host.error))))
            continue
        notable = host.notable() if not show_all else host.results
        shown = [r for r in notable if show_all or r.verdict in NOTABLE_VERDICTS]
        hits = host.hits()
        total_hits += len(hits)
        summary = []
        n_found = sum(1 for r in host.results if r.verdict == FOUND)
        n_list = sum(1 for r in host.results if r.verdict == LISTING)
        n_prot = sum(1 for r in host.results if r.verdict == PROTECTED)
        n_redir = sum(1 for r in host.results if r.verdict == REDIRECT)
        if n_found:
            summary.append(color.green('%d found' % n_found))
        if n_list:
            summary.append(color.red('%d listing' % n_list))
        if n_prot:
            summary.append(color.yellow('%d protected' % n_prot))
        if n_redir:
            summary.append(color.cyan('%d redirect' % n_redir))
        unchecked = _unchecked_line(host.results)
        head = '%s  %s' % (color.bold(title), ' · '.join(summary) if summary else color.dim('nothing answered'))
        if host.not_mapped:
            head = '%s  %s' % (color.bold(title), color.yellow(_plain(host.not_mapped)))
        out.write(head + '\n')
        for result in shown:
            out.write(_result_line(result, color) + '\n')
        if unchecked:
            out.write(color.dim('  not checked: %s\n' % unchecked))
        out.write('\n')
    counts = _counts(report)
    done = '%s · %s · %s · %s' % (
        color.green('%d found' % counts['found']),
        color.red('%s' % _plural(counts['listing'], 'open listing')),
        color.yellow('%d protected' % counts['protected']),
        color.cyan('%s' % _plural(counts['redirect'], 'redirect')))
    out.write('Summary: %s across %s.\n' % (done, _plural(len(report.hosts), 'target')))
    if not report.complete():
        out.write(color.dim('Some paths could not be checked (rate limited, timed out or failed); '
                            'a target that answered them is not fully mapped.\n'))
    for warning in report.warnings[:25]:
        out.write(color.dim('Note: %s\n' % _plain(warning)))
    return out.getvalue()


def _counts(report: ScanReport) -> Dict[str, int]:
    out = {v.lower(): 0 for v in VERDICTS}
    for host in report.hosts:
        for r in host.results:
            out[r.verdict.lower()] = out.get(r.verdict.lower(), 0) + 1
    out['hosts'] = len(report.hosts)
    out['reachable'] = sum(1 for h in report.hosts if h.reachable)
    out['paths'] = sum(len(h.results) for h in report.hosts)
    return out


def _result_dict(result: Result) -> Dict[str, Any]:
    out = {'path': result.path, 'url': result.url, 'verdict': result.verdict,
           'status': result.status, 'detail': result.detail}
    if result.content_type:
        out['contentType'] = result.content_type
    if result.verdict in (FOUND, LISTING):
        out['length'] = result.length
    if result.location:
        out['location'] = result.location
    return out


def report_to_dict(report: ScanReport) -> Dict[str, Any]:
    hosts = []
    for host in report.hosts:
        hosts.append({
            'host': host.target.host,
            'url': host.target.url,
            'scheme': host.target.scheme,
            'port': host.target.port,
            'reachable': host.reachable,
            'error': host.error,
            'baseline': {'kind': host.baseline.kind, 'status': host.baseline.status,
                         'note': host.baseline.note},
            'notMapped': host.not_mapped,
            'counts': {'found': sum(1 for r in host.results if r.verdict == FOUND),
                       'listing': sum(1 for r in host.results if r.verdict == LISTING),
                       'protected': sum(1 for r in host.results if r.verdict == PROTECTED),
                       'redirect': sum(1 for r in host.results if r.verdict == REDIRECT),
                       'unchecked': len(host.unchecked())},
            'results': [_result_dict(r) for r in host.results],
        })
    counts = _counts(report)
    return {
        'schema': SCHEMA,
        'tool': TOOL,
        'version': __version__,
        'generatedAt': report.generated_at,
        'options': dict(report.options),
        'summary': {'hosts': counts['hosts'], 'reachable': counts['reachable'], 'paths': counts['paths'],
                    'found': counts['found'], 'listing': counts['listing'],
                    'protected': counts['protected'], 'redirect': counts['redirect'],
                    'complete': report.complete()},
        'warnings': list(report.warnings),
        'hosts': hosts,
    }


CSV_COLUMNS = ('url', 'host', 'path', 'verdict', 'status', 'length', 'content_type', 'location', 'detail')


def render_csv(report: ScanReport, lineterminator: str = '\r\n') -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator=lineterminator)
    writer.writerow(CSV_COLUMNS)
    for host in report.hosts:
        for r in host.results:
            writer.writerow([csv_cell(v) for v in (
                r.url, host.target.host, '/' + r.path.lstrip('/'), r.verdict,
                r.status if r.status is not None else '', r.length or '', r.content_type,
                r.location, r.detail)])
    return out.getvalue()


# ---------------------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------------------

EPILOG = """examples:
  %(prog)s www.example.com                          the built-in names on one host
  %(prog)s https://app.example.com/ --extensions php,json,bak
  %(prog)s -t hosts.txt --wordlist my-paths.txt --json map.json
  %(prog)s --from-scan scan.json --rate 3 --csv map.csv   the hosts a scan already covered
  %(prog)s www.example.com --fail-on-found          exit 1 when any path answers (CI)

Map only hosts you own or are authorised to test. A path that answers is a fact about your
site, not a vulnerability; for leaked secret files use content_audit.py."""


def build_parser() -> argparse.ArgumentParser:
    description = ('Map the directories and endpoints of web hosts you own or may test: it tries '
                  'a list of common names and reports which answer, which are protected and which '
                  'redirect. A baseline per target suppresses catch-all pages; a per-host rate cap '
                  'keeps it polite. Python 3.9+, stdlib only.')
    parser = argparse.ArgumentParser(prog=PROG, formatter_class=argparse.RawDescriptionHelpFormatter,
                                     description=description, epilog=EPILOG)
    parser.add_argument('--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('targets', nargs='*', metavar='TARGET',
                        help='a host, a URL, or a file of them ("-" = stdin). A bare host is https')
    src = parser.add_argument_group('targets')
    src.add_argument('-t', '--targets-file', action='append', default=[], metavar='FILE',
                     help='a file of targets, one or more a line ("-" = stdin); repeatable')
    src.add_argument('--from-scan', action='append', default=[], metavar='FILE',
                     help='take host names from a DomainScope scan JSON report; repeatable')
    what = parser.add_argument_group('what is tried')
    what.add_argument('-w', '--wordlist', metavar='FILE',
                      help='your own names, one a line ("-" = stdin, "#" comments); added to the '
                           'built-in list unless --no-builtin')
    what.add_argument('--no-builtin', action='store_true',
                      help='do not try the built-in names (use only --wordlist)')
    what.add_argument('-x', '--extensions', metavar='LIST',
                      help='also try each name with these extensions, comma-separated (php,json,bak)')
    what.add_argument('--max-words', type=int, default=MAX_WORDS, metavar='N',
                      help='refuse more than N names to try (default: %(default)s)')
    what.add_argument('--list-words', action='store_true',
                      help='print the names that would be tried and exit')
    net = parser.add_argument_group('how')
    net.add_argument('--rate', type=float, default=DEFAULT_RATE, metavar='N',
                     help='requests a second, per host, shared by all its targets (default: '
                          '%(default)s; max ' + ('%g' % MAX_RATE) + ')')
    net.add_argument('--timeout', type=float, default=DEFAULT_TIMEOUT, metavar='SECONDS',
                     help='per request (default: %(default)s)')
    net.add_argument('--workers', type=int, default=DEFAULT_WORKERS, metavar='N',
                     help='targets mapped in parallel (default: %(default)s); a host keeps its rate')
    net.add_argument('--max-hosts', type=int, default=DEFAULT_MAX_HOSTS, metavar='N',
                     help='at most N targets (default: %(default)s)')
    net.add_argument('-H', '--header', action='append', default=[], metavar='"Name: value"',
                     help='an extra request header (a cookie or token for an authorised scan); '
                          'repeatable. Sent only to the target origin: a redirect elsewhere is not followed')
    net.add_argument('--insecure', action='store_true',
                     help='do not verify TLS certificates (for a self-signed host you trust)')
    net.add_argument('--cafile', metavar='FILE', help='verify TLS against this CA bundle (a private CA)')
    out = parser.add_argument_group('output')
    out.add_argument('--json', metavar='FILE', help='write a JSON report ("-" = stdout); the web app opens it')
    out.add_argument('--csv', metavar='FILE', help='write a CSV report ("-" = stdout)')
    out.add_argument('--show-all', action='store_true', help='list every path, not only the ones that answer')
    out.add_argument('--fail-on-found', action='store_true',
                     help='exit with code 1 when any path answers (for CI)')
    out.add_argument('--fail-on-error', action='store_true',
                     help='exit with code 1 when a target could not be fully mapped: unreachable, '
                          'or paths not checked (rate limited, timed out, failed)')
    out.add_argument('--no-color', action='store_true', help='no ANSI colors')
    out.add_argument('-q', '--quiet', action='store_true', help='no progress or warnings on stderr')
    return parser


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


def _same_path(first: Optional[str], second: Optional[str]) -> bool:
    if not first or not second or '-' in (first, second):
        return False
    return os.path.normcase(os.path.abspath(first)) == os.path.normcase(os.path.abspath(second))


def _check_output_paths(json_path: Optional[str], csv_path: Optional[str]) -> None:
    if json_path == '-' and csv_path == '-':
        raise UsageError('--json - and --csv - cannot both write to stdout')
    if _same_path(json_path, csv_path):
        raise UsageError('--json and --csv name the same file %s: give each its own'
                         % _plain(json_path or ''))
    for path, option in ((json_path, '--json'), (csv_path, '--csv')):
        if not path or path == '-':
            continue
        directory = os.path.dirname(os.path.abspath(path))
        if not os.path.isdir(directory):
            raise UsageError('%s: directory does not exist: %s' % (option, _plain(directory)))
        if os.path.isdir(path):
            raise UsageError('%s: %s is a directory' % (option, _plain(path)))
        try:
            if os.path.isfile(path):
                with open(path, 'r+b'):
                    pass
            elif not os.path.exists(path):
                with open(path, 'xb'):
                    pass
                os.remove(path)
        except OSError as exc:
            raise UsageError('%s: cannot write %s: %s' % (option, _plain(path), exc.strerror or exc))


def _write(path: str, text: str, encoding: str = 'utf-8') -> None:
    """stdout for "-", else a temporary file in the same directory renamed over the target."""
    if path == '-':
        sys.stdout.write(text)
        sys.stdout.flush()
        return
    directory = os.path.dirname(os.path.abspath(path)) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.dir_scan-', suffix='.tmp', dir=directory)
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
    if not 0 < args.rate <= MAX_RATE:
        raise UsageError('--rate must be > 0 and <= %g requests a second' % MAX_RATE)
    if not 1 <= args.workers <= MAX_WORKERS:
        raise UsageError('--workers must be between 1 and %d' % MAX_WORKERS)
    if not 1 <= args.max_hosts <= MAX_HOSTS:
        raise UsageError('--max-hosts must be between 1 and %d' % MAX_HOSTS)
    if not 1 <= args.max_words <= MAX_WORDS:
        raise UsageError('--max-words must be between 1 and %d' % MAX_WORDS)
    if args.cafile and args.insecure:
        raise UsageError('--cafile and --insecure cannot be combined')
    if args.cafile and not os.path.isfile(args.cafile):
        raise UsageError('--cafile %s is not a file' % _plain(args.cafile))
    _check_output_paths(args.json, args.csv)

    extensions = [e for e in re.split(r'[\s,]+', args.extensions or '') if e]
    if len(extensions) > MAX_EXTENSIONS:
        raise UsageError('--extensions: at most %d' % MAX_EXTENSIONS)
    words = load_words(args.wordlist, extensions=extensions, use_builtin=not args.no_builtin,
                       max_words=args.max_words)
    if args.list_words:
        sys.stdout.write(''.join('/' + w + '\n' for w in words))
        return EXIT_OK
    headers = _parse_headers(args.header)
    targets, warnings = parse_targets(args.targets, from_scan=args.from_scan,
                                      max_hosts=args.max_hosts, files=args.targets_file)
    if not targets:
        raise UsageError('no targets: give a host, a URL, -t FILE or --from-scan FILE')

    if not args.quiet:
        for warning in warnings[:25]:
            print('warning: %s' % _plain(warning), file=err)
        if len(warnings) > 25:
            print('warning: ... and %d more' % (len(warnings) - 25), file=err)
        print('note: mapping %s, %s each, on an explicit, authorised target list; %g req/s per host'
              % (_plural(len(targets), 'target'), _plural(len(words), 'name'), args.rate), file=err)
    tty = not args.quiet and hasattr(err, 'isatty') and err.isatty()

    def progress(done: int, total: int) -> None:
        if tty and (done == total or done % 1 == 0):
            err.write('\rmapped: %d / %d targets' % (done, total))
            if done == total:
                err.write('\n')
            err.flush()

    report = run_scan(targets, words, rate=args.rate, timeout=args.timeout, insecure=args.insecure,
                      cafile=args.cafile, headers=headers, workers=args.workers, progress=progress)
    report.warnings = warnings
    report.options = {'rate': args.rate, 'timeout': args.timeout, 'workers': args.workers,
                      'names': len(words), 'builtin': not args.no_builtin,
                      'extensions': extensions, 'wordlist': bool(args.wordlist),
                      'insecure': args.insecure, 'cafile': bool(args.cafile),
                      'headers': sorted(headers.keys())}

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

    if args.json != '-' and args.csv != '-':
        use_color = not args.no_color and not os.environ.get('NO_COLOR') \
            and hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
        sys.stdout.write(render_text(report, _Color(use_color), show_all=args.show_all))
        sys.stdout.flush()

    if failed:
        return EXIT_OUTPUT_ERROR
    if args.fail_on_found and report.hits():
        return EXIT_FOUND
    if args.fail_on_error and not report.complete():
        return EXIT_INCOMPLETE
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
    except BrokenPipeError:
        try:
            sys.stdout.close()
        except OSError:
            pass
        return EXIT_OK
    except KeyboardInterrupt:
        print('\ninterrupted', file=sys.stderr)
        return EXIT_INTERRUPTED
    except Exception as exc:  # noqa: BLE001 - an internal error must not look like a result
        print('%s: internal error: %s: %s' % (PROG, type(exc).__name__, _plain(str(exc))), file=sys.stderr)
        traceback.print_exc()
        return EXIT_INTERNAL_ERROR


# Fill the docstring's counts once the module is built.
__doc__ = __doc__.format(builtin=len(built_in_words()), maxwords=MAX_WORDS, rate='%g' % DEFAULT_RATE,
                         maxbody=MAX_BODY // 1024)


if __name__ == '__main__':
    sys.exit(main())
