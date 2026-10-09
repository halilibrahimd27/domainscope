"""Tests for cli/content_audit.py (stdlib unittest; no Internet access needed).

Everything runs over plain HTTP against local http.server instances on 127.0.0.1, or through a
fake ``get``, so no TLS handshake is made (nothing for a local HTTPS interceptor to trip over)
and nothing leaves the machine: no request and no DNS lookup. Only documentation names
(example.com / .net / .org), the scan fixtures' names and loopback appear.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import _thread
import contextlib
import http.server
import importlib.util
import io
import json
import os
import re
import shlex
import socket
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'content_audit.py'
FIXTURES = ROOT / 'tests' / 'fixtures'
SCAN_REPORT = FIXTURES / 'estate' / 'report-a.json'   # a real ssl_origin_scan report


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


ca = _load('content_audit', CLI_PATH)


def no_proxy():
    """urllib must not route the loopback server through a proxy of this machine."""
    return mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'})


# ---------------------------------------------------------------------------------------
# A local HTTP server with scripted routes and a soft- or hard-404 default
# ---------------------------------------------------------------------------------------

Route = Tuple[int, Dict[str, str], bytes]


class Server:
    def __init__(self, routes: Optional[Dict[str, Route]] = None, soft: bool = False,
                 delay: float = 0.0, default: Optional[Callable[[str], Route]] = None) -> None:
        self.routes = routes or {}
        self.soft = soft
        self.delay = delay
        self.default = default
        self.requests = []  # type: List[Tuple[str, str, Dict[str, str]]]
        receiver = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                receiver.requests.append(('GET', self.path, dict(self.headers)))
                if receiver.delay:
                    time.sleep(receiver.delay)
                route = receiver.routes.get(self.path)
                if route is None and receiver.default is not None:
                    route = receiver.default(self.path)
                if route is None:
                    if receiver.soft:
                        route = (200, {'Content-Type': 'text/html'},
                                 b'<!doctype html><html><body>home page, missing: '
                                 + self.path.encode() + b'</body></html>')
                    else:
                        route = (404, {'Content-Type': 'text/html'},
                                 b'<!doctype html><html><body>404 not found: '
                                 + self.path.encode() + b'</body></html>')
                status, headers, body = route
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def log_message(self, *args: Any) -> None:
                pass

        self.server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        self.server.handle_error = lambda request, address: None
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True,
                                       kwargs={'poll_interval': 0.02})
        self.thread.start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def url(self, path: str = '') -> str:
        return 'http://127.0.0.1:%d%s' % (self.port, path)

    def paths_requested(self) -> List[str]:
        return [p for _, p, _ in self.requests]

    def __enter__(self) -> 'Server':
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


def run_main(*args: str, stdin: str = '') -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(sys, 'stdin', io.StringIO(stdin)), no_proxy():
        ca._reset_openers()
        code = ca.main(list(args))
    return code, out.getvalue(), err.getvalue()


def _write(directory: str, name: str, text: str) -> str:
    path = os.path.join(directory, name)
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(text)
    return path


# ---------------------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------------------

class TargetTests(unittest.TestCase):
    def test_bare_host_is_https_on_443(self):
        t = ca.parse_target('example.com')
        self.assertEqual((t.scheme, t.host, t.port, t.base_path), ('https', 'example.com', 443, '/'))
        self.assertEqual(t.url, 'https://example.com/')

    def test_bare_host_port_80_is_http(self):
        t = ca.parse_target('example.com:80')
        self.assertEqual((t.scheme, t.port), ('http', 80))
        self.assertEqual(t.url, 'http://example.com/')

    def test_url_with_scheme_port_and_base_path(self):
        t = ca.parse_target('https://app.example.net:8443/portal')
        self.assertEqual((t.scheme, t.host, t.port, t.base_path),
                         ('https', 'app.example.net', 8443, '/portal/'))
        self.assertEqual(t.path_url('.git/HEAD'), 'https://app.example.net:8443/portal/.git/HEAD')

    def test_http_url_default_port_omitted_from_netloc(self):
        self.assertEqual(ca.parse_target('http://example.org/').url, 'http://example.org/')
        self.assertEqual(ca.parse_target('http://example.org:8080/').netloc, 'example.org:8080')

    def test_ipv6_literal(self):
        t = ca.parse_target('https://[2001:db8::1]:8443/')
        self.assertEqual((t.host, t.port), ('2001:db8::1', 8443))
        self.assertEqual(t.netloc, '[2001:db8::1]:8443')

    def test_bare_ipv6_address(self):
        t = ca.parse_target('2001:db8::1')
        self.assertEqual((t.scheme, t.host, t.port, t.url),
                         ('https', '2001:db8::1', 443, 'https://[2001:db8::1]/'))
        self.assertEqual(ca.parse_target('::1').host, '::1')
        for bad in ('2001:db8::zz', 'https://2001:db8::1/'):
            with self.subTest(bad=bad):
                with self.assertRaises(ca.UsageError) as cm:
                    ca.parse_target(bad)
                self.assertIn('[2001:db8::1]', str(cm.exception))  # how to write it instead

    def test_ipv4_literal_and_mapped(self):
        self.assertEqual(ca.parse_target('192.0.2.10').host, '192.0.2.10')
        self.assertEqual(ca.parse_target('[::ffff:192.0.2.10]').host, '192.0.2.10')

    def test_rejects_numbers_that_are_not_addresses(self):
        # The system resolver reads these the inet_aton way (010 is octal 8, 127.1 is 127.0.0.1),
        # so they would be audited somewhere else than the inventory meant.
        for bad in ('010.0.0.1', 'http://127.0.0.010:8080/', '192.0.2.010', '1.2.3', '127.1',
                    '0x7f.0.0.1'):
            with self.subTest(bad=bad):
                with self.assertRaises(ca.UsageError) as cm:
                    ca.parse_target(bad)
                self.assertIn('not an address', str(cm.exception))
        with self.assertRaises(ca.UsageError):
            ca.parse_target('example.123')  # no top-level domain is a number
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, 'hosts.txt', '127.0.0.010\nexample.com\n')
            targets, warnings = ca.parse_targets([], files=[path])
        self.assertEqual([t.host for t in targets], ['example.com'])
        self.assertEqual(len(warnings), 1)
        self.assertIn('line 1', warnings[0])
        self.assertIn('not an address', warnings[0])

    def test_idna_host(self):
        t = ca.parse_target('münchen.example')  # non-ASCII -> punycode
        self.assertTrue(t.host.startswith('xn--'))

    def test_only_http_https_schemes(self):
        for bad in ('ftp://example.com', 'file:///etc/passwd', 'gopher://example.com'):
            with self.assertRaises(ca.UsageError):
                ca.parse_target(bad)

    def test_rejects_non_hosts(self):
        for bad in ('', '   ', 'http://', 'https://:8443/', 'not a host'):
            with self.assertRaises(ca.UsageError):
                ca.parse_target(bad)

    def test_bad_port(self):
        for bad in ('example.com:0', 'example.com:70000', 'example.com:abc'):
            with self.assertRaises(ca.UsageError):
                ca.parse_target(bad)

    def test_parse_targets_dedupes_in_order(self):
        targets, warnings = ca.parse_targets(['example.com', 'https://example.com/', 'example.net'])
        self.assertEqual([t.host for t in targets], ['example.com', 'example.net'])
        self.assertEqual(warnings, [])

    def test_parse_targets_from_file(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, 'hosts.txt', '# my servers\nexample.com\nhttps://app.example.net:8443/\nhttp://\n')
            for targets, warnings in (ca.parse_targets([path]), ca.parse_targets([], files=[path])):
                self.assertEqual([t.host for t in targets], ['example.com', 'app.example.net'])
                self.assertEqual(len(warnings), 1)
                self.assertIn('line 4', warnings[0])

    def test_targets_file_must_exist(self):
        # -t is a file, never a host: a mistyped inventory path is an error, not a target.
        with tempfile.TemporaryDirectory() as d:
            missing = os.path.join(d, 'servers.txt')
            with self.assertRaises(ca.UsageError) as cm:
                ca.parse_targets([], files=[missing])
            self.assertIn('cannot read', str(cm.exception))
            code, out, err = run_main('audit', '-t', missing, '-t', os.path.join(d, 'inventory'))
        self.assertEqual(code, ca.EXIT_USAGE)
        self.assertIn('cannot read', err)

    def test_missing_file_name_on_the_command_line_is_not_a_host(self):
        with self.assertRaises(ca.UsageError) as cm:
            ca.parse_targets(['ds-no-such-servers.txt'])
        self.assertIn('cannot read', str(cm.exception))
        # Written as a URL it is a host name again.
        self.assertEqual(ca.parse_targets(['https://example.txt/'])[0][0].host, 'example.txt')

    def test_command_line_bad_target_raises(self):
        with self.assertRaises(ca.UsageError):
            ca.parse_targets(['example.com', 'ftp://bad'])

    def test_max_hosts(self):
        with self.assertRaises(ca.UsageError):
            ca.parse_targets(['a.example', 'b.example', 'c.example'], max_hosts=2)


class FromScanTests(unittest.TestCase):
    def _targets(self, doc: Any) -> Tuple[List[Any], List[str]]:
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, 'scan.json', json.dumps(doc))
            return ca.parse_targets([], from_scan=[path])

    def test_ssl_origin_scan_report(self):
        # names[].name are the host names the scan probed; servers[].name are inventory labels
        # (web01, origin, legacy-a ...) and must never become targets.
        targets, warnings = ca.parse_targets([], from_scan=[str(SCAN_REPORT)])
        self.assertEqual([t.url for t in targets],
                         ['https://www.example-test.com.tr/', 'https://a.wild.example.net/'])
        self.assertEqual(warnings, [])

    def test_ssl_origin_scan_wildcards_dropped(self):
        # The entries ssl_origin_scan.report_to_dict writes for "-n *.example.org": the base name
        # is a probe (and an entry) of its own, the wildcard entry is no host.
        doc = {'tool': 'ssl_origin_scan',
               'names': [{'name': 'example.org', 'sni': 'example.org', 'wildcard': False},
                         {'name': '*.example.org', 'sni': 'ssl-origin-scan-wildcard-probe.example.org',
                          'wildcard': True}],
               'servers': [{'name': 'web01', 'ips': ['192.0.2.10'], 'needsUpdate': ['*.example.org'],
                            'updated': [], 'originCert': [], 'privateCert': ['example.org'],
                            'hostedNotInNewCert': []}]}
        targets, _ = self._targets(doc)
        self.assertEqual([t.host for t in targets], ['example.org'])
        targets, _ = self._targets({'names': ['*.example.com', 'www.example.com']})
        self.assertEqual([t.host for t in targets], ['www.example.com'])  # no apex invented

    def test_ip_intel_report_here_names_only(self):
        ii = _load('ip_intel_for_content_audit', ROOT / 'cli' / 'ip_intel.py')
        rows = [ii.NameRow(name='www.example.com', sources=['ptr'], status=ii.HERE),
                ii.NameRow(name='old.example.net', sources=['otx'], status=ii.MOVED),
                ii.NameRow(name='*.example.org', sources=['tls'], status=ii.WILDCARD),
                ii.NameRow(name='later.example.org', sources=['otx'], status=ii.UNCHECKED),
                ii.NameRow(name='shop.example.net', sources=['tls'], status=ii.HERE)]
        report = ii.IntelReport(addresses=[ii.AddressReport(ip='203.0.113.10', public=True, names=rows)],
                                generated=datetime(2026, 10, 9, tzinfo=timezone.utc),
                                sources=['otx'], options={})
        targets, warnings = self._targets(ii.report_to_dict(report))
        # A MOVED name points at someone else's server now: it is not audited.
        self.assertEqual([t.host for t in targets], ['www.example.com', 'shop.example.net'])
        self.assertEqual(len(warnings), 1)
        self.assertIn('2 names', warnings[0])
        self.assertIn('HERE', warnings[0])

    def test_plain_lists(self):
        targets, _ = self._targets(['one.example.com', '192.0.2.5', 'two.example.net'])
        self.assertEqual([t.host for t in targets], ['one.example.com', 'two.example.net'])
        targets, _ = self._targets({'hosts': ['WWW.example.com.', 'www.example.com']})
        self.assertEqual([t.host for t in targets], ['www.example.com'])

    def test_nothing_usable_is_a_warning(self):
        targets, warnings = self._targets({'servers': [{'name': 'web01', 'ips': ['192.0.2.10']}]})
        self.assertEqual(targets, [])
        self.assertIn('no host names', warnings[0])

    def test_not_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, 'x.json', 'not json')
            with self.assertRaises(ca.UsageError):
                ca.parse_targets([], from_scan=[path])


# ---------------------------------------------------------------------------------------
# The curated path list
# ---------------------------------------------------------------------------------------

class PathListTests(unittest.TestCase):
    def test_probe_list_is_well_formed(self):
        self.assertGreaterEqual(len(ca.PROBES), 30)
        seen = set()
        for probe in ca.PROBES:
            self.assertNotIn(probe.path, seen, 'duplicate path %s' % probe.path)
            seen.add(probe.path)
            self.assertIn(probe.category, (ca.VCS, ca.SECRET, ca.CONFIG, ca.BACKUP, ca.INFO, ca.LISTING))
            self.assertIn(probe.severity, ca.SEVERITIES)
            self.assertFalse(probe.path.startswith('/'), probe.path)
            self.assertTrue(probe.note)
            self.assertIsNotNone(probe.confirm, probe.path)  # every curated path has a content check

    def test_curated_not_a_wordlist(self):
        self.assertLessEqual(len(ca.PROBES), 60)  # a curated list, not a scanner's dictionary

    def test_published_on_purpose_is_not_probed(self):
        # security.txt is meant to be public: it is not an exposure, so it is not asked.
        self.assertNotIn('.well-known/security.txt', [p.path for p in ca.PROBES])

    def test_paths_for_filters_by_category(self):
        only_vcs = ca.paths_for([ca.VCS])
        self.assertTrue(only_vcs)
        self.assertTrue(all(p.category == ca.VCS for p in only_vcs))

    def test_paths_for_adds_custom(self):
        probes = ca.paths_for(None, extra=['/my/secret.txt', 'other.bak'])
        customs = [p for p in probes if p.category == 'custom']
        self.assertEqual([p.path for p in customs], ['my/secret.txt', 'other.bak'])
        self.assertEqual(len(probes), len(ca.PROBES) + 2)

    def test_custom_paths_capped(self):
        with tempfile.TemporaryDirectory() as d:
            path = _write(d, 'big.txt', '\n'.join('p%d' % i for i in range(ca.MAX_CUSTOM_PATHS + 1)))
            with self.assertRaises(ca.UsageError):
                ca._custom_paths(path)

    def test_render_paths(self):
        text = ca.render_paths()
        self.assertIn('.git/HEAD', text)
        self.assertIn('vcs:', text)
        self.assertIn('secret:', text)
        self.assertIn('(%d)' % len(ca.PROBES), text)


# ---------------------------------------------------------------------------------------
# Content matchers
# ---------------------------------------------------------------------------------------

HTML_PAGE = b'<!doctype html><html><head><title>App</title></head><body>hello</body></html>'


def _probe(path: str):
    return next(p for p in ca.PROBES if p.path == path)


class MatcherTests(unittest.TestCase):
    def test_git_head(self):
        self.assertTrue(ca.git_head(b'ref: refs/heads/main\n', 'text/plain'))
        self.assertTrue(ca.git_head(b'a' * 40 + b'\n', 'text/plain'))
        self.assertFalse(ca.git_head(HTML_PAGE, 'text/html'))
        self.assertFalse(ca.git_head(b'just some text', 'text/plain'))

    def test_git_index_and_reflog(self):
        self.assertTrue(ca.git_index(b'DIRC\x00\x00\x00\x02', ''))
        self.assertFalse(ca.git_index(HTML_PAGE, ''))
        reflog = (b'0' * 40 + b' ' + b'f' * 40 + b' Dev <dev@example.com> 0 +0000\tcommit: x\n')
        self.assertTrue(ca.git_reflog(reflog, 'text/plain'))
        self.assertFalse(ca.git_reflog(HTML_PAGE, 'text/html'))

    def test_svn_entries(self):
        self.assertTrue(ca.svn_entries(b'12\n\ndir\n', 'text/plain'))
        self.assertTrue(ca.svn_entries(b'8\n\ndir\n1234\nhttps://svn.example.com/repo/trunk\n', 'text/plain'))
        self.assertTrue(ca.svn_entries(b'<?xml version="1.0"?><wc-entries/>', 'text/xml'))
        self.assertFalse(ca.svn_entries(HTML_PAGE, 'text/html'))
        self.assertFalse(ca.svn_entries(b'404', 'text/plain'))           # a bare number is no file
        self.assertFalse(ca.svn_entries(b'<?xml version="1.0"?><Error/>', 'text/xml'))

    def test_netrc_needs_a_machine_line_and_a_login(self):
        self.assertTrue(ca.netrc(b'machine api.example.com\n  login deploy\n  password x\n', 'text/plain'))
        self.assertTrue(ca.netrc(b'machine example.com login me password x\n', 'text/plain'))
        self.assertFalse(ca.netrc(b'{"error":"not found","message":"Please login to continue"}',
                                  'application/json'))
        self.assertFalse(ca.netrc(b'<div>Not found. Please login or register.</div>', 'text/html'))
        self.assertFalse(ca.netrc(b'machine learning is fun\n', 'text/plain'))

    def test_sftp_json_needs_a_remote_path(self):
        sftp = _probe('.vscode/sftp.json')
        self.assertFalse(sftp.confirm(b'{"error":"not found","host":"app.example.com"}', 'application/json'))
        self.assertTrue(sftp.confirm(b'{"name":"prod","host":"example.com","remotePath":"/var/www"}',
                                     'application/json'))

    def test_actuator_health_counts_only_with_details(self):
        health = _probe('actuator/health')
        self.assertFalse(health.confirm(b'{"status":"UP"}', 'application/json'))  # a normal health check
        self.assertTrue(health.confirm(
            b'{"status":"UP","components":{"db":{"status":"UP","details":{"database":"PostgreSQL"}}}}',
            'application/vnd.spring-boot.actuator.v3+json'))

    def test_dotenv(self):
        self.assertTrue(ca.dotenv(b'# comment\nAPP_ENV=production\nSECRET_KEY=abc123\n', 'text/plain'))
        self.assertTrue(ca.dotenv(b'export DB_PASSWORD=hunter2\n', 'text/plain'))
        self.assertFalse(ca.dotenv(HTML_PAGE, 'text/html'))
        self.assertFalse(ca.dotenv(b'just a sentence with = sign maybe', 'text/plain'))

    def test_listing(self):
        self.assertTrue(ca.listing(b'<html><head><title>Index of /uploads</title></head>', 'text/html'))
        self.assertTrue(ca.listing(b'<h1>Directory listing for /files/</h1>', 'text/html'))
        self.assertFalse(ca.listing(HTML_PAGE, 'text/html'))

    def test_sql_dump(self):
        self.assertTrue(ca.sql_dump(b'-- MySQL dump 10.13\nCREATE TABLE users (id int);', 'text/plain'))
        self.assertTrue(ca.sql_dump(b'SQLite format 3\x00rest', 'application/octet-stream'))
        self.assertFalse(ca.sql_dump(HTML_PAGE, 'text/html'))

    def test_php_source_rejects_html(self):
        self.assertTrue(ca.php_source(b"<?php define('DB_PASSWORD', 'x'); ?>", 'text/plain'))
        self.assertFalse(ca.php_source(HTML_PAGE, 'text/html'))

    def test_text_contains_rejects_html(self):
        m = ca.text_contains('services:', 'image:')
        self.assertTrue(m(b'services:\n  web:\n    image: nginx\n', 'text/plain'))
        self.assertFalse(m(b'<html>services: image:</html>', 'text/html'))

    def test_contains_allows_html(self):
        m = ca.contains('Apache Server Status')
        self.assertTrue(m(b'<html><body>Apache Server Status for host</body></html>', 'text/html'))


# ---------------------------------------------------------------------------------------
# The baseline
# ---------------------------------------------------------------------------------------

def _resp(status, ctype='text/html', body=b'', location='', final=''):
    return ca.Response(status, body, ctype, len(body), final, [location] if location else [], location)


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.target = ca.parse_target('https://example.com/')

    def _baseline(self, responder):
        calls = []

        def fetch(url):
            i = len(calls)
            calls.append(url)
            return responder(url, i)

        base = ca.probe_baseline(self.target, fetch)
        return base, calls

    def test_hard_404(self):
        base, calls = self._baseline(lambda url, i: _resp(404, 'text/html', b'nope ' + url.encode()))
        self.assertEqual(base.kind, ca.HARD_404)
        self.assertFalse(base.soft_404)
        self.assertEqual(base.status, 404)
        self.assertEqual(len(calls), ca.BASELINE_SAMPLES)
        self.assertIn('404', base.note)

    def test_soft_404_is_detected(self):
        base, _ = self._baseline(lambda url, i: _resp(200, 'text/html', b'<html>app ' + url.encode() + b'</html>'))
        self.assertEqual(base.kind, ca.SOFT_404)
        self.assertTrue(base.soft_404)
        self.assertEqual(base.status, 200)

    def test_steady_redirect_is_soft(self):
        base, _ = self._baseline(lambda url, i: _resp(302, 'text/html', b'', location='https://login.example.com'))
        self.assertEqual(base.kind, ca.CATCH_REDIRECT)
        self.assertTrue(base.soft_404)
        self.assertEqual(base.redirect_to, 'https://login.example.com')

    def test_inconsistent_is_not_soft(self):
        base, _ = self._baseline(lambda url, i: _resp(200 if i == 0 else 404, 'text/html', b'x'))
        self.assertEqual(base.kind, ca.MIXED)
        self.assertFalse(base.soft_404)
        self.assertIn('inconsistent', base.note)

    def test_denied_everywhere_is_said_so(self):
        body = lambda i: b'<Error><Code>AccessDenied</Code><RequestId>%d</RequestId></Error>' % i
        base, _ = self._baseline(lambda url, i: _resp(403, 'application/xml', body(i)))
        self.assertEqual(base.kind, ca.DENIED)
        self.assertFalse(base.soft_404)
        self.assertIn('every unknown path answers 403', base.note)
        self.assertNotIn('inconsistent', base.note)

    def test_steady_other_status_is_not_called_inconsistent(self):
        base, _ = self._baseline(lambda url, i: _resp(500, 'text/plain', b'boom'))
        self.assertEqual(base.kind, ca.STATUS_ONLY)
        self.assertIn('500', base.note)
        self.assertNotIn('inconsistent', base.note)

    def test_rate_limited_baseline_stops_at_once(self):
        base, calls = self._baseline(lambda url, i: _resp(429, 'text/plain', b'slow down'))
        self.assertEqual(base.kind, ca.RATE_LIMITED)
        self.assertEqual(len(calls), 1)

    def test_failed_baseline_request(self):
        def boom(url, i):
            raise ca.HttpFailure('timeout', 'no answer')
        base, _ = self._baseline(boom)
        self.assertEqual(base.kind, ca.NO_ANSWER)
        self.assertTrue(base.note.startswith('baseline request failed'))

    def test_baseline_paths_are_new_each_time(self):
        _, first = self._baseline(lambda url, i: _resp(404))
        _, second = self._baseline(lambda url, i: _resp(404))
        names = [u.rsplit('/', 1)[1] for u in first + second]
        self.assertEqual(len(set(names)), 4)
        self.assertTrue(all('baseline' in n for n in names), names)


# ---------------------------------------------------------------------------------------
# Classifying one answer
# ---------------------------------------------------------------------------------------

NON_HTML_CATCHALLS = (
    ('application/json', b'{"error":"not found","host":"app.example.com","message":"Please login to continue"}'),
    ('text/plain', b'404'),
    ('text/plain', b'status=not_found\n'),
    ('text/html', b'<div class="err">Not found. Please login or register.</div>'),
)


class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.hard = ca.Baseline(kind=ca.HARD_404, status=404, content_type='text/html', length=20)
        self.soft = ca.Baseline(kind=ca.SOFT_404, soft_404=True, status=200, content_type='text/html', length=50)
        self.env_probe = _probe('.env')
        self.status_probe = _probe('server-status')
        self.target = ca.parse_target('https://example.com/')

    def test_exposed_confirmed(self):
        resp = _resp(200, 'text/plain', b'APP_ENV=prod\nSECRET_KEY=abc\n')
        verdict, conf, _ = ca.classify(self.env_probe, resp, self.hard)
        self.assertEqual(verdict, ca.EXPOSED)
        self.assertEqual(conf, ca.CONFIRMED)

    def test_200_app_page_not_a_finding(self):
        resp = _resp(200, 'text/html', HTML_PAGE)
        verdict, _, _ = ca.classify(self.env_probe, resp, self.soft)
        self.assertEqual(verdict, ca.NOT_FOUND)

    def test_echoed_path_does_not_confirm(self):
        # A soft-404 page that quotes the requested path must not satisfy a content check.
        resp = _resp(200, 'text/html', b'<html>missing /.svn/entries here</html>')
        verdict, _, _ = ca.classify(_probe('.svn/entries'), resp, self.soft)
        self.assertEqual(verdict, ca.NOT_FOUND)

    def test_html_status_page_confirmed(self):
        resp = _resp(200, 'text/html', b'<html><body>Apache Server Status</body></html>')
        verdict, conf, _ = ca.classify(self.status_probe, resp, self.hard)
        self.assertEqual(verdict, ca.EXPOSED)
        self.assertEqual(conf, ca.CONFIRMED)

    def test_non_html_catchall_is_never_a_finding(self):
        # A host that answers 200 with the same small JSON / text body for every path: the
        # baseline sees it, and no curated check may turn that body into a finding.
        for ctype, body in NON_HTML_CATCHALLS:
            with self.subTest(body=body):
                baseline = ca.probe_baseline(self.target, lambda url: _resp(200, ctype, body))
                self.assertEqual(baseline.kind, ca.SOFT_404)
                for probe in ca.PROBES:
                    verdict, _, _ = ca.classify(probe, _resp(200, ctype, body), baseline)
                    self.assertNotIn(verdict, ca.FINDING_VERDICTS, probe.path)

    def test_real_file_the_size_of_the_catchall_is_still_found(self):
        baseline = ca.probe_baseline(self.target, lambda url: _resp(200, 'text/plain', b'404'))
        verdict, confidence, _ = ca.classify(self.env_probe, _resp(200, 'text/plain', b'A=1\nB=2\n'), baseline)
        self.assertEqual((verdict, confidence), (ca.EXPOSED, ca.CONFIRMED))

    def test_check_matching_the_catchall_counts_only_on_another_body(self):
        baseline = ca.probe_baseline(self.target, lambda url: _resp(200, 'text/plain', b'status=not_found\n'))
        same = ca.classify(self.env_probe, _resp(200, 'text/plain', b'status=not_found\n'), baseline)
        self.assertEqual(same[0], ca.BASELINE)
        real = b''.join(b'KEY_%d=value-%d\n' % (i, i) for i in range(40))
        other = ca.classify(self.env_probe, _resp(200, 'text/plain', real), baseline)
        self.assertEqual(other[:2], (ca.EXPOSED, ca.LIKELY))

    def test_protected(self):
        for code in (401, 403):
            verdict, conf, _ = ca.classify(self.env_probe, _resp(code), self.hard)
            self.assertEqual(verdict, ca.PROTECTED)
            self.assertEqual(conf, ca.PRESENT)

    def test_denied_host_status_says_nothing(self):
        denied = ca.Baseline(kind=ca.DENIED, status=403)
        self.assertEqual(ca.classify(self.env_probe, _resp(403), denied)[0], ca.BASELINE)
        self.assertEqual(ca.classify(self.env_probe, _resp(401), denied)[0], ca.PROTECTED)  # unlike the rest
        found = ca.classify(self.env_probe, _resp(200, 'text/plain', b'APP_ENV=prod\nSECRET_KEY=abc\n'), denied)
        self.assertEqual(found[:2], (ca.EXPOSED, ca.CONFIRMED))

    def test_blocked(self):
        for code in (429, 503):
            verdict, _, _ = ca.classify(self.env_probe, _resp(code), self.hard)
            self.assertEqual(verdict, ca.BLOCKED)

    def test_off_host_redirect(self):
        resp = _resp(302, 'text/html', b'', location='http://other.example.net')
        verdict, _, detail = ca.classify(self.env_probe, resp, self.hard)
        self.assertEqual(verdict, ca.REDIRECT)
        self.assertIn('other.example.net', detail)

    def test_404(self):
        verdict, _, _ = ca.classify(self.env_probe, _resp(404), self.hard)
        self.assertEqual(verdict, ca.NOT_FOUND)

    def test_custom_path_baseline_suppression(self):
        custom = ca.Probe('weird.path', 'custom', ca.MEDIUM, 'yours', None)
        same = _resp(200, 'text/html', b'<html>app home page padding</html>')
        self.soft.length = ca._stable_length(same.body, 'weird.path')
        verdict, _, _ = ca.classify(custom, same, self.soft)
        self.assertEqual(verdict, ca.BASELINE)

    def test_custom_path_unlike_catchall(self):
        custom = ca.Probe('weird.path', 'custom', ca.MEDIUM, 'yours', None)
        verdict, conf, _ = ca.classify(custom, _resp(200, 'application/json', b'{"a":1}' * 50), self.soft)
        self.assertEqual(verdict, ca.EXPOSED)
        self.assertEqual(conf, ca.LIKELY)


# ---------------------------------------------------------------------------------------
# http_get against a local server
# ---------------------------------------------------------------------------------------

class HttpGetTests(unittest.TestCase):
    def setUp(self):
        ca._reset_openers()

    def test_200_and_404(self):
        with Server({'/ok': (200, {'Content-Type': 'text/plain'}, b'hi')}) as s, no_proxy():
            self.assertEqual(ca.http_get(s.url('/ok')).status, 200)
            self.assertEqual(ca.http_get(s.url('/missing')).status, 404)

    def test_same_origin_redirect_followed_with_header(self):
        routes = {'/start': (302, {'Location': '/end'}, b''),
                  '/end': (200, {'Content-Type': 'text/plain'}, b'END')}
        with Server(routes) as s, no_proxy():
            resp = ca.http_get(s.url('/start'), headers={'X-Audit': 'tok'})
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.body, b'END')
            self.assertEqual(resp.location, '')
            self.assertTrue(resp.final_url.endswith('/end'))
            end = [h for m, p, h in s.requests if p == '/end']
            self.assertTrue(end and end[0].get('X-Audit') == 'tok')

    def test_redirect_to_another_port_is_not_followed(self):
        # Same host, another port: another service. Neither the header nor the request goes there,
        # and its file is never reported as the audited target's.
        token = 'Bearer ' + 'tok' + 'en-of-the-audit'
        with Server({'/.env': (200, {'Content-Type': 'text/plain'}, b'X=1\n')}) as other, no_proxy():
            moved = {'/.env': (302, {'Location': 'http://127.0.0.1:%d/.env' % other.port}, b'')}
            with Server(moved) as audited:
                resp = ca.http_get(audited.url('/.env'), headers={'Authorization': token})
            self.assertEqual(resp.status, 302)
            self.assertEqual(resp.location, 'http://127.0.0.1:%d' % other.port)
            self.assertEqual(other.requests, [])

    def test_same_origin_rules(self):
        same = ca._same_origin
        self.assertTrue(same('https://example.com/a', 'https://EXAMPLE.com:443/b'))
        self.assertTrue(same('http://example.com:8080/a', 'http://example.com:8080/b?x=1'))
        self.assertFalse(same('https://example.com/a', 'http://example.com/a'))       # scheme
        self.assertFalse(same('https://example.com/a', 'https://example.com:8443/a'))  # port
        self.assertFalse(same('https://example.com/a', 'https://www.example.com/a'))   # host
        self.assertFalse(same('https://example.com/a', 'ftp://example.com/a'))

    def test_off_host_redirect_not_followed(self):
        with Server({'/go': (302, {'Location': 'http://example.com/x'}, b'')}) as s, no_proxy():
            resp = ca.http_get(s.url('/go'), headers={'X-Audit': 'tok'})
            self.assertEqual(resp.status, 302)
            self.assertEqual(resp.location, 'http://example.com')  # the origin, never the path
            self.assertEqual(s.paths_requested(), ['/go'])  # it never left the audited host

    def test_unusable_location_is_the_answer(self):
        with Server({'/bad': (302, {'Location': 'http://[::1/x'}, b'')}) as s, no_proxy():
            resp = ca.http_get(s.url('/bad'))
        self.assertEqual((resp.status, resp.location), (302, ''))

    def test_body_is_capped(self):
        big = b'A' * (ca.MAX_BODY + 50_000)
        with Server({'/big': (200, {'Content-Type': 'text/plain'}, big)}) as s, no_proxy():
            resp = ca.http_get(s.url('/big'))
            self.assertEqual(len(resp.body), ca.MAX_BODY)

    def test_timeout(self):
        with Server({}, delay=1.0) as s, no_proxy():
            with self.assertRaises(ca.HttpFailure) as cm:
                ca.http_get(s.url('/slow'), timeout=0.2)
            self.assertEqual(cm.exception.kind, 'timeout')

    def test_connection_refused_is_failure(self):
        with no_proxy():
            with self.assertRaises(ca.HttpFailure):
                ca.http_get('http://127.0.0.1:%d/x' % _free_port(), timeout=1.0)


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


# ---------------------------------------------------------------------------------------
# Context (TLS) options, no handshake
# ---------------------------------------------------------------------------------------

class ContextTests(unittest.TestCase):
    def test_insecure_context_does_not_verify(self):
        ctx = ca._make_context(True, None)
        self.assertFalse(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, ca.ssl.CERT_NONE)

    def test_secure_context_verifies(self):
        ctx = ca._make_context(False, None)
        self.assertEqual(ctx.verify_mode, ca.ssl.CERT_REQUIRED)

    def test_opener_cached_per_ca_file(self):
        ca._reset_openers()
        plain = ca._opener(False, None)
        self.assertIs(ca._opener(False, None), plain)
        private = ca._opener(False, str(FIXTURES / 'ca.pem'))
        self.assertIsNot(private, plain)
        self.assertIs(ca._opener(False, str(FIXTURES / 'ca.pem')), private)
        self.assertIsNot(ca._opener(True, None), plain)
        ca._reset_openers()


# ---------------------------------------------------------------------------------------
# audit_host / run_audit
# ---------------------------------------------------------------------------------------

EXPOSED_ROUTES = {
    '/.git/HEAD': (200, {'Content-Type': 'text/plain'}, b'ref: refs/heads/main\n'),
    '/.env': (200, {'Content-Type': 'text/plain'}, b'APP_ENV=production\nSECRET_KEY=s3cr3t\n'),
    '/backup.sql': (401, {'Content-Type': 'text/html'}, b'denied'),
}


class AuditHostTests(unittest.TestCase):
    def setUp(self):
        ca._reset_openers()

    def test_end_to_end_hard_404(self):
        with Server(dict(EXPOSED_ROUTES), soft=False) as s, no_proxy():
            target = ca.parse_target(s.url(''))
            report = ca.audit_host(target, ca.PROBES, rate=50.0, timeout=5.0)
        self.assertTrue(report.reachable)
        self.assertFalse(report.baseline.soft_404)
        found = {r.path: r for r in report.findings()}
        self.assertIn('.git/HEAD', found)
        self.assertIn('.env', found)
        self.assertEqual(found['.env'].severity, ca.HIGH)
        protected = [r for r in report.results if r.verdict == ca.PROTECTED]
        self.assertEqual([r.path for r in protected], ['backup.sql'])
        self.assertEqual(report.baseline.body, b'')  # the catch-all body is not kept after the host

    def test_end_to_end_soft_404_suppresses_catchall(self):
        with Server(dict(EXPOSED_ROUTES), soft=True) as s, no_proxy():
            target = ca.parse_target(s.url(''))
            report = ca.audit_host(target, ca.PROBES, rate=50.0, timeout=5.0)
        self.assertTrue(report.baseline.soft_404)
        paths = {r.path for r in report.findings()}
        # Every other curated path returns the catch-all page and must not be a finding.
        self.assertEqual(paths, {'.git/HEAD', '.env'})

    def test_unreachable_host(self):
        target = ca.parse_target('http://127.0.0.1:%d/' % _free_port())
        with no_proxy():
            report = ca.audit_host(target, ca.PROBES, rate=50.0, timeout=1.0)
        self.assertFalse(report.reachable)
        self.assertTrue(report.error)

    def test_rate_cap_paces_requests(self):
        # A fake clock that only advances when the code sleeps: consecutive requests must be
        # at least one interval apart.
        now = [0.0]
        times = []  # type: List[float]

        def clock():
            return now[0]

        def sleep(seconds):
            now[0] += seconds

        def get(url, **kw):
            times.append(now[0])
            return _resp(404, 'text/html', b'x')

        target = ca.parse_target('https://example.com/')
        probes = ca.paths_for([ca.VCS])
        ca.audit_host(target, probes, rate=10.0, timeout=5.0, get=get, clock=clock, sleep=sleep)
        self.assertEqual(len(times), ca.BASELINE_SAMPLES + len(probes))
        gaps = [round(b - a, 6) for a, b in zip(times, times[1:])]
        self.assertTrue(all(g >= 0.1 - 1e-9 for g in gaps), gaps)  # interval = 1/10 s

    def test_rate_cap_holds_across_targets_on_one_host(self):
        # Three targets on example.com (two base paths, another scheme and port) and one on
        # example.net, in parallel. The clock stands still, so each request waits exactly as long
        # as its host's queue ahead of it: per host, the waits are 1, 2, 3 ... intervals.
        sleeps = []  # type: List[float]
        lock = threading.Lock()

        def sleep(seconds):
            with lock:
                sleeps.append(round(seconds, 6))

        targets = [ca.parse_target(t) for t in ('https://example.com/', 'https://example.com/app/',
                                                'http://example.com:8080/', 'https://example.net/')]
        probes = ca.paths_for([ca.VCS])
        per_target = ca.BASELINE_SAMPLES + len(probes)
        ca.run_audit(targets, probes, rate=10.0, workers=4, get=lambda url, **kw: _resp(404),
                     clock=lambda: 0.0, sleep=sleep)
        expected = [round(0.1 * i, 6) for i in range(1, 3 * per_target)]   # example.com
        expected += [round(0.1 * i, 6) for i in range(1, per_target)]      # example.net
        self.assertEqual(sorted(sleeps), sorted(expected))

    def test_backoff_after_429(self):
        calls = []

        def get(url, **kw):
            calls.append(url)
            if 'baseline' in url:
                return _resp(404, 'text/html', b'x')
            return _resp(429, 'text/html', b'slow down')

        target = ca.parse_target('https://example.com/')
        probes = ca.paths_for([ca.VCS])
        report = ca.audit_host(target, probes, rate=50.0, get=get)
        blocked = [r for r in report.results if r.verdict == ca.BLOCKED]
        self.assertEqual(len(blocked), len(probes))
        # After the first 429 the rest are "not asked", so only one probe request went out.
        probe_requests = [u for u in calls if 'baseline' not in u]
        self.assertEqual(len(probe_requests), 1)

    def test_rate_limited_baseline_asks_nothing_else(self):
        calls = []

        def get(url, **kw):
            calls.append(url)
            return _resp(429, 'text/plain', b'slow down')

        probes = ca.paths_for([ca.VCS])
        report = ca.audit_host(ca.parse_target('https://example.com/'), probes, rate=50.0, get=get)
        self.assertEqual(len(calls), 1)
        self.assertEqual(report.baseline.kind, ca.RATE_LIMITED)
        self.assertEqual([r.verdict for r in report.results], [ca.BLOCKED] * len(probes))

    def test_429_backs_off_every_target_on_the_host(self):
        calls = []

        def get(url, **kw):
            calls.append(url)
            if 'baseline' in url:
                return _resp(404, 'text/html', b'x')
            return _resp(429, 'text/plain', b'slow down')

        targets = [ca.parse_target('https://example.com/'), ca.parse_target('https://example.com/app/')]
        probes = ca.paths_for([ca.VCS])
        report = ca.run_audit(targets, probes, rate=50.0, workers=1, get=get, sleep=lambda s: None)
        self.assertEqual(len(calls), ca.BASELINE_SAMPLES + 1)  # the second target asks nothing
        self.assertTrue(all(r.verdict == ca.BLOCKED for h in report.hosts for r in h.results))
        self.assertEqual(len(report.hosts[1].results), len(probes))
        self.assertIn('another target', report.hosts[1].baseline.note)

    def test_interrupt_stops_every_host_promptly(self):
        # Ctrl+C while four hosts are being audited: the hosts stop at their next request
        # instead of finishing their whole path list.
        calls = []
        started = threading.Event()

        def get(url, **kw):
            calls.append(url)
            if len(calls) >= 4:
                started.set()
            time.sleep(0.02)
            return _resp(404, 'text/html', b'nf')

        def interrupt():
            if started.wait(10):
                _thread.interrupt_main()

        targets = [ca.parse_target('https://h%d.example.com/' % i) for i in range(4)]
        threading.Thread(target=interrupt, daemon=True).start()
        with self.assertRaises(KeyboardInterrupt):
            ca.run_audit(targets, ca.PROBES, rate=50.0, workers=4, get=get)
        stopped_at = len(calls)
        time.sleep(0.2)
        self.assertEqual(len(calls), stopped_at)  # nothing is still running
        everything = len(targets) * (ca.BASELINE_SAMPLES + len(ca.PROBES))
        self.assertLess(stopped_at, everything // 2, stopped_at)

    def test_run_audit_parallel(self):
        with Server(dict(EXPOSED_ROUTES)) as a, Server({}) as b, no_proxy():
            targets = [ca.parse_target(a.url('')), ca.parse_target(b.url(''))]
            report = ca.run_audit(targets, ca.paths_for([ca.VCS, ca.SECRET]), rate=50.0, timeout=5.0,
                                  workers=4)
        self.assertEqual(len(report.hosts), 2)
        self.assertTrue(report.findings())
        self.assertTrue(report.complete())


# ---------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------

ESC, RLO, BEL = '\x1b', '‮', '\x07'


class OutputTests(unittest.TestCase):
    def _report(self):
        with Server(dict(EXPOSED_ROUTES)) as s, no_proxy():
            ca._reset_openers()
            target = ca.parse_target(s.url(''))
            host = ca.audit_host(target, ca.PROBES, rate=50.0, timeout=5.0)
        report = ca.AuditReport(hosts=[host], generated_at='2026-10-09T00:00:00Z')
        return report

    def test_report_to_dict_schema(self):
        doc = ca.report_to_dict(self._report())
        self.assertEqual(doc['tool'], 'content_audit')
        self.assertEqual(doc['schema'], ca.SCHEMA)
        self.assertGreaterEqual(doc['summary']['findings'], 2)
        self.assertEqual(doc['summary']['unchecked'], 0)
        self.assertTrue(doc['summary']['complete'])
        host = doc['hosts'][0]
        self.assertEqual(host['baseline']['kind'], ca.HARD_404)
        self.assertEqual(host['unchecked'], 0)
        self.assertTrue(any(r['finding'] for r in host['results']))
        json.dumps(doc)  # serialisable

    def test_render_csv_columns_and_safety(self):
        report = self._report()
        # A hostile detail string must not become a spreadsheet formula or move the cursor.
        report.hosts[0].results[0].detail = '=cmd|/c calc'
        report.hosts[0].results[0].content_type = 'text/html\x1b[2K'
        csv_text = ca.render_csv(report, '\n')
        header = csv_text.splitlines()[0]
        self.assertEqual(header.split(','), list(ca.CSV_COLUMNS))
        self.assertIn("'=cmd", csv_text)
        self.assertIn('\\x1b[2K', csv_text)

    def test_render_text_findings_first(self):
        text = ca.render_text(self._report(), ca._Color(False))
        self.assertIn('EXPOSED', text)
        idx_exposed = text.index('EXPOSED')
        self.assertLess(idx_exposed, text.index('not exposed') if 'not exposed' in text else len(text))

    def test_render_text_escapes_server_text(self):
        # Content types, details, redirect targets, host errors and baseline notes all come from
        # the server (or the network): no escape or bidi character may reach the terminal.
        target = ca.parse_target('https://example.com/')
        host = ca.HostReport(target)
        host.baseline = ca.Baseline(kind=ca.CATCH_REDIRECT, soft_404=True, status=302,
                                    redirect_to='https://login.example.com' + ESC + '[2J',
                                    note='the server redirects unknown paths to x' + ESC + '[2J' + RLO)
        host.results = [
            ca.Result('.env', target.path_url('.env'), ca.SECRET, ca.HIGH, 'an env file', status=200,
                      content_type='text/plain' + ESC + '[2J' + RLO, verdict=ca.EXPOSED,
                      confidence=ca.CONFIRMED, detail='content' + ESC + ']0;title' + BEL),
            ca.Result('my' + ESC + '[31mpath', target.path_url('x'), 'custom', ca.MEDIUM, 'yours',
                      status=302, verdict=ca.REDIRECT, location='http://evil' + ESC + '[31m.example.com',
                      detail='redirects to http://evil' + ESC + '[31m.example.com'),
            ca.Result('.git/HEAD', target.path_url('.git/HEAD'), ca.VCS, ca.HIGH, 'git', verdict=ca.ERROR,
                      detail='reset' + RLO + ESC + '[2K'),
        ]
        down = ca.HostReport(ca.parse_target('https://example.net/'), reachable=False,
                             error='refused' + ESC + '[2K' + RLO)
        report = ca.AuditReport(hosts=[host, down], warnings=['w' + ESC])
        for show_all in (False, True):
            text = ca.render_text(report, ca._Color(False), show_all=show_all)
            for bad in (ESC, RLO, BEL):
                self.assertNotIn(bad, text)
            self.assertIn('\\x1b', text)  # escaped, not dropped
            self.assertIn('refused', text)

    def test_unchecked_paths_are_never_called_clean(self):
        target = ca.parse_target('https://example.com/')
        host = ca.HostReport(target)
        host.baseline = ca.Baseline(kind=ca.HARD_404, status=404, note='the server returns 404 for unknown paths')
        host.results = [ca.Result(p.path, target.path_url(p.path), p.category, p.severity, p.note,
                                  verdict=ca.TIMEOUT, detail='no answer in 0.3 s') for p in ca.PROBES]
        report = ca.AuditReport(hosts=[host])
        text = ca.render_text(report, ca._Color(False))
        self.assertNotIn('nothing exposed', text)
        self.assertNotIn('not exposed', text)
        self.assertIn('%d paths not checked' % len(ca.PROBES), text)
        doc = ca.report_to_dict(report)
        self.assertEqual(doc['summary']['unchecked'], len(ca.PROBES))
        self.assertFalse(doc['summary']['complete'])
        self.assertEqual(doc['hosts'][0]['unchecked'], len(ca.PROBES))


# ---------------------------------------------------------------------------------------
# The command line, end to end
# ---------------------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def test_paths_command(self):
        code, out, err = run_main('paths')
        self.assertEqual(code, ca.EXIT_OK)
        self.assertIn('.git/HEAD', out)

    def test_audit_writes_json_and_csv(self):
        with Server(dict(EXPOSED_ROUTES)) as s, tempfile.TemporaryDirectory() as d:
            jpath = os.path.join(d, 'out.json')
            cpath = os.path.join(d, 'out.csv')
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                      '--json', jpath, '--csv', cpath)
            with open(jpath, encoding='utf-8') as fh:
                doc = json.load(fh)
            with open(cpath, encoding='utf-8-sig') as fh:
                csv_text = fh.read()
        self.assertEqual(code, ca.EXIT_OK)
        self.assertGreaterEqual(doc['summary']['findings'], 2)
        self.assertIn('.env', csv_text)
        self.assertIn('EXPOSED', out)

    def test_fail_on_finding_exit_code(self):
        with Server(dict(EXPOSED_ROUTES)) as s:
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '-q')
        self.assertEqual(code, ca.EXIT_FINDINGS)

    def test_clean_host_exit_zero(self):
        with Server({}) as s:
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '--fail-on-error', '-q')
        self.assertEqual(code, ca.EXIT_OK)
        self.assertIn('nothing exposed', out)

    def test_published_files_and_a_plain_health_check_pass(self):
        routes = {'/.well-known/security.txt': (200, {'Content-Type': 'text/plain'},
                                                b'Contact: mailto:security@example.com\n'
                                                b'Expires: 2027-10-09T00:00:00.000Z\n'),
                  '/actuator/health': (200, {'Content-Type': 'application/json'}, b'{"status":"UP"}')}
        with Server(routes) as s:
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '-q')
        self.assertEqual(code, ca.EXIT_OK, out)
        self.assertIn('nothing exposed', out)

    def test_json_catchall_host_passes(self):
        body = NON_HTML_CATCHALLS[0][1]
        with Server(default=lambda path: (200, {'Content-Type': 'application/json'}, body)) as s:
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '-q')
        self.assertEqual(code, ca.EXIT_OK, out)

    def test_host_denying_everything(self):
        deny = lambda path: (403, {'Content-Type': 'application/xml'},
                             b'<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>')
        with Server(default=deny) as s:
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '-q')
        self.assertEqual(code, ca.EXIT_OK)
        self.assertIn('every unknown path answers 403', out)
        self.assertNotIn('inconsistent', out)
        self.assertIn(', 0 protected', out)

    def test_rate_limited_host_is_not_reported_clean(self):
        def answer(path):
            if 'baseline' in path:
                return (404, {'Content-Type': 'text/html'}, b'nf')
            return (429, {'Content-Type': 'text/plain'}, b'slow down')

        with Server(default=answer) as s, tempfile.TemporaryDirectory() as d:
            jpath = os.path.join(d, 'o.json')
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '-q', '--json', jpath)
            with open(jpath, encoding='utf-8') as fh:
                doc = json.load(fh)
            asked = len(s.requests)
            strict, _, _ = run_main('audit', s.url(''), '--rate', '50', '--no-color',
                                    '--fail-on-error', '-q')
        self.assertEqual(asked, ca.BASELINE_SAMPLES + 1)
        self.assertEqual(code, ca.EXIT_OK)          # nothing exposed was found ...
        self.assertEqual(strict, ca.EXIT_FINDINGS)  # ... but --fail-on-error fails an incomplete audit
        self.assertNotIn('nothing exposed', out)
        self.assertNotIn('not exposed', out)
        self.assertIn('%d paths not checked' % len(ca.PROBES), out)
        self.assertEqual(doc['summary']['unchecked'], len(ca.PROBES))
        self.assertFalse(doc['summary']['complete'])

    def test_header_values_are_never_written(self):
        secret = 'session=' + 'not-a-real-' + 'cookie-7'
        with Server(dict(EXPOSED_ROUTES)) as s, tempfile.TemporaryDirectory() as d:
            jpath = os.path.join(d, 'o.json')
            cpath = os.path.join(d, 'o.csv')
            code, out, err = run_main('audit', s.url(''), '--rate', '50', '--no-color', '--only', 'secret',
                                      '-H', 'Cookie: ' + secret, '--json', jpath, '--csv', cpath)
            sent = [h.get('Cookie') for _, _, h in s.requests]
            with open(jpath, encoding='utf-8') as fh:
                jtext = fh.read()
            with open(cpath, encoding='utf-8-sig') as fh:
                ctext = fh.read()
        self.assertEqual(code, ca.EXIT_OK)
        self.assertTrue(sent and all(v == secret for v in sent))  # it did reach the audited host
        for text in (jtext, ctext, out, err):
            self.assertNotIn('not-a-real-', text)
        self.assertEqual(json.loads(jtext)['options']['headers'], ['Cookie'])

    def test_only_category(self):
        with Server(dict(EXPOSED_ROUTES)) as s, tempfile.TemporaryDirectory() as d:
            jpath = os.path.join(d, 'o.json')
            run_main('audit', s.url(''), '--rate', '50', '--only', 'secret', '--json', jpath, '-q')
            with open(jpath, encoding='utf-8') as fh:
                doc = json.load(fh)
        cats = {r['category'] for r in doc['hosts'][0]['results']}
        self.assertEqual(cats, {'secret'})

    def test_from_scan_audits_only_the_scanned_names(self):
        # The real scan fixture, through a fake http_get: no request and no DNS lookup is made.
        asked = []

        def fake_get(url, **kw):
            asked.append(url)
            raise ca.HttpFailure('network', 'Connection refused')

        with tempfile.TemporaryDirectory() as d, mock.patch.object(ca, 'http_get', fake_get):
            jpath = os.path.join(d, 'o.json')
            code, out, err = run_main('audit', '--from-scan', str(SCAN_REPORT), '--json', jpath, '-q',
                                      '--only', 'vcs', '--fail-on-finding')
            strict, _, _ = run_main('audit', '--from-scan', str(SCAN_REPORT), '-q', '--only', 'vcs',
                                    '--fail-on-error')
            with open(jpath, encoding='utf-8') as fh:
                doc = json.load(fh)
        self.assertEqual(code, ca.EXIT_OK)
        self.assertEqual(strict, ca.EXIT_FINDINGS)
        self.assertEqual([h['target'] for h in doc['hosts']],
                         ['https://www.example-test.com.tr/', 'https://a.wild.example.net/'])
        self.assertTrue(all(not h['reachable'] for h in doc['hosts']))
        self.assertFalse(doc['summary']['complete'])
        self.assertEqual({urllib.parse.urlsplit(u).hostname for u in asked},
                         {'www.example-test.com.tr', 'a.wild.example.net'})

    def test_usage_errors(self):
        missing = os.path.join(tempfile.gettempdir(), 'ds-no-such-dir', 'servers.txt')
        for args in (
            ('audit', 'example.com', '--only', 'bogus'),
            ('audit', 'example.com', '--cafile', 'nope.pem', '--insecure'),
            ('audit', '--rate', '50'),  # no targets
            ('audit', 'example.com', '--json', '-', '--csv', '-'),
            ('audit', 'example.com', '--rate', '0'),
            ('audit', 'ftp://bad.example'),
            ('audit', '127.0.0.010'),
            ('audit', '-t', missing),
        ):
            code, out, err = run_main(*args)
            self.assertEqual(code, ca.EXIT_USAGE, args)
            self.assertIn('error:', err)

    def test_header_must_be_name_value(self):
        code, out, err = run_main('audit', 'example.com', '-H', 'bogus')
        self.assertEqual(code, ca.EXIT_USAGE)

    def test_documented_commands_parse(self):
        """The --help examples, the READMEs and About give valid command lines."""
        texts = [ca.EPILOG] + [(ROOT / name).read_text(encoding='utf-8')
                               for name in ('README.md', 'README.tr.md', 'assets/js/views/about.js')]
        commands = [c for text in texts
                    for c in re.findall(r"content_audit\.py ((?:audit|paths)\b[^'`\n]*)", text)]
        self.assertGreaterEqual(len(commands), 5)
        parser = ca.build_parser()
        for command in commands:
            with self.subTest(command=command):
                with contextlib.redirect_stderr(io.StringIO()):
                    parsed = parser.parse_args(shlex.split(command, comments=True))
                self.assertIn(parsed.command, ('audit', 'paths'))

    def test_help_and_version(self):
        code, out, _ = run_main('--help')
        self.assertEqual(code, 0)
        for text in ('audit', 'paths', 'Only audit servers you own'):
            self.assertIn(text, out)
        code, out, _ = run_main('audit', '--help')
        self.assertEqual(code, 0)
        for text in ('--from-scan', '--targets-file', '--fail-on-finding', '--fail-on-error'):
            self.assertIn(text, out)
        code, out, _ = run_main('--version')
        self.assertEqual((code, out.strip()), (0, 'content_audit.py 1.0.0'))
        for line in ca.EPILOG.splitlines():
            self.assertLessEqual(len(line), 100, line)


class CompatibilityTests(unittest.TestCase):
    """The CLI must stay runnable on Python 3.8 (the rules of test_ssl_origin_scan.py)."""

    def test_py_compile(self):
        import py_compile
        with tempfile.TemporaryDirectory() as tmp:
            py_compile.compile(str(CLI_PATH), cfile=os.path.join(tmp, 'x.pyc'), doraise=True)

    def test_no_py39_plus_syntax_or_apis(self):
        import ast
        source_text = CLI_PATH.read_text(encoding='utf-8')
        tree = ast.parse(source_text, feature_version=(3, 8))
        for node in ast.walk(tree):
            self.assertNotIsInstance(node, getattr(ast, 'Match', ()))
            if isinstance(node, ast.Subscript) and isinstance(node.value, ast.Name):
                self.assertNotIn(node.value.id, ('list', 'dict', 'tuple', 'set', 'type'), ast.dump(node))
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name) and node.func.value.id == 're'
                    and node.func.attr in ('split', 'sub', 'subn')):
                self.assertLessEqual(len(node.args), 2 if node.func.attr == 'split' else 3, 'line %d' % node.lineno)
        for api in ('removeprefix', 'removesuffix', 'functools.cache', 'zoneinfo', ' | None',
                    'strict=True)', 'BooleanOptionalAction', 'cancel_futures='):
            self.assertNotIn(api, source_text, api)
        self.assertIn('from __future__ import annotations', source_text)

    def test_shebang_and_stdlib_only(self):
        source_text = CLI_PATH.read_text(encoding='utf-8')
        self.assertTrue(source_text.startswith('#!/usr/bin/env python3'))
        imports = set(re.findall(r'^(?:from|import) ([a-zA-Z_][\w.]*)', source_text, re.M))
        stdlib = {'__future__', 'argparse', 'concurrent.futures', 'csv', 'dataclasses', 'datetime', 'io',
                  'ipaddress', 'json', 'os', 're', 'secrets', 'socket', 'ssl', 'sys', 'threading', 'time',
                  'typing', 'urllib.error', 'urllib.parse', 'urllib.request'}
        self.assertLessEqual(imports, stdlib, imports - stdlib)


if __name__ == '__main__':
    unittest.main()
