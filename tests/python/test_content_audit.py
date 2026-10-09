"""Tests for cli/content_audit.py (stdlib unittest; no Internet access needed).

Everything runs over plain HTTP against local http.server instances on 127.0.0.1, so no TLS
handshake is made (nothing for a local HTTPS interceptor to trip over) and nothing leaves the
machine. Only documentation names (example.com / .net / .org) and loopback appear.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import contextlib
import http.server
import importlib.util
import io
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'content_audit.py'


def _load_cli():
    spec = importlib.util.spec_from_file_location('content_audit', str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules['content_audit'] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


ca = _load_cli()


def no_proxy():
    """urllib must not route the loopback server through a proxy of this machine."""
    return mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'})


# ---------------------------------------------------------------------------------------
# A local HTTP server with scripted routes and a soft- or hard-404 default
# ---------------------------------------------------------------------------------------

Route = Tuple[int, Dict[str, str], bytes]


class Server:
    def __init__(self, routes: Optional[Dict[str, Route]] = None, soft: bool = False,
                 delay: float = 0.0) -> None:
        self.routes = routes or {}
        self.soft = soft
        self.delay = delay
        self.requests = []  # type: List[Tuple[str, str, Dict[str, str]]]
        receiver = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                receiver.requests.append(('GET', self.path, dict(self.headers)))
                if receiver.delay:
                    time.sleep(receiver.delay)
                route = receiver.routes.get(self.path)
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

    def test_ipv4_literal_and_mapped(self):
        self.assertEqual(ca.parse_target('192.0.2.10').host, '192.0.2.10')
        self.assertEqual(ca.parse_target('[::ffff:192.0.2.10]').host, '192.0.2.10')

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
            path = os.path.join(d, 'hosts.txt')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('# my servers\nexample.com\nhttps://app.example.net:8443/\nhttp://\n')
            targets, warnings = ca.parse_targets([path])
        self.assertEqual([t.host for t in targets], ['example.com', 'app.example.net'])
        self.assertEqual(len(warnings), 1)
        self.assertIn('line 4', warnings[0])

    def test_command_line_bad_target_raises(self):
        with self.assertRaises(ca.UsageError):
            ca.parse_targets(['example.com', 'ftp://bad'])

    def test_max_hosts(self):
        with self.assertRaises(ca.UsageError):
            ca.parse_targets(['a.example', 'b.example', 'c.example'], max_hosts=2)

    def test_from_scan_ssl_origin_scan_shape(self):
        doc = {'tool': 'ssl_origin_scan', 'names': ['www.example.com', 'WWW.example.com.'],
               'servers': [{'names': ['api.example.net', '*.example.org']}],
               'newCertificates': [{'names': ['new.example.com']}]}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'scan.json')
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(doc, fh)
            targets, warnings = ca.parse_targets([], from_scan=[path])
        hosts = [t.host for t in targets]
        self.assertIn('www.example.com', hosts)
        self.assertIn('api.example.net', hosts)
        self.assertIn('new.example.com', hosts)
        self.assertIn('example.org', hosts)  # the base of the *.example.org wildcard
        self.assertEqual(hosts.count('www.example.com'), 1)  # WWW.example.com. folds in
        self.assertTrue(all(t.scheme == 'https' for t in targets))

    def test_from_scan_plain_list(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'names.json')
            with open(path, 'w', encoding='utf-8') as fh:
                json.dump(['one.example.com', '192.0.2.5', 'two.example.net'], fh)
            targets, _ = ca.parse_targets([], from_scan=[path])
        self.assertEqual(sorted(t.host for t in targets), ['one.example.com', 'two.example.net'])

    def test_from_scan_not_json(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'x.json')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('not json')
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

    def test_curated_not_a_wordlist(self):
        self.assertLessEqual(len(ca.PROBES), 60)  # a curated list, not a scanner's dictionary

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
            path = os.path.join(d, 'big.txt')
            with open(path, 'w', encoding='utf-8') as fh:
                fh.write('\n'.join('p%d' % i for i in range(ca.MAX_CUSTOM_PATHS + 1)))
            with self.assertRaises(ca.UsageError):
                ca._custom_paths(path)

    def test_render_paths(self):
        text = ca.render_paths()
        self.assertIn('.git/HEAD', text)
        self.assertIn('vcs:', text)
        self.assertIn('secret:', text)


# ---------------------------------------------------------------------------------------
# Content matchers
# ---------------------------------------------------------------------------------------

HTML_PAGE = b'<!doctype html><html><head><title>App</title></head><body>hello</body></html>'


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
        self.assertTrue(ca.svn_entries(b'<?xml version="1.0"?><wc-entries/>', 'text/xml'))
        self.assertFalse(ca.svn_entries(HTML_PAGE, 'text/html'))

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

def _resp(status, ctype='text/html', body=b'', redirects=None, final=''):
    return ca.Response(status, body, ctype, len(body), final, list(redirects or []))


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
        self.assertFalse(base.soft_404)
        self.assertEqual(base.status, 404)
        self.assertEqual(len(calls), ca.BASELINE_SAMPLES)
        self.assertIn('404', base.note)

    def test_soft_404_is_detected(self):
        base, _ = self._baseline(lambda url, i: _resp(200, 'text/html', b'<html>app ' + url.encode() + b'</html>'))
        self.assertTrue(base.soft_404)
        self.assertEqual(base.status, 200)

    def test_steady_redirect_is_soft(self):
        base, _ = self._baseline(
            lambda url, i: _resp(302, 'text/html', b'', redirects=['login.example.com']))
        self.assertTrue(base.soft_404)
        self.assertEqual(base.redirect_host, 'login.example.com')

    def test_inconsistent_is_not_soft(self):
        base, _ = self._baseline(lambda url, i: _resp(200 if i == 0 else 404, 'text/html', b'x'))
        self.assertFalse(base.soft_404)
        self.assertIn('inconsistent', base.note)

    def test_failed_baseline_request(self):
        def boom(url, i):
            raise ca.HttpFailure('timeout', 'no answer')
        base, _ = self._baseline(boom)
        self.assertTrue(base.note.startswith('baseline request failed'))


# ---------------------------------------------------------------------------------------
# Classifying one answer
# ---------------------------------------------------------------------------------------

class ClassifyTests(unittest.TestCase):
    def setUp(self):
        self.hard = ca.Baseline(soft_404=False, status=404, content_type='text/html', length=20)
        self.soft = ca.Baseline(soft_404=True, status=200, content_type='text/html', length=50)
        self.env_probe = next(p for p in ca.PROBES if p.path == '.env')
        self.status_probe = next(p for p in ca.PROBES if p.path == 'server-status')

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
        svn = next(p for p in ca.PROBES if p.path == '.svn/entries')
        resp = _resp(200, 'text/html', b'<html>missing /.svn/entries here</html>')
        verdict, _, _ = ca.classify(svn, resp, self.soft)
        self.assertEqual(verdict, ca.NOT_FOUND)

    def test_html_status_page_confirmed(self):
        resp = _resp(200, 'text/html', b'<html><body>Apache Server Status</body></html>')
        verdict, conf, _ = ca.classify(self.status_probe, resp, self.hard)
        self.assertEqual(verdict, ca.EXPOSED)
        self.assertEqual(conf, ca.CONFIRMED)

    def test_protected(self):
        for code in (401, 403):
            verdict, conf, _ = ca.classify(self.env_probe, _resp(code), self.hard)
            self.assertEqual(verdict, ca.PROTECTED)
            self.assertEqual(conf, ca.PRESENT)

    def test_blocked(self):
        for code in (429, 503):
            verdict, _, _ = ca.classify(self.env_probe, _resp(code), self.hard)
            self.assertEqual(verdict, ca.BLOCKED)

    def test_off_host_redirect(self):
        resp = _resp(302, 'text/html', b'', redirects=['other.example.net'])
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

    def test_same_host_redirect_followed_with_header(self):
        routes = {'/start': (302, {'Location': '/end'}, b''),
                  '/end': (200, {'Content-Type': 'text/plain'}, b'END')}
        with Server(routes) as s, no_proxy():
            resp = ca.http_get(s.url('/start'), headers={'X-Audit': 'tok'})
            self.assertEqual(resp.status, 200)
            self.assertEqual(resp.body, b'END')
            self.assertTrue(resp.final_url.endswith('/end'))
            end = [h for m, p, h in s.requests if p == '/end']
            self.assertTrue(end and end[0].get('X-Audit') == 'tok')

    def test_off_host_redirect_not_followed(self):
        with Server({'/go': (302, {'Location': 'http://example.com/x'}, b'')}) as s, no_proxy():
            resp = ca.http_get(s.url('/go'), headers={'X-Audit': 'tok'})
            self.assertEqual(resp.status, 302)
            self.assertEqual(resp.redirects, ['example.com'])
            self.assertEqual(s.paths_requested(), ['/go'])  # it never left the audited host

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

    def test_end_to_end_soft_404_suppresses_catchall(self):
        with Server(dict(EXPOSED_ROUTES), soft=True) as s, no_proxy():
            target = ca.parse_target(s.url(''))
            report = ca.audit_host(target, ca.PROBES, rate=50.0, timeout=5.0)
        self.assertTrue(report.baseline.soft_404)
        paths = {r.path for r in report.findings()}
        self.assertIn('.git/HEAD', paths)
        self.assertIn('.env', paths)
        # Every other curated path returns the catch-all page and must not be a finding.
        self.assertEqual(paths, {'.git/HEAD', '.env'})

    def test_unreachable_host(self):
        target = ca.parse_target('http://127.0.0.1:%d/' % _free_port())
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

    def test_backoff_after_429(self):
        calls = []

        def get(url, **kw):
            calls.append(url)
            if url.endswith('ds-audit-baseline-7f3a90') or 'baseline' in url:
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

    def test_run_audit_parallel(self):
        with Server(dict(EXPOSED_ROUTES)) as a, Server({}) as b, no_proxy():
            targets = [ca.parse_target(a.url('')), ca.parse_target(b.url(''))]
            report = ca.run_audit(targets, ca.PROBES, rate=50.0, timeout=5.0, workers=4)
        self.assertEqual(len(report.hosts), 2)
        self.assertTrue(report.findings())


# ---------------------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------------------

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
        self.assertIn('summary', doc)
        self.assertGreaterEqual(doc['summary']['findings'], 2)
        host = doc['hosts'][0]
        self.assertIn('baseline', host)
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
        self.assertIn('exposed', text)
        idx_exposed = text.index('EXPOSED')
        self.assertLess(idx_exposed, text.index('not exposed') if 'not exposed' in text else len(text))


# ---------------------------------------------------------------------------------------
# The command line, end to end
# ---------------------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def test_paths_command(self):
        code, out, err = run_main('ds_paths')
        self.assertEqual(code, ca.EXIT_OK)
        self.assertIn('.git/HEAD', out)

    def test_audit_writes_json_and_csv(self):
        with Server(dict(EXPOSED_ROUTES)) as s, tempfile.TemporaryDirectory() as d:
            jpath = os.path.join(d, 'out.json')
            cpath = os.path.join(d, 'out.csv')
            code, out, err = run_main('ds_audit', s.url(''), '--rate', '50', '--no-color',
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
            code, out, err = run_main('ds_audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '-q')
        self.assertEqual(code, ca.EXIT_FINDINGS)

    def test_clean_host_exit_zero(self):
        with Server({}) as s:
            code, out, err = run_main('ds_audit', s.url(''), '--rate', '50', '--no-color',
                                      '--fail-on-finding', '-q')
        self.assertEqual(code, ca.EXIT_OK)
        self.assertIn('nothing exposed', out)

    def test_only_category(self):
        with Server(dict(EXPOSED_ROUTES)) as s, tempfile.TemporaryDirectory() as d:
            jpath = os.path.join(d, 'o.json')
            run_main('ds_audit', s.url(''), '--rate', '50', '--only', 'secret', '--json', jpath, '-q')
            with open(jpath, encoding='utf-8') as fh:
                doc = json.load(fh)
        cats = {r['category'] for r in doc['hosts'][0]['results']}
        self.assertEqual(cats, {'secret'})

    def test_from_scan_cli(self):
        # A scan lists host names; --from-scan turns them into https targets. The name here is
        # a reserved .invalid TLD, so the lookup fails fast and no request leaves the machine.
        with tempfile.TemporaryDirectory() as d:
            scan = os.path.join(d, 'scan.json')
            with open(scan, 'w', encoding='utf-8') as fh:
                json.dump({'names': ['audit-target.invalid']}, fh)
            jpath = os.path.join(d, 'o.json')
            code, out, err = run_main('ds_audit', '--from-scan', scan, '--rate', '50',
                                      '--timeout', '2', '--json', jpath, '-q', '--only', 'vcs')
            with open(jpath, encoding='utf-8') as fh:
                doc = json.load(fh)
        self.assertEqual(code, ca.EXIT_OK)
        self.assertEqual(doc['summary']['targets'], 1)
        self.assertEqual(doc['hosts'][0]['target'], 'https://audit-target.invalid/')
        self.assertFalse(doc['hosts'][0]['reachable'])

    def test_usage_errors(self):
        for args in (
            ('ds_audit', 'example.com', '--only', 'bogus'),
            ('ds_audit', 'example.com', '--cafile', 'nope.pem', '--insecure'),
            ('ds_audit', '--rate', '50'),  # no targets
            ('ds_audit', 'example.com', '--json', '-', '--csv', '-'),
            ('ds_audit', 'example.com', '--rate', '0'),
            ('ds_audit', 'ftp://bad.example'),
        ):
            code, out, err = run_main(*args)
            self.assertEqual(code, ca.EXIT_USAGE, args)
            self.assertIn('error:', err)

    def test_header_must_be_name_value(self):
        code, out, err = run_main('ds_audit', 'example.com', '-H', 'bogus')
        self.assertEqual(code, ca.EXIT_USAGE)


if __name__ == '__main__':
    unittest.main()
