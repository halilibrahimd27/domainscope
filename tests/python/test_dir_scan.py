"""Tests for cli/dir_scan.py (stdlib unittest; no Internet access needed).

Everything runs over plain HTTP against local http.server instances on 127.0.0.1, or through a
fake ``get``, so no TLS handshake is made and nothing leaves the machine: no request and no DNS
lookup. Only documentation names (example.com / .net / .org) and loopback appear.

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
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'dir_scan.py'


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ds = _load('dir_scan', CLI_PATH)


def no_proxy():
    return mock.patch.dict(os.environ, {'NO_PROXY': '*', 'no_proxy': '*'})


Route = Tuple[int, Dict[str, str], bytes]


class Server:
    """A local HTTP server; routes keyed by path, and a soft- or hard-404 default."""

    def __init__(self, routes: Optional[Dict[str, Route]] = None, soft: bool = False,
                 default: Optional[Callable[[str], Optional[Route]]] = None) -> None:
        self.routes = routes or {}
        self.soft = soft
        self.default = default
        self.requests = []  # type: List[str]
        receiver = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                receiver.requests.append(self.path)
                route = receiver.routes.get(self.path)
                if route is None and receiver.default is not None:
                    route = receiver.default(self.path)
                if route is None:
                    if receiver.soft:
                        route = (200, {'Content-Type': 'text/html'},
                                 b'<!doctype html><html><body>home page: ' + self.path.encode() + b'</body></html>')
                    else:
                        route = (404, {'Content-Type': 'text/html'}, b'404 not found: ' + self.path.encode())
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
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True, kwargs={'poll_interval': 0.02})
        self.thread.start()

    @property
    def port(self) -> int:
        return self.server.server_address[1]

    def url(self, path: str = '') -> str:
        return 'http://127.0.0.1:%d%s' % (self.port, path)

    def __enter__(self) -> 'Server':
        return self

    def __exit__(self, *exc: Any) -> None:
        self.server.shutdown()
        self.server.server_close()


def run_main(*args: str, stdin: str = '') -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(sys, 'stdin', io.StringIO(stdin)), no_proxy():
        ds._reset_openers()
        code = ds.main(list(args))
    return code, out.getvalue(), err.getvalue()


# ---------------------------------------------------------------------------------------
# A fake GET: a dict of path -> Response, a default for everything else
# ---------------------------------------------------------------------------------------

def resp(status: int, body: bytes = b'', ctype: str = 'text/html', location: str = '',
         redirects: Optional[List[str]] = None, requested: str = '', final: str = '') -> ds.Response:
    return ds.Response(status, body, ctype, len(body), final or requested, redirects or [], location, requested)


def fake_get(answers: Dict[str, ds.Response], default: ds.Response):
    """A ``get`` for run_scan / map_host: the answer for a URL's path, else `default`. Baseline
    paths (ds-dirscan-*) always get `default`."""
    def get(url: str, headers=None, timeout=0, insecure=False, cafile=None):
        path = '/' + url.split('://', 1)[1].split('/', 1)[1] if '://' in url else url
        key = path.rstrip('/')
        for want, r in answers.items():
            if key == '/' + want.strip('/'):
                return ds.Response(r.status, r.body, r.content_type, len(r.body), url, list(r.redirects),
                                   r.location, url)
        return ds.Response(default.status, default.body, default.content_type, len(default.body), url, [], '', url)
    return get


class TargetTests(unittest.TestCase):
    def test_bare_host_url_and_file(self):
        self.assertEqual(ds.parse_target('example.com').url, 'https://example.com/')
        self.assertEqual(ds.parse_target('example.com:80').scheme, 'http')
        t = ds.parse_target('https://app.example.net:8443/portal')
        self.assertEqual((t.host, t.port, t.base_path), ('app.example.net', 8443, '/portal/'))
        self.assertEqual(t.path_url('api'), 'https://app.example.net:8443/portal/api')

    def test_a_file_of_targets_and_dedup(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'hosts.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('# ours\nexample.com, https://example.com/\nwww.example.net  # note\n')
            targets, warnings = ds.parse_targets([], files=[path])
        self.assertEqual([t.url for t in targets], ['https://example.com/', 'https://www.example.net/'])
        self.assertEqual(warnings, [])

    def test_from_scan_reads_an_ssl_origin_scan_report(self):
        doc = {'names': [{'name': 'a.example.com'}, {'name': '*.example.com', 'wildcard': True}],
               'servers': [{'needsUpdate': ['b.example.com']}]}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'scan.json')
            with open(path, 'w', encoding='utf-8') as handle:
                json.dump(doc, handle)
            targets, _ = ds.parse_targets([], from_scan=[path])
        self.assertEqual(sorted(t.host for t in targets), ['a.example.com', 'b.example.com', 'example.com'])

    def test_a_bad_command_line_target_stops_the_run(self):
        with self.assertRaises(ds.UsageError):
            ds.parse_targets(['not a host'])


class WordlistTests(unittest.TestCase):
    def test_builtin_is_deduped_and_clean(self):
        words = ds.built_in_words()
        self.assertGreater(len(words), 150)
        self.assertEqual(len(words), len(set(words)))
        self.assertIn('api', words)
        self.assertIn('.well-known/security.txt', words)
        self.assertTrue(all(not w.startswith('/') for w in words))

    def test_clean_word_refuses_traversal_scheme_and_control(self):
        self.assertEqual(ds._clean_word('/admin/'), 'admin/')
        for bad in ('../etc', 'a/../b', 'http://x', 'a b', 'a\tb', '..'):
            self.assertIsNone(ds._clean_word(bad), bad)

    def test_wordlist_file_extensions_and_cap(self):
        words = ds.load_words(None, extensions=['php', '.bak', 'php'])
        self.assertIn('admin.php', words)
        self.assertIn('admin.bak', words)
        self.assertNotIn('.well-known.php', [w for w in words if w.startswith('.well-known')])  # has a dot already
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'w.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('# mine\nsecret\n/api/private\nsecret\n')
            only = ds.load_words(path, use_builtin=False)
        self.assertEqual(only, ['secret', 'api/private'])
        with self.assertRaises(ds.UsageError):
            ds.load_words(None, use_builtin=False)  # nothing to try
        with self.assertRaises(ds.UsageError):
            ds.load_words(None, max_words=5)


class ClassifyTests(unittest.TestCase):
    def soft(self):
        b = ds.Baseline(kind=ds.SOFT_404, soft_404=True, status=200, content_type='text/html', length=40)
        return b

    def hard(self):
        return ds.Baseline(kind=ds.HARD_404, status=404)

    def test_found_listing_protected_redirect_notfound(self):
        base = self.hard()
        v, _ = ds.classify('api', resp(200, b'{"ok":true}', 'application/json'), base)
        self.assertEqual(v, ds.FOUND)
        v, _ = ds.classify('files', resp(200, b'<title>Index of /files</title>'), base)
        self.assertEqual(v, ds.LISTING)
        v, _ = ds.classify('admin', resp(403, b'forbidden'), base)
        self.assertEqual(v, ds.PROTECTED)
        v, _ = ds.classify('old', resp(301, b'', location='https://example.com'), base)
        self.assertEqual(v, ds.REDIRECT)
        v, _ = ds.classify('nope', resp(404, b'no'), base)
        self.assertEqual(v, ds.NOT_FOUND)

    def test_catch_all_page_is_not_found(self):
        base = self.soft()
        page = resp(200, b'home page: /anything that is forty bytes xx', 'text/html')
        v, detail = ds.classify('whatever', page, base)
        self.assertEqual(v, ds.NOT_FOUND)
        self.assertIn('catch-all', detail)
        # a different 200 body on a soft-404 host is a real path
        v, _ = ds.classify('api', resp(200, b'{"x":1}', 'application/json'), base)
        self.assertEqual(v, ds.FOUND)

    def test_a_denied_host_makes_403_not_found(self):
        base = ds.Baseline(kind=ds.DENIED, status=403)
        v, _ = ds.classify('admin', resp(403, b'no'), base)
        self.assertEqual(v, ds.NOT_FOUND)

    def test_a_server_error_is_error_never_found(self):
        v, _ = ds.classify('x', resp(500, b'oops'), self.hard())
        self.assertEqual(v, ds.ERROR)

    def test_a_same_origin_redirect_to_another_path_is_a_redirect(self):
        r = resp(200, b'login page here', 'text/html', redirects=[''], requested='https://h/admin', final='https://h/login')
        v, _ = ds.classify('admin', r, self.hard())
        self.assertEqual(v, ds.REDIRECT)


class RunTests(unittest.TestCase):
    def setUp(self):
        self.words = ['api', 'admin', 'files', 'old', 'missing']
        self.targets = [ds.parse_target('https://web.example.com')]

    def run_fake(self, answers, default, **kw):
        get = fake_get(answers, default)
        return ds.run_scan(self.targets, self.words, get=get, sleep=lambda s: None, **kw)

    def test_a_full_map_over_a_hard_404_host(self):
        answers = {
            'api': resp(200, b'{"v":1}', 'application/json'),
            'admin': resp(401, b'auth'),
            'files': resp(200, b'<title>Index of /files</title><a>[To Parent Directory]</a>'),
            'old': resp(301, b'', location='https://cdn.example.net'),
        }
        report = self.run_fake(answers, resp(404, b'nope'))
        host = report.hosts[0]
        self.assertTrue(host.reachable)
        self.assertEqual(host.baseline.kind, ds.HARD_404)
        verdicts = {r.path: r.verdict for r in host.results}
        self.assertEqual(verdicts, {'api': ds.FOUND, 'admin': ds.PROTECTED, 'files': ds.LISTING,
                                    'old': ds.REDIRECT, 'missing': ds.NOT_FOUND})
        self.assertEqual([r.path for r in host.hits()], ['api', 'files'])
        self.assertTrue(report.complete())
        # results are sorted: found, listing, protected, redirect, then not-found
        self.assertEqual([r.verdict for r in host.results][:4], [ds.FOUND, ds.LISTING, ds.PROTECTED, ds.REDIRECT])

    def test_a_soft_404_host_reports_only_the_distinct_pages(self):
        base_body = b'<!doctype html><html>home, path unknown</html>'
        answers = {'api': resp(200, b'{"real":"endpoint"}', 'application/json')}
        report = self.run_fake(answers, resp(200, base_body))
        host = report.hosts[0]
        self.assertEqual(host.baseline.kind, ds.SOFT_404)
        self.assertEqual([r.path for r in host.hits()], ['api'])
        self.assertTrue(all(r.verdict == ds.NOT_FOUND for r in host.results if r.path != 'api'))

    def test_an_unreachable_target(self):
        def get(url, **kw):
            raise ds.HttpFailure('network', 'connection refused')
        report = ds.run_scan(self.targets, self.words, get=get, sleep=lambda s: None)
        self.assertFalse(report.hosts[0].reachable)
        self.assertFalse(report.complete())

    def test_a_timeout_is_not_checked_and_fails_complete(self):
        answers = {'api': resp(200, b'ok json here now', 'application/json')}
        def get(url, **kw):
            path = url.rsplit('/', 1)[-1]
            if path == 'admin':
                raise ds.HttpFailure('timeout', 'no answer in 10 s')
            return fake_get(answers, resp(404, b'no'))(url, **kw)
        report = ds.run_scan(self.targets, self.words, get=get, sleep=lambda s: None)
        host = report.hosts[0]
        self.assertEqual(next(r.verdict for r in host.results if r.path == 'admin'), ds.TIMEOUT)
        self.assertFalse(report.complete())

    def test_a_429_backs_the_host_off(self):
        calls = {'n': 0}
        def get(url, **kw):
            calls['n'] += 1
            return ds.Response(429, b'slow down', 'text/plain', 9, url, [], '', url)
        report = ds.run_scan(self.targets, self.words, get=get, sleep=lambda s: None)
        host = report.hosts[0]
        self.assertEqual(host.baseline.kind, ds.RATE_LIMITED)
        self.assertTrue(all(r.verdict == ds.BLOCKED for r in host.results))
        # the baseline hit the wall; no per-word request went out
        self.assertLessEqual(calls['n'], ds.BASELINE_SAMPLES)

    def test_a_bug_in_one_path_costs_only_that_path(self):
        def get(url, **kw):
            if url.endswith('/admin'):
                raise ValueError('boom')
            return ds.Response(404, b'no', 'text/html', 2, url, [], '', url)
        report = ds.run_scan(self.targets, self.words, get=get, sleep=lambda s: None)
        host = report.hosts[0]
        admin = next(r for r in host.results if r.path == 'admin')
        self.assertEqual(admin.verdict, ds.ERROR)
        self.assertIn('internal error', admin.detail)


class OutputTests(unittest.TestCase):
    def report(self):
        words = ['api', 'admin', 'missing']
        answers = {'api': resp(200, b'{"v":1}', 'application/json'), 'admin': resp(403, b'no')}
        return ds.run_scan([ds.parse_target('https://web.example.com')], words,
                           get=fake_get(answers, resp(404, b'nope')), sleep=lambda s: None)

    def test_json_is_the_schema_with_every_result(self):
        doc = ds.report_to_dict(self.report())
        self.assertEqual(doc['schema'], 'domainscope.dir-scan/1')
        self.assertEqual(doc['tool'], 'dir_scan')
        self.assertEqual(doc['summary']['found'], 1)
        self.assertEqual(doc['summary']['protected'], 1)
        host = doc['hosts'][0]
        self.assertEqual(host['host'], 'web.example.com')
        api = next(r for r in host['results'] if r['path'] == 'api')
        self.assertEqual([api['verdict'], api['status'], api['contentType']], ['FOUND', 200, 'application/json'])
        json.dumps(doc)

    def test_csv_is_spreadsheet_safe(self):
        words = ['api']
        answers = {'api': resp(301, b'', location='=HYPERLINK("x")')}
        report = ds.run_scan([ds.parse_target('https://web.example.com')], words,
                             get=fake_get(answers, resp(404, b'no')), sleep=lambda s: None)
        text = ds.render_csv(report)
        self.assertTrue(text.startswith('url,host,path,verdict,status'))
        self.assertIn("'=HYPERLINK", text)

    def test_text_lists_the_answered_paths(self):
        out = ds.render_text(self.report())
        self.assertIn('FOUND', out)
        self.assertIn('/api', out)
        self.assertIn('PROTECTED', out)
        self.assertIn('Summary:', out)
        self.assertNotIn('/missing', out)  # not shown unless --show-all


class MainTests(unittest.TestCase):
    def test_against_a_local_server_with_a_report(self):
        routes = {
            '/api': (200, {'Content-Type': 'application/json'}, b'{"v":1}'),
            '/admin': (401, {'Content-Type': 'text/html'}, b'auth'),
            '/old': (301, {'Location': 'https://cdn.example.net/'}, b''),
        }
        with Server(routes) as server, tempfile.TemporaryDirectory() as tmp:
            out_path = os.path.join(tmp, 'map.json')
            code, out, err = run_main(server.url(), '--wordlist', '-', '--no-builtin', '--rate', '50',
                                      '--timeout', '3', '--json', out_path, '--no-color',
                                      stdin='api\nadmin\nold\nmissing\n')
            self.assertEqual(code, 0, out + err)
            with open(out_path, encoding='utf-8') as handle:
                doc = json.load(handle)
        host = doc['hosts'][0]
        verdicts = {r['path']: r['verdict'] for r in host['results']}
        self.assertEqual(verdicts, {'api': 'FOUND', 'admin': 'PROTECTED', 'old': 'REDIRECT', 'missing': 'NOT_FOUND'})
        self.assertIn('FOUND', out)
        self.assertIn('authorised', err)

    def test_fail_on_found_exits_1(self):
        with Server({'/api': (200, {'Content-Type': 'application/json'}, b'{"v":1}')}) as server:
            code, _out, _err = run_main(server.url(), '-w', '-', '--no-builtin', '--rate', '50',
                                        '--fail-on-found', '-q', stdin='api\nmissing\n')
        self.assertEqual(code, 1)

    def test_list_words_prints_and_exits(self):
        code, out, _err = run_main('--list-words', '--extensions', 'php')
        self.assertEqual(code, 0)
        self.assertIn('/api\n', out)
        self.assertIn('/admin.php\n', out)

    def test_usage_errors(self):
        for argv, needle in (
            (['x.example.com', '--json', '-', '--csv', '-'], 'stdout'),
            (['x.example.com', '--rate', '0'], '--rate'),
            (['x.example.com', '--workers', '0'], '--workers'),
            ([], 'no targets'),
            (['not a host'], 'valid host'),
        ):
            code, _out, err = run_main(*argv)
            self.assertEqual(code, 2, argv)
            self.assertIn(needle, err, argv)
        with tempfile.TemporaryDirectory() as tmp:
            same = os.path.join(tmp, 'both')
            code, _out, err = run_main('x.example.com', '--json', same, '--csv', same)
            self.assertEqual(code, 2)
            self.assertIn('same file', err)

    def test_a_report_not_written_is_exit_3_and_a_crash_exit_70(self):
        with Server({}) as server:
            code, _out, err = run_main(server.url(), '-w', '-', '--no-builtin', '--rate', '50', '-q',
                                       '--json', os.path.join(str(ROOT), 'no-such-dir', 'x', 'm.json'),
                                       stdin='api\n')
            self.assertEqual(code, 2)  # the missing directory is caught before the run
            self.assertIn('directory does not exist', err)
        with mock.patch.object(ds, 'run_scan', side_effect=RuntimeError('boom')):
            code, _out, err = run_main('x.example.com', '-q')
        self.assertEqual(code, 70)
        self.assertIn('internal error: RuntimeError: boom', err)


if __name__ == '__main__':
    unittest.main()
