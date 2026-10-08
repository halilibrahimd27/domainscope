"""Tests for cli/ip_intel.py (stdlib unittest; no Internet access needed).

TLS servers on 127.0.0.1 serve the fixture certificates (the TlsServer and PlainServer
helpers of test_ssl_origin_scan.py). The sources are answered by a fake HTTP layer that
fails on any URL it does not know, and the system resolver by fakes, so nothing leaves the
machine. Documentation names and addresses only; where a test needs a public address it
treats the documentation ranges as public.

Run from the repository root:
    python3 -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import os
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CLI_PATH = ROOT / 'cli' / 'ip_intel.py'
FIXTURES = ROOT / 'tests' / 'fixtures'
sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_ssl_origin_scan import PlainServer, TlsServer  # noqa: E402  the fixture TLS servers


def _load_cli():
    spec = importlib.util.spec_from_file_location('ip_intel', str(CLI_PATH))
    module = importlib.util.module_from_spec(spec)
    sys.modules['ip_intel'] = module  # dataclasses need the module registered
    spec.loader.exec_module(module)
    return module


ii = _load_cli()

DOC_PREFIXES = ('192.0.2.', '198.51.100.', '203.0.113.', '2001:db8:')


def doc_public(ip: str) -> bool:
    """The documentation ranges stand in for public addresses."""
    return ip.startswith(DOC_PREFIXES)


def der_of(fixture: str) -> bytes:
    return ssl.PEM_cert_to_DER_cert((FIXTURES / (fixture + '.pem')).read_text(encoding='ascii'))


class FakeHttp:
    """Answers by URL prefix and records every request; any other URL fails the test."""

    def __init__(self, routes: Sequence[Tuple[str, Any]]) -> None:
        self.routes = list(routes)
        self.calls = []  # type: List[Tuple[str, Dict[str, str], Optional[bytes]]]
        self.lock = threading.Lock()

    def __call__(self, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[bytes] = None,
                 timeout: float = 0) -> Any:
        with self.lock:
            self.calls.append((url, dict(headers or {}), data))
        for prefix, answer in self.routes:
            if url.startswith(prefix):
                if callable(answer):
                    answer = answer(url)
                if isinstance(answer, Exception):
                    raise answer
                status, body = answer
                if isinstance(body, (dict, list)):
                    body = json.dumps(body).encode('utf-8')
                elif isinstance(body, str):
                    body = body.encode('utf-8')
                return ii.HttpResponse(status, body)
        raise AssertionError('unexpected request: %s' % url)

    def urls(self) -> List[str]:
        return [c[0] for c in self.calls]


def no_ptr(ip: str) -> List[str]:
    return []


def resolver(table: Dict[str, Any]) -> Callable[[str], List[str]]:
    """A fake system resolver: a list of addresses, or an exception to raise."""
    def lookup(name: str) -> List[str]:
        value = table.get(name, [])
        if isinstance(value, Exception):
            raise value
        return list(value)
    return lookup


def closed(ip: str, port: int, sni: Optional[str], timeout: float) -> Tuple[str, Optional[bytes], str]:
    return ii.PORT_CLOSED, None, 'connection refused'


@contextlib.contextmanager
def environment(**values: str):
    """os.environ without any key variable of the machine, plus ``values``."""
    clean = {k: v for k, v in os.environ.items() if k not in ii.KEY_VARIABLES}
    clean.update(values)
    with mock.patch.dict(os.environ, clean, clear=True):
        yield


def run_main(*args: str, stdin: str = '') -> Tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), \
            mock.patch.object(sys, 'stdin', io.StringIO(stdin)):
        code = ii.main(list(args))
    return code, out.getvalue(), err.getvalue()


OTX_BODY = {'passive_dns': [
    {'address': '203.0.113.10', 'first': '2019-03-01T10:00:00', 'last': '2024-05-06T08:00:00',
     'hostname': 'www.example.com', 'record_type': 'A', 'asset_type': 'hostname'},
    {'address': '203.0.113.10', 'first': '2018-01-02T00:00:00', 'last': '2019-02-03T00:00:00',
     'hostname': 'WWW.example.com.', 'record_type': 'A', 'asset_type': 'hostname'},
    {'address': '203.0.113.10', 'first': '2020-07-08T00:00:00', 'last': '2021-05-06T00:00:00',
     'hostname': 'old.example.org', 'record_type': 'A', 'asset_type': 'hostname'},
], 'count': 3}

ROBTEX_BODY = '\n'.join(json.dumps(r) for r in [
    {'rrname': 'www.example.com', 'rrdata': '203.0.113.10', 'rrtype': 'A', 'time_first': 1500000000,
     'time_last': 1790000000, 'count': 5},
    {'rrname': 'api.example.net', 'rrdata': '203.0.113.10', 'rrtype': 'A', 'time_first': 1600000000,
     'time_last': 1600000000, 'count': 1},
]) + '\n'

MNEMONIC_BODY = {'responseCode': 200, 'limit': 1000, 'offset': 0, 'count': 3, 'metaData': {}, 'messages': [],
                 'size': 3, 'data': [
                     {'query': 'mail.example.com', 'answer': '203.0.113.10', 'rrtype': 'a',
                      'firstSeenTimestamp': 1528386540397, 'lastSeenTimestamp': 1730035348201},
                     {'query': '10.113.0.203.in-addr.arpa', 'answer': 'host.example.net', 'rrtype': 'ptr',
                      'firstSeenTimestamp': 1600000000000, 'lastSeenTimestamp': 1700000000000},
                     {'query': 'alias.example.com', 'answer': 'www.example.com', 'rrtype': 'cname',
                      'firstSeenTimestamp': 1600000000000, 'lastSeenTimestamp': 1700000000000}]}


# ============================================================================ names, addresses

class NameTests(unittest.TestCase):

    def test_host_names_are_normalized_and_anything_else_is_dropped(self):
        n = ii.normalize_name
        self.assertEqual(n('WWW.Example.COM.'), 'www.example.com')
        self.assertEqual(n(' *.CDN.example.net '), '*.cdn.example.net')
        self.assertEqual(n('_sip._tcp.example.com'), '_sip._tcp.example.com')
        self.assertEqual(n('bücher.example'), 'xn--bcher-kva.example')
        for bad in ('localhost', '192.0.2.10', '2001:db8::1', 'a..example.com', '-a.example.com',
                    'a-.example.com', '*.*.example.com', 'x' * 64 + '.example.com', '',
                    '10.113.0.203.in-addr.arpa', 'host name.example.com', None, 42):
            self.assertIsNone(n(bad), bad)

    def test_a_wildcard_covers_exactly_one_label(self):
        self.assertTrue(ii.name_covers('*.example.com', 'www.example.com'))
        self.assertTrue(ii.name_covers('www.example.com', 'www.example.com'))
        self.assertFalse(ii.name_covers('*.example.com', 'example.com'))
        self.assertFalse(ii.name_covers('*.example.com', 'a.b.example.com'))
        self.assertFalse(ii.name_covers('www.example.com', 'api.example.com'))

    def test_only_global_unicast_addresses_are_public(self):
        for ip in ('10.0.0.5', '172.16.0.1', '192.168.1.1', '127.0.0.1', '100.64.0.1', '169.254.0.1',
                   '192.0.2.10', '198.51.100.7', '203.0.113.10', '224.0.0.1', '0.0.0.0', '::1', 'fe80::1',
                   'fd00::1', '2001:db8::1', '::ffff:10.0.0.5'):
            self.assertFalse(ii.is_public(ip), ip)
        for ip in ('1.1.1.1', '9.9.9.9', '2606:4700:4700::1111'):
            self.assertTrue(ii.is_public(ip), ip)


class TargetTests(unittest.TestCase):

    def test_addresses_ranges_and_repeats(self):
        addresses, warnings = ii.parse_targets(['203.0.113.10', '::ffff:198.51.100.7', '203.0.113.10',
                                                '192.0.2.0/30', '192.0.2.8/31', '192.0.2.16/32',
                                                '2001:DB8::/126'])
        self.assertEqual(addresses, ['203.0.113.10', '198.51.100.7', '192.0.2.1', '192.0.2.2', '192.0.2.8',
                                     '192.0.2.9', '192.0.2.16', '2001:db8::', '2001:db8::1', '2001:db8::2',
                                     '2001:db8::3'])
        self.assertEqual(warnings, [])

    def test_a_range_over_the_cap_is_refused_before_it_is_expanded(self):
        addresses, _ = ii.parse_targets(['203.0.113.0/22'])
        self.assertEqual(len(addresses), 1022)
        with self.assertRaisesRegex(ii.UsageError, '2048 addresses, more than --max 1024'):
            ii.parse_targets(['203.0.113.0/21'])
        with self.assertRaisesRegex(ii.UsageError, 'more than --max 4'):
            ii.parse_targets(['192.0.2.0/30', '198.51.100.0/30', '203.0.113.1'], max_addresses=4)
        with self.assertRaisesRegex(ii.UsageError, 'more than --max'):
            ii.parse_targets(['2001:db8::/64'])

    def test_files_and_stdin(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ips.txt')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write('# servers\n203.0.113.10, 203.0.113.11 ; 198.51.100.0/31\nweb01.example.com\n\n'
                             '2001:db8::5  # v6\n')
            addresses, warnings = ii.parse_targets([path])
            self.assertEqual(addresses, ['203.0.113.10', '203.0.113.11', '198.51.100.0', '198.51.100.1',
                                         '2001:db8::5'])
            self.assertEqual(len(warnings), 1)
            self.assertIn('line 3: web01.example.com is not an address', warnings[0])
        addresses, _ = ii.parse_targets(['-'], stdin=io.StringIO('192.0.2.1\n192.0.2.2\n'))
        self.assertEqual(addresses, ['192.0.2.1', '192.0.2.2'])
        with self.assertRaisesRegex(ii.UsageError, 'not an address, a CIDR range or a file'):
            ii.parse_targets(['www.example.com'])


# ============================================================================ certificates

class CertificateTests(unittest.TestCase):

    def test_names_issuer_expiry_and_fingerprint(self):
        der = der_of('rsa_multi_san')
        facts = ii.parse_certificate(der)
        self.assertEqual(facts.subject_cn, 'www.example-test.com.tr')
        self.assertEqual(facts.names(), ['example-test.com.tr', 'www.example-test.com.tr', 'api.example-test.com.tr',
                                         '*.cdn.example-test.com.tr', 'xn--mnchen-3ya.example-test.com.tr'])
        self.assertTrue(facts.issuer)
        self.assertRegex(facts.not_after or '', r'^\d{4}-\d{2}-\d{2}$')
        import hashlib
        self.assertEqual(facts.sha256, hashlib.sha256(der).hexdigest())

    def test_a_certificate_without_sans_names_its_cn(self):
        self.assertEqual(ii.parse_certificate(der_of('cn_only')).names(), ['legacy.example.org'])

    def test_not_a_certificate(self):
        for junk in (b'', b'\x30\x03\x02\x01', b'not der at all', der_of('cn_only')[:40]):
            with self.assertRaises(ValueError):
                ii.parse_certificate(junk)


# ============================================================================ the sources' answers

class ParserTests(unittest.TestCase):

    def test_hackertarget(self):
        result = ii.parse_hackertarget(b'www.example.com\nAPI.example.net\n\nnot a name\n')
        self.assertEqual((result.status, [h.name for h in result.hits]), (ii.OK, ['api.example.net', 'www.example.com']))
        self.assertEqual(ii.parse_hackertarget(b'API count exceeded - Increase Quota with Membership').status,
                         ii.RATE_LIMITED)
        failed = ii.parse_hackertarget(b'error check your search parameter')
        self.assertEqual((failed.status, failed.detail), (ii.ERROR, 'error check your search parameter'))
        self.assertEqual((ii.parse_hackertarget(b'No DNS A records found for 203.0.113.10').status,
                          ii.parse_hackertarget(b'').status), (ii.OK, ii.OK))
        self.assertEqual(ii.parse_hackertarget(b'<html>?</html>').status, ii.ERROR)

    def test_otx_merges_the_rows_of_a_name(self):
        result = ii.parse_otx(json.dumps(OTX_BODY).encode())
        self.assertEqual([(h.name, h.first, h.last) for h in result.hits],
                         [('old.example.org', '2020-07-08', '2021-05-06'),
                          ('www.example.com', '2018-01-02', '2024-05-06')])
        self.assertFalse(result.truncated)
        more = ii.parse_otx(json.dumps(dict(OTX_BODY, count=900)).encode())
        self.assertEqual((more.total, more.truncated), (900, True))
        with self.assertRaises(ValueError):
            ii.parse_otx(b'{"detail": "not found"}')

    def test_robtex_ndjson_in_epoch_seconds(self):
        result = ii.parse_robtex((ROBTEX_BODY + 'garbage\n').encode())
        self.assertEqual([(h.name, h.first, h.last) for h in result.hits],
                         [('api.example.net', '2020-09-13', '2020-09-13'),
                          ('www.example.com', '2017-07-14', '2026-09-21')])
        self.assertEqual(ii.parse_robtex(b'').hits, [])
        with self.assertRaises(ValueError):
            ii.parse_robtex(b'<html>busy</html>')

    def test_internetdb_names_and_intel(self):
        body = {'cpes': ['cpe:/a:example:web'], 'hostnames': ['www.example.com', 'example.com'],
                'ip': '203.0.113.10', 'ports': [80, 443], 'tags': ['cdn'], 'vulns': ['CVE-2026-0001']}
        result = ii.parse_internetdb(json.dumps(body).encode())
        self.assertEqual([h.name for h in result.hits], ['example.com', 'www.example.com'])
        self.assertEqual(result.intel, {'ports': [80, 443], 'tags': ['cdn'], 'vulns': ['CVE-2026-0001'],
                                        'cpes': ['cpe:/a:example:web']})

    def test_mnemonic_names_are_the_query_of_an_address_and_the_answer_of_a_ptr(self):
        result = ii.parse_mnemonic(json.dumps(MNEMONIC_BODY).encode())
        self.assertEqual([(h.name, h.first, h.last) for h in result.hits],
                         [('host.example.net', '2020-09-13', '2023-11-14'),
                          ('mail.example.com', '2018-06-07', '2024-10-27')])
        self.assertFalse(result.truncated)
        more = ii.parse_mnemonic(json.dumps(dict(MNEMONIC_BODY, count=1500)).encode())
        self.assertTrue(more.truncated)
        failed = ii.parse_mnemonic(json.dumps(dict(MNEMONIC_BODY, responseCode=503,
                                                   messages=[{'message': 'busy'}])).encode())
        self.assertEqual((failed.status, failed.detail), (ii.ERROR, 'responseCode 503: busy'))

    def test_key_sources(self):
        st = ii.parse_securitytrails(json.dumps({'records': [{'hostname': 'www.example.com'}, {'hostname': 'x'}],
                                                 'record_count': 120}).encode())
        self.assertEqual(([h.name for h in st.hits], st.total, st.truncated), (['www.example.com'], 120, True))
        vt = ii.parse_virustotal(json.dumps({'data': [{'attributes': {'host_name': 'www.example.com',
                                                                      'date': 1790000000}}],
                                             'links': {'next': 'https://www.virustotal.com/next'}}).encode())
        self.assertEqual(([(h.name, h.last) for h in vt.hits], vt.truncated), ([('www.example.com', '2026-09-21')], True))
        shodan = ii.parse_shodan(json.dumps({'hostnames': ['www.example.com'], 'domains': ['example.com'],
                                             'last_update': '2026-10-01T10:00:00.000000'}).encode())
        self.assertEqual([(h.name, h.last) for h in shodan.hits], [('www.example.com', '2026-10-01')])
        censys = ii.parse_censys(json.dumps({'code': 200, 'result': {'names': ['api.example.net'],
                                                                      'links': {'next': ''}}}).encode())
        self.assertEqual(([h.name for h in censys.hits], censys.truncated), (['api.example.net'], False))
        viewdns = ii.parse_viewdns(json.dumps({'query': {'tool': 'reverseip_PRO', 'host': '203.0.113.10'},
                                               'response': {'domain_count': '2', 'total_pages': '1',
                                                            'domains': [{'name': 'example.org',
                                                                         'last_resolved': '2026-01-02'},
                                                                        'www.example.org']}}).encode())
        self.assertEqual(([(h.name, h.last) for h in viewdns.hits], viewdns.total),
                         ([('example.org', '2026-01-02'), ('www.example.org', None)], 2))
        refused = ii.parse_viewdns(b'{"success": false, "error": {"code": 401, "message": "Invalid API key"}}')
        self.assertEqual((refused.status, refused.detail), (ii.ERROR, 'Invalid API key'))
        whois = ii.parse_whoisxml(json.dumps({'current_page': '0', 'size': 1, 'result': [
            {'name': 'example.net', 'first_seen': 1500000000, 'last_visit': 1790000000}]}).encode())
        self.assertEqual([(h.name, h.first, h.last) for h in whois.hits], [('example.net', '2017-07-14', '2026-09-21')])
        self.assertEqual(ii.parse_whoisxml(b'{"code": 403, "messages": "Access restricted"}').status, ii.ERROR)
        netlas = ii.parse_netlas(json.dumps({'items': [{'data': {'domain': 'www.example.net', 'a': ['203.0.113.10'],
                                                                 '@timestamp': '2026-09-27T21:35:09.782Z'}}]}).encode())
        self.assertEqual([(h.name, h.last) for h in netlas.hits], [('www.example.net', '2026-09-27')])

    def test_dates(self):
        self.assertEqual(ii._day('2026-10-08T08:33:08'), '2026-10-08')
        self.assertEqual(ii._day(1790000000), '2026-09-21')
        self.assertEqual(ii._day(1790000000000), '2026-09-21')
        self.assertEqual(ii._day('1790000000'), '2026-09-21')
        for nothing in (None, '', 'yesterday', True, -5, 10 ** 15):
            self.assertIsNone(ii._day(nothing), nothing)


# ============================================================================ asking a source

def source(source_id: str) -> Any:
    return next(s for s in ii.SOURCES if s.id == source_id)


def by_id(rep: Any, source_id: str) -> Any:
    return next(s for s in rep.sources if s.source == source_id)


KEYS = {'SECURITYTRAILS_API_KEY': 'st-key-0001', 'VT_API_KEY': 'vt-key-0002', 'SHODAN_API_KEY': 'sh+key/0003',
        'CENSYS_API_ID': 'censys-id-4', 'CENSYS_API_SECRET': 'censys-secret-5', 'VIEWDNS_API_KEY': 'vd-key-0006',
        'WHOISXML_API_KEY': 'wx-key-0007', 'NETLAS_API_KEY': 'nl-key-0008'}


class AskSourceTests(unittest.TestCase):

    def test_http_failures_become_statuses(self):
        cases = [((429, 'slow down'), ii.RATE_LIMITED, 'HTTP 429: slow down'),
                 ((402, '{"error": {"message": "quota"}}'), ii.RATE_LIMITED, 'HTTP 402: quota'),
                 ((401, '{"error": "no key"}'), ii.REFUSED, 'HTTP 401: no key'),
                 ((403, '<html>forbidden</html>'), ii.REFUSED, 'HTTP 403'),
                 ((500, 'oops'), ii.ERROR, 'HTTP 500: oops'),
                 ((301, ''), ii.ERROR, 'HTTP 301 (a redirect; not followed)'),
                 ((200, 'not json'), ii.ERROR, 'an answer that could not be read'),
                 (ii.HttpFailure('timeout', 'no answer in 10 s'), ii.TIMEOUT, 'no answer in 10 s'),
                 (ii.HttpFailure('network', 'Connection reset by peer'), ii.ERROR, 'Connection reset by peer')]
        for answer, status, detail in cases:
            http = FakeHttp([('https://otx.alienvault.com/', answer)])
            result = ii.ask_source(source('otx'), '203.0.113.10', {}, http, 5)
            self.assertEqual(result.status, status, answer)
            self.assertTrue(result.detail.startswith(detail), (answer, result.detail))
        http = FakeHttp([('https://internetdb.shodan.io/', (404, '{"detail": "No information available"}'))])
        self.assertEqual(ii.ask_source(source('internetdb'), '203.0.113.10', {}, http).status, ii.OK)

    def test_the_urls_of_the_free_sources(self):
        http = FakeHttp([('https://', (200, '{}'))])
        for sid in ('hackertarget', 'otx', 'robtex', 'internetdb', 'mnemonic'):
            ii.ask_source(source(sid), '203.0.113.10', {}, http)
        ii.ask_source(source('otx'), '2001:db8::5', {}, http)
        self.assertEqual(http.urls(), [
            'https://api.hackertarget.com/reverseiplookup/?q=203.0.113.10',
            'https://otx.alienvault.com/api/v1/indicators/IPv4/203.0.113.10/passive_dns',
            'https://freeapi.robtex.com/pdns/reverse/203.0.113.10',
            'https://internetdb.shodan.io/203.0.113.10',
            'https://api.mnemonic.no/pdns/v3/203.0.113.10?limit=1000',
            'https://otx.alienvault.com/api/v1/indicators/IPv6/2001:db8::5/passive_dns'])
        self.assertTrue(all(not c[1] for c in http.calls), 'no headers of ours to a free source')

    def test_keys_go_where_each_service_documents_them(self):
        http = FakeHttp([('https://', (200, '{}'))])
        for sid in ('securitytrails', 'virustotal', 'shodan', 'censys', 'viewdns', 'whoisxml', 'netlas'):
            ii.ask_source(source(sid), '203.0.113.10', KEYS, http)
        calls = {url.split('/')[2]: (url, headers, data) for url, headers, data in http.calls}
        url, headers, data = calls['api.securitytrails.com']
        self.assertEqual((headers['APIKEY'], json.loads(data)), ('st-key-0001', {'filter': {'ipv4': '203.0.113.10'}}))
        self.assertEqual(calls['www.virustotal.com'][1], {'x-apikey': 'vt-key-0002'})
        self.assertIn('key=sh%2Bkey%2F0003', calls['api.shodan.io'][0])
        import base64
        self.assertEqual(calls['search.censys.io'][1]['Authorization'],
                         'Basic ' + base64.b64encode(b'censys-id-4:censys-secret-5').decode())
        self.assertIn('apikey=vd-key-0006', calls['api.viewdns.info'][0])
        self.assertIn('apiKey=wx-key-0007', calls['reverse-ip.whoisxmlapi.com'][0])
        self.assertEqual(calls['app.netlas.io'][1], {'X-API-Key': 'nl-key-0008'})
        self.assertIn('q=a%3A203.0.113.10', calls['app.netlas.io'][0])
        ii.ask_source(source('securitytrails'), '2001:db8::5', KEYS, http)
        self.assertEqual(json.loads(http.calls[-1][2]), {'filter': {'ipv6': '2001:db8::5'}})

    def test_a_key_a_service_echoes_never_reaches_the_status(self):
        for sid, body in (('virustotal', '{"error": {"message": "key vt-key-0002 is wrong"}}'),
                          ('shodan', 'bad key sh%2Bkey%2F0003'), ('viewdns', 'bad key vd-key-0006')):
            http = FakeHttp([('https://', (401, body))])
            result = ii.ask_source(source(sid), '203.0.113.10', KEYS, http)
            self.assertEqual(result.status, ii.REFUSED)
            self.assertIn('[key]', result.detail)
            for secret in KEYS.values():
                self.assertNotIn(secret, result.detail)
            self.assertNotIn('sh%2Bkey', result.detail)


# ============================================================================ the run

def run(addresses: Sequence[str], **options: Any) -> Any:
    options.setdefault('tls', False)
    options.setdefault('ptr_lookup', no_ptr)
    options.setdefault('forward_lookup', resolver({}))
    options.setdefault('public', doc_public)
    options.setdefault('pace', False)
    options.setdefault('timeout', 5)
    return ii.run_domains(addresses, **options)


class RunTests(unittest.TestCase):

    def test_a_private_address_goes_to_no_third_party(self):
        http = FakeHttp([])
        report = run(['10.0.0.5', '127.0.0.1', '192.0.2.10'], sources=ii.SOURCES, keys=KEYS, http=http,
                     public=ii.is_public, ptr_lookup=resolver({'10.0.0.5': ['web01.corp.example.com']}))
        self.assertEqual(http.calls, [])
        for rep in report.addresses:
            self.assertFalse(rep.public)
            third = [s for s in rep.sources if s.source not in ii.LOCAL_SOURCES]
            self.assertEqual({(s.status, s.asked) for s in third}, {(ii.SKIPPED, False)})
        self.assertEqual([r.name for r in report.addresses[0].names], ['web01.corp.example.com'])
        text = ii.render_text(report)
        self.assertIn('a private or reserved address: TLS and PTR only, nothing sent to a third party', text)
        self.assertNotIn('SKIPPED', text)

    def test_an_ipv4_only_source_is_not_asked_for_ipv6(self):
        http = FakeHttp([('https://otx.alienvault.com/', (200, {'passive_dns': [], 'count': 0}))])
        report = run(['2001:db8::5'], sources=[source('hackertarget'), source('otx')], http=http)
        statuses = {s.source: (s.status, s.detail) for s in report.addresses[0].sources}
        self.assertEqual(statuses['hackertarget'], (ii.SKIPPED, 'IPv4 only'))
        self.assertEqual(statuses['otx'][0], ii.OK)
        self.assertEqual(len(http.calls), 1)

    def test_a_source_that_rate_limits_is_not_asked_again_in_the_run(self):
        http = FakeHttp([('https://api.hackertarget.com/', (200, 'API count exceeded - Increase Quota'))])
        report = run(['203.0.113.10', '203.0.113.11', '203.0.113.12'], sources=[source('hackertarget')],
                     http=http, workers=1)
        self.assertEqual(len(http.calls), 1)
        results = [by_id(rep, 'hackertarget') for rep in report.addresses]
        self.assertEqual([r.status for r in results], [ii.RATE_LIMITED] * 3)
        self.assertEqual([r.asked for r in results], [True, False, False])
        self.assertIn('not asked: it answered RATE_LIMITED for 203.0.113.10', results[1].detail)
        self.assertEqual(len(report.failures()), 3)

    def test_sources_are_paced(self):
        times = []  # type: List[float]

        def stamp(url: str) -> Any:
            times.append(time.monotonic())
            return 200, 'www.example.com'

        http = FakeHttp([('https://api.hackertarget.com/', stamp)])
        fast = ii.Source('hackertarget', 'HackerTarget', (), False, 0.2, source('hackertarget').request,
                         ii.parse_hackertarget)
        run(['203.0.113.10', '203.0.113.11', '203.0.113.12'], sources=[fast], http=http, pace=True, workers=3)
        gaps = [b - a for a, b in zip(times, times[1:])]
        self.assertEqual(len(times), 3)
        self.assertTrue(all(gap >= 0.15 for gap in gaps), gaps)

    def test_names_are_merged_and_checked_where_they_point_now(self):
        http = FakeHttp([('https://otx.alienvault.com/', (200, OTX_BODY)),
                         ('https://freeapi.robtex.com/', (200, ROBTEX_BODY)),
                         ('https://api.mnemonic.no/', (200, MNEMONIC_BODY))])
        forward = resolver({'www.example.com': ['203.0.113.10', '2001:db8::10'], 'old.example.org': ['198.51.100.7'],
                            'api.example.net': [], 'mail.example.com': ii.LookupFailure('temporary failure'),
                            'host.example.net': ['203.0.113.10']})
        report = run(['203.0.113.10'], sources=[source('otx'), source('robtex'), source('mnemonic')], http=http,
                     forward_lookup=forward, ptr_lookup=resolver({'203.0.113.10': ['host.example.net']}))
        rows = {r.name: r for r in report.addresses[0].names}
        www = rows['www.example.com']
        self.assertEqual((www.status, www.sources, www.first_seen, www.last_seen),
                         (ii.HERE, ['otx', 'robtex'], '2017-07-14', '2026-09-21'))
        self.assertEqual((rows['old.example.org'].status, rows['old.example.org'].resolves_to),
                         (ii.MOVED, ['198.51.100.7']))
        self.assertEqual(rows['api.example.net'].status, ii.NO_ADDRESS)
        self.assertEqual((rows['mail.example.com'].status, rows['mail.example.com'].detail),
                         (ii.LOOKUP_ERROR, 'temporary failure'))
        self.assertEqual((rows['host.example.net'].status, rows['host.example.net'].sources),
                         (ii.HERE, ['ptr', 'mnemonic']))
        self.assertNotIn('alias.example.com', rows)
        self.assertEqual([r.status for r in report.addresses[0].names],
                         [ii.HERE, ii.HERE, ii.MOVED, ii.NO_ADDRESS, ii.LOOKUP_ERROR])
        unchecked = run(['203.0.113.10'], sources=[source('otx')], http=http, verify=False,
                        forward_lookup=resolver({'www.example.com': AssertionError('no lookups')}))
        self.assertEqual({r.status for r in unchecked.addresses[0].names}, {ii.UNCHECKED})

    def test_tls_without_sni_then_with_the_names_found(self):
        server = TlsServer('rsa_multi_san', rules=[('wild.example.net', 'cli_public_wild')])
        try:
            http = FakeHttp([('https://otx.alienvault.com/', (200, {'passive_dns': [
                {'hostname': 'x.wild.example.net', 'first': '2025-01-01', 'last': '2026-01-01'},
                {'hostname': 'gone.example.org', 'first': '2020-01-01', 'last': '2021-01-01'}], 'count': 2}))])
            forward = resolver({'www.example-test.com.tr': ['127.0.0.1'], 'x.wild.example.net': ['198.51.100.7']})
            report = run(['127.0.0.1'], tls=True, ports=[server.port], sources=[source('otx')], http=http,
                         forward_lookup=forward, public=lambda ip: True, sni_max=8)
        finally:
            server.close()
        rep = report.addresses[0]
        self.assertEqual([(p.port, p.state) for p in rep.ports], [(server.port, ii.PORT_OK)])
        self.assertIn(None, server.seen)
        self.assertIn('www.example-test.com.tr', server.seen)
        self.assertIn('x.wild.example.net', server.seen)
        self.assertNotIn('*.cdn.example-test.com.tr', server.seen)
        self.assertLessEqual(len([s for s in server.seen if s]), 8)
        subjects = sorted(c.facts.subject_cn for c in rep.certificates)
        self.assertEqual(subjects, ['*.wild.example.net', 'www.example-test.com.tr'])
        rows = {r.name: r for r in rep.names}
        self.assertEqual((rows['x.wild.example.net'].tls, rows['x.wild.example.net'].status,
                          rows['x.wild.example.net'].sources), (ii.TLS_SNI, ii.MOVED, ['tls', 'otx']))
        self.assertEqual((rows['www.example-test.com.tr'].tls, rows['www.example-test.com.tr'].status),
                         (ii.TLS_SNI, ii.HERE))
        self.assertEqual((rows['*.cdn.example-test.com.tr'].status, rows['*.cdn.example-test.com.tr'].tls),
                         (ii.WILDCARD, ii.TLS_CERT))
        self.assertEqual((rows['gone.example.org'].tls, rows['gone.example.org'].status), (None, ii.NO_ADDRESS))
        self.assertEqual(rep.names[0].name, 'www.example-test.com.tr')
        self.assertEqual(rep.sources[0].source, 'tls')
        self.assertEqual(rep.sources[0].status, ii.OK)

    def test_a_closed_port_and_a_server_that_is_not_tls(self):
        plain = PlainServer()
        sock = socket.socket()
        sock.bind(('127.0.0.1', 0))
        closed_port = sock.getsockname()[1]
        sock.close()
        try:
            report = run(['127.0.0.1'], tls=True, ports=[plain.port, closed_port], sni_max=4)
        finally:
            plain.close()
        rep = report.addresses[0]
        self.assertEqual([(p.port, p.state) for p in rep.ports],
                         [(plain.port, ii.PORT_TLS_ERROR), (closed_port, ii.PORT_CLOSED)])
        self.assertEqual(rep.certificates, [])
        self.assertEqual(rep.sources[0].status, ii.OK)
        self.assertIn('%d: closed' % closed_port, rep.sources[0].detail)
        timed_out = run(['127.0.0.1'], tls=True, ports=[443],
                        handshake=lambda ip, port, sni, timeout: (ii.PORT_TIMEOUT, None, 'no answer in 5 s'))
        self.assertEqual(timed_out.addresses[0].sources[0].status, ii.TIMEOUT)


# ============================================================================ output

class OutputTests(unittest.TestCase):

    def test_csv_cells_are_spreadsheet_safe(self):
        self.assertEqual(ii.csv_cell('=HYPERLINK("x")'), '\'=HYPERLINK("x")')
        self.assertEqual(ii.csv_cell('-1+2'), "'-1+2")
        self.assertEqual(ii.csv_cell('a\x1b[31mb‮'), 'a\\x1b[31mb\\u202e')
        self.assertEqual((ii.csv_cell(443), ii.csv_cell(None)), (443, ''))

    def test_reports(self):
        http = FakeHttp([('https://otx.alienvault.com/', (200, OTX_BODY)),
                         ('https://freeapi.robtex.com/', (429, '=cmd|rate limited'))])
        report = run(['203.0.113.10', '203.0.113.99'], sources=[source('otx'), source('robtex')], http=http,
                     forward_lookup=resolver({'www.example.com': ['203.0.113.10']}), workers=1)
        doc = ii.report_to_dict(report)
        self.assertEqual(doc['schema'], 'domainscope.ip-intel/1')
        first = doc['addresses'][0]
        self.assertEqual([n['name'] for n in first['names']], ['www.example.com', 'old.example.org'])
        self.assertEqual(first['names'][0]['firstSeen'], '2018-01-02')
        self.assertEqual([(s['id'], s['status']) for s in first['sources']],
                         [('ptr', 'OK'), ('otx', 'OK'), ('robtex', 'RATE_LIMITED')])
        self.assertEqual(doc['summary']['sourceFailures'], 2)
        rows = list(__import__('csv').reader(io.StringIO(ii.render_csv(report))))
        self.assertEqual(tuple(rows[0]), ii.CSV_COLUMNS)
        self.assertEqual(rows[1][:3], ['203.0.113.10', 'www.example.com', 'HERE'])
        self.assertEqual(rows[1][-1], 'robtex:RATE_LIMITED')
        text = ii.render_text(report)
        self.assertIn('robtex RATE_LIMITED (HTTP 429: =cmd|rate limited)', text)
        self.assertIn('Incomplete: 2 source lookups failed (robtex on 2 addresses)', text)
        self.assertIn('otx OK (2 names)', text)


# ============================================================================ the command line

def patched(http: Optional[FakeHttp] = None, forward: Optional[Callable[[str], List[str]]] = None,
            public: Callable[[str], bool] = doc_public) -> contextlib.ExitStack:
    stack = contextlib.ExitStack()
    stack.enter_context(mock.patch.object(ii, 'http_request', http or FakeHttp([])))
    stack.enter_context(mock.patch.object(ii, 'system_ptr', no_ptr))
    stack.enter_context(mock.patch.object(ii, 'system_forward', forward or resolver({})))
    stack.enter_context(mock.patch.object(ii, 'is_public', public))
    return stack


class CommandLineTests(unittest.TestCase):

    def test_tls_on_a_local_server_with_reports(self):
        server = TlsServer('rsa_multi_san')
        try:
            with tempfile.TemporaryDirectory() as tmp, environment(), \
                    patched(forward=resolver({'www.example-test.com.tr': ['127.0.0.1']})):
                csv_path = os.path.join(tmp, 'names.csv')
                code, out, err = run_main('domains', '127.0.0.1', '-p', str(server.port), '--json', '-',
                                          '--csv', csv_path, '-q')
                self.assertEqual(code, 0, err)
                doc = json.loads(out)
                names = {n['name']: n for n in doc['addresses'][0]['names']}
                self.assertEqual(names['www.example-test.com.tr']['status'], 'HERE')
                self.assertEqual(names['www.example-test.com.tr']['tls'], 'SNI')
                self.assertEqual(doc['options']['sources'], list(ii.SOURCE_IDS[:5]))
                self.assertEqual({s['status'] for s in doc['addresses'][0]['sources'][2:]}, {'SKIPPED'})
                with open(csv_path, encoding='utf-8-sig') as handle:
                    self.assertIn('127.0.0.1,www.example-test.com.tr,HERE', handle.read())
                code, out, err = run_main('domains', '127.0.0.1', '-p', str(server.port), '--sni-max', '0')
                self.assertEqual(code, 0, err)
                self.assertIn('TLS %d: www.example-test.com.tr' % server.port, out)
                self.assertIn('www.example-test.com.tr', out)
                self.assertIn('CERT', out)
                self.assertNotIn(' SNI ', out.split('NAME', 1)[1].split('sources:')[0])
        finally:
            server.close()

    def test_the_default_sources_and_the_switches(self):
        http = FakeHttp([('https://', (200, '{}'))])
        with environment(VT_API_KEY='vt-key-0002'), patched(http):
            code, out, err = run_main('domains', '203.0.113.10', '--no-tls', '--json', '-')
            self.assertEqual(code, 0, err)
            self.assertEqual(json.loads(out)['options']['sources'],
                             ['hackertarget', 'otx', 'robtex', 'internetdb', 'mnemonic', 'virustotal'])
            for switches, expected in ((['--no-passive'], ['virustotal']), (['--no-keys'], ii.SOURCE_IDS[:5]),
                                       (['--no-passive', '--no-keys'], []), (['--sources', 'otx,virustotal'],
                                                                             ['otx', 'virustotal'])):
                code, out, err = run_main('domains', '203.0.113.10', '--no-tls', '--json', '-', *switches)
                self.assertEqual((code, json.loads(out)['options']['sources']), (0, list(expected)), switches)

    def test_keys_are_never_printed(self):
        secret = 'vt-key-0002-secret'
        http = FakeHttp([('https://www.virustotal.com/', (401, '{"error": {"message": "bad key %s"}}' % secret))])
        with environment(VT_API_KEY=secret), patched(http), tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'r.json')
            code, out, err = run_main('domains', '203.0.113.10', '--no-tls', '--no-passive', '--json', path,
                                      '--fail-on-error')
            self.assertEqual(code, ii.EXIT_SOURCE_ERRORS)
            with open(path, encoding='utf-8') as handle:
                report = handle.read()
            for text in (out, err, report):
                self.assertNotIn(secret, text)
            self.assertIn('virustotal REFUSED (HTTP 401: bad key [key])', out)
            code, out, _ = run_main('sources')
            self.assertEqual(code, 0)
            self.assertIn('VT_API_KEY: set', out)
            self.assertIn('SHODAN_API_KEY: not set', out)
            self.assertNotIn(secret, out)

    def test_exit_codes(self):
        http = FakeHttp([('https://', ii.HttpFailure('timeout', 'no answer in 1 s'))])
        with environment(), patched(http):
            code, out, _ = run_main('domains', '203.0.113.10', '--no-tls', '--sources', 'otx')
            self.assertEqual(code, ii.EXIT_OK)
            self.assertIn('otx TIMEOUT (no answer in 1 s)', out)
            code, _, _ = run_main('domains', '203.0.113.10', '--no-tls', '--sources', 'otx', '--fail-on-error')
            self.assertEqual(code, ii.EXIT_SOURCE_ERRORS)
            with tempfile.TemporaryDirectory() as tmp:
                code, _, err = run_main('domains', '203.0.113.10', '--no-tls', '--no-passive', '--json', tmp)
                self.assertEqual(code, ii.EXIT_OUTPUT_ERROR, err)
                self.assertIn('cannot write', err)

    def test_usage_errors(self):
        with environment(), patched():
            for args, message in ((['domains', 'www.example.com'], 'not an address, a CIDR range or a file'),
                                  (['domains', '203.0.113.0/21'], 'more than --max 1024'),
                                  (['domains', '192.0.2.0/30', '--max', '1'], 'more than --max 1'),
                                  (['domains', '192.0.2.1', '-w', '0'], '--workers'),
                                  (['domains', '192.0.2.1', '--timeout', '0'], '--timeout'),
                                  (['domains', '192.0.2.1', '-p', '0'], '--ports'),
                                  (['domains', '192.0.2.1', '--json', '-', '--csv', '-'], 'cannot both'),
                                  (['domains', '192.0.2.1', '--sources', 'otx,nope'], 'unknown source nope'),
                                  (['domains', '192.0.2.1', '--sources', 'censys'],
                                   'censys needs CENSYS_API_ID and CENSYS_API_SECRET')):
                code, _, err = run_main(*args)
                self.assertEqual(code, ii.EXIT_USAGE, args)
                self.assertIn(message, err, args)
            self.assertEqual(run_main()[0], ii.EXIT_USAGE)
            self.assertEqual(run_main('domains')[0], ii.EXIT_USAGE)

    def test_stdin_targets_and_file_warnings(self):
        with environment(), patched():
            code, out, err = run_main('domains', '-', '--no-tls', '--no-passive', stdin='192.0.2.1\nnot-an-ip\n')
        self.assertEqual(code, 0, err)
        self.assertIn('warning: stdin line 2: not-an-ip is not an address', err)
        self.assertIn('192.0.2.1', out)
        self.assertIn('no names', out)

    def test_help_and_version(self):
        code, out, _ = run_main('--help')
        self.assertEqual(code, 0)
        for text in ('domains', 'sources', 'HERE', 'MOVED', 'NO_ADDRESS', 'Türkçe', 'VT_API_KEY'):
            self.assertIn(text, out)
        code, out, _ = run_main('domains', '--help')
        self.assertEqual(code, 0)
        self.assertIn('--no-passive', out)
        code, out, _ = run_main('--version')
        self.assertEqual((code, out.strip()), (0, 'ip_intel.py 1.0.0'))
        for line in ii.EPILOG.splitlines():
            self.assertLessEqual(len(line), 100, line)
        self.assertNotIn('’', ii.EPILOG.split('Türkçe')[1])


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
        stdlib = {'__future__', 'argparse', 'base64', 'csv', 'hashlib', 'io', 'ipaddress', 'json', 'os', 're',
                  'socket', 'ssl', 'sys', 'threading', 'time', 'concurrent.futures', 'dataclasses', 'datetime',
                  'typing', 'urllib.error', 'urllib.parse', 'urllib.request'}
        self.assertLessEqual(imports, stdlib, imports - stdlib)


if __name__ == '__main__':
    unittest.main()
