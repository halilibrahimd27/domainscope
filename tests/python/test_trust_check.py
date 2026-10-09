"""The trust check (stdlib unittest): after the scan, one verifying handshake per certificate
served for a name - and per chain sent with it, where Python reads it (3.10+) - against this
machine's trust store or the CAs of --cafile; certTrusted / trustDetail in the JSON, the
cert_trusted / trust_detail columns of the CSV and of --estate (with the certificate flagged
untrusted), UNTRUSTED / TRUSTED against --baseline (PagerDuty: critical), and the summary's
words, "untrusted (Windows store may be incomplete)" on Windows without --cafile.

The scans run on a fake network with a fake verifier (run_scan's verify_fn); the last class
makes real handshakes with a TLS server on 127.0.0.1 serving tests/fixtures certificates under
tests/fixtures/ca.pem (antivirus software that inspects local TLS can break those on a
developer's machine; CI runs them).

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import csv
import io
import os
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple
from unittest import mock

from test_ssl_origin_scan import (CN_ONLY_DER, EC_DER, FIXTURES, RSA_DER, WILD_OLD, FakeNetwork, TlsServer,
                                  fixture_cert, run_main, sos)

WWW = 'www.example-test.com.tr'
WILD = 'a.wild.example.net'
NOW = datetime(2026, 10, 9, 3, 0, 0, tzinfo=timezone.utc)
CODE20 = sos.trust_detail(20)


class Verifier:
    """A fake ``verify_fn``: the verdict by (ip, name), else by name, else ``default``; calls kept."""

    def __init__(self, verdicts: Optional[Dict[object, object]] = None,
                 default: Tuple[Optional[bool], str] = (True, '')) -> None:
        self.verdicts = verdicts or {}
        self.default = default
        self.calls = []  # type: List[Tuple[str, int, str, str, str]]
        self.lock = threading.Lock()

    def __call__(self, ip: str, port: int, protocol: str, name: str, timeout: float,
                 cert: sos.CertInfo) -> Tuple[Optional[bool], str]:
        with self.lock:
            self.calls.append((ip, port, protocol, name, cert.sha256))
        verdict = self.verdicts.get((ip, name), self.verdicts.get(name, self.default))
        if isinstance(verdict, BaseException):
            raise verdict
        return verdict  # type: ignore[return-value]


def fleet(tls: Dict[str, object], verify: Optional[Verifier], names=(WWW, WILD), ports=(443,),
          servers=None, **kwargs) -> sos.ScanReport:
    """Two servers on the fake network (``tls``: ip -> behaviour by SNI), checked with ``verify``."""
    network = FakeNetwork({}, tls)
    servers = servers or [sos.Server('web01', ['192.0.2.10']), sos.Server('web02', ['192.0.2.11'])]

    def tls_fn(ip: str, port: int, sni: Optional[str], timeout: float, protocol: Optional[str] = None):
        return network.tls_fn(ip, port, sni, timeout)  # STARTTLS or not: the same answers

    with mock.patch.object(sos, '_utcnow', return_value=NOW):
        return sos.run_scan(servers, sos.build_probe_names(list(names)), list(ports), timeout=1, workers=4,
                            connect_fn=network.connect_fn, tls_fn=tls_fn, verify_fn=verify, **kwargs)


def sent_alone(der: bytes) -> sos.TlsResult:
    """A handshake whose server sent ``der`` with another chain than the others (Python 3.10+ tells)."""
    return sos.TlsResult(der=der, version='TLSv1.3', chain_sha256='a' * 64)


def serve(**by_sni):
    """A TLS behaviour: ``default`` for the no-SNI handshake, the names, ``other`` for the rest."""
    def pick(sni):
        return by_sni.get('default' if sni is None else sni, by_sni.get('other', CN_ONLY_DER))
    return pick


def rows_by(report: sos.ScanReport) -> Dict[Tuple[str, Optional[str]], sos.ProbeResult]:
    return {(row.ip, row.name): row for row in report.results}


class WordsTests(unittest.TestCase):

    def test_verify_codes_in_words(self):
        self.assertEqual(sos.trust_detail(20), 'missing intermediate or private CA (code 20)')
        self.assertEqual([sos.trust_detail(code) for code in (21, 18, 19, 10, 9, 62)], [
            'missing intermediate (code 21)', 'self-signed (code 18)', 'a root this machine does not trust (code 19)',
            'expired (code 10)', 'not yet valid (code 9)', 'hostname mismatch (code 62)'])
        self.assertEqual(sos.trust_detail(23, 'certificate revoked'), 'certificate revoked (code 23)')
        self.assertEqual(sos.trust_detail(None, 'odd answer'), 'odd answer')
        self.assertEqual(sos.trust_detail(None), 'not trusted')

    def test_the_windows_note_and_the_store(self):
        self.assertEqual(sos.untrusted_text(CODE20, 'windows'), 'untrusted (Windows store may be incomplete): ' + CODE20)
        self.assertEqual(sos.untrusted_text(CODE20, 'system'), 'untrusted: ' + CODE20)
        self.assertEqual(sos.untrusted_text('', 'cafile'), 'untrusted')
        with mock.patch.object(sos, '_IS_WINDOWS', True):
            self.assertEqual([sos.trust_store_name(None), sos.trust_store_name('ca.pem')], ['windows', 'cafile'])
        with mock.patch.object(sos, '_IS_WINDOWS', False):
            self.assertEqual(sos.trust_store_name(None), 'system')

    def test_a_chain_digest_tells_a_leaf_alone_from_a_leaf_with_its_intermediate(self):
        self.assertIsNone(sos.chain_digest(None))
        self.assertIsNone(sos.chain_digest([]))
        self.assertNotEqual(sos.chain_digest([RSA_DER]), sos.chain_digest([RSA_DER, EC_DER]))
        self.assertNotEqual(sos.chain_digest([b'ab']), sos.chain_digest([b'a', b'b']), 'each length counts')
        self.assertEqual(len(sos.chain_digest([RSA_DER])), 64)


class CheckTrustTests(unittest.TestCase):

    def test_once_per_certificate_chain_and_name_never_for_a_name_the_certificate_does_not_cover(self):
        verify = Verifier({WILD: (False, CODE20)})
        report = fleet({'192.0.2.10': serve(**{WWW: RSA_DER, WILD: EC_DER}),
                        '192.0.2.11': serve(**{WWW: RSA_DER, WILD: sos.TlsResult(status=sos.TLS_ERROR, error='alert')})}, verify)
        self.assertTrue(report.trust_checked)
        self.assertEqual(sorted((name, ip) for ip, _port, _proto, name, _sha in verify.calls),
                         [(WILD, '192.0.2.10'), (WWW, '192.0.2.10')], 'the same certificate for WWW on both: asked once')
        by = rows_by(report)
        self.assertEqual([by[('192.0.2.10', WWW)].trusted, by[('192.0.2.11', WWW)].trusted], [True, True])
        self.assertEqual((by[('192.0.2.10', WILD)].trusted, by[('192.0.2.10', WILD)].trust_detail), (False, CODE20))
        self.assertIsNone(by[('192.0.2.11', WILD)].trusted, 'a failed handshake has no verdict')
        self.assertTrue(all(row.trusted is None for row in report.results if row.probe == sos.PROBE_DEFAULT))
        # the default certificate covers neither name: NOT_HOSTED, never verified
        other = fleet({'192.0.2.10': serve(other=CN_ONLY_DER), '192.0.2.11': serve(other=CN_ONLY_DER)}, Verifier())
        self.assertTrue(all(row.trusted is None for row in other.results))

    def test_the_same_leaf_sent_with_another_chain_is_asked_again(self):
        alone = sos.TlsResult(der=RSA_DER, version='TLSv1.3', chain_sha256='a' * 64)
        full = sos.TlsResult(der=RSA_DER, version='TLSv1.3', chain_sha256='b' * 64)
        verify = Verifier({('192.0.2.11', WWW): (False, sos.trust_detail(21))})
        report = fleet({'192.0.2.10': serve(**{WWW: full}), '192.0.2.11': serve(**{WWW: alone})}, verify, names=(WWW,))
        self.assertEqual(sorted(ip for ip, *_rest in verify.calls), ['192.0.2.10', '192.0.2.11'])
        by = rows_by(report)
        self.assertEqual([by[('192.0.2.10', WWW)].trusted, by[('192.0.2.11', WWW)].trusted], [True, False])

    def test_a_verifier_that_fails_is_no_verdict_and_starttls_is_passed_on(self):
        report = fleet({'192.0.2.10': serve(**{WWW: RSA_DER}), '192.0.2.11': serve(**{WWW: RSA_DER})},
                       Verifier({WWW: OSError('connection reset')}), names=(WWW,))
        row = rows_by(report)[('192.0.2.10', WWW)]
        self.assertEqual((row.trusted, row.trust_detail), (None, 'connection reset'))
        verify = Verifier()
        fleet({'192.0.2.10': serve(**{WWW: RSA_DER}), '192.0.2.11': serve(**{WWW: RSA_DER})}, verify, names=(WWW,), ports=(25,))
        self.assertEqual({proto for _ip, _port, proto, _name, _sha in verify.calls}, {'smtp'})

    def test_an_injected_prober_without_a_verifier_checks_nothing(self):
        report = fleet({'192.0.2.10': serve(**{WWW: RSA_DER}), '192.0.2.11': serve(**{WWW: RSA_DER})}, None, names=(WWW,))
        self.assertFalse(report.trust_checked)
        doc = sos.report_to_dict(report)
        self.assertNotIn('trust', doc['options'])
        self.assertTrue(all('certTrusted' not in row for row in doc['results']))
        self.assertEqual(sos.render_csv(report).splitlines()[0].split(','), list(sos.CSV_COLUMNS))

    def test_the_json_the_csv_and_the_summary(self):
        report = fleet({'192.0.2.10': serve(**{WWW: RSA_DER, WILD: EC_DER}), '192.0.2.11': serve(**{WWW: RSA_DER, WILD: sent_alone(EC_DER)})},
                       Verifier({('192.0.2.11', WILD): (False, CODE20)}, default=(True, '')))
        doc = sos.report_to_dict(report)
        self.assertEqual(doc['options']['trust'], {'store': sos.trust_store_name(None), 'cafile': None})
        rows = {(r['ip'], r['name']): r for r in doc['results']}
        self.assertEqual((rows[('192.0.2.10', WWW)]['certTrusted'], rows[('192.0.2.10', WWW)]['trustDetail']), (True, None))
        self.assertEqual((rows[('192.0.2.11', WILD)]['certTrusted'], rows[('192.0.2.11', WILD)]['trustDetail']), (False, CODE20))
        self.assertTrue(all(r['certTrusted'] is None for r in doc['results'] if r['probe'] == 'default'))
        records = list(csv.DictReader(io.StringIO(sos.render_csv(report))))
        self.assertEqual(list(records[0])[-2:], list(sos.TRUST_CSV_COLUMNS), 'the trust columns come last')
        cells = {(r['ip'], r['name']): (r['cert_trusted'], r['trust_detail']) for r in records}
        self.assertEqual([cells[('192.0.2.10', WWW)], cells[('192.0.2.11', WILD)], cells[('192.0.2.10', '')]],
                         [('yes', ''), ('no', CODE20), ('', '')])
        for store, note in (('system', False), ('windows', True)):
            report.trust_store = store
            text = sos.render_summary(report, width=200)
            self.assertIn('untrusted%s: %s' % (' (Windows store may be incomplete)' if note else '', CODE20), text)
            self.assertIn('Not trusted by %s: 1 name on 1 endpoint' % ('the Windows trust store' if note else "this machine's trust store"), text)
            self.assertEqual('--cafile FILE checks against a CA bundle' in text, note)
        report.trust_store, report.cafile = 'cafile', 'bundle.pem'
        self.assertIn('Not trusted by the CAs of --cafile bundle.pem: 1 name on 1 endpoint', sos.render_summary(report, width=200))
        # every name trusted: nothing more to say
        fine = fleet({'192.0.2.10': serve(**{WWW: RSA_DER}), '192.0.2.11': serve(**{WWW: RSA_DER})}, Verifier(), names=(WWW,))
        self.assertNotIn('untrusted', sos.render_summary(fine, width=200))
        self.assertNotIn('Not trusted by', sos.render_summary(fine, width=200))


class BaselineTests(unittest.TestCase):
    """UNTRUSTED and TRUSTED against --baseline, PagerDuty's trigger and resolve."""

    def docs(self, *verdicts: Tuple[Optional[bool], str]) -> List[dict]:
        out = []
        for verdict in verdicts:
            report = fleet({'192.0.2.10': serve(**{WWW: RSA_DER}), '192.0.2.11': serve(**{WWW: RSA_DER})},
                           Verifier({('192.0.2.10', WWW): verdict}), names=(WWW,),
                           servers=[sos.Server('web01', ['192.0.2.10'])])
            out.append(sos.report_to_dict(report))
        return out

    def test_a_name_newly_untrusted_counts_trusted_again_too(self):
        trusted, untrusted = self.docs((True, ''), (False, CODE20))
        changes = sos.compare_reports(trusted, untrusted)
        self.assertEqual([(c['kind'], sos.change_tag(c), sos.counts_as_change(c)) for c in changes], [('untrusted', 'UNTRUSTED', True)])
        self.assertEqual(sos.change_text(changes[0]), 'web01 192.0.2.10:443 %s: NEEDS_UPDATE, not trusted by this machine: %s, serving %s'
                         % (WWW, CODE20, sos._cert_brief(changes[0]['after'])))
        back = sos.compare_reports(untrusted, trusted)
        self.assertEqual([(c['kind'], sos.change_tag(c)) for c in back], [('trusted', 'TRUSTED')])
        self.assertIn('trusted again (was: %s)' % CODE20, sos.change_text(back[0]))
        self.assertEqual(sos.compare_reports(untrusted, untrusted), [], 'said once')
        # no verdict before (a failed handshake): untrusted now counts
        unknown = self.docs((None, 'timed out'))[0]
        self.assertEqual([sos.change_tag(c) for c in sos.compare_reports(unknown, untrusted)], ['UNTRUSTED'])
        self.assertEqual(sos.compare_reports(untrusted, unknown), [], 'a verdict lost is no news')

    def test_runs_that_did_not_both_check_trust_compare_nothing_of_it(self):
        trusted, untrusted = self.docs((True, ''), (False, CODE20))
        older = dict(trusted, options={k: v for k, v in trusted['options'].items() if k != 'trust'},
                     results=[{k: v for k, v in r.items() if k not in ('certTrusted', 'trustDetail')} for r in trusted['results']])
        self.assertIsNone(sos.baseline_problem(older))
        self.assertEqual(sos.compare_reports(older, untrusted), [])
        info = sos.baseline_info(older, untrusted)
        self.assertEqual(info['trustCheckedIn'], 'this run')
        self.assertIn('Trust was checked in this run only: UNTRUSTED compares runs that both checked it.', sos.baseline_notes(info))
        self.assertNotIn('trustCheckedIn', sos.baseline_info(trusted, untrusted))
        bad = dict(untrusted, results=[dict(untrusted['results'][0], certTrusted='no')])
        self.assertIn('"certTrusted" that is not true, false or null', sos.baseline_problem(bad))

    def test_pagerduty_pages_it_critical_and_resolves_it_once_trusted_again(self):
        trusted, untrusted = self.docs((True, ''), (False, CODE20))
        monitor = sos.MonitorResult(changes=sos.order_changes(sos.compare_reports(trusted, untrusted)))
        plan = sos.pagerduty_plan(monitor, trusted, '2026-10-09T03:00:00Z', doc=untrusted)
        self.assertEqual([t['tag'] for t in plan['triggers']], ['UNTRUSTED'])
        _url, events = sos.pagerduty_events('https://events.pagerduty.com/v2/enqueue?routing_key=' + 'K' * 32, plan)
        self.assertEqual(events[0]['payload']['severity'], 'critical')
        opened = dict(untrusted, notify={'open': plan['open']})
        still = sos.pagerduty_plan(sos.MonitorResult(changes=[]), opened, None, doc=untrusted)
        self.assertEqual((still['resolves'], [k['tag'] for k in still['open']]), ([], ['UNTRUSTED']))
        fixed = sos.pagerduty_plan(sos.MonitorResult(changes=sos.order_changes(sos.compare_reports(untrusted, trusted))), opened, None, doc=trusted)
        self.assertEqual([e['tag'] for e in fixed['resolves']], ['UNTRUSTED'])
        self.assertEqual(fixed['open'], [])


class EstateTests(unittest.TestCase):

    def test_each_endpoint_says_whether_it_is_trusted_the_certificate_is_flagged_untrusted(self):
        report = fleet({'192.0.2.10': serve(**{WWW: RSA_DER, WILD: EC_DER}), '192.0.2.11': serve(**{WWW: RSA_DER, WILD: sent_alone(EC_DER)})},
                       Verifier({('192.0.2.11', WILD): (False, CODE20)}))
        report.trust_store = 'windows'
        estate = sos.estate_from_report(sos.report_to_dict(report), NOW)
        by_sha = {c['sha256']: c for c in estate['certificates']}
        ec = by_sha[fixture_cert('ec_wildcard.pem').sha256]
        self.assertIn('untrusted', ec['flags'])
        self.assertEqual({e['ip']: (e['trusted'], e['trustDetail']) for e in ec['endpoints']},
                         {'192.0.2.10': (True, None), '192.0.2.11': (False, CODE20)})
        rsa = by_sha[sos.parse_certificate(RSA_DER).sha256]
        self.assertNotIn('untrusted', rsa['flags'])
        cn = by_sha[fixture_cert('cn_only.pem').sha256]
        self.assertEqual({e['trusted'] for e in cn['endpoints']}, {None}, 'served without SNI only: not asked')
        text = sos.render_estate_csv(estate)
        header = text.splitlines()[0].split(',')
        self.assertEqual(header[-2:], list(sos.TRUST_CSV_COLUMNS))
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertIn(('192.0.2.11', 'no', CODE20), {(r['ip'], r['cert_trusted'], r['trust_detail']) for r in rows})
        summary = ' '.join(sos.render_estate(report, estate, width=200).split())
        self.assertIn('Not trusted by the Windows trust store: 1', summary)
        self.assertIn('missing intermediate or private CA (code 20) web02 192.0.2.11:443 (a.wild.example.net)', summary)
        self.assertIn('Windows store may be incomplete: --cafile FILE checks against a CA bundle', summary)
        # a report without the trust check: no verdict, no column, no section
        plain = fleet({'192.0.2.10': serve(**{WWW: RSA_DER}), '192.0.2.11': serve(**{WWW: RSA_DER})}, None, names=(WWW,))
        old = sos.estate_from_report(sos.report_to_dict(plain), NOW)
        self.assertFalse(any('trusted' in e for c in old['certificates'] for e in c['endpoints']))
        self.assertEqual(sos.estate_trust_columns(old), ())
        self.assertNotIn('Not trusted by', sos.render_estate(plain, old, width=200))


class CafileTests(unittest.TestCase):

    def test_a_cafile_that_cannot_be_read_stops_before_anything_is_sent(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty = os.path.join(tmp, 'empty.pem')
            with open(empty, 'w', encoding='ascii') as handle:
                handle.write('no certificate here\n')
            for path in (os.path.join(tmp, 'missing.pem'), empty):
                with mock.patch.object(sos, 'run_scan') as scan:
                    code, _out, err = run_main('-t', '192.0.2.10', '-n', WWW, '--cafile', path)
                self.assertEqual(code, 2, err)
                self.assertIn('--cafile: cannot read CA certificates from %s' % path, err)
                scan.assert_not_called()
            code, _out, err = run_main('--compare', '192.0.2.1', '192.0.2.2', '-n', WWW, '--cafile', os.path.join(tmp, 'missing.pem'))
            self.assertEqual(code, 2, err)

    def test_help_explains_the_trust_check(self):
        code, out, _err = run_main('--help')
        self.assertEqual(code, 0)
        text = ' '.join(out.split())
        for needle in ('--cafile FILE', 'untrusted (Windows store may be incomplete)', 'certTrusted', 'cert_trusted',
                       'UNTRUSTED', 'missing intermediate or private CA (20)'):
            self.assertIn(needle, text)


class LocalTrustTests(unittest.TestCase):
    """Real handshakes: tests/fixtures/rsa_multi_san under tests/fixtures/ca.pem on 127.0.0.1."""

    @classmethod
    def setUpClass(cls):
        cls.server = TlsServer('cn_only', WILD_OLD)

    @classmethod
    def tearDownClass(cls):
        cls.server.close()

    def scan(self, *extra: str) -> Tuple[int, dict, str]:
        import json  # noqa: PLC0415 - only here
        code, out, err = run_main('-t', '127.0.0.1:%d' % self.server.port, '-n', WWW, '--json', '-', '-q', *extra)
        return code, json.loads(out) if out.strip() else {}, err

    def test_the_store_does_not_trust_the_test_ca_cafile_and_private_ca_do(self):
        code, doc, err = self.scan()
        self.assertEqual(code, 0, err)
        row = next(r for r in doc['results'] if r['name'] == WWW)
        self.assertEqual(row['status'], 'NEEDS_UPDATE')
        self.assertIs(row['certTrusted'], False)
        self.assertIn('(code ', row['trustDetail'])
        code, doc, err = self.scan('--cafile', str(FIXTURES / 'ca.pem'))
        self.assertEqual(code, 0, err)
        row = next(r for r in doc['results'] if r['name'] == WWW)
        self.assertEqual((row['certTrusted'], row['trustDetail']), (True, None))
        self.assertEqual(doc['options']['trust'], {'store': 'cafile', 'cafile': 'ca.pem'})
        code, doc, err = self.scan('--private-ca', str(FIXTURES / 'ca.pem'))
        self.assertEqual(code, 0, err)
        row = next(r for r in doc['results'] if r['name'] == WWW)
        self.assertEqual((row['certTrusted'], row['trustDetail']), (True, 'issued by a --private-ca'))

    def test_another_name_is_a_hostname_mismatch(self):
        verify = sos.trust_verifier(str(FIXTURES / 'ca.pem'))
        cert = sos.parse_certificate(RSA_DER)
        self.assertEqual(verify('127.0.0.1', self.server.port, sos.PROTO_TLS, WWW, 3, cert), (True, ''))
        # routed to the same certificate, which does not carry the name
        trusted, detail = verify('127.0.0.1', self.server.port, sos.PROTO_TLS, 'mail.example-test.com.tr', 3, cert)
        self.assertEqual((trusted, detail), (False, 'hostname mismatch (code 62)'))


if __name__ == '__main__':
    unittest.main()
