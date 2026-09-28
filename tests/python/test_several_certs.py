"""--cert given several times: a renewal week of several certificates (stdlib unittest; no network).

An RSA + ECDSA pair, or several certificates renewed together, are checked in one run: every
file's names are probed, a server serving ANY of them is UPDATED, and the summary, the JSON and
the CSV name the --cert FILE it serves. With one --cert every report is exactly as before. The
web app builds this command in SSL Targets (Behind CDN and Verify) with one file per certificate.

Run from the repository root:
    python -m unittest discover -s tests/python -v
"""

from __future__ import annotations

import csv
import io
import os
import tempfile
import unittest
from typing import Dict, Optional, Tuple

from test_ssl_origin_scan import (EC_DER, FIXTURES, WILD_NEW, WILD_OLD, FakeNetwork, TlsServer,
                                  by_old_or_new, fixture_cert, read_json, run_main, sos)

RENEWED = fixture_cert('cli_renewed_wild.pem')   # *.wild.example.net, wild.example.net
RSA = fixture_cert('rsa_multi_san.pem')          # example-test.com.tr and its names
FILES = {RENEWED.sha256: 'certs/wild.pem', RSA.sha256: 'certs/tr.pem'}
NAMES = ['a.wild.example.net', 'www.example-test.com.tr']


def scan(new_certs, new_cert_files=None):
    """old: an old certificate for the wild names; new: both new certificates."""
    network = FakeNetwork({}, {'10.0.0.1': by_old_or_new(EC_DER),
                               '10.0.0.2': by_old_or_new(RENEWED.der)})
    servers = [sos.Server('old', ['10.0.0.1']), sos.Server('new', ['10.0.0.2'])]
    probes = sos.build_probe_names(NAMES + [h for c in new_certs for h in c.hostnames])
    return sos.run_scan(servers, probes, [443], new_certs=new_certs, timeout=1, workers=4,
                        connect_fn=network.connect_fn, tls_fn=network.tls_fn,
                        new_cert_files=new_cert_files)


def rows_of(report) -> Dict[Tuple[str, Optional[str]], object]:
    return {(r.server, r.name): r for r in report.results}


class SeveralCertsReportTests(unittest.TestCase):

    def test_any_new_certificate_is_updated_and_the_reports_name_it(self):
        report = scan([RENEWED, RSA], FILES)
        self.assertTrue(report.several_new_certs)
        rows = rows_of(report)
        self.assertEqual(rows[('new', 'a.wild.example.net')].status, sos.UPDATED)
        self.assertEqual(rows[('new', 'www.example-test.com.tr')].status, sos.UPDATED)
        self.assertEqual(rows[('old', 'www.example-test.com.tr')].status, sos.UPDATED)
        self.assertEqual(rows[('old', 'a.wild.example.net')].status, sos.NEEDS_UPDATE)
        self.assertEqual(report.new_cert_file(rows[('new', 'a.wild.example.net')].cert),
                         'certs/wild.pem')
        self.assertEqual(report.new_cert_file(rows[('old', 'www.example-test.com.tr')].cert),
                         'certs/tr.pem')
        self.assertIsNone(report.new_cert_file(rows[('old', 'a.wild.example.net')].cert))
        self.assertIsNone(report.new_cert_file(None))

        doc = sos.report_to_dict(report)
        self.assertEqual([c['file'] for c in doc['newCertificates']],
                         ['certs/wild.pem', 'certs/tr.pem'])
        by = {(r['server'], r['name']): r for r in doc['results']}
        self.assertEqual(by[('new', 'a.wild.example.net')]['newCertFile'], 'certs/wild.pem')
        self.assertEqual(by[('old', 'www.example-test.com.tr')]['newCertFile'], 'certs/tr.pem')
        self.assertIsNone(by[('old', 'a.wild.example.net')]['newCertFile'])
        self.assertIsNone(by[('new', None)]['newCertFile'])  # the no-SNI default certificate
        self.assertEqual(list(by[('new', 'a.wild.example.net')])[-1], 'newCertFile')

        text = sos.render_csv(report)
        records = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(text.splitlines()[0].split(','), list(sos.CSV_COLUMNS) + ['new_cert'])
        csv_by = {(r['server'], r['name']): r for r in records}
        self.assertEqual(csv_by[('new', 'a.wild.example.net')]['new_cert'], 'certs/wild.pem')
        self.assertEqual(csv_by[('old', 'a.wild.example.net')]['new_cert'], '')

        summary = ' '.join(sos.render_summary(report).split())  # the summary wraps long lines
        self.assertIn('New certificate (certs/wild.pem): ', summary)
        self.assertIn('New certificate (certs/tr.pem): ', summary)
        self.assertIn('(matches certs/wild.pem)', summary)
        self.assertIn('(matches certs/tr.pem)', summary)
        self.assertIn('Servers that need the new certificate: 1', summary)

    def test_one_new_certificate_reports_exactly_as_before(self):
        plain = scan([RENEWED])
        with_files = scan([RENEWED], {RENEWED.sha256: 'certs/wild.pem'})
        for report in (plain, with_files):
            self.assertFalse(report.several_new_certs)
            doc = sos.report_to_dict(report)
            self.assertNotIn('file', doc['newCertificates'][0])
            self.assertTrue(all('newCertFile' not in r for r in doc['results']))
            self.assertEqual(sos.render_csv(report).splitlines()[0].split(','),
                             list(sos.CSV_COLUMNS))
            summary = sos.render_summary(report)
            self.assertNotIn('matches', summary)
            self.assertIn('New certificate: ', summary)
        self.assertEqual(sos.render_summary(plain).split('\n')[1:],
                         sos.render_summary(with_files).split('\n')[1:])

    def test_several_certificates_without_file_names_still_scan(self):
        # library use: run_scan without new_cert_files - UPDATED as usual, no file to name
        report = scan([RENEWED, RSA])
        self.assertEqual(rows_of(report)[('new', 'a.wild.example.net')].status, sos.UPDATED)
        doc = sos.report_to_dict(report)
        self.assertEqual([c['file'] for c in doc['newCertificates']], [None, None])
        self.assertNotIn('matches', sos.render_summary(report))


class SeveralCertsCliTests(unittest.TestCase):
    """Real TLS handshakes against local servers, through main()."""

    @classmethod
    def setUpClass(cls):
        cls.old = TlsServer('cn_only', WILD_OLD)
        cls.new = TlsServer('cn_only', WILD_NEW)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.wild = str(FIXTURES / 'cli_renewed_wild.pem')
        cls.tr = str(FIXTURES / 'rsa_multi_san.pem')

    @classmethod
    def tearDownClass(cls):
        for server in (cls.old, cls.new):
            server.close()
        cls.tmp.cleanup()

    def run_scan(self, *certs: str):
        base = os.path.join(self.tmp.name, 'r%d' % len(os.listdir(self.tmp.name)))
        args = ['-t', 'old=127.0.0.1:%d' % self.old.port, 'new=127.0.0.1:%d' % self.new.port,
                '-n', *NAMES, '--timeout', '4', '--json', base + '.json', '--csv', base + '.csv']
        for cert in certs:
            args += ['--cert', cert]
        code, out, err = run_main(*args)
        with open(base + '.csv', encoding='utf-8-sig', newline='') as handle:
            records = list(csv.DictReader(handle))
        return code, out, err, read_json(base + '.json'), records

    def test_repeated_cert_names_the_file_each_server_serves(self):
        code, out, err, doc, records = self.run_scan(self.wild, self.tr)
        self.assertEqual(code, 0, err)
        by = {(r['server'], r['name']): r for r in doc['results']}
        self.assertEqual(by[('new', 'a.wild.example.net')]['status'], 'UPDATED')
        self.assertEqual(by[('new', 'a.wild.example.net')]['newCertFile'], self.wild)
        self.assertEqual(by[('old', 'a.wild.example.net')]['status'], 'NEEDS_UPDATE')
        self.assertIsNone(by[('old', 'a.wild.example.net')]['newCertFile'])
        self.assertEqual(by[('old', 'www.example-test.com.tr')]['status'], 'UPDATED')
        self.assertEqual(by[('old', 'www.example-test.com.tr')]['newCertFile'], self.tr)
        self.assertEqual([c['file'] for c in doc['newCertificates']], [self.wild, self.tr])
        self.assertEqual(set(records[0]), set(sos.CSV_COLUMNS) | {'new_cert'})
        self.assertIn(self.wild, {r['new_cert'] for r in records})
        self.assertIn('(matches %s)' % self.wild, ' '.join(out.split()))
        self.assertIn('Servers that need the new certificate: 1', out)

    def test_the_same_certificate_twice_is_one_certificate(self):
        code, out, err, doc, records = self.run_scan(self.wild, self.wild)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(doc['newCertificates']), 1)
        self.assertTrue(all('newCertFile' not in r for r in doc['results']))
        self.assertEqual(set(records[0]), set(sos.CSV_COLUMNS))
        self.assertNotIn('matches', out)

    def test_help_shows_the_renewal_week_example(self):
        code, out, _err = run_main('--help')
        self.assertEqual(code, 0)
        for needle in ('--cert a-rsa.pem --cert a-ecdsa.pem --cert b.pem', 'newCertFile',
                       'the reports name which', 'hangisi olduğunu'):
            self.assertIn(needle, ' '.join(out.split()))


if __name__ == '__main__':
    unittest.main()
