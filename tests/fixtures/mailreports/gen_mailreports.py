#!/usr/bin/env python3
"""Pack the mail report fixtures the way reporters send them (maintainers only).

The report bodies in src/ are hand-written after the real formats (a Google and a Microsoft
DMARC aggregate report, a DMARCbis-style one, a Google and a Microsoft TLS-RPT report) with
documentation data only: the reporters keep their organisation names, their contacts are under
example.org. This script packs them with Python's own zipfile and gzip modules, so
lib/zipread.js is tested against archives another implementation wrote:

  google.com!example.com!....zip        deflate, like Google's aggregate reports
  enterprise....!example.com!....xml.gz like Microsoft's
  ...!001.json.gz, microsoft.com!....json.gz   TLS-RPT (RFC 8460 asks for gzip)
  reports-2026-09.zip                   a mailbox export: the files above, the DMARCbis report
                                        stored (no compression), a notes.txt that is no report
                                        and the __MACOSX/ junk macOS adds
  descriptor.zip                        the Google report written to a pipe: sizes and CRC in
                                        data descriptors after the data (general purpose bit 3)

Every timestamp is fixed, so running it again writes the same files with the same zlib.

  python tests/fixtures/mailreports/gen_mailreports.py
"""

import gzip
import io
import os
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'src')
WHEN = (2026, 9, 27, 6, 0, 0)

GOOGLE_XML = 'google.com!example.com!1790380800!1790467199.xml'
MICROSOFT_XML = 'enterprise.protection.outlook.com!example.com!1790294400!1790380800.xml'
BIS_XML = 'mail.example.org!example.net!1790294400!1790380799.xml'
GOOGLE_TLS = 'google.com!example.com!1790380800!1790467199!001.json'
MICROSOFT_TLS = 'microsoft.com!example.com!1790294400!1790380800.json'


def read(name):
    with open(os.path.join(SRC, name), 'rb') as f:
        return f.read()


def write(name, data):
    with open(os.path.join(HERE, name), 'wb') as f:
        f.write(data)


def gz(name, data):
    """A gzip file with the original name in its header and no modification time."""
    buf = io.BytesIO()
    with gzip.GzipFile(filename=name, mode='wb', fileobj=buf, mtime=0) as g:
        g.write(data)
    return buf.getvalue()


def info(name, method=zipfile.ZIP_DEFLATED):
    z = zipfile.ZipInfo(name, date_time=WHEN)
    z.compress_type = method
    z.create_system = 3
    z.external_attr = 0o644 << 16
    return z


def zipped(entries):
    """entries: [(name, data, method)] → the archive's bytes."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, data, method in entries:
            zf.writestr(info(name, method), data)
    return buf.getvalue()


class Pipe(io.RawIOBase):
    """A write-only stream that cannot seek, so zipfile writes data descriptors."""

    def __init__(self):
        super().__init__()
        self.chunks = []

    def writable(self):
        return True

    def write(self, b):
        self.chunks.append(bytes(b))
        return len(b)


def main():
    google_zip = zipped([(GOOGLE_XML, read(GOOGLE_XML), zipfile.ZIP_DEFLATED)])
    microsoft_gz = gz(MICROSOFT_XML, read(MICROSOFT_XML))
    google_tls = gz(GOOGLE_TLS, read(GOOGLE_TLS))
    microsoft_tls = gz(MICROSOFT_TLS, read(MICROSOFT_TLS))
    write(GOOGLE_XML.replace('.xml', '.zip'), google_zip)
    write(MICROSOFT_XML + '.gz', microsoft_gz)
    write(GOOGLE_TLS + '.gz', google_tls)
    write(MICROSOFT_TLS + '.gz', microsoft_tls)

    write('reports-2026-09.zip', zipped([
        ('dmarc/' + GOOGLE_XML.replace('.xml', '.zip'), google_zip, zipfile.ZIP_STORED),
        ('dmarc/' + MICROSOFT_XML + '.gz', microsoft_gz, zipfile.ZIP_STORED),
        ('dmarc/' + BIS_XML, read(BIS_XML), zipfile.ZIP_STORED),
        ('tls/' + GOOGLE_TLS + '.gz', google_tls, zipfile.ZIP_STORED),
        ('tls/' + MICROSOFT_TLS + '.gz', microsoft_tls, zipfile.ZIP_STORED),
        ('notes.txt', b'Reports exported from the dmarc@ mailbox, September 2026.\n', zipfile.ZIP_DEFLATED),
        ('__MACOSX/dmarc/._' + BIS_XML, b'\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X        ', zipfile.ZIP_STORED),
    ]))

    pipe = Pipe()
    with zipfile.ZipFile(pipe, 'w') as zf:
        with zf.open(info(GOOGLE_XML), 'w') as f:
            f.write(read(GOOGLE_XML))
    write('descriptor.zip', b''.join(pipe.chunks))


if __name__ == '__main__':
    main()
