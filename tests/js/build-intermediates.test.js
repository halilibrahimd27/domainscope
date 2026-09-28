// Unit tests for tools/build-intermediates.mjs (the maintainers' builder of assets/data/intermediates)
// and checks of the dataset it wrote: the CSV reader, the download cache (only a report whose
// columns check out is kept) and time limit, the store statuses, the filtering, the
// intermediates only the CCADB certificate records list (their PEM from the PEM reports), the
// canaries, the lifecycle table (hand-kept events, Mozilla's dates from CCADB, the expiry window),
// the files' shape and determinism; then every shard, index and root of the checked-in dataset —
// the page reads it with lib/chainfix.js, which must find each certificate where the index says —
// and, on the site's dataset, a Let's Encrypt YE leaf repaired up to ISRG Root X2 and a TWCA leaf up
// to TWCA Global Root CA, a root without a key id.
// No network: report rows are built here from the chainfix_*.pem fixtures.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseCertificates, parseCertificate } from '../../assets/js/lib/x509.js';
import { fileURLToPath } from 'node:url';
import { dnHash, STORES, STORE_STATUSES, createIntermediateStore, repairChain } from '../../assets/js/lib/chainfix.js';
import {
  CANARIES, DN_DIGITS, FORMAT, MIN_INTERMEDIATES, MIN_ROOTS, MOZILLA_REPORT_URL, SKI_DIGITS, SOURCES,
  buildDataset, csvObjects, datasetDigest, downloadCsv, extraIntermediateRecords, parseCsv, pemSource, pemYears, storeStatuses, tlsCapable
} from '../../tools/build-intermediates.mjs';

const fixture = (f) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), 'utf8');
const certOf = (f) => parseCertificates(fixture(f)).certificates[0];
const fp = (f) => createHash('sha256').update(certOf(f).der).digest('hex').toUpperCase();
const NOW = new Date('2026-09-28T00:00:00Z');

const interRow = (f, owner = 'DomainScope Test') => ({ 'CA Owner': owner, 'SHA-256 Fingerprint': fp(f), 'PEM Info': `'${fixture(f)}` });
const record = (f, statuses, { tls = true, validTo = '2045.12.31', certName = certOf(f).subjectCN } = {}) => ({
  'CA Owner': 'DomainScope Test', 'Certificate Name': certName, 'Certificate Record Type': 'Root Certificate',
  'Apple Status': statuses, 'Chrome Status': statuses, 'Microsoft Status': statuses, 'Mozilla Status': statuses,
  'Revocation Status': '', 'SHA-256 Fingerprint': fp(f), 'Valid From (GMT)': '2025.01.01', 'Valid To (GMT)': validTo,
  'Subject Key Identifier': Buffer.from(certOf(f).subjectKeyId, 'hex').toString('base64'), 'TLS Capable': tls ? 'True' : 'False'
});
/** The certificate records row of an intermediate (CCADB writes 'Trusted' / 'Not Trusted' for them). */
const interRecord = (f, { owner = 'DomainScope Records Test', statuses = ['Trusted', 'Not Trusted', 'Trusted', 'Not Trusted'], revocation = 'Not Revoked',
  tls = true, validFrom = '2025.06.01', validTo = '2038.06.01' } = {}) => ({
  ...record(f, 'Not Trusted', { tls, validTo }),
  'CA Owner': owner, 'Certificate Record Type': 'Intermediate Certificate', 'Revocation Status': revocation, 'Valid From (GMT)': validFrom,
  'Apple Status': statuses[0], 'Chrome Status': statuses[1], 'Microsoft Status': statuses[2], 'Mozilla Status': statuses[3]
});
const pemRow = (f) => ({ 'SHA-256 Fingerprint': fp(f), 'X.509 Certificate (PEM)': fixture(f) });
const included = (f, distrust = '', bits = 'Websites;Email') => ({
  Owner: 'DomainScope Test', 'SHA-256 Fingerprint': fp(f), 'Trust Bits': bits, 'Distrust for TLS After Date': distrust, 'PEM Info': `'${fixture(f)}`
});
const baseInput = () => ({
  intermediates: [interRow('chainfix_inter.pem'), interRow('chainfix_inter_cross.pem'), interRow('chainfix_bad_ca.pem', 'DomainScope Distrust Test')],
  included: [included('chainfix_root.pem'), included('chainfix_bad_root.pem', '2026.06.30')],
  records: [
    record('chainfix_root.pem', 'Included'),
    record('chainfix_old_root.pem', 'Removed', { tls: false }),
    record('chainfix_bad_root.pem', 'Included', { validTo: '2040.03.01' }),
    { ...record('chainfix_leaf.pem', 'Included'), 'Certificate Record Type': 'Intermediate Certificate' }
  ],
  lifecycle: { events: [] },
  now: NOW
});
const json = (files, name) => JSON.parse(files.get(name));

describe('CSV', () => {
  test('RFC 4180: quotes, doubled quotes, line breaks inside a field, CRLF, a BOM, blank lines', () => {
    const text = '﻿a,b,c\r\n"x, y","say ""hi""","line 1\nline 2"\r\n\r\n1,,3\n';
    assert.deepEqual(parseCsv(text), [['a', 'b', 'c'], ['x, y', 'say "hi"', 'line 1\nline 2'], ['1', '', '3']]);
    assert.deepEqual(parseCsv('a,b'), [['a', 'b']], 'no final newline');
  });

  test('csvObjects keys each row by the header and names a missing column', () => {
    assert.deepEqual(csvObjects('A,B\n1,2\n3\n'), [{ A: '1', B: '2' }, { A: '3', B: '' }]);
    assert.throws(() => csvObjects('A,B\n1,2\n', ['A', 'PEM Info', 'C']), /missing column\(s\): PEM Info, C/);
  });
});

describe('downloadCsv', () => {
  const source = { url: 'https://example.com/ccadb/report.csv', file: 'report.csv' };
  const required = ['SHA-256 Fingerprint', 'PEM Info'];
  const good = 'SHA-256 Fingerprint,PEM Info\nAA,x\n';
  const errorPage = '<!DOCTYPE html><html><body>Service unavailable</body></html>';
  /** A cache directory of its own, and a fetch that answers `bodies` in turn and records its calls. */
  const setup = (...bodies) => {
    const cache = mkdtempSync(join(tmpdir(), 'ds-intermediates-'));
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url, init });
      const body = bodies.shift();
      return body instanceof Response ? body : new Response(body, { status: 200 });
    };
    return { cache, calls, file: join(cache, source.file), opts: { cache, fetchImpl, log: () => {} } };
  };

  test('a download whose columns check out is cached, and the cache is read while fresh', async () => {
    const t = setup(good);
    try {
      assert.deepEqual(await downloadCsv(source, required, t.opts), [{ 'SHA-256 Fingerprint': 'AA', 'PEM Info': 'x' }]);
      assert.equal(readFileSync(t.file, 'utf8'), good);
      assert.ok(t.calls[0].init.signal instanceof AbortSignal, 'with a time limit');
      assert.equal((await downloadCsv(source, required, t.opts)).length, 1);
      assert.equal(t.calls.length, 1, 'the second call read the cache');
    } finally {
      rmSync(t.cache, { recursive: true, force: true });
    }
  });

  test('an error page answered with 200, or an HTTP error, is never cached', async () => {
    const t = setup(errorPage, new Response('busy', { status: 503 }));
    try {
      await assert.rejects(downloadCsv(source, required, t.opts), /report\.csv: CSV is missing column\(s\): SHA-256 Fingerprint, PEM Info \(not cached\)/);
      assert.equal(existsSync(t.file), false);
      await assert.rejects(downloadCsv(source, required, t.opts), /HTTP 503/);
      assert.equal(existsSync(t.file), false);
    } finally {
      rmSync(t.cache, { recursive: true, force: true });
    }
  });

  test('a cached copy that fails the check is deleted and downloaded again; offline it is only deleted', async () => {
    const t = setup(good);
    try {
      writeFileSync(t.file, errorPage);
      assert.equal((await downloadCsv(source, required, t.opts)).length, 1);
      assert.equal(t.calls.length, 1);
      assert.equal(readFileSync(t.file, 'utf8'), good);
      writeFileSync(t.file, errorPage);
      const old = new Date(Date.now() - 48 * 3600 * 1000);
      utimesSync(t.file, old, old);
      await assert.rejects(downloadCsv(source, required, { ...t.opts, offline: true }), /--offline: .*missing column/);
      assert.equal(existsSync(t.file), false);
      await assert.rejects(downloadCsv(source, required, { ...t.opts, offline: true }), /--offline: .* is not cached/);
      assert.equal(t.calls.length, 1, 'offline never downloads');
    } finally {
      rmSync(t.cache, { recursive: true, force: true });
    }
  });

  test('a stalled answer fails after the time limit', async () => {
    const t = setup();
    // It would answer after five seconds; the limit is 20 ms.
    const fetchImpl = (url, { signal }) => new Promise((resolve, reject) => {
      const timer = setTimeout(resolve, 5000, new Response(good));
      signal.addEventListener('abort', () => {
        clearTimeout(timer);
        reject(signal.reason);
      });
    });
    try {
      await assert.rejects(downloadCsv(source, required, { ...t.opts, fetchImpl, timeoutMs: 20 }), /report\.csv: no complete answer within 0\.02 s/);
      assert.equal(existsSync(t.file), false);
    } finally {
      rmSync(t.cache, { recursive: true, force: true });
    }
  });
});

describe('filters and statuses', () => {
  test('tlsCapable: no EKU, serverAuth or anyExtendedKeyUsage', () => {
    assert.equal(tlsCapable({ extKeyUsage: [] }), true);
    assert.equal(tlsCapable({ extKeyUsage: ['clientAuth', 'serverAuth'] }), true);
    assert.equal(tlsCapable({ extKeyUsage: ['anyExtendedKeyUsage'] }), true);
    assert.equal(tlsCapable({ extKeyUsage: ['emailProtection', 'clientAuth'] }), false);
  });

  test('storeStatuses: CCADB statuses and Mozilla\'s trust bits', () => {
    const row = (status, tls = 'True') => ({ 'Chrome Status': status, 'Mozilla Status': status, 'Apple Status': status, 'Microsoft Status': status, 'TLS Capable': tls });
    assert.deepEqual(storeStatuses(row('Included')), { chrome: 'tls', mozilla: 'other', apple: 'tls', microsoft: 'tls' }, 'Mozilla without its report row: not for websites');
    assert.deepEqual(storeStatuses(row('Included'), { 'Trust Bits': 'Websites;Email' }), { chrome: 'tls', mozilla: 'tls', apple: 'tls', microsoft: 'tls' });
    assert.deepEqual(storeStatuses(row('Included', 'False'), { 'Trust Bits': 'Email' }), { chrome: 'tls', mozilla: 'other', apple: 'other', microsoft: 'other' });
    assert.deepEqual(storeStatuses({ 'Chrome Status': 'Blocked', 'Mozilla Status': 'Removed', 'Apple Status': 'Not Included', 'Microsoft Status': 'NotBefore' }),
      { chrome: 'removed', mozilla: 'removed', apple: 'absent', microsoft: 'not-before' });
    assert.equal(storeStatuses({ 'Microsoft Status': 'Disabled' }).microsoft, 'removed');
    for (const v of Object.values(storeStatuses(row('Removed')))) assert.ok(STORE_STATUSES.includes(v));
  });
});

describe('buildDataset', () => {
  test('keeps the TLS intermediates by key id, indexes their DNs, and lists the roots they need', () => {
    const { files, manifest } = buildDataset(baseInput());
    const inter = certOf('chainfix_inter.pem');
    const shard = json(files, `ski/${inter.subjectKeyId.slice(0, SKI_DIGITS)}.json`);
    assert.equal(shard[inter.subjectKeyId].length, 2, 'the issuing CA and its cross-signed copy share a key');
    assert.deepEqual(shard[inter.subjectKeyId].map((e) => parseCertificate(Buffer.from(e.der, 'base64')).issuerCN).sort(),
      ['DomainScope Test Old Root', 'DomainScope Test Root CA']);
    assert.equal(shard[inter.subjectKeyId][0].owner, 'DomainScope Test');
    const dn = json(files, `dn/${dnHash(inter.subjectDN).slice(0, DN_DIGITS)}.json`);
    assert.deepEqual(dn[dnHash(inter.subjectDN)], [inter.subjectKeyId]);
    const roots = json(files, 'roots.json');
    assert.deepEqual(roots.roots.map((r) => r.name), ['DomainScope Test Distrusted Root', 'DomainScope Test Old Root', 'DomainScope Test Root CA'],
      'the old root is kept although no store trusts it: an intermediate of the list names it');
    const old = roots.roots.find((r) => r.name === 'DomainScope Test Old Root');
    assert.deepEqual(old.stores, { chrome: 'removed', mozilla: 'removed', apple: 'removed', microsoft: 'removed' });
    assert.equal(old.dn, certOf('chainfix_old_root.pem').subjectDN, 'its DN from the issuer name of its intermediate');
    assert.equal(old.notAfter, '2045-12-31', 'the record\'s date when no PEM carries it');
    assert.equal(roots.roots.find((r) => r.name === 'DomainScope Test Root CA').notAfter, '2045-12-31T23:59:59Z', 'the certificate\'s own time');
    assert.equal(manifest.format, FORMAT);
    assert.deepEqual([manifest.counts.intermediates, manifest.counts.keys, manifest.counts.roots], [3, 2, 3]);
    assert.equal(manifest.shards.ski.files, 16 ** SKI_DIGITS, 'every shard file, empty ones too');
    assert.equal(manifest.shards.dn.files, 16 ** DN_DIGITS);
    assert.equal(files.size, 16 ** SKI_DIGITS + 16 ** DN_DIGITS + 2);
    assert.deepEqual(manifest.sources.map((s) => s.url), Object.values(SOURCES).map((s) => s.url));
    assert.equal(manifest.license.id, 'CDLA-Permissive-2.0');
  });

  test('skips duplicates, e-mail-only, expired and not yet valid intermediates, and counts each', () => {
    const input = baseInput();
    input.intermediates.push(interRow('chainfix_inter.pem'));
    const leafAsRow = interRow('chainfix_leaf.pem'); // not a CA: unreadable as an intermediate
    input.intermediates.push(leafAsRow, interRow('chainfix_mail_ca.pem'), interRow('chainfix_expired_ca.pem'));
    const { manifest, report } = buildDataset(input);
    assert.deepEqual(report.skipped, { unreadable: 1, notTls: 1, noKeyId: 0, expired: 1, notYetValid: 0, duplicate: 1, noPem: 0 });
    assert.equal(manifest.counts.skipped, undefined, 'the build log has them, not the manifest');
    const later = buildDataset({ ...baseInput(), now: new Date('2035-07-01T00:00:00Z') }).report;
    assert.equal(later.skipped.expired, 2, 'the issuing CA and its cross-signed copy expire on 2035-06-01');
    const earlier = buildDataset({ ...baseInput(), now: new Date('2025-01-01T00:00:00Z') }).report;
    assert.equal(earlier.skipped.notYetValid, 3);
    // The test dataset was built from the Mail CA (emailProtection only) and a CA that expired in 2025 too.
    const skis = readdirSync(new URL('../fixtures/intermediates/ski/', import.meta.url))
      .flatMap((f) => Object.keys(JSON.parse(fixture(`intermediates/ski/${f}`))));
    for (const f of ['chainfix_mail_ca.pem', 'chainfix_expired_ca.pem']) assert.ok(!skis.includes(certOf(f).subjectKeyId), f);
  });

  test('the intermediates only the certificate records list: which records, which PEM reports', () => {
    const deep = interRecord('chainfix_deep_ca.pem');
    const rows = [
      deep,
      interRecord('chainfix_policy.pem', { statuses: ['Not Trusted', 'Not Trusted', 'Not Trusted', 'Not Trusted'] }),
      interRecord('chainfix_bad_ca.pem', { revocation: 'Revoked' }),
      interRecord('chainfix_mail_ca.pem', { revocation: 'Parent Cert Revoked' }),
      interRecord('chainfix_expired_ca.pem', { validFrom: '2025.01.01', validTo: '2025.12.31' }),
      interRecord('chainfix_old_root_cross.pem', { tls: false }),
      interRecord('chainfix_inter.pem'), // in Mozilla's report already
      record('chainfix_root.pem', 'Included')
    ];
    const picked = extraIntermediateRecords(rows, baseInput().intermediates, NOW);
    assert.deepEqual(picked, [deep], 'TLS capable, trusted somewhere, not revoked, unexpired, not in Mozilla\'s report');
    assert.deepEqual(pemYears([deep, { 'Valid From (GMT)': '2019.03.04' }, { 'Valid From (GMT)': '2025.12.31' }, { 'Valid From (GMT)': '' }]), ['2019', '2025']);
    assert.deepEqual(pemSource('2025'), {
      name: SOURCES.pems.name, url: 'https://ccadb.my.salesforce-sites.com/ccadb/AllCertificatePEMsCSVFormat?NotBeforeYear=2025', file: 'AllCertificatePEMs-2025.csv'
    });
  });

  test('an intermediate only the certificate records list is added with its PEM and the record\'s owner', () => {
    const deep = certOf('chainfix_deep_ca.pem');
    const input = { ...baseInput(), records: [...baseInput().records, interRecord('chainfix_deep_ca.pem')], pems: [pemRow('chainfix_deep_ca.pem')] };
    const { files, manifest, report } = buildDataset(input);
    const shard = json(files, `ski/${deep.subjectKeyId.slice(0, SKI_DIGITS)}.json`);
    assert.deepEqual(shard[deep.subjectKeyId].map((e) => e.owner), ['DomainScope Records Test']);
    assert.equal(parseCertificate(Buffer.from(shard[deep.subjectKeyId][0].der, 'base64')).subjectCN, 'DomainScope Test Deep CA');
    assert.deepEqual(json(files, `dn/${dnHash(deep.subjectDN).slice(0, DN_DIGITS)}.json`)[dnHash(deep.subjectDN)], [deep.subjectKeyId]);
    assert.equal(manifest.counts.intermediates, 4);
    assert.equal(report.fromRecords, 1);
    // No PEM for it in the reports read: counted and named in the log, nothing added.
    const noPem = buildDataset({ ...input, pems: [] });
    assert.equal(noPem.manifest.counts.intermediates, 3);
    assert.equal(noPem.report.skipped.noPem, 1);
    assert.ok(noPem.report.notes.some((n) => /no PEM in the reports read for 1 record\(s\): DomainScope Test Deep CA/.test(n)), noPem.report.notes.join('\n'));
    // A PEM row whose certificate is not the record's fingerprint is never taken.
    const wrong = buildDataset({ ...input, pems: [{ ...pemRow('chainfix_policy.pem'), 'SHA-256 Fingerprint': fp('chainfix_deep_ca.pem') }] });
    assert.equal(wrong.manifest.counts.intermediates, 3);
    assert.equal(wrong.report.skipped.unreadable, 1);
    // One certificate in both places is kept once, with Mozilla's report's row.
    const both = buildDataset({ ...input, intermediates: [...input.intermediates, interRow('chainfix_deep_ca.pem')] });
    assert.equal(both.manifest.counts.intermediates, 4);
    assert.equal(both.report.fromRecords, 0);
    assert.deepEqual(json(both.files, `ski/${deep.subjectKeyId.slice(0, SKI_DIGITS)}.json`)[deep.subjectKeyId].map((e) => e.owner), ['DomainScope Test']);
  });

  test('canaries: a well-known issuer missing is reported until its own expiry', () => {
    const canaries = [
      { cn: 'DomainScope Test Deep CA', owner: 'DomainScope Records Test', until: '2038-06-01' },
      { cn: 'DomainScope Test Issuing CA', owner: 'DomainScope Test', until: '2035-06-01' },
      { cn: 'DomainScope Test Gone CA', owner: 'DomainScope Test', until: '2026-01-01' }
    ];
    const input = { ...baseInput(), records: [...baseInput().records, interRecord('chainfix_deep_ca.pem')], pems: [pemRow('chainfix_deep_ca.pem')], canaries };
    assert.deepEqual(buildDataset(input).report.missingCanaries, [], 'both there; the third one\'s date has passed');
    assert.deepEqual(buildDataset({ ...input, pems: [] }).report.missingCanaries, ['DomainScope Test Deep CA (DomainScope Records Test)']);
    assert.deepEqual(buildDataset({ ...input, canaries: [{ ...canaries[1], owner: 'Someone Else' }] }).report.missingCanaries,
      ['DomainScope Test Issuing CA (Someone Else)'], 'the owner must match too');
    // The real list: YE1 and YR1 come from the certificate records, the others from Mozilla's report.
    assert.ok(CANARIES.length >= 5);
    for (const c of CANARIES) {
      assert.ok(c.cn && c.owner, JSON.stringify(c));
      assert.match(c.until, /^\d{4}-\d{2}-\d{2}$/);
    }
    assert.ok(CANARIES.some((c) => c.cn === 'YE1') && CANARIES.some((c) => c.cn === 'YR1'));
  });

  test('the lifecycle table: hand-kept events, Mozilla\'s date from CCADB (it wins), its other dates, expiries in the window', () => {
    const bad = fp('chainfix_bad_root.pem').toLowerCase();
    const lifecycle = {
      events: [
        { store: 'chrome', type: 'distrust-after', date: '2026-01-31', basis: 'sct', url: 'https://example.com/chrome', roots: [bad.toUpperCase()] },
        { store: 'mozilla', type: 'distrust-after', date: '2026-07-15', basis: 'notBefore', url: 'https://example.com/mozilla', roots: [bad] },
        { store: 'opera', type: 'distrust-after', date: '2026-01-31', roots: [bad] },
        { store: 'chrome', type: 'distrust-after', date: '2026-01-31', roots: ['0'.repeat(64)] }
      ]
    };
    const { files, report } = buildDataset({ ...baseInput(), lifecycle, window: { from: '2025-01-01', to: '2040-12-31' } });
    const { events } = json(files, 'roots.json');
    assert.deepEqual(events.map((e) => [e.type, e.store, e.date, e.basis, e.url, e.source]), [
      ['distrust-after', 'chrome', '2026-01-31', 'sct', 'https://example.com/chrome', 'announcement'],
      ['distrust-after', 'mozilla', '2026-06-30', 'notBefore', 'https://example.com/mozilla', 'announcement'],
      ['expiry', null, '2040-03-01T23:59:59Z', null, null, null]
    ]);
    assert.ok(events.every((e) => e.root === bad));
    assert.ok(report.notes.some((n) => /Mozilla's date in CCADB is 2026-06-30 \(root-lifecycle\.json: 2026-07-15\)/.test(n)));
    assert.ok(report.notes.some((n) => /skipped an entry \(opera/.test(n)));
    assert.ok(report.notes.some((n) => /names a root CCADB does not list: 0{64}/.test(n)));
    // Without a hand-kept Mozilla entry, CCADB's date comes with the report's page as its link,
    // marked as data (the page calls it a source, not an announcement).
    const auto = json(buildDataset(baseInput()).files, 'roots.json').events;
    assert.deepEqual(auto.map((e) => [e.store, e.date, e.url, e.source]), [['mozilla', '2026-06-30', MOZILLA_REPORT_URL, 'ccadb']],
      'the 2040 expiry is outside the default window');
  });

  test('the default expiry window is January 1 of last year to December 31 of next year', () => {
    const { manifest } = buildDataset({ ...baseInput(), now: new Date('2039-05-01T00:00:00Z') });
    assert.deepEqual(manifest.lifecycleWindow, { from: '2038-01-01', to: '2040-12-31' });
    assert.equal(manifest.counts.expiryEvents, 1, 'the distrusted root expires on 2040-03-01');
  });

  test('deterministic, and the date moves only with the data', () => {
    const a = buildDataset(baseInput());
    const b = buildDataset({ ...baseInput(), now: new Date('2026-10-05T00:00:00Z'), previous: a.manifest });
    for (const [name, content] of a.files) if (name !== 'manifest.json') assert.equal(b.files.get(name), content, name);
    assert.equal(b.manifest.generated, '2026-09-28', 'same data: the previous date');
    assert.equal(b.manifest.digest, a.manifest.digest);
    const c = buildDataset({ ...baseInput(), intermediates: baseInput().intermediates.slice(0, 1), now: new Date('2026-10-05T00:00:00Z'), previous: a.manifest });
    assert.equal(c.manifest.generated, '2026-10-05');
    // Only a skipped count changes (CCADB added an e-mail-only CA): manifest.json stays byte for byte.
    const quiet = buildDataset({
      ...baseInput(), intermediates: [...baseInput().intermediates, interRow('chainfix_mail_ca.pem')], now: new Date('2026-10-05T00:00:00Z'), previous: a.manifest
    });
    assert.equal(quiet.report.skipped.notTls, 1);
    assert.equal(quiet.files.get('manifest.json'), a.files.get('manifest.json'));
    // What the manifest says is part of the digest: another source moves the date.
    const moved = buildDataset({ ...baseInput(), sources: { ...SOURCES, extra: { name: 'x', url: 'https://example.com/x.csv' } }, now: new Date('2026-10-05T00:00:00Z'), previous: a.manifest });
    assert.notEqual(moved.manifest.digest, a.manifest.digest);
    assert.equal(moved.manifest.generated, '2026-10-05');
    const { generated, digest, ...body } = a.manifest;
    assert.equal(datasetDigest(a.files, body), digest, 'datasetDigest leaves manifest.json itself out');
    assert.equal(generated, '2026-09-28');
    const small = buildDataset({ ...baseInput(), emptyShards: false });
    assert.ok(small.files.size < a.files.size);
    assert.ok([...small.files.keys()].filter((f) => f.startsWith('ski/')).every((f) => Object.keys(json(small.files, f)).length));
  });
});

describe('the checked-in datasets', () => {
  for (const [label, dir, full] of [['assets/data/intermediates', '../../assets/data/intermediates/', true], ['the test dataset', '../fixtures/intermediates/', false]]) {
    const base = new URL(dir, import.meta.url);
    const readJson = (rel) => JSON.parse(readFileSync(new URL(rel, base), 'utf8'));
    const manifest = readJson('manifest.json');

    test(`${label}: manifest, shard files and digest agree`, () => {
      assert.equal(manifest.format, FORMAT);
      assert.match(manifest.generated, /^\d{4}-\d{2}-\d{2}$/);
      const ski = readdirSync(new URL('ski/', base)).sort();
      const dn = readdirSync(new URL('dn/', base)).sort();
      assert.equal(ski.length, manifest.shards.ski.files);
      assert.equal(dn.length, manifest.shards.dn.files);
      if (full) {
        assert.equal(ski.length, 16 ** SKI_DIGITS);
        assert.ok(manifest.counts.intermediates >= MIN_INTERMEDIATES && manifest.counts.roots >= MIN_ROOTS, JSON.stringify(manifest.counts));
      }
      // The data files in name order, then the manifest without its date and digest.
      const digest = createHash('sha256');
      const files = [...ski.map((f) => `ski/${f}`), ...dn.map((f) => `dn/${f}`), 'roots.json'].sort();
      for (const f of files) digest.update(`${f}\n${readFileSync(new URL(f, base), 'utf8').replace(/\r\n/g, '\n')}\n`);
      const { generated, digest: listed, ...body } = manifest;
      digest.update(`manifest.json\n${JSON.stringify(body)}\n`);
      assert.equal(digest.digest('hex'), listed, 'a hand edit, or a rebuild that did not update the manifest');
      assert.match(generated, /^\d{4}-\d{2}-\d{2}$/);
      assert.equal(manifest.counts.skipped, undefined, 'the skipped counts stay in the build log');
    });

    test(`${label}: every certificate sits under its key id, the DN index points at it, and it is a TLS CA`, () => {
      const bySki = new Map();
      let count = 0;
      for (const f of readdirSync(new URL('ski/', base))) {
        const shard = readJson(`ski/${f}`);
        for (const [ski, entries] of Object.entries(shard)) {
          assert.equal(ski.slice(0, SKI_DIGITS), f.slice(0, SKI_DIGITS), `${ski} in ${f}`);
          for (const e of entries) {
            const c = parseCertificate(Buffer.from(e.der, 'base64'));
            assert.equal(c.subjectKeyId, ski);
            assert.ok(c.isCA && tlsCapable(c), c.subjectDN);
            assert.equal(typeof e.owner, 'string');
            bySki.set(ski, [...(bySki.get(ski) || []), c]);
            count += 1;
          }
        }
      }
      assert.equal(count, manifest.counts.intermediates);
      let indexed = 0;
      for (const f of readdirSync(new URL('dn/', base))) {
        for (const [key, skis] of Object.entries(readJson(`dn/${f}`))) {
          assert.equal(key.slice(0, DN_DIGITS), f.slice(0, DN_DIGITS));
          for (const ski of skis) {
            assert.ok((bySki.get(ski) || []).some((c) => dnHash(c.subjectDN) === key), `${key} → ${ski}`);
            indexed += 1;
          }
        }
      }
      assert.ok(indexed >= bySki.size);
    });

    test(`${label}: roots and the lifecycle table are well formed`, () => {
      const { roots, events } = readJson('roots.json');
      assert.equal(roots.length, manifest.counts.roots);
      const shas = new Set(roots.map((r) => r.sha256));
      assert.equal(shas.size, roots.length);
      for (const r of roots) {
        assert.match(r.sha256, /^[0-9a-f]{64}$/);
        assert.deepEqual(Object.keys(r.stores).sort(), [...STORES].sort());
        for (const s of STORES) assert.ok(STORE_STATUSES.includes(r.stores[s]), `${r.name} ${s}`);
      }
      assert.equal(events.length, manifest.counts.events);
      for (const e of events) {
        assert.ok(shas.has(e.root), e.root);
        assert.ok(['distrust-after', 'expiry'].includes(e.type));
        if (e.url) assert.match(e.url, /^https:\/\//);
      }
      if (full) {
        // The announced Entrust distrust (Chrome 131+) is in the table with its announcement.
        const entrust = roots.find((r) => r.sha256 === '73c176434f1bc6d5adf45b0e76e727287c8de57616c1e6e6141a2b2cbc7d8e4c');
        assert.equal(entrust.name, 'Entrust Root Certification Authority');
        assert.ok(events.some((e) => e.root === entrust.sha256 && e.store === 'chrome' && e.date === '2024-11-11'
          && e.url === 'https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html'));
        // Roots named only by a shared CN are told apart by their OU.
        assert.ok(roots.filter((r) => /^GlobalSign \(GlobalSign .*Root CA - R\d\)$/.test(r.name)).length >= 3);
        // Let's Encrypt's intermediates are listed.
        const owners = new Set(readdirSync(new URL('ski/', base)).flatMap((f) => Object.values(readJson(`ski/${f}`)).flat().map((e) => e.owner)));
        assert.ok(owners.has('Internet Security Research Group'));
      }
    });
  }

  // The site's dataset as the page reads it: every intermediate parsed with its owner, a store over
  // the files, and a www.example.com leaf under a CA of it, valid from the day before for 60 days.
  const site = (() => {
    const base = new URL('../../assets/data/intermediates/', import.meta.url);
    const manifest = JSON.parse(readFileSync(new URL('manifest.json', base), 'utf8'));
    return {
      manifest,
      now: new Date(`${manifest.generated}T12:00:00Z`),
      roots: () => JSON.parse(readFileSync(new URL('roots.json', base), 'utf8')).roots,
      all: () => readdirSync(new URL('ski/', base))
        .flatMap((f) => Object.values(JSON.parse(readFileSync(new URL(`ski/${f}`, base), 'utf8'))).flat())
        .map((e) => ({ owner: e.owner, cert: parseCertificate(Buffer.from(e.der, 'base64')) })),
      store: () => createIntermediateStore({ url: new URL('manifest.json', base).href, fetchImpl: async (url) => new Response(readFileSync(fileURLToPath(url))) })
    };
  })();
  const leafUnder = (ca, now) => ({
    subjectDN: 'CN=www.example.com', subjectCN: 'www.example.com', issuerDN: ca.subjectDN, issuerCN: ca.subjectCN,
    authorityKeyId: ca.subjectKeyId, subjectKeyId: '00', serialHex: '01', selfSigned: false, isCA: false,
    notBefore: new Date(now.getTime() - 86400000), notAfter: new Date(now.getTime() + 60 * 86400000), scts: []
  });

  test('assets/data/intermediates: the well-known current issuers, and a Let\'s Encrypt YE leaf repaired up to ISRG Root X2', async () => {
    const all = site.all();
    for (const c of CANARIES.filter((x) => x.until >= site.manifest.generated)) {
      assert.ok(all.some((e) => e.cert.subjectCN === c.cn && e.owner === c.owner), `${c.cn} (${c.owner})`);
    }
    // YE1–YE3 are only in the certificate records (Root YE is in no store; browsers reach it
    // through its ISRG Root X2 cross-sign, which Mozilla's report lists).
    const ye = all.find((e) => e.owner === 'Internet Security Research Group' && /^YE\d$/.test(e.cert.subjectCN));
    assert.ok(ye, 'a Let\'s Encrypt YE issuer');
    const leaf = leafUnder(ye.cert, site.now);
    const r = await repairChain({ certificates: [leaf], leaf }, { store: site.store(), now: site.now });
    assert.equal(r.status, 'repaired');
    assert.deepEqual(r.added.map((a) => `${a.cert.subjectCN} ← ${a.cert.issuerCN}`), [`${ye.cert.subjectCN} ← Root YE`, 'Root YE ← ISRG Root X2'],
      'Let\'s Encrypt\'s hierarchy changed? Check the path and update this test');
    assert.equal(r.root.name, 'ISRG Root X2');
    assert.deepEqual(r.standing.trusted, STORES);
    assert.deepEqual(r.standing.warnings, []);
  });

  test('assets/data/intermediates: TWCA Global Root CA, a root without a key id, ends the chain of a CA it issued', async () => {
    // Its certificate has no subject key id and CCADB lists none, so roots.json says `ski: null`;
    // the CAs under it name it by an authority key id all the same. Every store trusts it, while
    // TWCA Root Certification Authority, which cross-signed it, is no longer in Chrome.
    const all = site.all();
    const root = site.roots().find((r) => r.name === 'TWCA Global Root CA');
    assert.ok(root && root.dn, 'TWCA Global Root CA left the list? Pick another root without a key id or drop this test');
    const ca = all.find((e) => e.cert.subjectCN === 'TWCA Global EVSSL Certification Authority' && e.cert.issuerDN === root.dn);
    const cross = all.find((e) => e.cert.subjectDN === root.dn);
    assert.ok(ca && ca.cert.authorityKeyId && cross, 'TWCA\'s hierarchy changed? Check it and update this test');
    const leaf = leafUnder(ca.cert, site.now);
    const store = site.store();
    const check = (r, status) => {
      assert.equal(r.status, status);
      assert.ok(STORES.every((s) => r.standing.stores[s].root.name === 'TWCA Global Root CA'), 'every store stops at it');
      assert.deepEqual(r.standing.trusted, STORES);
      assert.deepEqual(r.standing.warnings, [], 'no store rejects it');
    };
    const alone = await repairChain({ certificates: [leaf], leaf }, { store, now: site.now });
    check(alone, 'repaired');
    assert.equal(alone.root.name, 'TWCA Global Root CA');
    assert.deepEqual(alone.added.map((a) => a.cert.subjectCN), ['TWCA Global EVSSL Certification Authority'], 'never through the cross-signed root');
    // the CA alone, and as the server sends it: with the root's cross-signature
    check(await repairChain({ certificates: [leaf, ca.cert], leaf }, { store, now: site.now }), 'complete');
    check(await repairChain({ certificates: [leaf, ca.cert, cross.cert], leaf }, { store, now: site.now }), 'complete');
  });

  test('the hand-kept lifecycle input names its sources', () => {
    const input = JSON.parse(readFileSync(new URL('../../tools/root-lifecycle.json', import.meta.url), 'utf8'));
    assert.ok(input.events.length >= 4);
    for (const e of input.events) {
      assert.ok(STORES.includes(e.store), e.store);
      assert.equal(e.type, 'distrust-after');
      assert.match(e.date, /^\d{4}-\d{2}-\d{2}$/);
      assert.match(e.url, /^https:\/\//);
      assert.ok(['sct', 'notBefore'].includes(e.basis));
      for (const r of e.roots) assert.match(r, /^[0-9A-F]{64}$/);
    }
  });
});
