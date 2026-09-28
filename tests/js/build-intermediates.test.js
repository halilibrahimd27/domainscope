// Unit tests for tools/build-intermediates.mjs (the maintainers' builder of assets/data/intermediates)
// and checks of the dataset it wrote: the CSV reader, the store statuses, the filtering, the
// lifecycle table (hand-kept events, Mozilla's dates from CCADB, the expiry window), the files'
// shape and determinism; then every shard, index and root of the checked-in dataset — the page
// reads it with lib/chainfix.js, which must find each certificate where the index says.
// No network: report rows are built here from the chainfix_*.pem fixtures.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync, readdirSync } from 'node:fs';
import { parseCertificates, parseCertificate } from '../../assets/js/lib/x509.js';
import { dnHash, STORES, STORE_STATUSES } from '../../assets/js/lib/chainfix.js';
import {
  DN_DIGITS, FORMAT, MIN_INTERMEDIATES, MIN_ROOTS, MOZILLA_REPORT_URL, SKI_DIGITS, SOURCES,
  buildDataset, csvObjects, parseCsv, storeStatuses, tlsCapable
} from '../../tools/build-intermediates.mjs';

const fixture = (f) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url), 'utf8');
const certOf = (f) => parseCertificates(fixture(f)).certificates[0];
const fp = (f) => createHash('sha256').update(certOf(f).der).digest('hex').toUpperCase();
const NOW = new Date('2026-09-28T00:00:00Z');

const interRow = (f, owner = 'DomainScope Test') => ({ 'CA Owner': owner, 'SHA-256 Fingerprint': fp(f), 'PEM Info': `'${fixture(f)}` });
const record = (f, statuses, { tls = true, validTo = '2045.12.31', certName = certOf(f).subjectCN } = {}) => ({
  'CA Owner': 'DomainScope Test', 'Certificate Name': certName, 'Certificate Record Type': 'Root Certificate',
  'Apple Status': statuses, 'Chrome Status': statuses, 'Microsoft Status': statuses, 'Mozilla Status': statuses,
  'SHA-256 Fingerprint': fp(f), 'Valid To (GMT)': validTo,
  'Subject Key Identifier': Buffer.from(certOf(f).subjectKeyId, 'hex').toString('base64'), 'TLS Capable': tls ? 'True' : 'False'
});
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
    input.intermediates.push(leafAsRow);
    const { manifest } = buildDataset(input);
    assert.deepEqual(manifest.counts.skipped, { unreadable: 1, notTls: 0, noKeyId: 0, expired: 0, notYetValid: 0, duplicate: 1 });
    const later = buildDataset({ ...baseInput(), now: new Date('2035-07-01T00:00:00Z') }).manifest.counts;
    assert.equal(later.skipped.expired, 2, 'the issuing CA and its cross-signed copy expire on 2035-06-01');
    const earlier = buildDataset({ ...baseInput(), now: new Date('2025-01-01T00:00:00Z') }).manifest.counts;
    assert.equal(earlier.skipped.notYetValid, 3);
    // The test dataset was built from a "Mail CA" (emailProtection only) and a CA that expired in 2025 too.
    const testSet = JSON.parse(fixture('intermediates/manifest.json'));
    assert.equal(testSet.counts.skipped.notTls, 1);
    assert.equal(testSet.counts.skipped.expired, 1);
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
    assert.deepEqual(events.map((e) => [e.type, e.store, e.date, e.basis, e.url]), [
      ['distrust-after', 'chrome', '2026-01-31', 'sct', 'https://example.com/chrome'],
      ['distrust-after', 'mozilla', '2026-06-30', 'notBefore', 'https://example.com/mozilla'],
      ['expiry', null, '2040-03-01T23:59:59Z', null, null]
    ]);
    assert.ok(events.every((e) => e.root === bad));
    assert.ok(report.notes.some((n) => /Mozilla's date in CCADB is 2026-06-30 \(root-lifecycle\.json: 2026-07-15\)/.test(n)));
    assert.ok(report.notes.some((n) => /skipped an entry \(opera/.test(n)));
    assert.ok(report.notes.some((n) => /names a root CCADB does not list: 0{64}/.test(n)));
    // Without a hand-kept Mozilla entry, CCADB's date comes with the report's page as its link.
    const auto = json(buildDataset(baseInput()).files, 'roots.json').events;
    assert.deepEqual(auto.map((e) => [e.store, e.date, e.url]), [['mozilla', '2026-06-30', MOZILLA_REPORT_URL]], 'the 2040 expiry is outside the default window');
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
      const digest = createHash('sha256');
      const files = [...ski.map((f) => `ski/${f}`), ...dn.map((f) => `dn/${f}`), 'roots.json'].sort();
      for (const f of files) digest.update(`${f}\n${readFileSync(new URL(f, base), 'utf8').replace(/\r\n/g, '\n')}\n`);
      assert.equal(digest.digest('hex'), manifest.digest, 'a hand edit, or a rebuild that did not update the manifest');
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
