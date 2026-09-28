// Unit tests for assets/js/lib/chainfix.js — the missing intermediate found in the bundled CCADB
// list and the root-store lifecycle warnings. Fixtures: tests/fixtures/chainfix_*.pem and the
// test dataset tests/fixtures/intermediates/ (both from gen_chainfix_fixtures.mjs: a current
// root every store includes, an old root every store removed, an issuing CA signed by both, a
// Policy CA → Deep CA pair, a distrusted root with its CA). The dataset is read from disk through
// an injected fetch that counts the files it serves; shard files the test dataset leaves out
// (nothing in them) answer `{}`, as the site's full dataset does.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import {
  DATASET_URL, MAX_ADDED, STORES, chainStanding, createIntermediateStore, datasetDate, dnHash, fileChain, issuedAt,
  repairChain, rootEntryFor, rootStanding, rootTable, rootsIssuing, rootsWithKey, shardOf
} from '../../assets/js/lib/chainfix.js';

const FIXTURES = new URL('../fixtures/', import.meta.url);
const MANIFEST = new URL('intermediates/manifest.json', FIXTURES).href;
const NOW = new Date('2026-09-28T12:00:00Z');
const read = (f) => readFileSync(new URL(f, FIXTURES), 'utf8');
const load = (...files) => parseCertificates(files.map(read).join('\n'));
const cert = (f) => load(f).certificates[0];

/** A store over the test dataset; `served` lists the files it read, `fail` makes the next fetches fail. */
function diskStore() {
  const served = [];
  const state = { fail: 0 };
  const fetchImpl = async (url) => {
    if (state.fail > 0) {
      state.fail -= 1;
      throw new TypeError('Failed to fetch');
    }
    const rel = url.slice(MANIFEST.lastIndexOf('/') + 1);
    served.push(rel);
    try {
      return new Response(readFileSync(fileURLToPath(url)), { status: 200, headers: { 'content-type': 'application/json' } });
    } catch {
      return /^(ski|dn)\/[0-9a-f]+\.json$/.test(rel) ? new Response('{}', { status: 200 }) : new Response('not found', { status: 404 });
    }
  };
  return { store: createIntermediateStore({ url: MANIFEST, fetchImpl }), served, state };
}

const names = (certs) => certs.map((c) => c.subjectCN);

/**
 * The test roots as TWCA Global Root CA stands in the real list: the old root is a root without
 * a key id (its certificate has no subject key id extension and CCADB's column is empty, so
 * roots.json says `ski: null`) that every store trusts, while the current root — which
 * cross-signed it — is no longer in Chrome. The Issuing CA's cross-signed copy (issued by the old
 * root) and the old root's cross-signature carry authority key ids all the same.
 */
function keylessRoots() {
  const json = JSON.parse(read('intermediates/roots.json'));
  const tls = { chrome: 'tls', mozilla: 'tls', apple: 'tls', microsoft: 'tls' };
  return rootTable({
    roots: json.roots.map((r) => {
      if (r.name === 'DomainScope Test Old Root') return { ...r, ski: null, stores: tls };
      if (r.name === 'DomainScope Test Root CA') return { ...r, stores: { ...tls, chrome: 'removed' } };
      return r;
    }),
    events: json.events
  });
}

describe('small helpers', () => {
  test('the dataset URL sits next to the other data files, relative to the module', () => {
    assert.match(DATASET_URL, /\/assets\/data\/intermediates\/manifest\.json$/);
  });

  test('dnHash: 16 hex digits of SHA-256 over the DN, stable', () => {
    const h = dnHash('CN=DomainScope Test Issuing CA,O=DomainScope Test,C=XX');
    assert.match(h, /^[0-9a-f]{16}$/);
    assert.equal(h, dnHash('CN=DomainScope Test Issuing CA,O=DomainScope Test,C=XX'));
    assert.notEqual(h, dnHash('CN=DomainScope Test Issuing CA,O=DomainScope Test,C=XY'));
    // SHA-256("") starts e3b0c442…
    assert.equal(dnHash(''), 'e3b0c44298fc1c14');
  });

  test('shardOf: the first hex digits, null for anything else', () => {
    assert.equal(shardOf('AB12cd', 2), 'ab');
    assert.equal(shardOf('f', 1), 'f');
    assert.equal(shardOf('xyz', 2), null);
    assert.equal(shardOf('a', 2), null);
    assert.equal(shardOf('', 1), null);
    assert.equal(shardOf('../x', 1), null, 'never a path');
  });

  test('datasetDate: a day is its end (UTC), a time is kept, junk is null', () => {
    assert.equal(datasetDate('2024-11-11').toISOString(), '2024-11-11T23:59:59.999Z');
    assert.equal(datasetDate('2040-03-01T23:59:59Z').toISOString(), '2040-03-01T23:59:59.000Z');
    assert.equal(datasetDate('soon'), null);
    assert.equal(datasetDate(null), null);
  });

  test('issuedAt: Chrome counts the earliest embedded SCT, else notBefore', () => {
    const notBefore = new Date('2025-01-10T00:00:00Z');
    const c = { notBefore, scts: [{ timestamp: new Date('2025-01-09T10:00:00Z') }, { timestamp: new Date('2025-01-09T09:00:00Z') }, { timestamp: null }] };
    assert.equal(issuedAt(c, 'sct').toISOString(), '2025-01-09T09:00:00.000Z');
    assert.equal(issuedAt(c, 'notBefore'), notBefore);
    assert.equal(issuedAt({ notBefore, scts: [] }, 'sct'), notBefore, 'no SCT in the certificate');
  });

  test('fileChain: leaf first, the root held apart, strangers left out', () => {
    const r = load('chainfix_root.pem', 'chainfix_inter.pem', 'chainfix_leaf.pem', 'chainfix_leaf_deep.pem');
    const leaf = r.certificates[2];
    const { chain, rootCert } = fileChain(r.certificates, leaf);
    assert.deepEqual(names(chain), ['www.example.com', 'DomainScope Test Issuing CA']);
    assert.equal(rootCert.subjectCN, 'DomainScope Test Root CA');
    assert.deepEqual(names(fileChain([leaf], leaf).chain), ['www.example.com']);
  });
});

describe('rootTable', () => {
  const json = JSON.parse(read('intermediates/roots.json'));

  test('indexes the roots by key id and DN and attaches their events in date order', () => {
    const table = rootTable({ ...json, generated: '2026-09-28' });
    assert.equal(table.generated, '2026-09-28');
    assert.equal(table.roots.length, 3);
    const bad = table.roots.find((r) => r.name === 'DomainScope Test Distrusted Root');
    assert.deepEqual(bad.events.map((e) => `${e.type}:${e.store}`), ['distrust-after:chrome', 'distrust-after:mozilla', 'expiry:null']);
    assert.equal(bad.events[0].basis, 'sct');
    assert.equal(bad.events[0].url, 'https://example.com/announcements/chrome-distrust');
    assert.deepEqual(bad.events.map((e) => e.source), ['announcement', 'ccadb', null], 'a hand-kept announcement, Mozilla\'s date from CCADB, the expiry');
    assert.equal(table.bySki.get(bad.ski)[0], bad);
    assert.equal(table.byDn.get(bad.dn)[0], bad);
  });

  test('ignores junk: unknown statuses become absent, bad events and non-https links are dropped', () => {
    const table = rootTable({
      roots: [{ sha256: 'AA', name: 'X', stores: { chrome: 'maybe', mozilla: 'tls' }, ski: 'not hex' }, null, { name: 'no fingerprint' }],
      events: [
        { root: 'aa', type: 'distrust-after', store: 'chrome', date: '2025-01-01', url: 'http://example.com/' },
        { root: 'aa', type: 'explode', date: '2025-01-01' },
        { root: 'aa', type: 'expiry', date: 'never' }
      ]
    });
    assert.equal(table.roots.length, 1);
    const [r] = table.roots;
    assert.deepEqual(r.stores, { chrome: 'absent', mozilla: 'tls', apple: 'absent', microsoft: 'absent' });
    assert.equal(r.ski, null);
    assert.equal(r.events.length, 1);
    assert.equal(r.events[0].url, null);
    assert.equal(r.events[0].source, null, 'no link, nothing to name');
    assert.deepEqual(rootTable(null).roots, []);
  });

  test('rootsIssuing by key id (the DN must agree), else by issuer DN; rootsWithKey finds a cross-signed root', () => {
    const table = rootTable(json);
    assert.deepEqual(rootsIssuing(table, cert('chainfix_inter.pem')).map((r) => r.name), ['DomainScope Test Root CA']);
    assert.deepEqual(rootsIssuing(table, cert('chainfix_leaf.pem')), [], 'a leaf is issued by an intermediate');
    const inter = cert('chainfix_inter.pem');
    assert.deepEqual(rootsIssuing(table, { ...inter, issuerDN: 'CN=Someone Else' }), [], 'same key id, another name');
    assert.deepEqual(rootsIssuing(table, { ...inter, authorityKeyId: null }).map((r) => r.name), ['DomainScope Test Root CA'], 'no key id: the DN');
    assert.deepEqual(rootsWithKey(table, cert('chainfix_old_root_cross.pem')).map((r) => r.name), ['DomainScope Test Old Root']);
    assert.equal(rootEntryFor(table, cert('chainfix_root.pem')).name, 'DomainScope Test Root CA');
    assert.equal(rootEntryFor(table, cert('chainfix_leaf.pem')), null);
    assert.deepEqual(rootsIssuing(table, { ...inter, authorityKeyId: 'ff'.repeat(20) }), [], 'the right name under another key id is not its root');
  });

  test('a root without a key id is found by its DN, under a certificate that names a key id', () => {
    const table = keylessRoots();
    const old = table.roots.find((r) => r.name === 'DomainScope Test Old Root');
    assert.equal(old.ski, null);
    assert.deepEqual(rootsIssuing(table, cert('chainfix_inter_cross.pem')), [old]);
    assert.ok(cert('chainfix_inter_cross.pem').authorityKeyId);
    assert.deepEqual(rootsIssuing(table, { ...cert('chainfix_inter_cross.pem'), issuerDN: 'CN=Someone Else' }), [], 'the DN must match');
    assert.deepEqual(rootsWithKey(table, cert('chainfix_old_root_cross.pem')), [old], 'its cross-signed copy (which has a key id)');
    assert.deepEqual(rootsWithKey(table, cert('chainfix_inter_cross.pem')), [], 'another name');
    assert.equal(rootEntryFor(table, { ...cert('chainfix_old_root.pem'), der: new Uint8Array([1]) }), old, 'another certificate of the root: by the DN');
    // The current root still needs its key id: a DN alone never matches a root that has one.
    assert.deepEqual(rootsIssuing(table, { ...cert('chainfix_inter.pem'), authorityKeyId: 'ff'.repeat(20) }), []);
  });
});

describe('chainStanding — the lifecycle warnings', () => {
  const table = rootTable(JSON.parse(read('intermediates/roots.json')));
  const byName = (n) => table.roots.find((r) => r.name === n);
  const leaf = cert('chainfix_leaf_lifecycle.pem');

  test('a distrusted root: Chrome distrusts this certificate (issued after its cut-off), Mozilla only its renewal, the root expires first', () => {
    const s = rootStanding(byName('DomainScope Test Distrusted Root'), leaf, NOW);
    assert.deepEqual(s.trusted, ['mozilla', 'apple', 'microsoft']);
    assert.equal(s.stores.chrome.status, 'distrusted');
    const w = s.warnings.map((x) => [x.code, x.severity, x.stores.join('+'), x.date.toISOString().slice(0, 10)]);
    assert.deepEqual(w, [
      ['distrusted', 'error', 'chrome', '2026-01-31'],
      ['renewal-distrusted', 'warn', 'mozilla', '2026-06-30'],
      ['root-expires', 'warn', 'mozilla+apple+microsoft', '2040-03-01']
    ]);
    const chrome = s.warnings[0];
    assert.equal(chrome.issued.toISOString(), '2026-03-01T00:00:00.000Z', 'no SCT: notBefore');
    assert.equal(chrome.url, 'https://example.com/announcements/chrome-distrust');
    assert.equal(chrome.root.name, 'DomainScope Test Distrusted Root');
  });

  test('a certificate issued before every cut-off: only renewal warnings; after the root expired: an error', () => {
    const early = { ...leaf, notBefore: new Date('2025-12-01T00:00:00Z'), scts: [] };
    const s = rootStanding(byName('DomainScope Test Distrusted Root'), early, NOW);
    assert.deepEqual(s.trusted, STORES);
    assert.deepEqual(s.warnings.map((x) => x.code), ['renewal-distrusted', 'renewal-distrusted', 'root-expires']);
    const later = rootStanding(byName('DomainScope Test Distrusted Root'), early, new Date('2040-04-01T00:00:00Z'));
    assert.deepEqual(later.trusted, []);
    assert.deepEqual(later.warnings.map((x) => [x.code, x.stores.length]), [['root-expired', 4]]);
  });

  test('a root every store removed: one error naming all four', () => {
    const s = rootStanding(byName('DomainScope Test Old Root'), cert('chainfix_leaf.pem'), NOW);
    assert.deepEqual(s.trusted, []);
    assert.deepEqual(s.warnings.map((x) => [x.code, x.severity, x.stores]), [['removed', 'error', STORES]]);
  });

  test('statuses: e-mail-only, Microsoft NotBefore, never included (a warning only while another store trusts it)', () => {
    const root = { ...byName('DomainScope Test Root CA'), stores: { chrome: 'tls', mozilla: 'other', apple: 'absent', microsoft: 'not-before' }, events: [] };
    const s = rootStanding(root, cert('chainfix_leaf.pem'), NOW);
    assert.deepEqual(s.trusted, ['chrome']);
    assert.deepEqual(s.warnings.map((x) => [x.code, x.severity, x.stores.join('+')]),
      [['not-for-tls', 'error', 'mozilla'], ['cut-off', 'warn', 'microsoft'], ['not-included', 'warn', 'apple']]);
    const none = rootStanding({ ...root, stores: { chrome: 'absent', mozilla: 'absent', apple: 'absent', microsoft: 'absent' } }, cert('chainfix_leaf.pem'), NOW);
    assert.deepEqual(none.warnings, [], 'nothing trusts it and nothing changed: no store to name');
  });

  test('a cross-signed root in the chain is an anchor: stores that hold it stop there', () => {
    const current = byName('DomainScope Test Root CA');
    const old = byName('DomainScope Test Old Root');
    const s = chainStanding([current, old], cert('chainfix_leaf.pem'), NOW);
    assert.deepEqual(s.trusted, STORES);
    assert.ok(STORES.every((k) => s.stores[k].root === current));
    assert.deepEqual(s.warnings, [], 'the old root behind it says nothing');
    assert.equal(chainStanding([], cert('chainfix_leaf.pem'), NOW), null);
  });
});

describe('repairChain', () => {
  test('a leaf alone: the issuing CA is added from the list — the one issued by the current root, not the cross-signed copy', async () => {
    const { store, served } = diskStore();
    const r = await repairChain(load('chainfix_leaf.pem'), { store, now: NOW });
    assert.equal(r.status, 'repaired');
    assert.equal(r.reason, 'missing');
    assert.deepEqual(r.added.map((a) => [a.cert.subjectCN, a.cert.issuerCN, a.owner]), [['DomainScope Test Issuing CA', 'DomainScope Test Root CA', 'DomainScope Test']]);
    assert.deepEqual(names(r.fullchain), ['www.example.com', 'DomainScope Test Issuing CA']);
    assert.equal(r.root.name, 'DomainScope Test Root CA');
    assert.deepEqual(r.standing.trusted, STORES);
    assert.deepEqual(r.standing.warnings, []);
    assert.equal(r.alternatives, 3, 'the cross-signed copy, alone and through the old root\'s cross-signature, and the direct one');
    assert.equal(r.generated, '2026-09-28');
    // Only the shard of the leaf's authority key id was read (and the old root's, to look past
    // it for the cross-signed copy), never the whole list.
    const skiFiles = served.filter((f) => f.startsWith('ski/'));
    assert.equal(skiFiles[0], `ski/${load('chainfix_leaf.pem').leaf.authorityKeyId.slice(0, 2)}.json`);
    assert.equal(skiFiles[1], `ski/${cert('chainfix_old_root.pem').subjectKeyId.slice(0, 2)}.json`);
    assert.equal(skiFiles.length, 2);
    assert.ok(!served.some((f) => f.startsWith('dn/')), 'no DN lookup with a key id');
    assert.deepEqual(served.slice(0, 2), ['manifest.json', 'roots.json']);
  });

  test('leaf + intermediate issued by the current root: complete, nothing read beyond the roots', async () => {
    const { store, served } = diskStore();
    const r = await repairChain(load('chainfix_inter.pem', 'chainfix_leaf.pem'), { store, now: NOW });
    assert.equal(r.status, 'complete');
    assert.deepEqual(r.added, []);
    assert.deepEqual(names(r.fullchain), ['www.example.com', 'DomainScope Test Issuing CA'], 'the file order does not matter');
    assert.equal(r.root.name, 'DomainScope Test Root CA');
    assert.deepEqual(served, ['manifest.json', 'roots.json']);
  });

  test('the root in the file: complete, never in fullchain', async () => {
    const { store } = diskStore();
    const r = await repairChain(load('chainfix_leaf.pem', 'chainfix_root.pem', 'chainfix_inter.pem'), { store, now: NOW });
    assert.equal(r.status, 'complete');
    assert.equal(r.rootCert.subjectCN, 'DomainScope Test Root CA');
    assert.deepEqual(names(r.fullchain), ['www.example.com', 'DomainScope Test Issuing CA']);
    assert.equal(r.root.name, 'DomainScope Test Root CA');
  });

  test('the file ends at a root no store trusts: a cross-signed copy of that root leads on to the current one', async () => {
    const { store } = diskStore();
    const r = await repairChain(load('chainfix_leaf.pem', 'chainfix_inter_cross.pem'), { store, now: NOW });
    assert.equal(r.status, 'repaired');
    assert.equal(r.reason, 'untrusted-root');
    assert.equal(r.ownRoot.name, 'DomainScope Test Old Root', 'where the file\'s own chain ends');
    assert.deepEqual(r.added.map((a) => `${a.cert.subjectCN} ← ${a.cert.issuerCN}`), ['DomainScope Test Old Root ← DomainScope Test Root CA']);
    assert.deepEqual(r.anchors.map((a) => a.name), ['DomainScope Test Old Root', 'DomainScope Test Root CA']);
    assert.deepEqual(r.standing.trusted, STORES);
  });

  test('two intermediates missing: both added, in chain order; one of them in the file: the other one', async () => {
    const { store } = diskStore();
    const deep = await repairChain(load('chainfix_leaf_deep.pem'), { store, now: NOW });
    assert.equal(deep.status, 'repaired');
    assert.deepEqual(names(deep.fullchain), ['deep.example.org', 'DomainScope Test Deep CA', 'DomainScope Test Policy CA']);
    assert.deepEqual(deep.added.map((a) => a.owner), ['DomainScope Test', 'DomainScope Test'], 'the Deep CA comes from the certificate records only');
    const half = await repairChain(load('chainfix_leaf_deep.pem', 'chainfix_deep_ca.pem'), { store, now: NOW });
    assert.equal(half.status, 'repaired');
    assert.deepEqual(half.added.map((a) => a.cert.subjectCN), ['DomainScope Test Policy CA']);
    assert.deepEqual(names(half.fullchain), ['deep.example.org', 'DomainScope Test Deep CA', 'DomainScope Test Policy CA']);
  });

  test('no authority key id: found by the issuer DN', async () => {
    const { store, served } = diskStore();
    const r = await repairChain(load('chainfix_leaf_noaki.pem'), { store, now: NOW });
    assert.equal(r.leaf.authorityKeyId, null);
    assert.equal(r.status, 'repaired');
    assert.deepEqual(r.added.map((a) => a.cert.subjectCN), ['DomainScope Test Issuing CA']);
    assert.ok(served.some((f) => f === `dn/${dnHash(r.leaf.issuerDN)[0]}.json`), served.join(', '));
  });

  test('an intermediate the list does not hold: not-found, with the issuer looked for', async () => {
    const { store } = diskStore();
    const r = await repairChain(load('chainfix_leaf_unknown.pem'), { store, now: NOW });
    assert.equal(r.status, 'not-found');
    assert.deepEqual(r.added, []);
    assert.deepEqual(names(r.fullchain), ['internal.example.net']);
    assert.equal(r.missing.issuerDN, 'CN=DomainScope Test Unlisted CA,O=DomainScope Unlisted Test,C=XX');
    assert.match(r.missing.authorityKeyId, /^[0-9a-f]{40}$/);
    assert.equal(r.standing, null);
  });

  test('the lifecycle: repaired under a distrusted root, with its warnings', async () => {
    const { store } = diskStore();
    const r = await repairChain(load('chainfix_leaf_lifecycle.pem'), { store, now: NOW });
    assert.equal(r.status, 'repaired');
    assert.deepEqual(r.added.map((a) => [a.cert.subjectCN, a.owner]), [['DomainScope Test Distrusted CA', 'DomainScope Distrust Test']]);
    assert.equal(r.root.name, 'DomainScope Test Distrusted Root');
    assert.deepEqual(r.standing.warnings.map((w) => w.code), ['distrusted', 'renewal-distrusted', 'root-expires']);
  });

  test('an expired intermediate is never added', async () => {
    const { store } = diskStore();
    const r = await repairChain(load('chainfix_leaf.pem'), { store, now: new Date('2035-07-01T00:00:00Z') });
    assert.equal(r.status, 'not-found', 'the issuing CA expired on 2035-06-01');
  });

  test('self-signed, no leaf', async () => {
    const { store } = diskStore();
    const own = await repairChain(load('chainfix_root.pem'), { store, now: NOW });
    assert.equal(own.status, 'self-signed');
    assert.equal(own.root.name, 'DomainScope Test Root CA');
    const none = await repairChain({ certificates: [], leaf: null }, { store, now: NOW });
    assert.equal(none.status, 'no-leaf');
    assert.equal(none.generated, '2026-09-28');
  });

  test('scoring: among a root in three stores and a cross-signed path to one in four, the wider one wins', async () => {
    const { store } = diskStore();
    const table = await store.roots();
    const current = table.roots.find((r) => r.name === 'DomainScope Test Root CA');
    const narrow = { ...current, stores: { ...current.stores, apple: 'absent' } };
    // The issuing CA is issued by `narrow` (key and DN of the current root); the old root's key is
    // cross-signed by the real current root and trusted everywhere in this table.
    const old = table.roots.find((r) => r.name === 'DomainScope Test Old Root');
    const wide = { ...old, stores: { chrome: 'tls', mozilla: 'tls', apple: 'tls', microsoft: 'tls' } };
    const fake = {
      manifest: store.manifest,
      bySki: store.bySki,
      byDn: store.byDn,
      roots: async () => rootTable({
        roots: [narrow, wide].map((r) => ({ ...r, notAfter: r.notAfter.toISOString() })), events: []
      })
    };
    const r = await repairChain(load('chainfix_leaf.pem'), { store: fake, now: NOW });
    assert.equal(r.status, 'repaired');
    assert.deepEqual(r.added.map((a) => `${a.cert.subjectCN} ← ${a.cert.issuerCN}`), ['DomainScope Test Issuing CA ← DomainScope Test Old Root'],
      'the cross-signed copy reaches the root every store trusts');
    assert.deepEqual(r.standing.trusted, STORES);
  });

  test('a root without a key id (TWCA Global Root CA): a complete file stays complete, a leaf alone chains to it, its cross-signed copy never wins', async () => {
    const { store } = diskStore();
    const table = keylessRoots();
    const fake = { ...store, roots: async () => table };
    const old = table.roots.find((r) => r.name === 'DomainScope Test Old Root');
    // leaf + the CA the keyless root issued: complete, every store trusts it, nothing to warn about
    const complete = await repairChain(load('chainfix_leaf.pem', 'chainfix_inter_cross.pem'), { store: fake, now: NOW });
    assert.equal(complete.status, 'complete');
    assert.equal(complete.root, old);
    assert.deepEqual(complete.added, []);
    assert.deepEqual(complete.standing.trusted, STORES);
    assert.deepEqual(complete.standing.warnings, []);
    // … as the server sends it, with the root's cross-signature by the root Chrome removed:
    // the keyless root is where every store stops, the removed one behind it says nothing
    const served = await repairChain(load('chainfix_leaf.pem', 'chainfix_inter_cross.pem', 'chainfix_old_root_cross.pem'), { store: fake, now: NOW });
    assert.equal(served.status, 'complete');
    assert.deepEqual(served.anchors.map((a) => a.name), ['DomainScope Test Old Root', 'DomainScope Test Root CA']);
    assert.ok(STORES.every((s) => served.standing.stores[s].root === old));
    assert.deepEqual(served.standing.trusted, STORES);
    assert.deepEqual(served.standing.warnings, []);
    // a leaf alone: the CA under the keyless root, not the one under the removed root, and not
    // the way through the keyless root's cross-signature
    const alone = await repairChain(load('chainfix_leaf.pem'), { store: fake, now: NOW });
    assert.equal(alone.status, 'repaired');
    assert.equal(alone.reason, 'missing');
    assert.deepEqual(alone.added.map((a) => `${a.cert.subjectCN} ← ${a.cert.issuerCN}`), ['DomainScope Test Issuing CA ← DomainScope Test Old Root']);
    assert.equal(alone.root, old);
    assert.deepEqual(alone.standing.trusted, STORES);
    assert.deepEqual(alone.standing.warnings, []);
  });

  test('no known root above: the shortest partial way is added, root unknown', async () => {
    const { store } = diskStore();
    const fake = { ...store, roots: async () => rootTable({ roots: [], events: [] }) };
    const r = await repairChain(load('chainfix_leaf.pem'), { store: fake, now: NOW });
    assert.equal(r.status, 'repaired');
    assert.equal(r.root, null);
    assert.equal(r.standing, null);
    assert.deepEqual(r.added.map((a) => `${a.cert.subjectCN} ← ${a.cert.issuerCN}`), ['DomainScope Test Issuing CA ← DomainScope Test Root CA']);
  });

  test('never more than MAX_ADDED certificates, and a loop of cross-signatures ends', async () => {
    assert.equal(MAX_ADDED, 4);
    const day = (d) => new Date(`${d}T00:00:00Z`);
    const ca = (n, parent) => ({
      subjectDN: `CN=CA ${n}`, issuerDN: `CN=CA ${parent}`, subjectKeyId: `a${n}`, authorityKeyId: `a${parent}`, serialHex: String(n),
      selfSigned: false, isCA: true, notBefore: day('2025-01-01'), notAfter: day('2035-01-01'), scts: []
    });
    const leaf = { ...ca(0, 1), subjectDN: 'CN=www.example.com', isCA: false };
    const manifest = async () => ({ format: 1, generated: '2026-09-28', shards: { ski: { dir: 'ski', digits: 2 }, dn: { dir: 'dn', digits: 1 } } });
    const roots = async () => rootTable({ roots: [], events: [] });
    // A ladder of ten CAs, each issued by the next: the search stops after MAX_ADDED.
    const ladder = { manifest, roots, byDn: async () => [], bySki: async (ski) => [{ cert: ca(Number(ski.slice(1)), Number(ski.slice(1)) + 1), owner: 'Test' }] };
    const long = await repairChain({ certificates: [leaf], leaf }, { store: ladder, now: NOW });
    assert.equal(long.added.length, MAX_ADDED);
    // CA 1 and CA 2 cross-signed by each other: the loop ends.
    const loop = { manifest, roots, byDn: async () => [], bySki: async (ski) => [{ cert: ski === 'a1' ? ca(1, 2) : ca(2, 1), owner: 'Test' }] };
    const r = await repairChain({ certificates: [leaf], leaf }, { store: loop, now: NOW });
    assert.deepEqual(r.added.map((a) => a.cert.subjectDN), ['CN=CA 1', 'CN=CA 2'], 'each certificate once');
  });

  test('a failed download rejects, and the next call fetches again', async () => {
    const { store, state } = diskStore();
    state.fail = 1;
    await assert.rejects(repairChain(load('chainfix_leaf.pem'), { store, now: NOW }), /Failed to fetch/);
    const r = await repairChain(load('chainfix_leaf.pem'), { store, now: NOW });
    assert.equal(r.status, 'repaired');
  });

  test('an unknown dataset format is refused; an aborted repair stops', async () => {
    const odd = createIntermediateStore({ url: MANIFEST, fetchImpl: async () => new Response('{"format":99}') });
    await assert.rejects(repairChain(load('chainfix_leaf.pem'), { store: odd, now: NOW }), /unsupported dataset format 99/);
    const { store } = diskStore();
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(repairChain(load('chainfix_leaf.pem'), { store, now: NOW, signal: ctl.signal }), (err) => err.name === 'AbortError');
  });

  test('a damaged entry in a shard is skipped', async () => {
    const leaf = load('chainfix_leaf.pem').leaf;
    const shard = leaf.authorityKeyId.slice(0, 2);
    const { store: base } = diskStore();
    const manifest = await base.manifest();
    const fetchImpl = async (url) => {
      if (url.endsWith(`ski/${shard}.json`)) return new Response(JSON.stringify({ [leaf.authorityKeyId]: [{ owner: 'X', der: 'AAAA' }] }));
      if (url.endsWith('manifest.json')) return new Response(JSON.stringify(manifest));
      return new Response(readFileSync(fileURLToPath(url)));
    };
    const store = createIntermediateStore({ url: pathToFileURL(fileURLToPath(MANIFEST)).href, fetchImpl });
    const r = await repairChain(load('chainfix_leaf.pem'), { store, now: NOW });
    assert.equal(r.status, 'not-found');
  });
});
