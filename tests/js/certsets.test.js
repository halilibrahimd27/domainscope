// Unit tests for assets/js/lib/certsets.js — several certificates renewed together (SSL Targets'
// renewal week): leaves from several files, grouping into sets, the set each name gets, the
// server × set plan over a ScanResult, the CSV work list and the CLI's --cert file names.
// Pure: fixtures from tests/fixtures (renew_*.pem: an RSA + ECDSA pair for example.com and
// *.example.com, and one certificate for shop.example.com / pay.example.com), hand-built scans.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parseCertificates, leafCertificates } from '../../assets/js/lib/x509.js';
import { toCsv } from '../../assets/js/lib/export.js';
import {
  SKIP_ISSUES, WORKLIST_COLUMNS, assignSet, certSetsJson, cliCertFiles, groupCertSets, keyTypeOf, planRenewal,
  fileForLeaf, primaryFile, renewalBundle, replacedLeaves, setId, setOfName, withoutLeaf, workListRows, leafKey
} from '../../assets/js/lib/certsets.js';

const read = (f) => readFileSync(new URL(`../fixtures/${f}`, import.meta.url));
const load = (f, name = f) => ({ name, result: parseCertificates(read(f)) });
const RSA_A = 'renew_a_rsa.pem';
const EC_A = 'renew_a_ecdsa.pem';
const RSA_B = 'renew_b_rsa.pem';
const three = () => renewalBundle([load(RSA_A), load(EC_A), load(RSA_B)]);

/** A set built by hand (names + notAfter), for the assignment rules. */
const fakeSet = (id, names, notAfter) => ({ id, names, leaves: [], certs: [], keyTypes: [], files: [], notAfter: new Date(notAfter), expires: new Date(notAfter) });

describe('lib/x509 leafCertificates', () => {
  test('a chain gives its one leaf, CA certificates none, pasted PEM blocks each leaf', () => {
    assert.equal(leafCertificates(parseCertificates(read('chain.pem')).certificates).length, 1);
    assert.equal(leafCertificates(parseCertificates(read('chain_reversed.pem')).certificates)[0].subjectCN, 'www.example-test.com.tr');
    assert.deepEqual(leafCertificates(parseCertificates(read('ca.pem')).certificates), []);
    const pasted = `${read(RSA_A)}\n${read(EC_A)}`;
    const r = parseCertificates(pasted);
    assert.deepEqual(leafCertificates(r.certificates).map((c) => c.keyAlgorithm), ['RSA', 'EC']);
    assert.equal(r.leaf, r.certificates[0], 'parseCertificates still picks the first leaf');
    assert.deepEqual(leafCertificates(null), []);
  });

  test('self-signed twins with the same subject and no key ids are both leaves, neither the CA of the other', () => {
    const selfSigned = (keyAlgorithm) => ({ subjectDN: 'CN=example.com', issuerDN: 'CN=example.com', isCA: false, keyAlgorithm,
      subjectKeyId: null, authorityKeyId: null });
    const twins = [selfSigned('RSA'), selfSigned('EC')];
    assert.deepEqual(leafCertificates(twins).map((c) => c.keyAlgorithm), ['RSA', 'EC']);
    // a CA still issues: a v1-style root (no basic constraints, so not isCA) keeps out of the leaves
    const root = { subjectDN: 'CN=Test Root', issuerDN: 'CN=Test Root', isCA: false, subjectKeyId: null, authorityKeyId: null };
    const leaf = { subjectDN: 'CN=www.example.com', issuerDN: 'CN=Test Root', isCA: false, subjectKeyId: null, authorityKeyId: null };
    assert.deepEqual(leafCertificates([root, leaf]), [leaf]);
    const ca = { subjectDN: 'CN=example.com', issuerDN: 'CN=example.com', isCA: true, subjectKeyId: null, authorityKeyId: null };
    assert.deepEqual(leafCertificates([ca, twins[0]]), [twins[0]], 'a self-signed CA with the same name is no leaf');
    // twins whose key ids name their own keys; a self-issued certificate whose key id names the other's key was issued by it
    const own = (keyAlgorithm, id) => ({ ...selfSigned(keyAlgorithm), subjectKeyId: id, authorityKeyId: id });
    assert.equal(leafCertificates([own('RSA', 'aa'), own('EC', 'bb')]).length, 2);
    const rolled = { ...own('RSA', 'cc'), authorityKeyId: 'aa' };
    assert.deepEqual(leafCertificates([own('RSA', 'aa'), rolled]), [rolled]);
  });
});

describe('keyTypeOf / setId', () => {
  test('technical key labels and file slugs', () => {
    assert.deepEqual(keyTypeOf({ keyAlgorithm: 'RSA', keyBits: 2048 }), { label: 'RSA 2048', slug: 'rsa' });
    assert.deepEqual(keyTypeOf({ keyAlgorithm: 'EC', keyBits: 256, curve: 'P-256' }), { label: 'ECDSA P-256', slug: 'ecdsa' });
    assert.deepEqual(keyTypeOf({ keyAlgorithm: 'EC', keyBits: 256, curve: null }), { label: 'ECDSA 256', slug: 'ecdsa' });
    assert.deepEqual(keyTypeOf({ keyAlgorithm: 'Ed25519' }), { label: 'Ed25519', slug: 'ed25519' });
    assert.deepEqual(keyTypeOf({ keyAlgorithm: 'DSA', keyBits: 2048 }), { label: 'DSA 2048', slug: 'dsa' });
    assert.deepEqual(keyTypeOf({ keyAlgorithm: 'unknown' }), { label: 'unknown', slug: 'cert' });
  });

  test('set ids count like spreadsheet columns', () => {
    assert.deepEqual([0, 1, 25, 26, 27, 51, 52, 701, 702].map(setId), ['A', 'B', 'Z', 'AA', 'AB', 'AZ', 'BA', 'ZZ', 'AAA']);
  });
});

describe('renewalBundle — leaves and sets', () => {
  test('an RSA + ECDSA pair for the same names is one set; another name set is the next', () => {
    const b = three();
    assert.equal(b.leaves.length, 3);
    assert.deepEqual(b.sets.map((s) => s.id), ['A', 'B']);
    const [a, bb] = b.sets;
    assert.deepEqual(a.names, ['example.com', '*.example.com']);
    assert.deepEqual(a.keyTypes, ['RSA 2048', 'ECDSA P-256']);
    assert.deepEqual(a.files, [RSA_A, EC_A]);
    assert.equal(a.certs.length, 2);
    assert.equal(a.notAfter.toISOString(), '2036-09-01T00:00:00.000Z');
    assert.deepEqual(bb.names, ['pay.example.com', 'shop.example.com']);
    assert.deepEqual(bb.keyTypes, ['RSA 2048']);
    assert.equal(bb.expires.toISOString(), '2036-06-01T00:00:00.000Z');
    assert.deepEqual(b.skipped, []);
    assert.equal(b.duplicates, 0);
    assert.equal(b.leaves[1].keySlug, 'ecdsa');
  });

  test('several PEM blocks pasted at once give every leaf; sets in the order pasted, a set\'s certificates by key type', () => {
    const text = [RSA_B, EC_A, RSA_A].map((f) => read(f).toString('utf8')).join('\n');
    const b = renewalBundle([{ name: 'pasted', result: parseCertificates(text) }]);
    assert.deepEqual(b.sets.map((s) => [s.id, s.names[0], s.keyTypes.join('+')]),
      [['A', 'pay.example.com', 'RSA 2048'], ['B', 'example.com', 'RSA 2048+ECDSA P-256']]);
    assert.deepEqual(b.sets[1].files, ['pasted']);
    assert.deepEqual(b.leaves.map((l) => l.keySlug), ['rsa', 'ecdsa', 'rsa'], 'leaves stay in load order');
    // a folder lists files by name: the ECDSA twin before the RSA one, the same set either way
    const folder = renewalBundle([load(EC_A, 'a-ecdsa.pem'), load(RSA_A, 'a-rsa.pem')]);
    assert.deepEqual(folder.sets[0].keyTypes, ['RSA 2048', 'ECDSA P-256']);
    assert.deepEqual(folder.sets[0].files, ['a-rsa.pem', 'a-ecdsa.pem']);
    assert.deepEqual(cliCertFiles(folder.sets).map((f) => f.file), ['new-cert-a-rsa.pem', 'new-cert-a-ecdsa.pem']);
  });

  test('the same certificate from two files is one leaf with both file names (a folder with cert.pem and fullchain.pem)', () => {
    const b = renewalBundle([load(RSA_A, 'cert.pem'), load(RSA_A, 'fullchain.pem'), load(EC_A)]);
    assert.equal(b.leaves.length, 2);
    assert.deepEqual(b.leaves[0].files, ['cert.pem', 'fullchain.pem']);
    assert.equal(b.duplicates, 1);
    assert.deepEqual(b.sets[0].files, ['cert.pem', 'fullchain.pem', EC_A]);
  });

  test('files that add no certificate are listed with the reason; a chain\'s CA certificates are kept apart', () => {
    const b = renewalBundle([
      load('ec_wildcard.key', 'privkey.pem'), load('ca.pem', 'chain.pem'), load('x509_v1_legacy.pem'), load('chain.pem', 'fullchain.pem'),
      null, { name: 'odd' }
    ]);
    assert.deepEqual(b.skipped.map((s) => [s.file, s.issue]), [
      ['privkey.pem', 'no-certificate'], ['chain.pem', 'ca-only'], ['x509_v1_legacy.pem', 'no-names'], ['odd', 'no-certificate']
    ]);
    assert.deepEqual(b.skipped[0].codes, ['PRIVATE_KEY_PRESENT', 'NO_CERTIFICATE']);
    assert.equal(b.skipped[1].count, 1);
    for (const s of b.skipped) assert.ok(SKIP_ISSUES.includes(s.issue), s.issue);
    assert.equal(b.leaves.length, 1);
    assert.equal(b.chain.length, 1, 'the root from chain.pem and fullchain.pem is one chain certificate');
    assert.ok(b.chain[0].isCA);
  });

  test('withoutLeaf removes one certificate from every file; a file left without a leaf goes, one that never had one stays', () => {
    const pasted = { name: 'pasted', result: parseCertificates(`${read(RSA_A)}\n${read(EC_A)}`) };
    const files = [load('ec_wildcard.key', 'privkey.pem'), pasted, load(RSA_A, 'cert.pem'), load('chain.pem', 'fullchain.pem')];
    const b = renewalBundle(files);
    const rsaKey = b.leaves.find((l) => l.keySlug === 'rsa' && l.names[0] === 'example.com').key;
    const next = withoutLeaf(files, rsaKey);
    assert.deepEqual(next.map((f) => f.name), ['privkey.pem', 'pasted', 'fullchain.pem'], 'cert.pem held only that leaf');
    assert.equal(next[0], files[0]);
    assert.notEqual(next[1], files[1], 'a changed file is a copy');
    assert.deepEqual(next[1].result.certificates.map((c) => c.keyAlgorithm), ['EC']);
    assert.equal(next[1].result.leaf.keyAlgorithm, 'EC');
    assert.equal(files[1].result.certificates.length, 2, 'the input is not mutated');
    assert.equal(renewalBundle(next).leaves.length, 2);
    // the leaf of fullchain.pem: its root alone adds nothing, so the file goes
    const chainKey = renewalBundle([files[3]]).leaves[0].key;
    assert.deepEqual(withoutLeaf(files, chainKey).map((f) => f.name), ['privkey.pem', 'pasted', 'cert.pem']);
    assert.equal(leafKey(files[2].result.leaf), rsaKey);
    assert.deepEqual(withoutLeaf(null, 'x'), []);
  });

  test('skipped entries say which file (index) or leaf (key) to remove', () => {
    const files = [load(RSA_A), load('ec_wildcard.key', 'privkey.pem'), load('x509_v1_legacy.pem', 'legacy.pem')];
    const { skipped } = renewalBundle(files);
    assert.deepEqual(skipped.map((s) => [s.file, s.index, s.issue]), [['privkey.pem', 1, 'no-certificate'], ['legacy.pem', 2, 'no-names']]);
    assert.equal(typeof skipped[1].key, 'string');
    assert.deepEqual(withoutLeaf(files, skipped[1].key).map((f) => f.name), [RSA_A, 'privkey.pem']);
  });

  test('fileForLeaf: the file itself when it shows that leaf, else a copy with it as the leaf and the chain', () => {
    const pasted = { name: 'pasted', source: 'paste', result: parseCertificates(`${read(RSA_A)}\n${read(EC_A)}\n${read('ca.pem')}`) };
    const b = renewalBundle([pasted]);
    const [rsa, ec] = b.leaves;
    assert.equal(fileForLeaf([pasted], rsa.key), pasted);
    const copy = fileForLeaf([pasted], ec.key);
    assert.notEqual(copy, pasted);
    assert.deepEqual([copy.name, copy.source], ['pasted', 'paste']);
    assert.equal(copy.result.leaf.keyAlgorithm, 'EC');
    assert.deepEqual(copy.result.certificates.map((c) => (c.isCA ? 'CA' : c.keyAlgorithm)), ['EC', 'CA'], 'the chain stays, the other leaf goes');
    assert.equal(fileForLeaf([pasted], 'nope'), null);
  });

  test('primaryFile: the first file with a leaf, else the first', () => {
    const key = load('ec_wildcard.key', 'privkey.pem');
    const a = load(RSA_A);
    assert.equal(primaryFile([key, a]), a);
    assert.equal(primaryFile([key]), key);
    assert.equal(primaryFile([load('ca.pem'), a]), a);
    assert.equal(primaryFile([]), null);
  });

  test('nothing loaded, nothing to group', () => {
    assert.deepEqual(renewalBundle([]), { leaves: [], sets: [], chain: [], skipped: [], unread: [], replaced: [], duplicates: 0, keyFiles: [] });
    assert.deepEqual(renewalBundle([load('with_key.pem'), load('ec_wildcard.key')]).keyFiles, ['with_key.pem'], 'a key file without a certificate is a skipped file instead');
    assert.deepEqual(renewalBundle(null).sets, []);
    assert.deepEqual(groupCertSets([{ names: [] }, null]), []);
  });
});

describe('renewalBundle — what could make a verdict wrong', () => {
  // cli_public_wild.pem (issued 2025, expires 2050) and its renewal cli_renewed_wild.pem (issued
  // 2026, expires 2052): ECDSA P-256, *.wild.example.net and wild.example.net both.
  const OLD = 'cli_public_wild.pem';
  const NEW = 'cli_renewed_wild.pem';

  test('last year\'s certificate next to its renewal: one set, the old one flagged and named -2 for the CLI', () => {
    for (const files of [[load(OLD), load(NEW)], [load(NEW), load(OLD)]]) {
      const b = renewalBundle(files);
      assert.equal(b.sets.length, 1);
      const [set] = b.sets;
      assert.deepEqual(set.leaves.map((l) => l.files[0]), [NEW, OLD], 'the newest first within one key type');
      assert.deepEqual(b.replaced.map((r) => [r.leaf.files[0], r.by.files[0], r.set, r.bySet]), [[OLD, NEW, 'A', 'A']]);
      assert.deepEqual(cliCertFiles(b.sets).map((f) => [f.file, f.leaf.files[0]]),
        [['new-cert-a-ecdsa.pem', NEW], ['new-cert-a-ecdsa-2.pem', OLD]]);
    }
    // an RSA + ECDSA pair and certificates for other names: nothing flagged
    assert.deepEqual(three().replaced, []);
    assert.deepEqual(renewalBundle([load(NEW), load(RSA_A), load(EC_A)]).replaced, []);
  });

  test('replacedLeaves: the same kind of key, every name in a newer leaf; the newest names it', () => {
    const leaf = (names, keySlug, notBefore, notAfter = '2030-01-01') => ({
      names, keySlug, files: [`${keySlug}-${notBefore}`], cert: { notBefore: new Date(notBefore), notAfter: new Date(notAfter) }
    });
    const flagged = (list) => replacedLeaves(list).map((r) => `${list.indexOf(r.leaf)}<${list.indexOf(r.by)}`);
    const old = leaf(['shop.example.com'], 'rsa', '2025-01-01');
    // another set: its names are a subset of a newer certificate's (a SAN list that grew)
    assert.deepEqual(flagged([old, leaf(['pay.example.com', 'shop.example.com'], 'rsa', '2026-01-01')]), ['0<1']);
    // an older certificate that names more is not replaced by one that names less
    assert.deepEqual(flagged([leaf(['pay.example.com', 'shop.example.com'], 'rsa', '2025-01-01'), leaf(['shop.example.com'], 'rsa', '2026-01-01')]), []);
    // another kind of key (the RSA + ECDSA pair) or a newer one issued earlier: never
    assert.deepEqual(flagged([old, leaf(['shop.example.com'], 'ecdsa', '2026-01-01')]), []);
    assert.deepEqual(flagged([leaf(['shop.example.com'], 'rsa', '2026-01-01'), old]), ['1<0']);
    // names are compared as they are: a wildcard covering the name is another name
    assert.deepEqual(flagged([leaf(['www.example.com'], 'rsa', '2025-01-01'), leaf(['*.example.com'], 'rsa', '2026-01-01')]), []);
    // the same notBefore: the later notAfter is the newer one
    assert.deepEqual(flagged([leaf(['a.example.com'], 'rsa', '2026-01-01', '2027-01-01'), leaf(['a.example.com'], 'rsa', '2026-01-01', '2026-06-01')]), ['1<0']);
    // the same names and dates: the one loaded later; nested names with the same dates: neither
    assert.deepEqual(flagged([leaf(['a.example.com'], 'rsa', '2026-01-01'), leaf(['a.example.com'], 'rsa', '2026-01-01')]), ['1<0']);
    assert.deepEqual(flagged([leaf(['a.example.com'], 'rsa', '2026-01-01'), leaf(['a.example.com', 'b.example.com'], 'rsa', '2026-01-01')]), []);
    // three generations: each older one names the newest
    assert.deepEqual(flagged([old, leaf(['shop.example.com'], 'rsa', '2026-01-01'), leaf(['shop.example.com'], 'rsa', '2027-01-01')]), ['0<2', '1<2']);
    assert.deepEqual(replacedLeaves(null), []);
  });

  test('a damaged PEM block next to good ones: the good ones load, the file is listed as read in part', () => {
    // renew_b_rsa.pem with four lines of its base64 cut out: the third block is truncated
    const lines = read(RSA_B).toString('utf8').trim().split('\n');
    const damaged = [...lines.slice(0, 4), ...lines.slice(8)].join('\n');
    const text = [read(RSA_A).toString('utf8'), read(EC_A).toString('utf8'), damaged].join('\n');
    const b = renewalBundle([load('ec_wildcard.key', 'privkey.pem'), { name: 'Pasted text', result: parseCertificates(text) }]);
    assert.deepEqual([b.leaves.length, b.sets.length], [2, 1]);
    assert.deepEqual(b.unread.map((u) => [u.file, u.index, u.details.length]), [['Pasted text', 1, 1]]);
    assert.match(b.unread[0].details[0], /^PEM block 3 \(CERTIFICATE\): /);
    assert.deepEqual(b.skipped.map((s) => s.file), ['privkey.pem'], 'a file without a certificate is still "not used", not "read in part"');
    assert.deepEqual(three().unread, []);
  });
});

describe('assignSet — the set each name gets', () => {
  test('an exact name before a wildcard, whatever the load order', () => {
    const { sets } = three();
    const id = (n) => (assignSet(n, sets) || { set: { id: null } }).set.id;
    assert.equal(id('shop.example.com'), 'B', 'exact in B beats *.example.com in A');
    assert.equal(id('pay.example.com'), 'B');
    assert.equal(id('www.example.com'), 'A');
    assert.equal(id('example.com'), 'A');
    assert.equal(id('WWW.Example.COM'), 'A');
    assert.equal(id('a.dev.example.com'), null, 'a wildcard covers one label only');
    assert.equal(id('example.net'), null);
    assert.deepEqual(Object.keys(assignSet('shop.example.com', sets)).sort(), ['by', 'exact', 'set']);
    assert.equal(assignSet('shop.example.com', sets).exact, true);
    assert.deepEqual([assignSet('www.example.com', sets).by, assignSet('www.example.com', sets).exact], ['*.example.com', false]);
    const reversed = [...sets].reverse();
    assert.equal(assignSet('shop.example.com', reversed).set.id, 'B');
  });

  test('two sets with the same wildcard: the one that expires last, then the one loaded first', () => {
    const older = fakeSet('A', ['*.example.com', 'example.com'], '2027-01-01');
    const newer = fakeSet('B', ['*.example.com', 'example.org'], '2027-06-01');
    assert.equal(assignSet('www.example.com', [older, newer]).set.id, 'B');
    assert.equal(assignSet('www.example.com', [newer, older]).set.id, 'B');
    const twin = fakeSet('C', ['*.example.com', 'example.net'], '2027-06-01');
    assert.equal(assignSet('www.example.com', [newer, twin]).set.id, 'B');
    assert.equal(assignSet('www.example.com', [twin, newer]).set.id, 'C');
    // an older certificate naming it exactly still wins over a newer wildcard
    const exactOld = fakeSet('D', ['www.example.com'], '2026-01-01');
    assert.equal(assignSet('www.example.com', [newer, exactOld]).set.id, 'D');
  });

  test('setOfName memoises the lookup and says null for an uncovered name', () => {
    const { sets } = three();
    const of = setOfName(sets);
    assert.equal(of('shop.example.com'), 'B');
    assert.equal(of('www.example.com'), 'A');
    assert.equal(of('x.example.net'), null);
    assert.equal(of(undefined), null);
  });
});

/** A small scan of example.com: two inventory servers, an address outside the inventory. */
function scan() {
  const host = (name, ipv4, extra = {}) => ({
    name, origins: ['wordlist'], resolution: { status: ipv4.length ? 'NOERROR' : 'NXDOMAIN', ipv4, ipv6: [], cnames: [] },
    classification: { kind: 'direct' }, cert: null, servers: [], wildcardSuspect: false, ...extra
  });
  const web01 = { id: 'w1', name: 'web01', ips: ['203.0.113.10'], groups: ['web'] };
  const web02 = { id: 'w2', name: 'web02', ips: ['203.0.113.20'], groups: [] };
  return {
    hosts: [
      host('example.com', ['203.0.113.10'], { servers: [{ serverId: 'w1', name: 'web01', ip: '203.0.113.10' }] }),
      host('www.example.com', ['203.0.113.10'], { servers: [{ serverId: 'w1', name: 'web01', ip: '203.0.113.10' }] }),
      host('shop.example.com', ['203.0.113.20'], { servers: [{ serverId: 'w2', name: 'web02', ip: '203.0.113.20' }] }),
      host('api.example.com', ['198.51.100.7']),
      // proxied: an origin hint ties it to web01
      host('pay.example.com', ['104.16.1.1'], { classification: { kind: 'cloudflare', hidesOrigin: true } }),
      host('x.dev.example.com', ['203.0.113.10'], { servers: [{ serverId: 'w1', name: 'web01', ip: '203.0.113.10' }] }),
      host('old.dev.example.com', []),
      host('ghost.example.com', ['203.0.113.10'], { wildcardSuspect: true })
    ],
    servers: [
      {
        server: web01, needsCert: true,
        hosts: [
          { name: 'example.com', ip: '203.0.113.10', covered: true, via: 'dns' },
          { name: 'www.example.com', ip: '203.0.113.10', covered: true, via: 'dns' },
          { name: 'ghost.example.com', ip: '203.0.113.10', covered: true, via: 'dns' },
          { name: 'x.dev.example.com', ip: '203.0.113.10', covered: false, via: 'dns' },
          { name: 'pay.example.com', ip: '203.0.113.10', covered: true, via: 'hint' }
        ]
      },
      {
        server: web02, needsCert: true,
        hosts: [
          { name: 'shop.example.com', ip: '203.0.113.20', covered: true, via: 'hint' },
          { name: 'shop.example.com', ip: '203.0.113.20', covered: true, via: 'dns' }
        ]
      },
      { server: { id: 'db', name: 'db01', ips: ['10.0.0.5'] }, needsCert: false, hosts: [{ name: 'x.dev.example.com', ip: '10.0.0.5', covered: false, via: 'dns' }] }
    ],
    unmatchedIps: [{ ip: '198.51.100.7', hosts: ['api.example.com'], provider: null, private: false }]
  };
}

describe('planRenewal — the server × set matrix', () => {
  test('rows are your servers (then outside addresses), cells the names each needs from each set', () => {
    const { sets } = three();
    const plan = planRenewal(scan(), sets);
    assert.deepEqual(plan.rows.map((r) => r.key), ['s:w1', 's:w2', 'ip:198.51.100.7']);
    const [w1, w2, out] = plan.rows;
    assert.deepEqual(Object.keys(w1.cells).sort(), ['A', 'B']);
    assert.deepEqual(w1.cells.A.map((e) => [e.name, e.ips.join(), e.via]), [['example.com', '203.0.113.10', 'dns'], ['www.example.com', '203.0.113.10', 'dns']]);
    assert.deepEqual(w1.cells.B.map((e) => [e.name, e.via]), [['pay.example.com', 'hint']], 'an origin hint stays a candidate');
    assert.equal(w1.needsCert, true);
    assert.equal(w1.maybe, false);
    assert.deepEqual(w1.server, { id: 'w1', name: 'web01', ips: ['203.0.113.10'], groups: ['web'] });
    assert.deepEqual(w2.cells.B.map((e) => [e.name, e.via]), [['shop.example.com', 'dns']], 'the DNS match outranks the hint for the same name');
    assert.equal(w2.cells.A, undefined, 'shop is B\'s exact name, not A\'s wildcard');
    assert.deepEqual([out.server, out.ip, out.private, out.cells.A.map((e) => e.name)], [null, '198.51.100.7', false, ['api.example.com']]);
    // an address outside the inventory is a row, not one of your servers
    assert.deepEqual(plan.perSet, { A: { names: 3, rows: 2, servers: 1, addresses: 1 }, B: { names: 2, rows: 2, servers: 2, addresses: 0 } });
  });

  test('the names no certificate covers: on your servers first, then resolving ones; wildcard look-alikes left out', () => {
    const plan = planRenewal(scan(), three().sets);
    assert.deepEqual(plan.uncovered.map((u) => [u.name, u.servers.map((s) => s.name).join(), u.resolving]), [
      ['x.dev.example.com', 'web01', true], ['old.dev.example.com', '', false]
    ]);
    assert.ok(!plan.assigned.has('ghost.example.com'));
    assert.deepEqual(plan.assigned.get('shop.example.com'), { set: 'B', by: 'shop.example.com', exact: true });
    assert.deepEqual(plan.assigned.get('www.example.com'), { set: 'A', by: '*.example.com', exact: false });
  });

  test('a server reached only through origin hints is a "maybe" row; no sets, no rows', () => {
    const s = scan();
    s.servers = [{ server: { id: 'h', name: 'origin1', ips: ['203.0.113.30'] }, needsCert: false, hosts: [{ name: 'www.example.com', ip: '203.0.113.30', covered: true, via: 'hint' }] }];
    s.unmatchedIps = [];
    const plan = planRenewal(s, three().sets);
    assert.deepEqual(plan.rows.map((r) => [r.key, r.needsCert, r.maybe]), [['s:h', false, true]]);
    const empty = planRenewal(s, []);
    assert.deepEqual(empty.rows, []);
    assert.equal(empty.uncovered.length, 7);
    assert.deepEqual(planRenewal(null, null).rows, []);
  });
});

describe('workListRows — the CSV work list', () => {
  test('one row per server and set, with names, candidates, key types and files', () => {
    const plan = planRenewal(scan(), three().sets);
    const rows = workListRows(plan);
    assert.deepEqual(rows.map((r) => [r.server, r.ip.join(' '), r.set, r.names.join(' '), r.candidates.join(' ')]), [
      ['web01', '203.0.113.10', 'A', 'example.com www.example.com', ''],
      ['web01', '203.0.113.10', 'B', '', 'pay.example.com'],
      ['web02', '203.0.113.20', 'B', 'shop.example.com', ''],
      ['', '198.51.100.7', 'A', 'api.example.com', '']
    ]);
    assert.deepEqual(rows[0].keyTypes, ['RSA 2048', 'ECDSA P-256']);
    assert.deepEqual(rows[0].files, [RSA_A, EC_A]);
    assert.deepEqual(rows[0].setNames, ['example.com', '*.example.com']);
    const csv = toCsv(rows, WORKLIST_COLUMNS, { bom: false });
    const [header, first] = csv.split('\r\n');
    assert.equal(header, 'Server,IP,Names,Possible origin names,Certificate set,Key types,Expires,Files');
    // key types and file names hold spaces: joined with " + " and "; ", so each stays whole
    assert.equal(first, 'web01,203.0.113.10,example.com www.example.com,,A,RSA 2048 + ECDSA P-256,2036-09-01T00:00:00.000Z,renew_a_rsa.pem; renew_a_ecdsa.pem');
    const spaced = toCsv([{ ...rows[0], files: ['example.com RSA.pem', 'cert (1).pem'] }], WORKLIST_COLUMNS, { bom: false });
    assert.match(spaced.split('\r\n')[1], /,example\.com RSA\.pem; cert \(1\)\.pem$/);
    assert.deepEqual(workListRows(null), []);
  });
});

describe('cliCertFiles / certSetsJson', () => {
  test('one plain --cert file per certificate: set and key type in the name', () => {
    const files = cliCertFiles(three().sets);
    assert.deepEqual(files.map((f) => [f.file, f.set]), [['new-cert-a-rsa.pem', 'A'], ['new-cert-a-ecdsa.pem', 'A'], ['new-cert-b-rsa.pem', 'B']]);
    assert.equal(files[1].leaf.keyType, 'ECDSA P-256');
    for (const f of files) assert.match(f.file, /^[a-z0-9.-]+$/);
    // two RSA certificates for the same names (a re-issue loaded with the original)
    const twin = { ...three().sets[0], leaves: [{ keySlug: 'rsa' }, { keySlug: 'rsa' }, { keySlug: 'rsa' }] };
    assert.deepEqual(cliCertFiles([twin]).map((f) => f.file), ['new-cert-a-rsa.pem', 'new-cert-a-rsa-2.pem', 'new-cert-a-rsa-3.pem']);
    assert.deepEqual(cliCertFiles(null), []);
  });

  test('the JSON form names each certificate without its DER', () => {
    const json = certSetsJson(three().sets);
    assert.equal(json.length, 2);
    assert.deepEqual(Object.keys(json[0]), ['id', 'names', 'keyTypes', 'expires', 'certificates']);
    assert.deepEqual(json[0].certificates.map((c) => [c.keyType, c.files.join()]), [['RSA 2048', RSA_A], ['ECDSA P-256', EC_A]]);
    assert.ok(!JSON.stringify(json).includes('"der"'));
    assert.match(json[0].certificates[0].issuer, /DomainScope Test Renewal CA/);
  });
});
