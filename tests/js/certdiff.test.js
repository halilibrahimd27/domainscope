/**
 * certdiff.test.js — lib/certdiff.js (old-vs-new certificate comparison) over the
 * tests/fixtures/certdiff_*.pem pair (gen_certdiff_fixtures.mjs), plus single rules on parsed
 * fixture certificates with one field changed, and the panel's words (ui/cert-diff-panel.js).
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parseCertificates } from '../../assets/js/lib/x509.js';
import {
  compareCertificates, diffCertificates, chainAbove, keyLabel, olderOf,
  CERTDIFF_AREAS, CERTDIFF_AREA, CERTDIFF_CODES, CERTDIFF_SEVERITIES, CERTDIFF_SEVERITY, CERTDIFF_VERDICTS
} from '../../assets/js/lib/certdiff.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const parse = (file) => parseCertificates(readFileSync(join(FIXTURES, file)));
const side = (file) => {
  const r = parse(file);
  return { cert: r.leaf, chain: r.certificates };
};
const NOW = new Date('2026-10-08T12:00:00Z');
const OLD = side('certdiff_old.pem');
const NEW = side('certdiff_new.pem');
const RENEWED = side('certdiff_renewed.pem');
const codes = (d) => d.changes.map((c) => c.code);
const change = (d, code) => d.changes.find((c) => c.code === code);
const spkiHex = (s) => createHash('sha256').update(s.cert.spkiDer).digest('hex');
/** The old certificate with some fields changed (a leaf alone unless `chain` is given). */
const tweak = (base, over, chain = null) => ({ cert: { ...base.cert, ...over }, chain: chain || [] });
const diff = (o, n, now = NOW) => compareCertificates(o, n, { now });
/** The old certificate's extensions without the one with this OID. */
const without = (oid) => OLD.cert.extensions.filter((e) => e.oid !== oid);

test('the codes, severities, areas and verdicts are frozen and consistent', () => {
  for (const arr of [CERTDIFF_CODES, CERTDIFF_SEVERITIES, CERTDIFF_AREAS, CERTDIFF_VERDICTS]) assert.ok(Object.isFrozen(arr));
  assert.deepEqual(CERTDIFF_SEVERITIES, ['blocker', 'action', 'check', 'info']);
  assert.equal(new Set(CERTDIFF_CODES).size, CERTDIFF_CODES.length, 'no duplicate code');
  for (const code of CERTDIFF_CODES) {
    assert.ok(CERTDIFF_SEVERITIES.includes(CERTDIFF_SEVERITY[code]), code);
    assert.ok(CERTDIFF_AREAS.includes(CERTDIFF_AREA[code]), code);
  }
  // The list is in impact order: every blocker before every action, and so on.
  const ranks = CERTDIFF_CODES.map((c) => CERTDIFF_SEVERITIES.indexOf(CERTDIFF_SEVERITY[c]));
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
});

test('the fixture pair: every difference, ordered by impact, and the verdict', async () => {
  const d = await diffCertificates(OLD, NEW, { now: NOW });
  assert.equal(d.verdict, 'blocked');
  assert.equal(d.identical, false);
  assert.deepEqual(codes(d), [
    'name-removed', 'wildcard-removed', 'eku-client-dropped',
    'issuer-changed', 'key-type', 'staple-added',
    'key-new', 'root-changed', 'sct-few', 'ocsp-changed',
    'name-added', 'lifetime', 'expires-sooner', 'sig-changed', 'ku-changed', 'crl-changed', 'aia-changed'
  ]);
  assert.deepEqual(d.counts, { blocker: 3, action: 3, check: 4, info: 7 });
  assert.deepEqual(d.unchanged, ['subject']);
  // names: the wildcard goes (www and api stay by name), legacy.example.net and the IP address go
  assert.deepEqual(change(d, 'name-removed').items, ['legacy.example.net', '192.0.2.10']);
  assert.deepEqual(change(d, 'wildcard-removed').params, { name: '*.example.com', kept: ['api.example.com', 'www.example.com'] });
  assert.deepEqual(change(d, 'name-added').items, ['shop.example.org'], 'www and api were covered by the old wildcard');
  // key: RSA → EC, a new key with both SPKI hashes
  assert.deepEqual(change(d, 'key-type').params, { from: 'RSA 2048', to: 'EC P-256', ec: true });
  assert.deepEqual(change(d, 'key-new').params, { from: spkiHex(OLD), to: spkiHex(NEW) });
  assert.deepEqual(d.key, { reused: false, old: spkiHex(OLD), new: spkiHex(NEW) });
  // issuer and chain: the new file brings its intermediate, under another root
  assert.deepEqual(change(d, 'issuer-changed').params, {
    from: 'DomainScope Test Diff CA 1', to: 'DomainScope Test Diff CA 2', chain: ['DomainScope Test Diff CA 2'], missing: false
  });
  assert.deepEqual(change(d, 'root-changed').params, { from: 'DomainScope Test Diff Root 1', to: 'DomainScope Test Diff Root 2' });
  assert.deepEqual(d.chain, { old: ['DomainScope Test Diff CA 1'], new: ['DomainScope Test Diff CA 2'] });
  // CT, OCSP and the other URLs
  assert.deepEqual(change(d, 'sct-few').params, { count: 2, need: 3 }, 'five years need 3 SCTs');
  assert.deepEqual(change(d, 'ocsp-changed').params, { from: ['http://ocsp.example.com'], to: ['http://ocsp.example.net'], hosts: ['ocsp.example.net'] });
  assert.deepEqual(change(d, 'staple-added').params, { ocsp: ['http://ocsp.example.net'] });
  assert.deepEqual(change(d, 'crl-changed').params, { removed: [], added: ['http://crl.example.com/diff-ca-2.crl'] });
  assert.deepEqual(change(d, 'aia-changed').params, { removed: ['http://ca.example.com/diff-ca-1.der'], added: ['http://ca.example.com/diff-ca-2.der'] });
  assert.deepEqual(change(d, 'ku-changed').params, { added: [], removed: ['keyEncipherment'] }, 'an EC key needs no keyEncipherment: no check');
  assert.deepEqual(change(d, 'sig-changed').params, { from: 'sha256WithRSAEncryption', to: 'ecdsa-with-SHA384' });
  // validity: the overlap to switch over in, days left, lifetimes
  assert.equal(d.validity.oldLifetimeDays, 3654);
  assert.equal(d.validity.newLifetimeDays, 1827);
  assert.deepEqual(change(d, 'lifetime').params, { from: 3654, to: 1827, shorter: true });
  assert.equal(d.validity.oldDaysLeft, 3432);
  assert.deepEqual(d.validity.overlap, { from: new Date('2026-09-01T00:00:00Z'), to: new Date('2031-09-01T23:59:59Z'), days: 1827 });
  assert.equal(d.validity.gap, null);
});

test('a renewal with the same key, names and issuer is safe to deploy everywhere', async () => {
  const d = await diffCertificates(OLD, RENEWED, { now: NOW });
  assert.equal(d.verdict, 'safe');
  assert.deepEqual(codes(d), ['key-reused']);
  assert.deepEqual(change(d, 'key-reused').params, { spki: spkiHex(OLD) });
  assert.deepEqual(d.unchanged, ['names', 'chain', 'signature', 'usage', 'ct', 'revocation', 'subject']);
  assert.deepEqual(d.chain, { old: ['DomainScope Test Diff CA 1'], new: [] }, 'a leaf alone: no chain to compare');
});

test('the same certificate twice is identical, with no change', async () => {
  const d = await diffCertificates(OLD, side('certdiff_old.pem'), { now: NOW });
  assert.equal(d.verdict, 'identical');
  assert.equal(d.identical, true);
  assert.deepEqual(d.changes, []);
  assert.equal(d.key.reused, true);
});

test('a rollback (the new pair the other way round) words the opposite changes', () => {
  const d = diff(NEW, OLD);
  assert.equal(d.verdict, 'blocked', 'www, api and shop are not named by the old one');
  assert.deepEqual(change(d, 'name-removed').items, ['shop.example.org']);
  assert.deepEqual(change(d, 'name-covered').items, [
    { name: 'api.example.com', by: '*.example.com' }, { name: 'www.example.com', by: '*.example.com' }
  ]);
  assert.deepEqual(change(d, 'key-type').params, { from: 'EC P-256', to: 'RSA 2048', ec: false });
  assert.ok(codes(d).includes('staple-removed'));
  assert.deepEqual(change(d, 'eku-changed').params, { added: ['clientAuth'], removed: [] });
  assert.equal(change(d, 'sct-count').params.to, 3);
  assert.ok(!codes(d).includes('lifetime') || change(d, 'lifetime').params.shorter === false);
});

test('identity: a precertificate, a CA certificate, a self-signed one', () => {
  assert.ok(codes(diff(OLD, tweak(OLD, { isPrecertificate: true, der: new Uint8Array([1]) }))).includes('precert'));
  assert.ok(codes(diff(OLD, tweak(OLD, { isCA: true, der: new Uint8Array([1]) }))).includes('new-is-ca'));
  const selfSigned = diff(OLD, tweak(OLD, { selfSigned: true, der: new Uint8Array([1]) }));
  assert.ok(codes(selfSigned).includes('self-signed'));
  assert.equal(selfSigned.verdict, 'blocked');
});

test('validity: expired, not valid yet, a gap, the old one expired', () => {
  const expired = diff(OLD, RENEWED, new Date('2037-01-01T00:00:00Z'));
  assert.deepEqual(change(expired, 'expired').params.date, RENEWED.cert.notAfter);
  assert.ok(codes(expired).includes('old-expired'));
  const early = diff(OLD, NEW, new Date('2026-08-01T00:00:00Z'));
  assert.deepEqual(change(early, 'not-yet-valid').params, { date: NEW.cert.notBefore, days: 31 });
  const gapNew = tweak(RENEWED, { notBefore: new Date('2036-03-11T00:00:00Z'), notAfter: new Date('2037-01-01T00:00:00Z'), der: new Uint8Array([2]) });
  const gap = diff(OLD, gapNew);
  assert.equal(change(gap, 'gap').params.days, 10);
  assert.equal(gap.validity.overlap, null);
  assert.ok(gap.validity.gap);
  const older = diff(OLD, RENEWED, new Date('2036-06-01T00:00:00Z'));
  assert.deepEqual(change(older, 'old-expired').params, { date: OLD.cert.notAfter, days: 91 });
  assert.ok(!codes(older).includes('expired'));
  assert.equal(older.validity.oldDaysLeft, -92, 'negative once expired (rounded down)');
});

test('names: a name kept only by a new wildcard, no SAN at all, an added wildcard', () => {
  const wild = tweak(OLD, { hostnames: ['*.example.net', 'example.com', '*.example.com', 'mail.example.org'], dnsNames: ['*.example.net', 'example.com', '*.example.com', 'mail.example.org'], ipAddresses: [], der: new Uint8Array([3]) });
  const d = diff(OLD, wild);
  assert.deepEqual(change(d, 'name-covered').items, [{ name: 'legacy.example.net', by: '*.example.net' }]);
  assert.deepEqual(change(d, 'name-added').items, ['*.example.net']);
  assert.deepEqual(change(d, 'name-removed').items, ['192.0.2.10'], 'the IP address still goes');
  const noSan = diff(OLD, tweak(OLD, { dnsNames: [], ipAddresses: [], hostnames: ['example.com'], der: new Uint8Array([4]) }));
  assert.ok(codes(noSan).includes('no-san'));
  // a deeper name is never covered by a wildcard one level up
  const deep = diff(tweak(OLD, { hostnames: ['a.b.example.com'], dnsNames: ['a.b.example.com'], ipAddresses: [] }), tweak(OLD, { hostnames: ['*.example.com'], dnsNames: ['*.example.com'], ipAddresses: [], der: new Uint8Array([5]) }));
  assert.deepEqual(change(deep, 'name-removed').items, ['a.b.example.com']);
});

test('usage: serverAuth and clientAuth dropped, digitalSignature and keyEncipherment dropped', () => {
  const noServer = diff(OLD, tweak(OLD, { extKeyUsage: ['clientAuth'], der: new Uint8Array([6]) }));
  assert.ok(codes(noServer).includes('eku-server-dropped'));
  assert.ok(!change(noServer, 'eku-changed'), 'serverAuth is reported once');
  // No EKU extension at all allows any usage: dropping to serverAuth only drops clientAuth.
  const anyOld = tweak(OLD, { extKeyUsage: [], extensions: without('2.5.29.37') });
  const d = diff(anyOld, tweak(OLD, { extKeyUsage: ['serverAuth'], der: new Uint8Array([7]) }));
  assert.ok(codes(d).includes('eku-client-dropped'));
  assert.ok(!codes(d).includes('eku-server-dropped'));
  // anyExtendedKeyUsage allows clientAuth too
  assert.ok(!codes(diff(OLD, tweak(OLD, { extKeyUsage: ['serverAuth', 'anyExtendedKeyUsage'], der: new Uint8Array([8]) }))).includes('eku-client-dropped'));
  const ku = diff(OLD, tweak(OLD, { keyUsage: ['keyEncipherment'], der: new Uint8Array([9]) }));
  assert.ok(codes(ku).includes('ku-signature-dropped'));
  const enc = diff(OLD, tweak(OLD, { keyUsage: ['digitalSignature'], der: new Uint8Array([10]) }));
  assert.ok(codes(enc).includes('ku-encipher-dropped'), 'RSA to RSA without keyEncipherment');
  assert.equal(enc.verdict, 'check');
  assert.ok(!change(enc, 'ku-changed'));
  // no key usage extension in the new one: every bit allowed
  assert.ok(!codes(diff(OLD, tweak(OLD, { keyUsage: [], extensions: without('2.5.29.15'), der: new Uint8Array([11]) }))).some((c) => c.startsWith('ku-') && c !== 'ku-changed'));
});

test('key: unsupported, weak, odd curve, another size; weaknesses both share are no blocker', () => {
  assert.deepEqual(change(diff(OLD, tweak(OLD, { keyAlgorithm: 'Ed25519', keyBits: null, curve: null, der: new Uint8Array([12]) })), 'key-unsupported').params, { key: 'Ed25519' });
  assert.deepEqual(change(diff(OLD, tweak(OLD, { keyBits: 1024, der: new Uint8Array([13]) })), 'key-weak').params, { key: 'RSA 1024' });
  const curve = diff(NEW, tweak(NEW, { curve: 'secp256k1', der: new Uint8Array([14]) }));
  assert.deepEqual(change(curve, 'key-curve').params, { key: 'EC secp256k1', curve: 'secp256k1' });
  assert.ok(!codes(diff(tweak(NEW, { curve: 'secp256k1' }), tweak(NEW, { curve: 'secp256k1', der: new Uint8Array([15]) }))).includes('key-curve'));
  assert.ok(!codes(diff(tweak(OLD, { keyBits: 1024 }), tweak(OLD, { keyBits: 1024, der: new Uint8Array([16]) }))).includes('key-weak'));
  const size = diff(OLD, tweak(OLD, { keyBits: 4096, der: new Uint8Array([17]) }));
  assert.deepEqual(change(size, 'key-size').params, { from: 'RSA 2048', to: 'RSA 4096' });
  assert.equal(keyLabel(NEW.cert), 'EC P-256');
  assert.equal(keyLabel({ keyAlgorithm: 'Ed25519', keyBits: null }), 'Ed25519');
});

test('signature, SCTs and must-staple', () => {
  assert.deepEqual(change(diff(OLD, tweak(OLD, { signatureAlgorithm: 'sha1WithRSAEncryption', der: new Uint8Array([18]) })), 'sig-weak').params, { alg: 'sha1WithRSAEncryption' });
  assert.deepEqual(change(diff(OLD, tweak(OLD, { sctCount: null, der: new Uint8Array([19]) })), 'sct-none').params, { from: 3 });
  const pre = diff(tweak(OLD, { isPrecertificate: true, sctCount: null }), RENEWED);
  assert.ok(codes(pre).includes('old-precert'));
  assert.ok(!codes(pre).some((c) => c.startsWith('sct-')));
  const short = tweak(NEW, { notBefore: new Date('2026-09-01T00:00:00Z'), notAfter: new Date('2027-02-01T00:00:00Z'), der: new Uint8Array([20]) });
  assert.ok(!codes(diff(OLD, short)).includes('sct-few'), 'two SCTs are enough for 153 days');
  const noOcsp = diff(OLD, tweak(OLD, { mustStaple: true, ocspUrls: [], der: new Uint8Array([21]) }));
  assert.ok(codes(noOcsp).includes('staple-no-ocsp'));
  assert.ok(!codes(noOcsp).includes('staple-added'));
  assert.ok(codes(noOcsp).includes('ocsp-removed'));
  assert.ok(codes(diff(tweak(OLD, { ocspUrls: [] }), tweak(OLD, { der: new Uint8Array([22]) }))).includes('ocsp-added'));
  assert.deepEqual(change(diff(OLD, tweak(OLD, { ocspUrls: ['http://ocsp.example.com/v2'], der: new Uint8Array([23]) })), 'ocsp-changed').params.hosts, [], 'same host, another path');
});

test('issuer and chain: a re-keyed intermediate, other intermediates, a root in the file', () => {
  const rekeyed = diff(OLD, tweak(OLD, { authorityKeyId: 'ff'.repeat(20), der: new Uint8Array([24]) }));
  assert.deepEqual(change(rekeyed, 'issuer-rekeyed').params, { issuer: 'DomainScope Test Diff CA 1', chain: [], missing: true });
  assert.ok(!codes(rekeyed).includes('issuer-changed'));
  const ca = OLD.chain[1];
  const crossed = { ...ca, serialHex: 'abcdef', der: new Uint8Array([25]) };
  const chain = diff(OLD, { cert: { ...RENEWED.cert }, chain: [RENEWED.cert, crossed] });
  assert.deepEqual(change(chain, 'chain-changed').params, { removed: ['DomainScope Test Diff CA 1'], added: ['DomainScope Test Diff CA 1'] });
  assert.equal(chain.verdict, 'steps');
  // a root in the file: the chain ends there, and an issuer the file lacks is the next anchor
  const root = { ...ca, subjectDN: ca.issuerDN, subjectCN: 'DomainScope Test Diff Root 1', subjectKeyId: ca.authorityKeyId, selfSigned: true, der: new Uint8Array([26]) };
  assert.deepEqual(chainAbove({ cert: OLD.cert, chain: [...OLD.chain, root] }).map((c) => c.subjectCN), ['DomainScope Test Diff CA 1', 'DomainScope Test Diff Root 1']);
  assert.deepEqual(chainAbove(RENEWED), []);
  assert.ok(!codes(diff(OLD, { cert: RENEWED.cert, chain: [...OLD.chain.slice(1), root] })).includes('root-changed'), 'the same root, named by the file or not');
});

test('subject and validation level', () => {
  const d = diff(OLD, tweak(OLD, { subjectDN: 'CN=example.com,O=Example', validationLevel: 'OV', der: new Uint8Array([27]) }));
  assert.deepEqual(change(d, 'level-changed').params, { from: 'DV', to: 'OV' });
  assert.deepEqual(change(d, 'subject-changed').params, { from: 'CN=example.com', to: 'CN=example.com,O=Example' });
});

test('diffCertificates hashes the keys in JavaScript without Web Crypto, and compareCertificates refuses garbage', async () => {
  const d = await diffCertificates(OLD, RENEWED, { now: NOW, subtle: null });
  assert.deepEqual(d.key, { reused: true, old: spkiHex(OLD), new: spkiHex(OLD) });
  assert.equal(compareCertificates(OLD, RENEWED, { now: NOW }).key.reused, true, 'without hashes: the SPKI bytes');
  assert.throws(() => compareCertificates(OLD, null), TypeError);
  assert.throws(() => compareCertificates({ cert: {} }, NEW), TypeError);
});

test('olderOf: the one issued first is the old one, unless swapped', () => {
  assert.equal(olderOf(OLD.cert, NEW.cert), 'x');
  assert.equal(olderOf(NEW.cert, OLD.cert), 'y');
  assert.equal(olderOf(OLD.cert, NEW.cert, { swap: true }), 'y');
  // the same start: the one that ends first
  assert.equal(olderOf(NEW.cert, RENEWED.cert), 'x');
  assert.equal(olderOf(RENEWED.cert, NEW.cert), 'y');
});

test('the panel words every code in both languages, and the text report', async () => {
  const i18n = await import('../../assets/js/i18n.js');
  const panel = await import('../../assets/js/ui/cert-diff-panel.js');
  const keys = panel.generatedKeys();
  const en = new Set(i18n.listKeys('en'));
  const tr = new Set(i18n.listKeys('tr'));
  assert.deepEqual(keys.filter((k) => !en.has(k) || !tr.has(k)), []);
  const d = await diffCertificates(OLD, NEW, { now: NOW });
  const kit = { certName: (c) => c.subjectCN, issuerName: (c) => c.issuerCN };
  i18n.setLang('en');
  const text = panel.diffReport(d, OLD, NEW, kit);
  assert.match(text, /^Certificate comparison: example\.com → example\.com\n/);
  assert.match(text, /Not a drop-in replacement: 3 blockers/);
  assert.match(text, /- 2 names no longer covered: legacy\.example\.net, 192\.0\.2\.10 — /);
  assert.match(text, /- Wildcard \*\.example\.com goes — Hosts directly under example\.com /);
  assert.match(text, /Steps on the servers:\n- Another issuer: DomainScope Test Diff CA 1 → DomainScope Test Diff CA 2/);
  assert.match(text, /Unchanged: subject\./);
  i18n.setLang('tr');
  assert.match(panel.diffReport(d, OLD, NEW, kit), /Doğrudan yerine konamaz: 3 engel/);
  i18n.setLang('en');
});
