#!/usr/bin/env node
/**
 * Generates the missing-intermediate fixtures (assets/js/lib/chainfix.js, tests/js/chainfix.test.js,
 * the chainfix E2E suite): a throwaway PKI whose keys are never written, its leaves, and a test
 * dataset in the format of assets/data/intermediates/, built by tools/build-intermediates.mjs
 * from CCADB-shaped report rows. Dev tool — no OpenSSL needed.
 *
 *   node tests/fixtures/gen_chainfix_fixtures.mjs             # create when missing
 *   node tests/fixtures/gen_chainfix_fixtures.mjs --force     # new keys, every file rewritten
 *   node tests/fixtures/gen_chainfix_fixtures.mjs --dataset   # only the test dataset, from the PEM files
 *
 * The PKI (EC P-256, names under "DomainScope Test"):
 *   chainfix_root.pem        DomainScope Test Root CA — the current root: every store includes it
 *   chainfix_old_root.pem    DomainScope Test Old Root — removed from every store
 *   chainfix_inter.pem       DomainScope Test Issuing CA, issued by the current root
 *   chainfix_inter_cross.pem the same CA (same name, same key) cross-signed by the old root
 *   chainfix_old_root_cross.pem  the old root's key cross-signed by the current root
 *   chainfix_policy.pem      DomainScope Test Policy CA (current root) → chainfix_deep_ca.pem DomainScope Test Deep CA
 *   chainfix_bad_root.pem    DomainScope Test Distrusted Root: Chrome distrusts what it issues after
 *                            2026-01-31 (the test lifecycle input), Mozilla after 2026-06-30 (its
 *                            "CCADB" date), and it expires on 2040-03-01
 *   chainfix_bad_ca.pem      DomainScope Test Distrusted CA, under it
 * Leaves (www.example.com and friends, valid 2026–2036 unless noted):
 *   chainfix_leaf.pem           issued by the Issuing CA (its authority key id names it)
 *   chainfix_leaf_noaki.pem     the same issuer, without an authority key id (found by the issuer DN)
 *   chainfix_leaf_unknown.pem   issued by "DomainScope Test Unlisted CA", which no list holds
 *   chainfix_leaf_deep.pem      issued by the Deep CA (two intermediates to add)
 *   chainfix_leaf_lifecycle.pem issued by the Distrusted CA on 2026-03-01, valid until 2040-06-01
 *   chainfix_mail_ca.pem / chainfix_expired_ca.pem  a CA for e-mail only and one that expired in 2025:
 *                            the build leaves both out
 * The dataset (tests/fixtures/intermediates/) is built from CCADB-shaped rows as the real one is:
 * Mozilla's report holds the intermediates above except the Deep CA, which only the certificate
 * records list (its PEM from a PEM report row, as for Let's Encrypt's YE / YR issuers), plus the
 * three roots and the lifecycle table; shard files that would be empty are left out (the tests'
 * fetch answers `{}` for them).
 */
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { seq, ctx, oid, bool, octet, bits, utf8, printable, utc, gen, name, ext, ALG, A, buildCert, pem, spkiOf, signWith } from './der-builder.mjs';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { buildDataset } from '../../tools/build-intermediates.mjs';

const DIR = dirname(fileURLToPath(import.meta.url));
const FORCE = process.argv.includes('--force');
const DATASET_ONLY = process.argv.includes('--dataset');
const DATASET = join(DIR, 'intermediates');
const fx = (file) => join(DIR, file);

const FILES = {
  root: 'chainfix_root.pem', oldRoot: 'chainfix_old_root.pem', badRoot: 'chainfix_bad_root.pem',
  inter: 'chainfix_inter.pem', interCross: 'chainfix_inter_cross.pem', oldRootCross: 'chainfix_old_root_cross.pem',
  policy: 'chainfix_policy.pem', deep: 'chainfix_deep_ca.pem', bad: 'chainfix_bad_ca.pem',
  mail: 'chainfix_mail_ca.pem', expired: 'chainfix_expired_ca.pem',
  leaf: 'chainfix_leaf.pem', leafNoAki: 'chainfix_leaf_noaki.pem', leafUnknown: 'chainfix_leaf_unknown.pem',
  leafDeep: 'chainfix_leaf_deep.pem', leafLifecycle: 'chainfix_leaf_lifecycle.pem'
};

if (!FORCE && !DATASET_ONLY && Object.values(FILES).every((f) => existsSync(fx(f))) && existsSync(join(DATASET, 'manifest.json'))) {
  console.log('chainfix fixtures exist (use --force to regenerate, --dataset for the test dataset only)');
  process.exit(0);
}

/** RFC 5280 key identifier: SHA-1 of the subjectPublicKey bits (a P-256 point is the last 65 bytes). */
const keyIdOf = (key) => createHash('sha1').update(spkiOf(key).subarray(-65)).digest();
const serial = () => {
  const b = randomBytes(16);
  b[0] &= 0x7f;
  return b.toString('hex');
};
const dn = (cn, org = 'DomainScope Test') => name([[[A.C, printable('XX')]], [[A.O, utf8(org)]], [[A.CN, utf8(cn)]]]);
/** 'YYYY-MM-DD' → UTCTime before 2050, GeneralizedTime after (RFC 5280). */
const time = (d, end = false) => {
  const s = `${d.replace(/-/g, '').slice(2)}${end ? '235959' : '000000'}Z`;
  return Number(d.slice(0, 4)) < 2050 ? utc(s) : gen(`${d.slice(0, 2)}${s}`);
};

const keys = {};
const key = (id) => (keys[id] ||= generateKeyPairSync('ec', { namedCurve: 'P-256' }));
const EKU_SERVER = seq(oid('1.3.6.1.5.5.7.3.1'), oid('1.3.6.1.5.5.7.3.2'));

/** A CA certificate: `subjectKey` with `subjectName`, signed by `issuerKey` as `issuerName`. */
function caCert({ subjectName, subjectKey, issuerName, issuerKey, from, to, eku = null, aki = true }) {
  return buildCert({
    serial: serial(), sigAlg: ALG.ecdsa256, issuer: issuerName, notBefore: time(from), notAfter: time(to, true),
    subject: subjectName, spki: spkiOf(key(subjectKey).publicKey),
    extensions: [
      ext('2.5.29.19', seq(bool(true)), true),
      ext('2.5.29.15', bits(Buffer.from([0x06]), 1), true), // keyCertSign, cRLSign
      ...(eku ? [ext('2.5.29.37', eku)] : []),
      ext('2.5.29.14', octet(keyIdOf(key(subjectKey).publicKey))),
      ...(aki ? [ext('2.5.29.35', seq(ctx(0, false, keyIdOf(key(issuerKey).publicKey))))] : [])
    ],
    signer: signWith(key(issuerKey).privateKey, 'sha256')
  });
}

/** A server leaf for `names`, signed by `issuerKey` as `issuerName`. */
function leafCert({ names, issuerName, issuerKey, from = '2026-01-01', to = '2036-01-01', aki = true }) {
  const leafKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return buildCert({
    serial: serial(), sigAlg: ALG.ecdsa256, issuer: issuerName, notBefore: time(from), notAfter: time(to, true),
    subject: name([[[A.CN, utf8(names[0])]]]), spki: spkiOf(leafKey.publicKey),
    extensions: [
      ext('2.5.29.19', seq(), true),
      ext('2.5.29.15', bits(Buffer.from([0x80]), 7), true), // digitalSignature
      ext('2.5.29.37', seq(oid('1.3.6.1.5.5.7.3.1'))),
      ext('2.5.29.17', seq(...names.map((n) => ctx(2, false, Buffer.from(n))))),
      ext('2.5.29.14', octet(keyIdOf(leafKey.publicKey))),
      ...(aki ? [ext('2.5.29.35', seq(ctx(0, false, keyIdOf(key(issuerKey).publicKey))))] : [])
    ],
    signer: signWith(key(issuerKey).privateKey, 'sha256')
  });
}

const N = {
  root: dn('DomainScope Test Root CA'),
  oldRoot: dn('DomainScope Test Old Root', 'DomainScope Old Test'),
  badRoot: dn('DomainScope Test Distrusted Root', 'DomainScope Distrust Test'),
  inter: dn('DomainScope Test Issuing CA'),
  policy: dn('DomainScope Test Policy CA'),
  deep: dn('DomainScope Test Deep CA'),
  bad: dn('DomainScope Test Distrusted CA', 'DomainScope Distrust Test'),
  unlisted: dn('DomainScope Test Unlisted CA', 'DomainScope Unlisted Test'),
  mail: dn('DomainScope Test Mail CA'),
  expired: dn('DomainScope Test Expired CA')
};
const selfSigned = (id, from, to) => caCert({ subjectName: N[id], subjectKey: id, issuerName: N[id], issuerKey: id, from, to });

/** The throwaway PKI with new keys: each certificate's DER by id. */
const craft = () => ({
  root: selfSigned('root', '2025-01-01', '2045-12-31'),
  oldRoot: selfSigned('oldRoot', '2015-01-01', '2045-12-31'),
  badRoot: selfSigned('badRoot', '2020-01-01', '2040-03-01'),
  inter: caCert({ subjectName: N.inter, subjectKey: 'inter', issuerName: N.root, issuerKey: 'root', from: '2025-06-01', to: '2035-06-01', eku: EKU_SERVER }),
  interCross: caCert({ subjectName: N.inter, subjectKey: 'inter', issuerName: N.oldRoot, issuerKey: 'oldRoot', from: '2025-06-01', to: '2035-06-01', eku: EKU_SERVER }),
  oldRootCross: caCert({ subjectName: N.oldRoot, subjectKey: 'oldRoot', issuerName: N.root, issuerKey: 'root', from: '2025-06-01', to: '2035-06-01' }),
  policy: caCert({ subjectName: N.policy, subjectKey: 'policy', issuerName: N.root, issuerKey: 'root', from: '2025-06-01', to: '2040-06-01' }),
  deep: caCert({ subjectName: N.deep, subjectKey: 'deep', issuerName: N.policy, issuerKey: 'policy', from: '2025-06-01', to: '2038-06-01', eku: EKU_SERVER }),
  bad: caCert({ subjectName: N.bad, subjectKey: 'bad', issuerName: N.badRoot, issuerKey: 'badRoot', from: '2025-06-01', to: '2040-01-01', eku: EKU_SERVER }),
  mail: caCert({ subjectName: N.mail, subjectKey: 'mail', issuerName: N.root, issuerKey: 'root', from: '2025-06-01', to: '2035-06-01', eku: seq(oid('1.3.6.1.5.5.7.3.4')) }),
  expired: caCert({ subjectName: N.expired, subjectKey: 'expired', issuerName: N.root, issuerKey: 'root', from: '2025-01-01', to: '2025-12-31', eku: EKU_SERVER }),
  leaf: leafCert({ names: ['www.example.com', 'example.com'], issuerName: N.inter, issuerKey: 'inter' }),
  leafNoAki: leafCert({ names: ['legacy.example.com'], issuerName: N.inter, issuerKey: 'inter', aki: false }),
  leafUnknown: leafCert({ names: ['internal.example.net'], issuerName: N.unlisted, issuerKey: 'unlisted' }),
  leafDeep: leafCert({ names: ['deep.example.org'], issuerName: N.deep, issuerKey: 'deep' }),
  leafLifecycle: leafCert({ names: ['shop.example.com'], issuerName: N.bad, issuerKey: 'bad', from: '2026-03-01', to: '2040-06-01' })
});

/** The DER of a PEM fixture on disk. */
const derOf = (file) => Buffer.from(parseCertificates(readFileSync(fx(file), 'utf8')).certificates[0].der);

const der = DATASET_ONLY ? Object.fromEntries(Object.entries(FILES).map(([id, file]) => [id, derOf(file)])) : craft();
if (!DATASET_ONLY) {
  for (const [id, file] of Object.entries(FILES)) {
    writeFileSync(fx(file), pem(der[id]));
    console.log('crafted', file);
  }
}

// ---------------------------------------------------------------------------
// The test dataset: CCADB-shaped rows through the real builder
// ---------------------------------------------------------------------------
const fp = (d) => createHash('sha256').update(d).digest('hex').toUpperCase();
const ccadbDate = (d) => d.replace(/-/g, '.');
const keyIdB64 = (id) => Buffer.from(parseCertificates(pem(der[id])).certificates[0].subjectKeyId, 'hex').toString('base64');
const interRow = (id, owner = 'DomainScope Test') => ({ 'CA Owner': owner, 'SHA-256 Fingerprint': fp(der[id]), 'PEM Info': `'${pem(der[id])}` });
const included = (id, owner, distrust = '') => ({
  Owner: owner, 'SHA-256 Fingerprint': fp(der[id]), 'Trust Bits': 'Websites;Email', 'Distrust for TLS After Date': distrust, 'PEM Info': `'${pem(der[id])}`
});
const record = (id, { owner, certName, statuses, validTo, tls }) => ({
  'CA Owner': owner, 'Certificate Name': certName, 'Certificate Record Type': 'Root Certificate',
  'Apple Status': statuses, 'Chrome Status': statuses, 'Microsoft Status': statuses, 'Mozilla Status': statuses,
  'Revocation Status': '', 'SHA-256 Fingerprint': fp(der[id]), 'Valid From (GMT)': '', 'Valid To (GMT)': ccadbDate(validTo),
  'Subject Key Identifier': keyIdB64(id), 'TLS Capable': tls ? 'True' : 'False'
});
/** The record of an intermediate every store trusts (the Deep CA: not in "Mozilla's report"). */
const interRecord = (id, { owner, certName, validFrom, validTo }) => ({
  ...record(id, { owner, certName, statuses: 'Trusted', validTo, tls: true }),
  'Certificate Record Type': 'Intermediate Certificate', 'Revocation Status': 'Not Revoked', 'Valid From (GMT)': ccadbDate(validFrom)
});

const { files, manifest } = buildDataset({
  intermediates: [
    interRow('inter'), interRow('interCross'), interRow('oldRootCross'), interRow('policy'),
    interRow('bad', 'DomainScope Distrust Test'), interRow('mail'), interRow('expired')
  ],
  included: [included('root', 'DomainScope Test'), included('badRoot', 'DomainScope Distrust Test', '2026.06.30')],
  records: [
    record('root', { owner: 'DomainScope Test', certName: 'DomainScope Test Root CA', statuses: 'Included', validTo: '2045-12-31', tls: true }),
    record('oldRoot', { owner: 'DomainScope Old Test', certName: 'DomainScope Test Old Root', statuses: 'Removed', validTo: '2045-12-31', tls: false }),
    record('badRoot', { owner: 'DomainScope Distrust Test', certName: 'DomainScope Test Distrusted Root', statuses: 'Included', validTo: '2040-03-01', tls: true }),
    interRecord('deep', { owner: 'DomainScope Test', certName: 'DomainScope Test Deep CA', validFrom: '2025-06-01', validTo: '2038-06-01' })
  ],
  pems: [{ 'SHA-256 Fingerprint': fp(der.deep), 'X.509 Certificate (PEM)': pem(der.deep) }],
  lifecycle: {
    events: [{
      store: 'chrome', type: 'distrust-after', date: '2026-01-31', basis: 'sct',
      url: 'https://example.com/announcements/chrome-distrust', roots: [fp(der.badRoot)]
    }]
  },
  now: new Date('2026-09-28T00:00:00Z'),
  window: { from: '2025-01-01', to: '2040-12-31' },
  emptyShards: false,
  canaries: [],
  sources: {
    intermediates: { name: 'Test: intermediates (gen_chainfix_fixtures.mjs)', url: 'https://example.com/ccadb/intermediates.csv' },
    included: { name: 'Test: included roots', url: 'https://example.com/ccadb/included.csv' },
    records: { name: 'Test: certificate records', url: 'https://example.com/ccadb/records.csv' },
    pems: { name: 'Test: certificate PEMs', url: 'https://example.com/ccadb/pems.csv' }
  }
});
rmSync(DATASET, { recursive: true, force: true });
for (const [file, content] of files) {
  const path = join(DATASET, ...file.split('/'));
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, content);
}
console.log(`test dataset: ${manifest.counts.intermediates} intermediates, ${manifest.counts.roots} roots, ${manifest.counts.events} events, ${files.size} files`);
// The fixtures parse back as generated (a quick self-check, not the tests).
for (const file of Object.values(FILES)) if (!readFileSync(fx(file), 'utf8').includes('BEGIN CERTIFICATE')) throw new Error(file);
