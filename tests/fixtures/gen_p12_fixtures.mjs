#!/usr/bin/env node
/**
 * Generates the PKCS#12 (.p12 / .pfx) fixtures of lib/pkcs12.js and their OpenSSL ground truth
 * (tests/fixtures/p12_expected.json). Dev tool — needs `openssl` 3.4+ on PATH (-not_before, PBMAC1)
 * with the legacy provider (RC2 / 3DES). The committed files were made with it; the tests never
 * regenerate them:
 *
 *   node tests/fixtures/gen_p12_fixtures.mjs            # create the missing fixtures, refresh p12_expected.json
 *   node tests/fixtures/gen_p12_fixtures.mjs --force    # regenerate everything (new keys!)
 *
 * A throwaway test PKI (valid 2025-01-01 .. 2050-01-01): an EC P-256 root and intermediate
 * ("Example P12 Test Root / Intermediate") issuing three leaves — RSA 2048 (p12.example.com),
 * EC P-256 (*.p12.example.net) and EC P-384 (p384.example.org). Only the certificates are
 * written (p12_*.pem); the keys stay in a temporary directory and exist nowhere else than inside
 * the .p12 files, which protect nothing.
 *
 * Every bundle is made with `openssl pkcs12 -export`: the certificate file order is leaf, root,
 * intermediate (the CA file lists the root first), so a reader has to put the chain in order.
 * The expectations — MAC and encryption as `openssl pkcs12 -info` prints them, the SHA-256 of
 * every certificate in file order, the number of private keys and whether the key belongs to the
 * leaf — are read back with OpenSSL, never with the code under test.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = dirname(fileURLToPath(import.meta.url));
const FORCE = process.argv.includes('--force');
const TMP = mkdtempSync(join(tmpdir(), 'p12fx-'));
const fx = (name) => join(DIR, name);
const tmp = (name) => join(TMP, name);
const DATES = ['-not_before', '20250101000000Z', '-not_after', '20500101000000Z'];
/** Every read goes through both providers: RC2 and the PKCS#12 3DES PBE live in the legacy one. */
const PROVIDERS = ['-provider', 'legacy', '-provider', 'default'];

function openssl(args, { input } = {}) {
  return execFileSync('openssl', args, { input, stdio: ['pipe', 'pipe', 'pipe'] });
}

/** The password of each bundle, as a user types it. */
const PASSWORDS = {
  test: 'pfx-test-pass',
  unicode: 'Şifre-ğüı 🔑',
  // OpenSSL 1.0.x took each UTF-8 byte of the password as one BMPString character; OpenSSL 3
  // (UTF-8 → BMPString) makes that same BMPString of the characters U+00C5 U+009E "ifre", so a
  // bundle made with them is the bundle an old OpenSSL wrote for the password "Şifre".
  oldOpenssl: 'Şifre',
  empty: ''
};
const OPENSSL_INPUT = { oldOpenssl: String.fromCharCode(...Buffer.from(PASSWORDS.oldOpenssl, 'utf8')) };

/** -passin / -passout for a bundle's password: a file holding the UTF-8 bytes OpenSSL gets. */
function passArg(name) {
  const value = OPENSSL_INPUT[name] ?? PASSWORDS[name];
  if (!value) return 'pass:'; // OpenSSL cannot read an empty password file
  const file = tmp(`${name}.pass`);
  writeFileSync(file, Buffer.from(value, 'utf8'));
  return `file:${file}`;
}

// ---------------------------------------------------------------------------
// The test PKI
// ---------------------------------------------------------------------------

function ecKey(name, curve = 'prime256v1') {
  openssl(['ecparam', '-name', curve, '-genkey', '-noout', '-out', tmp(`${name}.key`)]);
}

function makePki() {
  ecKey('root');
  ecKey('inter');
  openssl(['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048', '-out', tmp('rsa.key')]);
  ecKey('ec');
  ecKey('p384', 'secp384r1');
  openssl(['req', '-new', '-x509', '-key', tmp('root.key'), '-subj', '/O=Example P12 Test PKI/CN=Example P12 Test Root',
    ...DATES, '-sha256', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
    '-out', tmp('root.pem')]);
  writeFileSync(tmp('inter.ext'), [
    'basicConstraints=critical,CA:TRUE,pathlen:0', 'keyUsage=critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier=hash', 'authorityKeyIdentifier=keyid'
  ].join('\n'));
  openssl(['req', '-new', '-key', tmp('inter.key'), '-subj', '/O=Example P12 Test PKI/CN=Example P12 Test Intermediate', '-out', tmp('inter.csr')]);
  openssl(['x509', '-req', '-in', tmp('inter.csr'), '-CA', tmp('root.pem'), '-CAkey', tmp('root.key'), '-set_serial', '0x1001',
    ...DATES, '-sha256', '-extfile', tmp('inter.ext'), '-out', tmp('inter.pem')]);
  const leaf = (name, cn, sans, serial) => {
    writeFileSync(tmp(`${name}.ext`), [
      'basicConstraints=critical,CA:FALSE', 'keyUsage=critical,digitalSignature,keyEncipherment', 'extendedKeyUsage=serverAuth',
      'subjectKeyIdentifier=hash', 'authorityKeyIdentifier=keyid', `subjectAltName=${sans.map((s) => `DNS:${s}`).join(',')}`
    ].join('\n'));
    openssl(['req', '-new', '-key', tmp(`${name}.key`), '-subj', `/CN=${cn}`, '-out', tmp(`${name}.csr`)]);
    openssl(['x509', '-req', '-in', tmp(`${name}.csr`), '-CA', tmp('inter.pem'), '-CAkey', tmp('inter.key'), '-set_serial', serial,
      ...DATES, '-sha256', '-extfile', tmp(`${name}.ext`), '-out', tmp(`${name}.pem`)]);
  };
  leaf('rsa', 'p12.example.com', ['p12.example.com', 'www.p12.example.com'], '0x2001');
  leaf('ec', '*.p12.example.net', ['*.p12.example.net', 'p12.example.net'], '0x2002');
  leaf('p384', 'p384.example.org', ['p384.example.org'], '0x2003');
  // The CA file lists the root first: bundles hold leaf, root, intermediate.
  writeFileSync(tmp('cas.pem'), Buffer.concat([readFileSync(tmp('root.pem')), readFileSync(tmp('inter.pem'))]));
  for (const n of ['root', 'inter', 'rsa', 'ec', 'p384']) writeFileSync(fx(`p12_${n}.pem`), readFileSync(tmp(`${n}.pem`)));
}

// ---------------------------------------------------------------------------
// The bundles
// ---------------------------------------------------------------------------

/**
 * name → { leaf, key, readerLeaf, certfile, chain, password, args, about }. `leaf`: the -in
 * certificate; `key`: the private key put in (the -in certificate's own unless noted);
 * `readerLeaf`: the certificate a reader takes as the leaf when it is not `leaf` (a CA
 * certificate is never one); `certfile`: the extra certificates (default: root and
 * intermediate, unless `chain` is false); `args`: the export options that make the bundle.
 */
const BUNDLES = {
  'p12_rsa_aes.p12': {
    leaf: 'rsa', password: 'test', args: ['-name', 'p12.example.com'],
    about: 'OpenSSL 3 defaults: PBES2 (PBKDF2-HMAC-SHA256, AES-256-CBC) for certificates and key, HMAC-SHA256 MAC'
  },
  'p12_rsa_legacy.p12': {
    leaf: 'rsa', password: 'test', args: ['-legacy'],
    about: '-legacy: RC2-40 certificates, 3DES key, HMAC-SHA1 MAC (what Windows and older Java write)'
  },
  'p12_rsa_rc2_128.p12': {
    leaf: 'rsa', password: 'test', args: ['-legacy', '-certpbe', 'PBE-SHA1-RC2-128', '-keypbe', 'PBE-SHA1-2DES', '-macalg', 'sha1'],
    about: 'RC2-128 certificates, two-key 3DES key, HMAC-SHA1 MAC'
  },
  'p12_ec_aes128.p12': {
    leaf: 'ec', password: 'test', args: ['-certpbe', 'AES-128-CBC', '-keypbe', 'AES-192-CBC', '-macalg', 'sha512', '-iter', '10000'],
    about: 'EC P-256: AES-128-CBC certificates, AES-192-CBC key, HMAC-SHA512 MAC, 10000 iterations'
  },
  'p12_p384_pbmac1.p12': {
    leaf: 'p384', password: 'test', args: ['-pbmac1_pbkdf2'],
    about: 'EC P-384, PBMAC1 (RFC 9579: PBKDF2-HMAC-SHA256 key, HMAC-SHA256) in place of the PKCS#12 MAC'
  },
  'p12_empty_password.p12': {
    leaf: 'rsa', password: 'empty', chain: false, args: [],
    about: 'the empty password, leaf and key only'
  },
  'p12_nomac.p12': {
    leaf: 'rsa', password: 'test', args: ['-nomac', '-certpbe', 'AES-256-CBC'],
    about: 'no MAC (-nomac alone leaves the certificates unencrypted, so AES-256 is asked for): a wrong password shows only when decryption fails'
  },
  'p12_unicode.p12': {
    leaf: 'ec', password: 'unicode', args: [],
    about: 'a Turkish password with an emoji: BMPString (surrogate pair) for the MAC, UTF-8 for PBKDF2'
  },
  'p12_old_openssl.p12': {
    leaf: 'ec', password: 'oldOpenssl', args: ['-legacy'],
    about: 'the BMPString OpenSSL 1.0.x made of the password "Şifre" (each UTF-8 byte one character)'
  },
  'p12_plain.p12': {
    leaf: 'ec', password: 'test', args: ['-certpbe', 'NONE', '-keypbe', 'NONE'],
    about: 'nothing encrypted: certificates and a plain keyBag, only a MAC'
  },
  'p12_certs_only.p12': {
    leaf: 'rsa', password: 'test', args: ['-nokeys'],
    about: 'certificates only, no private key (a trust store)'
  },
  'p12_mismatch.p12': {
    leaf: 'inter', key: 'inter', readerLeaf: 'rsa', password: 'test', certfile: 'rsa', args: [],
    about: 'the intermediate CA with its key, plus the RSA leaf: the key does not belong to the leaf'
  }
};

function makeBundle(file, spec) {
  const out = ['pkcs12', '-export', ...PROVIDERS, '-in', tmp(`${spec.leaf}.pem`), '-passout', passArg(spec.password)];
  if (!spec.args.includes('-nokeys')) out.push('-inkey', tmp(`${spec.key || spec.leaf}.key`));
  if (spec.certfile) out.push('-certfile', tmp(`${spec.certfile}.pem`));
  else if (spec.chain !== false) out.push('-certfile', tmp('cas.pem'));
  out.push(...spec.args, '-out', fx(file));
  openssl(out);
}

// ---------------------------------------------------------------------------
// Ground truth, read back with OpenSSL
// ---------------------------------------------------------------------------

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');
const pemBlocks = (text, label) => text.match(new RegExp(`-----BEGIN ${label}-----[\\s\\S]*?-----END ${label}-----\\n?`, 'g')) || [];

function expectation(file, spec) {
  const pass = passArg(spec.password);
  const read = (...args) => openssl(['pkcs12', ...PROVIDERS, '-in', fx(file), '-passin', pass, ...args]).toString('utf8');
  // -info prints to stderr.
  const info = spawnSync('openssl', ['pkcs12', ...PROVIDERS, '-in', fx(file), '-passin', pass, '-info', '-noout'], { encoding: 'utf8' }).stderr;
  const lines = info.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  const certs = pemBlocks(read('-nokeys'), 'CERTIFICATE').map((pem) => sha256(openssl(['x509', '-outform', 'DER'], { input: pem })));
  const keys = spec.args.includes('-nokeys') ? [] : pemBlocks(read('-nocerts', '-noenc'), 'PRIVATE KEY');
  const leafPem = fx(`p12_${spec.readerLeaf || spec.leaf}.pem`);
  const leafSpki = sha256(openssl(['pkey', '-pubin', '-outform', 'DER'], { input: openssl(['x509', '-in', leafPem, '-pubkey', '-noout']) }));
  const keySpki = keys.map((pem) => sha256(openssl(['pkey', '-pubout', '-outform', 'DER'], { input: pem })));
  return {
    about: spec.about,
    password: spec.password,
    mac: lines.find((l) => /^MAC: /.test(l)) || null,
    encryption: lines.filter((l) => /^(PKCS7 Encrypted data|Shrouded Keybag):/.test(l)),
    bags: lines.filter((l) => /^(Certificate bag|Key bag|Shrouded Keybag|PKCS7 Data|PKCS7 Encrypted data)/.test(l)).map((l) => l.split(':')[0]),
    certificates: certs,
    leaf: sha256(openssl(['x509', '-outform', 'DER', '-in', leafPem])),
    keys: keys.length,
    keyMatchesLeaf: keys.length ? keySpki.includes(leafSpki) : null
  };
}

try {
  const pki = ['root', 'inter', 'rsa', 'ec', 'p384'].map((n) => fx(`p12_${n}.pem`));
  const missing = Object.keys(BUNDLES).filter((f) => !existsSync(fx(f)));
  if (FORCE || pki.some((f) => !existsSync(f)) || missing.length) {
    if (!FORCE && pki.every((f) => existsSync(f)) && missing.length) {
      throw new Error(`missing ${missing.join(', ')}: their keys are gone with the last run's work directory; run with --force`);
    }
    makePki();
    for (const [file, spec] of Object.entries(BUNDLES)) {
      makeBundle(file, spec);
      console.log('made', file);
    }
  }
  const expected = {};
  for (const [file, spec] of Object.entries(BUNDLES)) expected[file] = expectation(file, spec);
  writeFileSync(fx('p12_expected.json'), `${JSON.stringify({ passwords: PASSWORDS, bundles: expected }, null, 2)}\n`);
  console.log('wrote p12_expected.json');
} finally {
  rmSync(TMP, { recursive: true, force: true });
}
