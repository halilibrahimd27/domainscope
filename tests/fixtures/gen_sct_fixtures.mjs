#!/usr/bin/env node
/**
 * Generates the embedded-SCT fixtures (assets/js/lib/sct.js, tests/js/sct.test.js, the
 * "Transparency" group of the cert E2E suite): a throwaway CA and CT logs whose keys are never
 * written, leaves whose SignedCertificateTimestampList extension holds SCTs those logs signed
 * (RFC 6962 §3.2: the precertificate entry, issuer key hash and the TBS without the SCT
 * extension), and a log list in the format of Google's CT log list v3. Documentation data only:
 * www.example.com, the logs under ct.example.com / ct.example.net. Dev tool — no OpenSSL needed.
 *
 *   node tests/fixtures/gen_sct_fixtures.mjs           # create when missing
 *   node tests/fixtures/gen_sct_fixtures.mjs --force   # new keys, every file rewritten
 *
 * The logs (sct/log_list.json; operator: state):
 *   Alpha    Example Log Operator A: usable, RFC 6962
 *   Bravo    Example Log Operator A: retired on 2026-09-15, RFC 6962
 *   Charlie  Example Log Operator B: usable, static-ct-api (its SCTs carry a leaf_index extension)
 *   Delta    Example Log Operator B: readonly since 2026-06-01, RFC 6962
 *   Echo     Example Log Operator C: pending, RFC 6962
 *   Hotel    Example Log Operator C: usable, static-ct-api
 *   Foxtrot  in no list (an unknown log)
 * The leaves (issued by "DomainScope Test SCT CA" from 2026-09-01; SCTs a few seconds later):
 *   sct_compliant.pem      90 days: Alpha, Charlie — both policies met
 *   sct_one_operator.pem   90 days: Alpha, Bravo (retired after the SCT) — one operator
 *   sct_long.pem           397 days: Alpha, Charlie — three SCTs needed
 *   sct_long_ok.pem        397 days: Alpha, Charlie, Delta — both policies met
 *   sct_unknown.pem        90 days: Alpha, Foxtrot, Echo — one SCT counts
 *   sct_static_only.pem    90 days: Charlie, Hotel — Chrome met, Apple wants an RFC 6962 log
 *   sct_precert.pem        a precertificate (CT poison, no SCTs)
 *   sct_ca.pem             the CA (no SCTs)
 */
import { createHash, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { seq, ctx, oid, bool, octet, utf8, printable, utc, nul, name, ext, ALG, A, buildCert, pem, spkiOf, signWith } from './der-builder.mjs';

const DIR = join(dirname(fileURLToPath(import.meta.url)), 'sct');
const FORCE = process.argv.includes('--force');
const LEAVES = ['sct_compliant', 'sct_one_operator', 'sct_long', 'sct_long_ok', 'sct_unknown', 'sct_static_only', 'sct_precert'];
const FILES = [...LEAVES.map((f) => `${f}.pem`), 'sct_ca.pem', 'log_list.json'];

if (!FORCE && FILES.every((f) => existsSync(join(DIR, f)))) {
  process.stdout.write('SCT fixtures present (use --force to regenerate)\n');
  process.exit(0);
}
mkdirSync(DIR, { recursive: true });

const ec = () => generateKeyPairSync('ec', { namedCurve: 'P-256' });
const sha256 = (b) => createHash('sha256').update(b).digest();
const u16 = (n) => Buffer.from([(n >> 8) & 0xff, n & 0xff]);
const u24 = (n) => Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
const u64 = (ms) => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(ms));
  return b;
};
const OID_SCT = '1.3.6.1.4.1.11129.2.4.2';
const OID_POISON = '1.3.6.1.4.1.11129.2.4.3';

/* --- the logs --------------------------------------------------------------------------------- */
const LOGS = {
  alpha: { op: 'A', name: "Example 'Alpha2026h2' log", url: 'https://ct.example.com/alpha2026h2/', state: ['usable', '2026-01-15T00:00:00Z'], api: 'rfc6962' },
  bravo: { op: 'A', name: "Example 'Bravo2026h2' log", url: 'https://ct.example.com/bravo2026h2/', state: ['retired', '2026-09-15T00:00:00Z'], api: 'rfc6962' },
  charlie: { op: 'B', name: "Example 'Charlie2026h2'", url: 'https://charlie2026h2.ct.example.net/', state: ['usable', '2026-02-01T00:00:00Z'], api: 'static' },
  delta: { op: 'B', name: "Example 'Delta2027h1' log", url: 'https://ct.example.net/delta2027h1/', state: ['readonly', '2026-06-01T00:00:00Z'], api: 'rfc6962' },
  echo: { op: 'C', name: "Example 'Echo2026h2' log", url: 'https://ct.example.org/echo2026h2/', state: ['pending', '2026-08-01T00:00:00Z'], api: 'rfc6962' },
  hotel: { op: 'C', name: "Example 'Hotel2026h2'", url: 'https://hotel2026h2.ct.example.org/', state: ['usable', '2026-03-01T00:00:00Z'], api: 'static' },
  foxtrot: { op: null, name: 'Foxtrot (in no list)', url: '', state: null, api: 'rfc6962' }
};
for (const log of Object.values(LOGS)) {
  log.key = ec();
  log.spki = spkiOf(log.key.publicKey);
  log.id = sha256(log.spki);
}
const OPERATORS = { A: 'Example Log Operator A', B: 'Example Log Operator B', C: 'Example Log Operator C' };
const logList = {
  version: '1.0',
  log_list_timestamp: '2026-09-30T12:00:00Z',
  operators: Object.entries(OPERATORS).map(([code, opName]) => {
    const own = Object.values(LOGS).filter((l) => l.op === code);
    const entry = (l) => ({
      description: l.name,
      log_id: l.id.toString('base64'),
      key: l.spki.toString('base64'),
      ...(l.api === 'static' ? { submission_url: l.url, monitoring_url: `${l.url}tiles/` } : { url: l.url }),
      mmd: l.api === 'static' ? 60 : 86400,
      state: { [l.state[0]]: { timestamp: l.state[1] } },
      temporal_interval: { start_inclusive: '2026-07-01T00:00:00Z', end_exclusive: '2028-01-01T00:00:00Z' }
    });
    return { name: opName, email: [`ct-${code.toLowerCase()}@example.com`], logs: own.filter((l) => l.api === 'rfc6962').map(entry), tiled_logs: own.filter((l) => l.api === 'static').map(entry) };
  })
};

/* --- the CA ----------------------------------------------------------------------------------- */
const caKey = ec();
const caName = name([[[A.C, printable('XX')]], [[A.O, utf8('DomainScope Test')]], [[A.CN, utf8('DomainScope Test SCT CA')]]]);
const caSpki = spkiOf(caKey.publicKey);
const caSki = sha256(caSpki).subarray(0, 20);
const caDer = buildCert({
  serial: '5c7a',
  sigAlg: ALG.ecdsa256,
  issuer: caName,
  notBefore: utc('260101000000Z'),
  notAfter: utc('360101000000Z'),
  subject: caName,
  spki: caSpki,
  extensions: [
    ext('2.5.29.19', seq(bool(true)), true),
    ext('2.5.29.15', Buffer.from([0x03, 0x02, 0x01, 0x06]), true),
    ext('2.5.29.14', octet(caSki))
  ],
  signer: signWith(caKey.privateKey, 'sha256')
});
const issuerKeyHash = sha256(caSpki);

/* --- the leaves ------------------------------------------------------------------------------- */
const DAY = 86400000;
const START = Date.parse('2026-09-01T00:00:00Z');
const utcTime = (ms) => utc(`${new Date(ms).toISOString().slice(2, 19).replace(/[-T:]/g, '')}Z`);

/** One serialized SCT from `log` over the precertificate entry of `tbs`. */
function signSct(log, tbs, timestamp, extensions) {
  const signed = Buffer.concat([
    Buffer.from([0, 0]), u64(timestamp), u16(1), issuerKeyHash, u24(tbs.length), tbs, u16(extensions.length), extensions
  ]);
  const sig = cryptoSign('sha256', signed, log.key.privateKey);
  return Buffer.concat([Buffer.from([0]), log.id, u64(timestamp), u16(extensions.length), extensions, Buffer.from([4, 3]), u16(sig.length), sig]);
}

/** static-ct-api's leaf_index SCT extension: type 0, a 40-bit index. */
const leafIndex = (n) => Buffer.concat([Buffer.from([0]), u16(5), Buffer.from([0, 0, 0, (n >> 8) & 0xff, n & 0xff])]);

function leaf(serial, days, logs, { precert = false } = {}) {
  const key = ec();
  const subject = name([[[A.CN, utf8('www.example.com')]]]);
  const sanDer = seq(ctx(2, false, Buffer.from('www.example.com')), ctx(2, false, Buffer.from('example.com')));
  const base = [
    ext('2.5.29.15', Buffer.from([0x03, 0x02, 0x07, 0x80]), true),
    ext('2.5.29.37', seq(oid('1.3.6.1.5.5.7.3.1'))),
    ext('2.5.29.19', seq(), true),
    ext('2.5.29.35', seq(ctx(0, false, caSki))),
    ext('2.5.29.17', sanDer)
  ];
  const fields = {
    serial, sigAlg: ALG.ecdsa256, issuer: caName, notBefore: utcTime(START), notAfter: utcTime(START + days * DAY),
    subject, spki: spkiOf(key.publicKey)
  };
  if (precert) return buildCert({ ...fields, extensions: [...base, ext(OID_POISON, nul(), true)], signer: signWith(caKey.privateKey, 'sha256') });
  let tbs = null;
  buildCert({ ...fields, extensions: base, signer: (t) => { tbs = t; return Buffer.alloc(1); } });
  const scts = logs.map((l, i) => signSct(LOGS[l], tbs, START + 5000 + i * 1137, LOGS[l].api === 'static' ? leafIndex(4660 + i) : Buffer.alloc(0)));
  const list = Buffer.concat(scts.map((s) => Buffer.concat([u16(s.length), s])));
  const sctExt = ext(OID_SCT, octet(Buffer.concat([u16(list.length), list])));
  return buildCert({ ...fields, extensions: [...base, sctExt], signer: signWith(caKey.privateKey, 'sha256') });
}

const out = {
  sct_compliant: leaf('0101', 90, ['alpha', 'charlie']),
  sct_one_operator: leaf('0102', 90, ['alpha', 'bravo']),
  sct_long: leaf('0103', 397, ['alpha', 'charlie']),
  sct_long_ok: leaf('0104', 397, ['alpha', 'charlie', 'delta']),
  sct_unknown: leaf('0105', 90, ['alpha', 'foxtrot', 'echo']),
  sct_static_only: leaf('0106', 90, ['charlie', 'hotel']),
  sct_precert: leaf('0107', 90, [], { precert: true })
};
for (const [file, der] of Object.entries(out)) writeFileSync(join(DIR, `${file}.pem`), pem(der));
writeFileSync(join(DIR, 'sct_ca.pem'), pem(caDer));
writeFileSync(join(DIR, 'log_list.json'), `${JSON.stringify(logList, null, 2)}\n`);
process.stdout.write(`wrote ${FILES.length} files to tests/fixtures/sct/\n`);
