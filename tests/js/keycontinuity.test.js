/**
 * Key continuity (lib/keycontinuity.js): the SHA-256 of a certificate's SubjectPublicKeyInfo, the
 * crt.sh search by it, the rows folded into certificates, and what they say of crt.sh — a key
 * carried over renewals, no earlier certificate with it there, a logged certificate crt.sh has not
 * indexed (SCTs, a public CA) or nothing that says it was logged. The rows follow the shape crt.sh
 * answered on 2026-09-28 (`name_value` is the hash, the precertificate and the certificate share a
 * serial). No network: fetch is a fake.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, X509Certificate } from 'node:crypto';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import {
  CRTSH_BASE, KEY_MAX_ROWS, KEY_STATUSES, crtshKeyUrl, keyContinuity, lookupKeyContinuity, parseKeyRows, spkiSha256
} from '../../assets/js/lib/keycontinuity.js';

const FIXTURES = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const pem = (name) => readFileSync(join(FIXTURES, name), 'utf8');
const leafOf = (name) => parseCertificates(pem(name)).leaf;
/** The SPKI SHA-256 as Node's crypto computes it, for comparison. */
const nodeSpki = (name) => createHash('sha256').update(new X509Certificate(pem(name)).publicKey.export({ type: 'spki', format: 'der' })).digest('hex');

const GITHUB = leafOf('real_github.pem');
const SECTIGO = 'C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36';
const HASH = nodeSpki('real_github.pem');
const row = (id, serial, from, to, issuer = SECTIGO) => ({
  issuer_ca_id: 204407, issuer_name: issuer, name_value: HASH, id, not_before: from, not_after: to, serial_number: serial, result_count: 0
});
const NOW = Date.parse('2026-09-28T12:00:00Z');

describe('the key and its search', () => {
  test('spkiSha256 is the SHA-256 of the SubjectPublicKeyInfo (RSA and EC), with or without WebCrypto', async () => {
    for (const name of ['real_github.pem', 'ec_wildcard.pem', 'rsa_multi_san.pem']) {
      const cert = leafOf(name);
      assert.equal(await spkiSha256(cert), nodeSpki(name), name);
      assert.equal(await spkiSha256(cert, { subtle: null }), nodeSpki(name), `${name}: pure-JS fallback`);
    }
    await assert.rejects(spkiSha256({}), TypeError);
  });

  test('crtshKeyUrl searches crt.sh by the hash and nothing else', () => {
    assert.equal(crtshKeyUrl(HASH.toUpperCase()), `${CRTSH_BASE}?spkisha256=${HASH}&output=json`);
    for (const bad of ['', 'abc', `${HASH}0`, 'x'.repeat(64), null]) assert.throws(() => crtshKeyUrl(bad), TypeError, String(bad));
  });
});

describe('parseKeyRows', () => {
  test('folds the precertificate and the certificate, oldest first, and finds the certificate looked up', () => {
    const rows = [
      row(300, '00a59ebdb596751db7f5c095079613953c', '2026-09-01T00:00:00', '2026-11-29T23:59:59'),
      row(299, 'a59ebdb596751db7f5c095079613953c', '2026-09-01T00:00:00', '2026-11-29T23:59:59'),
      row(100, '0102', '2026-03-04T00:00:00', '2026-06-02T23:59:59'),
      row(101, '0102', '2026-03-04T00:00:00', '2026-06-02T23:59:59'),
      row(200, '0203', '2026-06-01T00:00:00', '2026-08-30T23:59:59'),
      null,
      'junk'
    ];
    const out = parseKeyRows(rows, { cert: GITHUB });
    assert.equal(out.rows, 7);
    assert.equal(out.truncated, false);
    assert.deepEqual(out.certs.map((c) => [c.serialHex, c.ids, c.isThis]), [
      ['0102', ['100', '101'], false],
      ['0203', ['200'], false],
      ['a59ebdb596751db7f5c095079613953c', ['299', '300'], true]
    ]);
    assert.equal(out.certs[2].url, `${CRTSH_BASE}?id=299`);
    assert.equal(out.certs[0].notBefore.toISOString(), '2026-03-04T00:00:00.000Z');
    assert.equal(out.certs[0].issuer, SECTIGO);
  });

  test('the same serial from another CA is not the certificate looked up', () => {
    const out = parseKeyRows([row(1, 'a59ebdb596751db7f5c095079613953c', '2026-09-01T00:00:00', '2026-11-29T23:59:59', 'C=US, O=Other CA, CN=Other R1')], { cert: GITHUB });
    assert.equal(out.certs[0].isThis, false);
  });

  test('reads at most KEY_MAX_ROWS rows and refuses what is not a list', () => {
    const many = Array.from({ length: KEY_MAX_ROWS + 5 }, (_, i) => row(i + 1, (i + 1).toString(16).padStart(4, '0'), '2026-01-01T00:00:00', '2026-04-01T00:00:00'));
    const out = parseKeyRows(many);
    assert.equal(out.certs.length, KEY_MAX_ROWS);
    assert.equal(out.truncated, true);
    for (const bad of [null, {}, 'x']) assert.throws(() => parseKeyRows(bad), { name: 'ParseError' }, String(bad));
  });
});

describe('keyContinuity', () => {
  const certs = parseKeyRows([
    row(100, '0102', '2026-03-04T00:00:00', '2026-06-02T23:59:59'),
    row(200, '0203', '2026-06-01T00:00:00', '2026-08-30T23:59:59'),
    row(299, 'a59ebdb596751db7f5c095079613953c', '2026-09-01T00:00:00', '2026-11-29T23:59:59'),
    row(400, '0304', '2026-09-20T00:00:00', '2026-12-19T23:59:59')
  ], { cert: GITHUB }).certs;

  test('a key in other certificates was reused: since when, how long, how many before and after', () => {
    const k = keyContinuity(certs, { cert: GITHUB, now: NOW });
    assert.deepEqual({ ...k, firstSeen: k.firstSeen.toISOString(), lastUntil: k.lastUntil.toISOString() }, {
      status: 'reused',
      sctCount: 2,
      expectLogged: true,
      total: 4,
      others: 3,
      thisLogged: true,
      before: 2,
      after: 1,
      current: 2,
      firstSeen: '2026-03-04T00:00:00.000Z',
      lastUntil: '2026-12-19T23:59:59.000Z',
      days: 208,
      issuers: [SECTIGO]
    });
  });

  test('only this certificate: none earlier on crt.sh; others without this one: still reused', () => {
    const self = certs.filter((c) => c.isThis);
    assert.equal(keyContinuity(self, { cert: GITHUB, now: NOW }).status, 'single');
    const others = keyContinuity(certs.filter((c) => !c.isThis), { cert: GITHUB, now: NOW });
    assert.deepEqual([others.status, others.thisLogged, others.before, others.after], ['reused', false, 2, 1], 'dated from the certificate itself');
    assert.deepEqual([...KEY_STATUSES], ['reused', 'single', 'not-indexed', 'not-found']);
  });

  test('nothing on crt.sh: a certificate with SCTs or from a public CA was logged, just not indexed; without either, not found', () => {
    assert.equal(GITHUB.sctCount, 2, 'the fixture carries two embedded SCTs');
    const scts = keyContinuity([], { cert: GITHUB, now: NOW });
    assert.deepEqual([scts.status, scts.sctCount, scts.expectLogged, scts.total, scts.days, scts.firstSeen], ['not-indexed', 2, true, 0, null, null]);
    const privateCa = leafOf('rsa_multi_san.pem');
    assert.equal(privateCa.sctCount, null);
    const none = keyContinuity([], { cert: privateCa, now: NOW });
    assert.deepEqual([none.status, none.sctCount, none.expectLogged], ['not-found', null, false]);
    const publicCa = keyContinuity([], { cert: privateCa, now: NOW, publicCa: true });
    assert.deepEqual([publicCa.status, publicCa.expectLogged], ['not-indexed', true], 'a public CA logs what it issues');
    assert.equal(keyContinuity([], { cert: { ...privateCa, sctCount: 0 }, now: NOW }).status, 'not-found', 'an empty SCT list says nothing');
  });

  test('a key whose certificates all expired counts its days up to the last one', () => {
    const old = parseKeyRows([row(1, '01', '2024-01-01T00:00:00', '2024-03-31T00:00:00'), row(2, '02', '2024-03-01T00:00:00', '2024-05-30T00:00:00')]).certs;
    const k = keyContinuity(old, { now: NOW });
    assert.equal(k.days, 150);
    assert.equal(k.current, 0);
  });
});

describe('lookupKeyContinuity', () => {
  const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

  test('sends one search with only the key\'s hash and returns what the certificates say', async () => {
    const urls = [];
    const fetchImpl = async (url, init) => {
      urls.push({ url: String(url), init });
      return json([row(299, 'a59ebdb596751db7f5c095079613953c', '2026-09-01T00:00:00', '2026-11-29T23:59:59')]);
    };
    const r = await lookupKeyContinuity(GITHUB, { fetchImpl, now: NOW });
    assert.deepEqual(urls.map((u) => u.url), [`https://crt.sh/?spkisha256=${HASH}&output=json`]);
    assert.equal(urls[0].init.credentials, 'omit');
    assert.equal(urls[0].init.body, undefined);
    assert.equal(r.status, 'single');
    assert.equal(r.spki, HASH);
    assert.equal(r.url, urls[0].url);
    assert.equal(r.certs.length, 1);
    assert.equal(r.checkedAt.getTime(), NOW);
  });

  test('a certificate with SCTs that crt.sh answers nothing for is logged but not indexed, never "not logged"', async () => {
    const empty = async () => json([]);
    const r = await lookupKeyContinuity(GITHUB, { fetchImpl: empty, now: NOW });
    assert.deepEqual([r.status, r.sctCount, r.expectLogged, r.total, r.thisLogged], ['not-indexed', 2, true, 0, false]);
    const privateCa = leafOf('rsa_multi_san.pem');
    assert.equal((await lookupKeyContinuity(privateCa, { fetchImpl: empty, now: NOW })).status, 'not-found');
    assert.equal((await lookupKeyContinuity(privateCa, { fetchImpl: empty, now: NOW, publicCa: true })).status, 'not-indexed');
  });

  test('retries once after a server error or a CORS-less error page, never after a timeout, and passes an abort on', async () => {
    let calls = 0;
    const flaky = async () => {
      calls += 1;
      if (calls === 1) throw new TypeError('Failed to fetch');
      return json([]);
    };
    assert.equal((await lookupKeyContinuity(GITHUB, { fetchImpl: flaky, retryDelayMs: 0, now: NOW })).status, 'not-indexed');
    assert.equal(calls, 2);

    calls = 0;
    const down = async () => {
      calls += 1;
      return json({ error: 'busy' }, 502);
    };
    await assert.rejects(lookupKeyContinuity(GITHUB, { fetchImpl: down, retryDelayMs: 0 }), { name: 'HttpError' });
    assert.equal(calls, 2);

    calls = 0;
    const slow = (url, init) => new Promise((resolve, reject) => {
      calls += 1;
      init.signal.addEventListener('abort', () => reject(init.signal.reason));
    });
    await assert.rejects(lookupKeyContinuity(GITHUB, { fetchImpl: slow, timeoutMs: 20, retryDelayMs: 0 }), { name: 'TimeoutError' });
    assert.equal(calls, 1);

    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(lookupKeyContinuity(GITHUB, { fetchImpl: flaky, signal: ctl.signal }), { name: 'AbortError' });
    await assert.rejects(lookupKeyContinuity(GITHUB, { fetchImpl: async () => json({ not: 'a list' }) }), { name: 'ParseError' });
  });
});
