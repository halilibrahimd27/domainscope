/**
 * revocation.test.js — lib/revocation.js: Cert Spotter's revocation fields and the CA's
 * problem-reporting text, and the Certificate view's "Is it revoked?" (one exact-name request, the
 * issuance matched by the certificate's SHA-256 computed locally, or by its public key and
 * validity when only the precertificate is logged). Cert Spotter rows in the shape the live API
 * returned on 2026-10-08 (tests/js/ct-fake.mjs); a fake fetch, an injected clock and cool-down.
 * Documentation names only.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  REVOCATION_STATUSES, REVOCATION_MAX_PAGES, PROBLEM_REPORTING_MAX_CHARS, spotterRevocation, problemReportingText, revocationName,
  revocationUrl, matchIssuance, checkRevocation
} from '../../assets/js/lib/revocation.js';
import { CERTSPOTTER_ISSUANCES, createCtCooldown } from '../../assets/js/lib/ctcert.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { sha256 } from '../../assets/js/lib/sha.js';
import { REVOCATION_REASON_NAMES, CRL_UNKNOWN } from '../../assets/js/lib/crl.js';
import { spotterRow, CT_PROBLEM_REPORTING } from './ct-fake.mjs';

const FIX = join(dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');
const LEAF = parseCertificates(readFileSync(join(FIX, 'crl_leaf.pem'))).certificates[0];
const NOW = Date.parse('2026-10-09T12:00:00Z');
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const SHA = hex(sha256(LEAF.der));
const SPKI = hex(sha256(LEAF.spkiDer));

/** A row of this certificate: its SHA-256, its key, its validity. */
const own = (extra = {}) => ({
  ...spotterRow({ names: ['www.example.com', 'example.com'], ...extra }),
  cert_sha256: SHA, pubkey_sha256: SPKI, not_before: '2025-01-01T00:00:00Z', not_after: '2060-01-01T00:00:00Z'
});
const other = () => spotterRow({ names: ['www.example.com'] });

function fakeFetch(pages, calls = []) {
  const impl = async (url) => {
    calls.push(String(url));
    const page = typeof pages === 'function' ? pages(calls.length - 1) : pages[calls.length - 1] ?? [];
    if (page instanceof Response) return page;
    return new Response(JSON.stringify(page), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  impl.calls = calls;
  return impl;
}

test('the statuses and limits', () => {
  assert.deepEqual([...REVOCATION_STATUSES], ['good', 'revoked', 'not-found', 'expired', 'no-name', 'rate-limited', 'error']);
  assert.equal(REVOCATION_MAX_PAGES, 3);
  assert.ok(Object.isFrozen(REVOCATION_STATUSES));
});

test('Cert Spotter’s revocation fields: revoked with its reason, not revoked, not expanded', () => {
  assert.deepEqual(spotterRevocation(spotterRow({ names: ['www.example.com'], revokedAt: '2026-09-21T10:15:00Z', reason: 4 })), {
    revoked: true, time: new Date('2026-09-21T10:15:00Z'), reasonCode: 4, reason: 'superseded', checkedAt: new Date('2026-10-08T06:00:00Z')
  });
  assert.deepEqual(spotterRevocation(spotterRow({ names: ['www.example.com'] })), { revoked: false, time: null, reasonCode: null, reason: null, checkedAt: new Date('2026-10-08T06:00:00Z') });
  assert.equal(spotterRevocation(spotterRow({ names: ['www.example.com'], problemReporting: null })), null);
  assert.equal(spotterRevocation(null), null);
  assert.equal(spotterRevocation({ revocation: [1] }), null);
  assert.equal(spotterRevocation({ revoked: true, revocation: { time: 'garbage', reason: 99, checked_at: null } }).reason, null, 'a code RFC 5280 does not define');
});

test('the CA’s problem-reporting text: kept as text, controls out, cut', () => {
  assert.equal(problemReportingText(CT_PROBLEM_REPORTING), CT_PROBLEM_REPORTING);
  assert.equal(problemReportingText('a\r\nb\u0000\u001b[2Jc⁦d'), 'a\nb[2Jcd');
  assert.equal(problemReportingText('   '), null);
  assert.equal(problemReportingText(7), null);
  const long = problemReportingText('x'.repeat(5000));
  assert.equal(long.length, PROBLEM_REPORTING_MAX_CHARS);
  assert.ok(long.endsWith('…'));
});

test('the name asked: the first that is no wildcard, else the wildcard itself; the URL holds the name only', () => {
  assert.equal(revocationName(LEAF), 'www.example.com');
  assert.equal(revocationName({ hostnames: ['*.example.com', 'example.org'] }), 'example.org');
  assert.equal(revocationName({ hostnames: ['*.example.com'] }), '*.example.com');
  assert.equal(revocationName({ hostnames: [] }), null);
  const u = new URL(revocationUrl('*.example.com', { after: '42' }));
  assert.equal(u.origin + u.pathname, CERTSPOTTER_ISSUANCES);
  assert.deepEqual([...u.searchParams.keys()], ['domain', 'expand', 'expand', 'after']);
  assert.equal(u.searchParams.get('domain'), '*.example.com');
  assert.deepEqual(u.searchParams.getAll('expand'), ['revocation', 'problem_reporting']);
});

test('the issuance is this certificate by its SHA-256, or by its key and exact validity', () => {
  const want = { sha256: SHA, spkiSha256: SPKI, notBefore: LEAF.notBefore, notAfter: LEAF.notAfter };
  const exact = own();
  assert.deepEqual(matchIssuance([other(), exact], want), { item: exact, by: 'certificate' });
  const precert = { ...own(), cert_sha256: 'cd'.repeat(32) };
  assert.deepEqual(matchIssuance([precert], want), { item: precert, by: 'issuance' });
  assert.equal(matchIssuance([{ ...precert, not_after: '2059-12-31T00:00:00Z' }], want), null, 'another validity: another issuance');
  assert.equal(matchIssuance([precert], { ...want, spkiSha256: null }), null);
  assert.equal(matchIssuance('x', want), null);
});

test('Is it revoked? good, revoked with the CA’s contact, matched by the issuance', async () => {
  const cooldown = createCtCooldown();
  const fetchImpl = fakeFetch([[other(), own()]]);
  const good = await checkRevocation(LEAF, { fetchImpl, now: NOW, cooldown });
  assert.equal(good.status, 'good');
  assert.equal(good.name, 'www.example.com');
  assert.equal(good.requests, 1);
  assert.equal(good.matchedBy, 'certificate');
  assert.deepEqual(good.revocation, { time: null, reasonCode: null, reason: null, checkedAt: new Date('2026-10-08T06:00:00Z') });
  assert.equal(good.problemReporting, CT_PROBLEM_REPORTING);
  assert.equal(fetchImpl.calls.length, 1);
  assert.ok(!fetchImpl.calls[0].includes(SHA) && !fetchImpl.calls[0].includes(SPKI), 'only the name leaves the page');
  const revoked = await checkRevocation(LEAF, { fetchImpl: fakeFetch([[own({ revokedAt: '2026-09-21T10:15:00Z', reason: 1 })]]), now: new Date(NOW), cooldown });
  assert.deepEqual([revoked.status, revoked.revocation.reason, revoked.revocation.time.toISOString()], ['revoked', 'keyCompromise', '2026-09-21T10:15:00.000Z']);
  const pre = await checkRevocation(LEAF, { fetchImpl: fakeFetch([[{ ...own(), cert_sha256: 'cd'.repeat(32) }]]), now: NOW, cooldown });
  assert.deepEqual([pre.status, pre.matchedBy], ['good', 'issuance']);
});

test('Is it revoked? not listed (pages on to the empty one, at most three), expired, no name: nothing more sent', async () => {
  const cooldown = createCtCooldown();
  const twoPages = fakeFetch([[other()], []]);
  const nf = await checkRevocation(LEAF, { fetchImpl: twoPages, now: NOW, cooldown });
  assert.deepEqual([nf.status, nf.requests, nf.truncated], ['not-found', 2, false]);
  assert.match(twoPages.calls[1], /&after=\d+$/);
  const many = fakeFetch(() => [other()]);
  const cut = await checkRevocation(LEAF, { fetchImpl: many, now: NOW, cooldown });
  assert.deepEqual([cut.status, cut.requests, cut.truncated], ['not-found', 3, true]);
  const none = fakeFetch([]);
  const expired = await checkRevocation(LEAF, { fetchImpl: none, now: Date.parse('2061-01-01T00:00:00Z'), cooldown });
  assert.deepEqual([expired.status, expired.name, expired.requests], ['expired', null, 0]);
  const nameless = await checkRevocation({ ...LEAF, hostnames: [] }, { fetchImpl: none, now: NOW, cooldown });
  assert.equal(nameless.status, 'no-name');
  assert.equal(none.calls.length, 0, 'nothing sent');
});

test('the page words every reason lib/crl.js names and every code the CLI writes', async () => {
  const ui = await import('../../assets/js/ui/revocation.js');
  assert.deepEqual([...ui.REASON_KEYS], [...REVOCATION_REASON_NAMES]);
  assert.ok(CRL_UNKNOWN.every((c) => ui.REVOCATION_UNKNOWN_CODES.includes(c)));
  const cli = readFileSync(join(FIX, '..', '..', 'cli', 'ssl_origin_scan.py'), 'utf8');
  const keysOf = (name) => {
    const start = cli.indexOf(`${name} = {`);
    return [...cli.slice(start, cli.indexOf('}\n', start)).matchAll(/'([a-z-]+)':/g)].map((m) => m[1]);
  };
  assert.deepEqual(keysOf('_ARI_WHY'), [...ui.ARI_ERROR_CODES]);
  assert.deepEqual(keysOf('_REVOCATION_WHY'), [...ui.REVOCATION_UNKNOWN_CODES]);
});

test('Is it revoked? a 429 starts the shared cool-down; an error says so; an abort rejects', async () => {
  const cooldown = createCtCooldown();
  const limited = fakeFetch([new Response('{}', { status: 429, headers: { 'retry-after': '600' } })]);
  const r = await checkRevocation(LEAF, { fetchImpl: limited, now: NOW, cooldown });
  assert.equal(r.status, 'rate-limited');
  assert.equal(r.quota.resetAt.getTime(), NOW + 600000);
  const again = fakeFetch([[own()]]);
  const skipped = await checkRevocation(LEAF, { fetchImpl: again, now: NOW + 1000, cooldown });
  assert.deepEqual([skipped.status, skipped.requests, again.calls.length], ['rate-limited', 0, 0], 'not asked during the cool-down');
  const down = await checkRevocation(LEAF, { fetchImpl: fakeFetch([new Response('busy', { status: 503 })]), now: NOW, cooldown: createCtCooldown() });
  assert.deepEqual([down.status, down.errorKind], ['error', 'http']);
  const junk = await checkRevocation(LEAF, { fetchImpl: fakeFetch([{ not: 'a list' }]), now: NOW, cooldown: createCtCooldown() });
  assert.deepEqual([junk.status, junk.errorKind], ['error', 'parse']);
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(checkRevocation(LEAF, { fetchImpl: fakeFetch([[own()]]), now: NOW, signal: controller.signal, cooldown: createCtCooldown() }), { name: 'AbortError' });
});
