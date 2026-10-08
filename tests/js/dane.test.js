// Unit tests for assets/js/lib/dane.js — the DANE / TLSA renewal guard. No network: the
// end-to-end cases drive a real DohClient whose fetchImpl decodes the RFC 8484 `?dns=` query
// and answers with wire-format messages built by dnswire.encodeMessage (as doh.test.js does),
// so the DO / CD bits, the AD flag, CNAMEs and RRSIGs travel the same path as in a browser.
// Certificates: cli_renewed_wild.pem is "the new certificate" for *.wild.example.net,
// ec_wildcard.pem the old one (another key); chain.pem is a leaf with its issuing root.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as D from '../../assets/js/lib/dane.js';
import { parseCertificates } from '../../assets/js/lib/x509.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { RESOLVERS } from '../../assets/js/lib/resolvers.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';

const ROOT = new URL('../../', import.meta.url);
const certsOf = (file) => parseCertificates(readFileSync(new URL(`tests/fixtures/${file}`, ROOT)));
const NEW = certsOf('cli_renewed_wild.pem').leaf;
const OLD = certsOf('ec_wildcard.pem').leaf;
const CHAIN = certsOf('chain.pem');
const CHAIN_LEAF = CHAIN.leaf;
const CHAIN_ROOT = CHAIN.certificates.find((c) => c !== CHAIN_LEAF);

const sha = (alg, bytes) => createHash(alg).update(bytes).digest('hex');
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const NEW_A = await D.certAssociations(NEW);
const OLD_A = await D.certAssociations(OLD);
const ROOT_A = await D.certAssociations(CHAIN_ROOT);
const CHAIN_A = await D.certAssociations(CHAIN_LEAF);

const rec = (usage, selector, matchingType, data) => ({ usage, selector, matchingType, data });

/* ------------------------------------------------------------------------ */
/* Mock DoH                                                                 */
/* ------------------------------------------------------------------------ */

function resolverIdOf(url) {
  const r = RESOLVERS.find((x) => url.startsWith(`${x.url}?`) || url.startsWith(`${x.url}&`));
  return r ? r.id : new URL(url).host;
}

/**
 * A DoH server answering from `zone`: keys `name|TYPE` → { rcode, answers, ad, cd: { … } }
 * (`cd`: the answer when the query has CD set). Unknown names get NXDOMAIN. Every call is
 * recorded with its decoded query.
 */
function zoneFetch(zone) {
  const calls = [];
  const fetchImpl = async (url) => {
    const query = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns')));
    const q = query.questions[0];
    calls.push({ resolver: resolverIdOf(url), name: q.name, type: q.type, dnssecOk: !!(query.edns && query.edns.dnssecOk), cd: !!query.flags.cd });
    let node = zone[`${q.name}|${q.type}`] || { rcode: 'NXDOMAIN', answers: [], ad: true };
    if (query.flags.cd && node.cd) node = node.cd;
    const bytes = encodeMessage({
      id: 0,
      flags: { qr: true, rd: true, ra: true, ad: !!node.ad, cd: query.flags.cd },
      rcode: node.rcode || 'NOERROR',
      questions: [{ name: q.name, type: q.type }],
      answers: node.answers || [],
      edns: { dnssecOk: true }
    });
    return new Response(bytes, { status: 200, headers: { 'content-type': 'application/dns-message' } });
  };
  return { fetchImpl, calls };
}

const client = (zone) => {
  const f = zoneFetch(zone);
  return { dns: new DohClient({ chain: ['cloudflare'], fetchImpl: f.fetchImpl, cache: false, retries: 0, baseDelayMs: 1, timeoutMs: 2000 }), calls: f.calls };
};

const mx = (owner, list, { ad = true, ttl = 300 } = {}) => ({
  rcode: 'NOERROR', ad, answers: list.map(([preference, exchange]) => ({ name: owner, type: 'MX', ttl, data: { preference, exchange } }))
});
const tlsa = (owner, records, { ad = true, ttl = 1800, originalTtl = 3600, sig = true } = {}) => ({
  rcode: 'NOERROR',
  ad,
  answers: [
    ...records.map((r) => ({ name: owner, type: 'TLSA', ttl, data: r })),
    ...(sig ? [{
      name: owner, type: 'RRSIG', ttl,
      data: {
        typeCovered: 'TLSA', algorithm: 13, labels: owner.split('.').length, originalTtl,
        expiration: new Date('2030-01-01T00:00:00Z'), inception: new Date('2026-01-01T00:00:00Z'),
        keyTag: 12345, signerName: owner.split('.').slice(-2).join('.'), signature: 'AAAA'
      }
    }] : [])
  ]
});

/* ------------------------------------------------------------------------ */
/* Association data and records                                             */
/* ------------------------------------------------------------------------ */

describe('certAssociations / associationData', () => {
  test('selector 0/1 × matching 0/1/2 equal the raw bytes and their SHA-256 / SHA-512 (node:crypto)', () => {
    assert.equal(NEW_A[0][0], hex(NEW.der));
    assert.equal(NEW_A[0][1], sha('sha256', NEW.der));
    assert.equal(NEW_A[0][2], sha('sha512', NEW.der));
    assert.equal(NEW_A[1][0], hex(NEW.spkiDer));
    assert.equal(NEW_A[1][1], sha('sha256', NEW.spkiDer));
    assert.equal(NEW_A[1][2], sha('sha512', NEW.spkiDer));
    assert.ok(Object.isFrozen(NEW_A) && Object.isFrozen(NEW_A[1]));
    assert.notEqual(NEW_A[1][1], OLD_A[1][1], 'the renewed fixture has a new key');
  });

  test('associationData reads one cell; unknown fields give null', () => {
    assert.equal(D.associationData(NEW_A, 1, 1), NEW_A[1][1]);
    assert.equal(D.associationData(NEW_A, 2, 1), null);
    assert.equal(D.associationData(NEW_A, 1, 3), null);
    assert.equal(D.associationData(null, 1, 1), null);
  });

  test('no WebCrypto → DaneError no-crypto; no DER → bad-input', async () => {
    await assert.rejects(D.certAssociations(NEW, { subtle: null }), (e) => e instanceof D.DaneError && e.code === 'no-crypto');
    await assert.rejects(D.certAssociations({ hostnames: [] }), (e) => e instanceof D.DaneError && e.code === 'bad-input');
  });
});

describe('tlsaOwner / tlsaRecordText', () => {
  test('owner names and the paste-ready presentation line', () => {
    assert.equal(D.tlsaOwner('mx.example.com'), '_25._tcp.mx.example.com');
    assert.equal(D.tlsaOwner('www.example.com', 443), '_443._tcp.www.example.com');
    assert.equal(D.tlsaRecordText('_25._tcp.mx.example.com', rec(3, 1, 1, 'ab:cd ef')), '_25._tcp.mx.example.com. IN TLSA 3 1 1 ABCDEF');
  });
});

describe('matchRecord', () => {
  const ctx = { service: 'smtp', leaf: NEW_A, anchors: [] };

  test('DANE-EE matches the leaf for every selector and matching type', () => {
    for (const s of [0, 1]) {
      for (const m of [0, 1, 2]) {
        assert.deepEqual(D.matchRecord(rec(3, s, m, NEW_A[s][m]), ctx), { usable: true, matches: true, matchedBy: 'leaf', anchor: null, issue: null }, `3 ${s} ${m}`);
      }
    }
  });

  test('data is compared case- and separator-insensitively; another key does not match', () => {
    assert.equal(D.matchRecord(rec(3, 1, 1, NEW_A[1][1].toUpperCase().replace(/(..)/g, '$1 ')), ctx).matches, true);
    assert.deepEqual(D.matchRecord(rec(3, 1, 1, OLD_A[1][1]), ctx), { usable: true, matches: false, matchedBy: null, anchor: null, issue: null });
  });

  test('DANE-TA is compared with the chain; without one it is unknown (null)', () => {
    const anchors = [{ assoc: ROOT_A }];
    const r = D.matchRecord(rec(2, 1, 1, ROOT_A[1][1]), { service: 'smtp', leaf: CHAIN_A, anchors });
    assert.deepEqual(r, { usable: true, matches: true, matchedBy: 'chain', anchor: 0, issue: null });
    assert.equal(D.matchRecord(rec(2, 0, 2, ROOT_A[0][2]), { service: 'smtp', leaf: CHAIN_A, anchors }).matches, true);
    assert.equal(D.matchRecord(rec(2, 1, 1, OLD_A[1][1]), { service: 'smtp', leaf: CHAIN_A, anchors }).matches, false);
    assert.equal(D.matchRecord(rec(2, 1, 1, ROOT_A[1][1]), { service: 'smtp', leaf: CHAIN_A, anchors: [] }).matches, null);
    // A DANE-TA record never matches the leaf itself.
    assert.equal(D.matchRecord(rec(2, 1, 1, CHAIN_A[1][1]), { service: 'smtp', leaf: CHAIN_A, anchors }).matches, false);
  });

  test('PKIX usages: unusable for SMTP (RFC 7672), compared for HTTPS', () => {
    assert.equal(D.matchRecord(rec(1, 1, 1, NEW_A[1][1]), ctx).issue, 'pkix-smtp');
    assert.equal(D.matchRecord(rec(0, 1, 1, NEW_A[1][1]), ctx).usable, false);
    assert.equal(D.matchRecord(rec(1, 1, 1, NEW_A[1][1]), { ...ctx, service: 'https' }).matches, true);
    assert.equal(D.matchRecord(rec(0, 1, 1, ROOT_A[1][1]), { service: 'https', leaf: CHAIN_A, anchors: [{ assoc: ROOT_A }] }).matches, true);
  });

  test('unknown parameters and digests of the wrong length are unusable', () => {
    assert.equal(D.matchRecord(rec(4, 1, 1, NEW_A[1][1]), ctx).issue, 'bad-usage');
    assert.equal(D.matchRecord(rec(3, 2, 1, NEW_A[1][1]), ctx).issue, 'bad-selector');
    assert.equal(D.matchRecord(rec(3, 1, 3, NEW_A[1][1]), ctx).issue, 'bad-matching');
    assert.equal(D.matchRecord(rec(3, 1, 1, NEW_A[1][1].slice(2)), ctx).issue, 'bad-length');
    assert.equal(D.matchRecord(rec(3, 1, 2, NEW_A[1][1]), ctx).issue, 'bad-length');
    assert.equal(D.matchRecord(rec(3, 1, 0, ''), ctx).issue, 'bad-length');
    assert.equal(D.matchRecord(null, ctx).issue, 'bad-usage');
  });
});

describe('evaluateRecords / suggestRecords', () => {
  const smtp = { service: 'smtp', leaf: NEW_A, anchors: [] };
  const verdict = (records, ctx = smtp) => D.evaluateRecords(records, ctx).verdict;

  test('verdict matrix', () => {
    assert.equal(verdict([]), 'none');
    assert.equal(verdict([rec(1, 1, 1, NEW_A[1][1]), rec(3, 1, 7, 'aa')]), 'unusable', 'SMTP: PKIX and unknown only');
    assert.equal(verdict([rec(3, 1, 1, OLD_A[1][1]), rec(3, 1, 1, NEW_A[1][1])]), 'safe', 'the new record next to the old one');
    assert.equal(verdict([rec(3, 1, 1, OLD_A[1][1])]), 'danger');
    assert.equal(verdict([rec(3, 1, 1, OLD_A[1][1]), rec(2, 1, 1, ROOT_A[1][1])]), 'ta-unchecked', 'a TA record that may match (no chain) is not a certain break');
    assert.equal(verdict([rec(2, 1, 1, OLD_A[1][1])], { ...smtp, anchors: [{ assoc: ROOT_A }] }), 'ta-mismatch');
    assert.equal(verdict([rec(3, 1, 1, OLD_A[1][1]), rec(2, 1, 1, OLD_A[1][1])], { ...smtp, anchors: [{ assoc: ROOT_A }] }), 'danger');
    assert.equal(verdict([rec(1, 1, 1, OLD_A[1][1])], { ...smtp, service: 'https' }), 'pkix');
    assert.equal(verdict([rec(1, 1, 1, NEW_A[1][1])], { ...smtp, service: 'https' }), 'safe');
  });

  test('danger: one new record per published selector / matching type, duplicates collapsed', () => {
    const ev = D.evaluateRecords([rec(3, 1, 1, OLD_A[1][1]), rec(3, 0, 1, OLD_A[0][1]), rec(3, 1, 1, '11'.repeat(32))], smtp);
    const out = D.suggestRecords('_25._tcp.mx.example.net', ev, { leaf: NEW_A });
    assert.deepEqual(out.map((s) => s.text), [
      `_25._tcp.mx.example.net. IN TLSA 3 1 1 ${NEW_A[1][1].toUpperCase()}`,
      `_25._tcp.mx.example.net. IN TLSA 3 0 1 ${NEW_A[0][1].toUpperCase()}`
    ]);
    assert.deepEqual(Object.keys(out[0]).sort(), ['data', 'matchingType', 'owner', 'selector', 'text', 'usage']);
  });

  test('DANE-TA: the issuing CA of the file, else 3 1 1 of the leaf; PKIX-EE: the leaf; safe: nothing', () => {
    const ta = D.evaluateRecords([rec(2, 1, 1, OLD_A[1][1])], { ...smtp, leaf: CHAIN_A, anchors: [{ assoc: ROOT_A }] });
    assert.deepEqual(D.suggestRecords('_25._tcp.mx.example.net', ta, { leaf: CHAIN_A, issuer: ROOT_A }).map((s) => [s.usage, s.selector, s.matchingType, s.data]),
      [[2, 1, 1, ROOT_A[1][1]]]);
    const unchecked = D.evaluateRecords([rec(2, 1, 1, OLD_A[1][1])], smtp);
    assert.equal(unchecked.verdict, 'ta-unchecked');
    assert.deepEqual(D.suggestRecords('_25._tcp.mx.example.net', unchecked, { leaf: NEW_A }).map((s) => [s.usage, s.selector, s.matchingType]), [[3, 1, 1]]);
    const pkix = D.evaluateRecords([rec(1, 0, 2, OLD_A[0][2]), rec(0, 1, 1, OLD_A[1][1])], { service: 'https', leaf: CHAIN_A, anchors: [{ assoc: ROOT_A }] });
    assert.equal(pkix.verdict, 'pkix');
    assert.deepEqual(D.suggestRecords('_443._tcp.www.example.net', pkix, { leaf: CHAIN_A, issuer: ROOT_A }).map((s) => [s.usage, s.data]),
      [[1, CHAIN_A[0][2]], [0, ROOT_A[1][1]]]);
    assert.deepEqual(D.suggestRecords('_443._tcp.www.example.net', pkix, { leaf: CHAIN_A }).map((s) => s.usage), [1], 'PKIX-TA without the issuer: nothing to offer for it');
    // PKIX-TA without a chain may still match, like DANE-TA.
    assert.equal(D.evaluateRecords([rec(0, 1, 1, OLD_A[1][1])], { ...smtp, service: 'https' }).verdict, 'ta-unchecked');
    assert.deepEqual(D.suggestRecords('_25._tcp.mx.example.net', D.evaluateRecords([rec(3, 1, 1, NEW_A[1][1])], smtp), { leaf: NEW_A }), []);
    assert.deepEqual(D.suggestRecords('_25._tcp.mx.example.net', D.evaluateRecords([], smtp), { leaf: NEW_A }), []);
  });
});

/* ------------------------------------------------------------------------ */
/* Answers and verdicts                                                     */
/* ------------------------------------------------------------------------ */

describe('tlsaFromAnswer / authenticated', () => {
  test('a captured wire answer (tests/fixtures/dns/cf-tlsa-ietf.bin) yields its record', () => {
    const msg = decodeMessage(new Uint8Array(readFileSync(new URL('tests/fixtures/dns/cf-tlsa-ietf.bin', ROOT))));
    const owner = msg.questions[0].name;
    const found = D.tlsaFromAnswer({ ok: true, answers: msg.answers }, owner);
    assert.equal(found.records.length, 1);
    assert.deepEqual([found.records[0].usage, found.records[0].selector, found.records[0].matchingType], [3, 1, 1]);
    assert.match(found.records[0].data, /^[0-9a-f]{64}$/);
    assert.deepEqual([found.ttl, found.ttlSource], [msg.answers[0].ttl, 'answer']);
  });

  test('follows a CNAME, prefers the RRSIG original TTL, drops duplicates and other owners', () => {
    const owner = '_25._tcp.mx.example.net';
    const target = '_dane.example.org';
    const msg = decodeMessage(encodeMessage({
      answers: [
        { name: owner, type: 'CNAME', ttl: 60, data: target },
        ...tlsa(target, [rec(3, 1, 1, NEW_A[1][1]), rec(3, 1, 1, NEW_A[1][1])], { ttl: 120, originalTtl: 86400 }).answers,
        { name: 'other.example.org', type: 'TLSA', ttl: 5, data: rec(3, 1, 1, OLD_A[1][1]) }
      ]
    }));
    const found = D.tlsaFromAnswer({ ok: true, answers: msg.answers }, owner);
    assert.equal(found.target, target);
    assert.deepEqual(found.cnames, [target]);
    assert.equal(found.records.length, 1);
    assert.deepEqual([found.ttl, found.ttlSource], [86400, 'rrsig']);
  });

  test('AD from a validating resolver; unknown resolvers and failures are null', () => {
    assert.equal(D.authenticated({ ok: true, resolver: 'cloudflare', flags: { ad: true } }), true);
    assert.equal(D.authenticated({ ok: true, resolver: 'google', flags: { ad: false } }), false);
    assert.equal(D.authenticated({ ok: true, resolver: 'custom', flags: { ad: false } }), null);
    assert.equal(D.authenticated({ ok: false, resolver: 'cloudflare', flags: {} }), null);
    assert.equal(D.authenticated(null), null);
  });
});

describe('endpointVerdict', () => {
  const ep = { service: 'smtp', host: 'mx.example.net', qname: '_25._tcp.mx.example.net', covered: true };
  const ok = (answers, { ad = true, rcode = 'NOERROR' } = {}) => ({ ok: true, rcode, resolver: 'cloudflare', flags: { ad }, answers });
  const ctx = { leaf: NEW_A, anchors: [], issuer: null };
  const v = (response, extra = {}) => D.endpointVerdict(extra.ep || ep, { ...ctx, response, ...extra });

  test('danger: the exact record to add and 2 × the RRSIG original TTL', () => {
    const r = v(ok(tlsa(ep.qname, [rec(3, 1, 1, OLD_A[1][1])], { originalTtl: 3600 }).answers));
    assert.equal(r.status, 'danger');
    assert.equal(r.severity, 'error');
    assert.deepEqual(r.suggestions.map((s) => s.text), [`_25._tcp.mx.example.net. IN TLSA 3 1 1 ${NEW_A[1][1].toUpperCase()}`]);
    assert.equal(r.waitSeconds, 7200);
    assert.deepEqual(r.notes, []);
    assert.equal(r.lookup.authenticated, true);
  });

  test('without an RRSIG the returned TTL is used and flagged as a remaining one', () => {
    const r = v(ok(tlsa(ep.qname, [rec(3, 1, 1, OLD_A[1][1])], { sig: false, ttl: 900 }).answers));
    assert.equal(r.waitSeconds, 1800);
    assert.deepEqual(r.notes.map((n) => n.code), ['ttl-remaining']);
  });

  test('safe: stale records and a key-only match are noted, nothing to add', () => {
    const r = v(ok(tlsa(ep.qname, [rec(3, 1, 1, NEW_A[1][1]), rec(3, 0, 1, OLD_A[0][1])]).answers));
    assert.equal(r.status, 'safe');
    assert.deepEqual(r.notes, [{ code: 'stale-records', params: { count: 1 } }, { code: 'spki-match' }]);
    assert.deepEqual(r.suggestions, []);
    assert.equal(r.waitSeconds, null);
    const full = v(ok(tlsa(ep.qname, [rec(3, 0, 1, NEW_A[0][1])]).answers));
    assert.deepEqual(full.notes, [], 'a full-certificate match is not a key-reuse note');
  });

  test('no record, NXDOMAIN: DANE not used', () => {
    assert.equal(v(ok([])).status, 'none');
    assert.equal(v(ok([], { rcode: 'NXDOMAIN', ad: false })).status, 'none');
  });

  test('not DNSSEC-validated: ignored by senders, with what it would mean', () => {
    const r = v(ok(tlsa(ep.qname, [rec(3, 1, 1, OLD_A[1][1])], { ad: false }).answers, { ad: false }));
    assert.equal(r.status, 'insecure');
    assert.equal(r.severity, 'info');
    assert.equal(r.wouldBe, 'danger');
    assert.equal(r.suggestions.length, 1, 'the record to publish is still offered');
  });

  test('SMTP: an unvalidated MX record set makes TLSA irrelevant (RFC 7672 §2.2.1); HTTPS ignores it', () => {
    const answers = tlsa(ep.qname, [rec(3, 1, 1, OLD_A[1][1])]).answers;
    const r = v(ok(answers), { mxAuthenticated: false });
    assert.deepEqual([r.status, r.wouldBe, r.notes.map((n) => n.code)], ['insecure', 'danger', ['mx-insecure']]);
    assert.equal(v(ok(answers), { mxAuthenticated: null }).status, 'danger');
    const https = { service: 'https', host: 'www.example.net', qname: '_443._tcp.www.example.net', covered: true };
    assert.equal(v(ok(tlsa(https.qname, [rec(3, 1, 1, OLD_A[1][1])]).answers), { ep: https, mxAuthenticated: false }).status, 'danger');
  });

  test('a host the certificate does not name: not-covered unless it matches anyway', () => {
    const other = { ...ep, covered: false };
    const r = v(ok(tlsa(ep.qname, [rec(3, 1, 1, OLD_A[1][1])]).answers), { ep: other });
    assert.deepEqual([r.status, r.wouldBe, r.severity], ['not-covered', 'danger', 'info']);
    assert.equal(v(ok(tlsa(ep.qname, [rec(3, 1, 1, NEW_A[1][1])]).answers), { ep: other }).status, 'safe');
  });

  test('lookup failures: SERVFAIL (bogus when CD answers), REFUSED and transport errors', () => {
    const bogus = v(ok([], { rcode: 'SERVFAIL', ad: false }), { cdResponse: ok(tlsa(ep.qname, [rec(3, 1, 1, NEW_A[1][1])]).answers, { ad: false }) });
    assert.deepEqual([bogus.status, bogus.severity, bogus.lookup.bogus, bogus.notes.map((n) => n.code)], ['servfail', 'error', true, ['bogus']]);
    const broken = v(ok([], { rcode: 'SERVFAIL', ad: false }), { cdResponse: ok([], { rcode: 'SERVFAIL', ad: false }) });
    assert.deepEqual([broken.status, broken.lookup.bogus, broken.notes], ['servfail', false, []]);
    assert.deepEqual([v(ok([], { rcode: 'REFUSED' })).status, v(ok([], { rcode: 'REFUSED' })).lookup.error], ['error', 'REFUSED']);
    const down = v({ ok: false, rcode: null, resolver: 'cloudflare', error: 'offline', errorKind: 'network', answers: [] });
    assert.deepEqual([down.status, down.severity, down.lookup.error, down.lookup.errorKind], ['error', 'warn', 'offline', 'network']);
  });

  test('an unknown resolver: the AD flag cannot be judged', () => {
    const r = v({ ok: true, rcode: 'NOERROR', resolver: 'custom', flags: { ad: false }, answers: tlsa(ep.qname, [rec(3, 1, 1, NEW_A[1][1])]).answers });
    assert.equal(r.status, 'safe');
    assert.ok(r.notes.some((n) => n.code === 'ad-unknown' && n.params.resolver === 'custom'));
  });
});

/* ------------------------------------------------------------------------ */
/* Plan                                                                     */
/* ------------------------------------------------------------------------ */

describe('planDane', () => {
  test('wildcards skipped (never the apex), registrable domains for MX, names deduplicated', () => {
    const p = D.planDane(NEW);
    assert.deepEqual(p.domains, ['example.net']);
    assert.deepEqual(p.https, [{ host: 'wild.example.net', source: 'cert' }]);
    assert.deepEqual(p.skipped.wildcard, ['*.wild.example.net']);
  });

  test('extra names: only concrete names the certificate covers', () => {
    const p = D.planDane(NEW, { extraNames: ['www.wild.example.net', 'WWW.wild.example.net.', 'a.b.wild.example.net', 'example.org', 'wild.example.net', 'bad name', 7] });
    assert.deepEqual(p.https.map((x) => `${x.source}:${x.host}`), ['cert:wild.example.net', 'extra:www.wild.example.net']);
    assert.deepEqual(p.skipped.notCovered, ['a.b.wild.example.net', 'example.org']);
  });

  test('hostile certificate names are never queried', () => {
    const p = D.planDane({ hostnames: ['ok.example.com', 'evil.example.com;rm -rf', 'sp ace.example.com', 'localhost'] });
    assert.deepEqual(p.https.map((x) => x.host), ['ok.example.com']);
    assert.deepEqual(p.skipped.invalid, ['evil.example.com;rm -rf', 'sp ace.example.com', 'localhost']);
  });

  test('caps and switches', () => {
    const names = Array.from({ length: 30 }, (_, i) => `h${i}.example${i % 12}.com`);
    const p = D.planDane({ hostnames: names });
    assert.equal(p.https.length, D.DANE_LIMITS.httpsNames);
    assert.equal(p.skipped.httpsOverCap, 30 - D.DANE_LIMITS.httpsNames);
    assert.equal(p.domains.length, D.DANE_LIMITS.mxDomains);
    assert.equal(p.skipped.domainsOverCap, 2);
    assert.deepEqual(D.planDane(NEW, { mx: false }).domains, []);
    assert.deepEqual(D.planDane(NEW, { https: false }).https, []);
    assert.equal(D.planDane({ hostnames: names }, { limits: { httpsNames: 3 } }).https.length, 3);
  });
});

/* ------------------------------------------------------------------------ */
/* checkDane end to end (DohClient + wire format)                           */
/* ------------------------------------------------------------------------ */

const RENEWAL_ZONE = {
  'example.net|MX': mx('example.net', [[10, 'mail.wild.example.net'], [20, 'mx.example.org']]),
  '_25._tcp.mail.wild.example.net|TLSA': tlsa('_25._tcp.mail.wild.example.net', [rec(3, 1, 1, OLD_A[1][1])], { originalTtl: 3600 }),
  '_25._tcp.mx.example.org|TLSA': tlsa('_25._tcp.mx.example.org', [rec(3, 1, 1, '22'.repeat(32))]),
  '_443._tcp.wild.example.net|TLSA': tlsa('_443._tcp.wild.example.net', [rec(3, 0, 1, NEW_A[0][1])]),
  '_443._tcp.www.wild.example.net|TLSA': tlsa('_443._tcp.www.wild.example.net', [rec(3, 1, 1, OLD_A[1][1])], { ad: false })
};

describe('checkDane', () => {
  test('a renewal: the MX host breaks, a third-party MX is not ours, a name is safe; DO on every query', async () => {
    const { dns, calls } = client(RENEWAL_ZONE);
    const phases = [];
    const report = await D.checkDane({ leaf: NEW, chain: [NEW] }, { dns, extraNames: ['www.wild.example.net'], onProgress: (p) => phases.push(`${p.phase}:${p.done}/${p.total}`) });
    const by = Object.fromEntries(report.endpoints.map((e) => [e.qname, e]));
    assert.deepEqual(report.endpoints.map((e) => e.qname), [
      '_25._tcp.mail.wild.example.net', '_25._tcp.mx.example.org', '_443._tcp.wild.example.net', '_443._tcp.www.wild.example.net'
    ]);
    const mail = by['_25._tcp.mail.wild.example.net'];
    assert.deepEqual([mail.status, mail.service, mail.port, mail.host, mail.source, mail.via, mail.covered], ['danger', 'smtp', 25, 'mail.wild.example.net', 'mx', ['example.net'], true]);
    assert.deepEqual(mail.suggestions.map((s) => s.text), [`_25._tcp.mail.wild.example.net. IN TLSA 3 1 1 ${sha('sha256', NEW.spkiDer).toUpperCase()}`]);
    assert.equal(mail.waitSeconds, 7200);
    assert.equal(mail.lookup.authenticated, true);
    assert.deepEqual([by['_25._tcp.mx.example.org'].status, by['_25._tcp.mx.example.org'].covered], ['not-covered', false]);
    assert.equal(by['_443._tcp.wild.example.net'].status, 'safe');
    assert.deepEqual([by['_443._tcp.www.wild.example.net'].status, by['_443._tcp.www.wild.example.net'].source], ['insecure', 'extra']);
    assert.deepEqual(report.domains.map((d) => [d.domain, d.authenticated, d.mx.map((m) => m.exchange)]), [['example.net', true, ['mail.wild.example.net', 'mx.example.org']]]);
    assert.deepEqual(report.skipped.wildcard, ['*.wild.example.net']);
    // Exactly one MX and four TLSA queries, all with DO set and without CD; no query for the wildcard.
    assert.equal(report.queries, 5);
    assert.deepEqual(calls.map((c) => `${c.type} ${c.name}`).sort(), [
      'MX example.net', 'TLSA _25._tcp.mail.wild.example.net', 'TLSA _25._tcp.mx.example.org',
      'TLSA _443._tcp.wild.example.net', 'TLSA _443._tcp.www.wild.example.net'
    ]);
    assert.ok(calls.every((c) => c.dnssecOk && !c.cd));
    assert.deepEqual([phases[0], phases.at(-1)], ['mx:0/1', 'tlsa:4/4']);
    // The summary: one endpoint breaks, its record to publish and the wait.
    const s = D.daneSummary(report);
    assert.deepEqual([s.headline, s.variant, s.count, s.total], ['danger', 'error', 1, 4]);
    assert.deepEqual(s.action.map((e) => e.qname), ['_25._tcp.mail.wild.example.net']);
    assert.equal(s.waitSeconds, 7200);
    assert.deepEqual([s.counts.safe, s.counts.insecure, s.counts['not-covered']], [1, 1, 1]);
  });

  test('null MX, no MX (the domain itself), NXDOMAIN and a failed MX lookup', async () => {
    const zone = {
      'example.com|MX': mx('example.com', [[0, '.']]),
      'example.org|MX': { rcode: 'NOERROR', ad: true, answers: [] },
      'example.net|MX': { rcode: 'REFUSED', answers: [] },
      '_25._tcp.example.org|TLSA': tlsa('_25._tcp.example.org', [rec(3, 1, 1, NEW_A[1][1])])
    };
    const { dns } = client(zone);
    const leaf = { ...NEW, hostnames: ['example.com', 'example.org', 'example.net', 'example.edu'] };
    const report = await D.checkDane({ leaf }, { dns, https: false, subtle: globalThis.crypto.subtle });
    const d = Object.fromEntries(report.domains.map((x) => [x.domain, x]));
    assert.equal(d['example.com'].nullMx, true);
    assert.equal(d['example.org'].implicit, true);
    assert.equal(d['example.net'].error, 'REFUSED');
    assert.deepEqual([d['example.edu'].rcode, d['example.edu'].mx], ['NXDOMAIN', []]);
    assert.deepEqual(report.endpoints.map((e) => [e.qname, e.status, e.implicit]), [['_25._tcp.example.org', 'safe', true]]);
    assert.deepEqual(report.endpoints[0].notes.map((n) => n.code), ['spki-match', 'implicit-mx']);
    // The failed MX lookup is a failed lookup in the summary, never "safe" or "DANE not used".
    const s = D.daneSummary(report);
    assert.deepEqual([s.mxFailed, s.nullMx], [['example.net'], ['example.com']]);
    assert.deepEqual([s.headline, s.variant, s.count], ['error', 'warn', 1]);
  });

  test('a shared MX host is checked once for every domain; an unvalidated MX set makes its TLSA irrelevant', async () => {
    const zone = {
      'example.com|MX': mx('example.com', [[10, 'mx.example.com']], { ad: false }),
      'example.net|MX': mx('example.net', [[10, 'mx.example.com']], { ad: false }),
      '_25._tcp.mx.example.com|TLSA': tlsa('_25._tcp.mx.example.com', [rec(3, 1, 1, OLD_A[1][1])])
    };
    const { dns } = client(zone);
    const leaf = { ...NEW, hostnames: ['mx.example.com', 'example.net'] };
    const report = await D.checkDane({ leaf }, { dns, https: false });
    assert.equal(report.endpoints.length, 1);
    const [ep] = report.endpoints;
    assert.deepEqual(ep.via, ['example.com', 'example.net']);
    assert.deepEqual([ep.status, ep.wouldBe, ep.notes.map((n) => n.code)], ['insecure', 'danger', ['mx-insecure']]);
    // One validated MX set naming the host is enough for senders to use its TLSA.
    zone['example.net|MX'] = mx('example.net', [[10, 'mx.example.com']]);
    assert.equal((await D.checkDane({ leaf }, { dns: client(zone).dns, https: false })).endpoints[0].status, 'danger');
  });

  test('SERVFAIL on TLSA: one CD re-query tells bogus DNSSEC apart', async () => {
    const zone = {
      'example.net|MX': mx('example.net', [[10, 'wild.example.net']]),
      '_25._tcp.wild.example.net|TLSA': { rcode: 'SERVFAIL', answers: [], cd: tlsa('_25._tcp.wild.example.net', [rec(3, 1, 1, NEW_A[1][1])], { ad: false }) }
    };
    const { dns, calls } = client(zone);
    const report = await D.checkDane({ leaf: NEW }, { dns, https: false });
    assert.deepEqual([report.endpoints[0].status, report.endpoints[0].lookup.bogus], ['servfail', true]);
    assert.deepEqual(calls.filter((c) => c.type === 'TLSA').map((c) => c.cd), [false, true]);
    assert.equal(report.queries, 3);
    assert.equal(D.daneSummary(report).headline, 'servfail');
  });

  test('DANE-TA against the chain of the file (the leaf\'s issuer is marked)', async () => {
    const owner = '_443._tcp.www.example-test.com.tr';
    const zone = { [`${owner}|TLSA`]: tlsa(owner, [rec(2, 1, 1, ROOT_A[1][1])]) };
    const report = await D.checkDane({ leaf: CHAIN_LEAF, chain: CHAIN.certificates }, { dns: client(zone).dns, mx: false });
    const ep = report.endpoints.find((e) => e.qname === owner);
    assert.equal(ep.status, 'safe');
    assert.deepEqual([ep.records[0].matchedBy, ep.records[0].anchor], ['chain', 0]);
    assert.deepEqual(report.associations.anchors.map((a) => [a.subjectCN, a.issuer]), [['Subdomain Scanner Test Root CA', true]]);
    assert.equal(D.issuedBy(CHAIN_LEAF, CHAIN_ROOT), true);
    assert.equal(D.issuedBy(CHAIN_LEAF, CHAIN_LEAF), false, 'never itself');
    assert.equal(D.issuedBy(CHAIN_LEAF, { ...CHAIN_ROOT, subjectKeyId: '00' }), false, 'the AKI of the leaf names another key');
    assert.equal(D.issuedBy(CHAIN_LEAF, { ...CHAIN_ROOT, subjectKeyId: null }), true, 'no SKI: the subject decides');
    assert.equal(D.issuedBy(NEW, CHAIN_ROOT), false);
    // Leaf only: the same record cannot be compared.
    const alone = await D.checkDane({ leaf: CHAIN_LEAF }, { dns: client(zone).dns, mx: false });
    const ep2 = alone.endpoints.find((e) => e.qname === owner);
    assert.equal(ep2.status, 'ta-unchecked');
    assert.deepEqual(ep2.suggestions.map((s) => [s.usage, s.selector, s.matchingType, s.data]), [[3, 1, 1, CHAIN_A[1][1]]]);
    assert.equal(D.daneSummary(alone).headline, 'warn');
  });

  test('DANE-TA: only the CA certificates on the leaf\'s issuance path count, never another leaf\'s CA (RFC 7671 §5.2.2)', async () => {
    // A renewal bundle: www.example.com (Bundle Intermediate > Bundle Root) next to the root of another file.
    const B = certsOf('bundle_leaf.pem').leaf;
    const INTER = certsOf('bundle_inter.pem').certificates[0];
    const BROOT = certsOf('bundle_root.pem').certificates[0];
    const [INTER_A, BROOT_A] = [await D.certAssociations(INTER), await D.certAssociations(BROOT)];
    const run = async (leaf, chain, data, owner = '_443._tcp.www.example.com') => {
      const zone = { [`${owner}|TLSA`]: tlsa(owner, [rec(2, 1, 1, data)]) };
      const report = await D.checkDane({ leaf, chain }, { dns: client(zone).dns, mx: false });
      return { report, ep: report.endpoints.find((e) => e.qname === owner) };
    };
    // A record pinning the other file's root: its CA issued nothing on this leaf's path.
    const off = await run(B, [CHAIN_ROOT, INTER, BROOT], ROOT_A[1][1]);
    assert.equal(off.ep.status, 'ta-mismatch');
    assert.deepEqual(off.ep.suggestions.map((s) => [s.usage, s.selector, s.matchingType, s.data]), [[2, 1, 1, INTER_A[1][1]]]);
    assert.deepEqual(off.report.associations.anchors.map((a) => [a.subjectCN, a.issuer]),
      [['Example Test Bundle Intermediate CA', true], ['Example Test Bundle Root CA', false]]);
    assert.equal(D.daneSummary(off.report).headline, 'warn');
    // The root two levels up is on the path: it matches.
    const up = await run(B, [CHAIN_ROOT, INTER, BROOT], BROOT_A[1][1]);
    assert.deepEqual([up.ep.status, up.ep.records[0].matchedBy, up.ep.records[0].anchor], ['safe', 'chain', 1]);
    // Only certificates of another chain: nothing to compare with, not a match.
    const none = await run(CHAIN_LEAF, [INTER, BROOT], INTER_A[1][1], '_443._tcp.www.example-test.com.tr');
    assert.equal(none.ep.status, 'ta-unchecked');
    assert.deepEqual(none.report.associations.anchors, []);
  });

  test('noCache: a check again right after publishing asks the resolvers again', async () => {
    const zone = {
      'example.net|MX': mx('example.net', [[10, 'wild.example.net']]),
      '_25._tcp.wild.example.net|TLSA': tlsa('_25._tcp.wild.example.net', [rec(3, 1, 1, OLD_A[1][1])])
    };
    const f = zoneFetch(zone);
    const dns = new DohClient({ chain: ['cloudflare'], fetchImpl: f.fetchImpl, retries: 0 }); // caching on, as in the app
    assert.equal((await D.checkDane({ leaf: NEW }, { dns, https: false })).endpoints[0].status, 'danger');
    // The new record is published next to the old one.
    zone['_25._tcp.wild.example.net|TLSA'] = tlsa('_25._tcp.wild.example.net', [rec(3, 1, 1, OLD_A[1][1]), rec(3, 1, 1, NEW_A[1][1])]);
    const n = f.calls.length;
    assert.equal((await D.checkDane({ leaf: NEW }, { dns, https: false })).endpoints[0].status, 'danger', 'the cached answer');
    assert.equal(f.calls.length, n, 'served from the cache');
    assert.equal((await D.checkDane({ leaf: NEW }, { dns, https: false, noCache: true })).endpoints[0].status, 'safe');
    assert.equal(f.calls.length, n + 2);
  });

  test('caps the MX hosts; every name unused → "unused"; an abort rejects', async () => {
    const hosts = Array.from({ length: 25 }, (_, i) => [i, `mx${i}.example.net`]);
    const { dns } = client({ 'example.net|MX': mx('example.net', hosts) });
    const report = await D.checkDane({ leaf: NEW }, { dns, https: false });
    assert.equal(report.endpoints.length, D.DANE_LIMITS.mxHosts);
    assert.equal(report.skipped.mxHostsOverCap, 5);
    assert.equal(D.daneSummary(report).headline, 'unused');
    // A host past the cap that several domains name is one host not checked, not one per domain.
    const shared = client({ 'example.net|MX': mx('example.net', hosts), 'example.com|MX': mx('example.com', hosts) });
    const both = await D.checkDane({ leaf: { ...NEW, hostnames: ['example.net', 'example.com'] } }, { dns: shared.dns, https: false });
    assert.equal(both.endpoints.length, D.DANE_LIMITS.mxHosts);
    assert.deepEqual(both.endpoints[0].via, ['example.net', 'example.com']);
    assert.equal(both.skipped.mxHostsOverCap, 5);
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(D.checkDane({ leaf: NEW }, { dns, signal: ctl.signal }), { name: 'AbortError' });
    await assert.rejects(D.checkDane({ leaf: NEW }, {}), TypeError);
    await assert.rejects(D.checkDane({}, { dns }), TypeError);
  });
});

describe('daneSummary / daneExportJson', () => {
  const report = (statuses) => ({ endpoints: statuses.map((status) => ({ status, suggestions: [], waitSeconds: null })) });

  test('headline order: danger > servfail > warn > error > safe > unused / clear', () => {
    const head = (s) => D.daneSummary(report(s)).headline;
    const pick = (s) => [s.headline, s.count, s.mxFailed, s.nullMx];
    assert.equal(head(['safe', 'danger', 'servfail']), 'danger');
    assert.equal(head(['safe', 'servfail', 'pkix']), 'servfail');
    assert.equal(head(['safe', 'ta-unchecked', 'error']), 'warn');
    assert.equal(head(['safe', 'error']), 'error');
    assert.equal(head(['safe', 'insecure', 'none']), 'safe');
    assert.equal(head(['none', 'none']), 'unused');
    assert.equal(head(['none', 'insecure', 'not-covered', 'unusable']), 'clear');
    assert.equal(head([]), null);
    // A domain whose MX lookup failed: its mail servers were not checked.
    const failedMx = { ...report(['safe']), domains: [{ domain: 'example.net', error: 'offline' }, { domain: 'example.com', nullMx: true, error: null }] };
    assert.deepEqual(pick(D.daneSummary(failedMx)), ['error', 1, ['example.net'], ['example.com']]);
    assert.deepEqual(pick(D.daneSummary({ ...failedMx, endpoints: [] })), ['error', 1, ['example.net'], ['example.com']]);
    assert.deepEqual(pick(D.daneSummary({ ...report(['danger', 'error']), domains: failedMx.domains })), ['danger', 1, ['example.net'], ['example.com']]);
    assert.deepEqual(pick(D.daneSummary({ ...report(['error']), domains: failedMx.domains })), ['error', 2, ['example.net'], ['example.com']]);
    for (const s of D.DANE_STATUSES) assert.ok(D.DANE_SEVERITY[s], s);
    assert.ok(D.DANE_HEADLINES.includes('clear'));
  });

  test('JSON export: plain data, digests only, the records to add', async () => {
    const report = await D.checkDane({ leaf: NEW }, { dns: client(RENEWAL_ZONE).dns, https: false, now: () => Date.parse('2026-09-27T10:00:00Z') });
    const json = D.daneExportJson(report, { version: 'test' });
    assert.equal(json.schema, 'domainscope.dane/1');
    assert.deepEqual(json.certificate.tlsa.spki, { sha256: NEW_A[1][1], sha512: NEW_A[1][2] });
    assert.equal(json.startedAt.toISOString(), '2026-09-27T10:00:00.000Z');
    const mail = json.endpoints.find((e) => e.qname === '_25._tcp.mail.wild.example.net');
    assert.deepEqual([mail.status, mail.dnssec, mail.waitSeconds], ['danger', true, 7200]);
    assert.deepEqual(mail.add, [`_25._tcp.mail.wild.example.net. IN TLSA 3 1 1 ${NEW_A[1][1].toUpperCase()}`]);
    assert.equal(json.summary.headline, 'danger');
    const text = JSON.stringify(json);
    assert.ok(!text.includes(NEW_A[0][0]), 'no certificate bytes');
    assert.ok(!text.includes(NEW_A[1][0]), 'no public key bytes');
    assert.deepEqual(JSON.parse(text).endpoints.length, 2);
    // The documented exception: a published Full record (3 1 0) is answered with the full SPKI.
    const zone = { ...RENEWAL_ZONE, '_25._tcp.mail.wild.example.net|TLSA': tlsa('_25._tcp.mail.wild.example.net', [rec(3, 1, 0, OLD_A[1][0])]) };
    const full = D.daneExportJson(await D.checkDane({ leaf: NEW }, { dns: client(zone).dns, https: false }));
    assert.deepEqual(full.endpoints.find((e) => e.qname === '_25._tcp.mail.wild.example.net').add,
      [`_25._tcp.mail.wild.example.net. IN TLSA 3 1 0 ${NEW_A[1][0].toUpperCase()}`]);
  });
});
