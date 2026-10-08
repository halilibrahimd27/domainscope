// Unit tests for assets/js/lib/expected.js — Global DNS › Expected value: exact / contains / regex
// against the answer values a check shows, the counts, how long a cached answer may live and the
// worst-case wait after a change. Pure: every time is passed in. Documentation names and addresses only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  EXPECT_MODES, EXPECT_ERRORS, EXPECT_VERDICTS, EXPECT_MAX_LENGTH, EXPECT_SPECIALS, COMMON_TTLS, FLUSH_LINKS, canonValue, likelyTtl,
  parseExpected, matchExpected, expectedVerdict, expectedTally, negativeTtl, cachedTtl, cacheEnd, worstCaseEta, expectedEta
} from '../../assets/js/lib/expected.js';
import * as cutover from '../../assets/js/lib/cutover.js';
import { answerValues } from '../../assets/js/lib/propagation.js';

const T0 = Date.UTC(2026, 9, 8, 12, 0, 0);
const exp = (pattern, mode = 'exact', type = 'A') => {
  const e = parseExpected({ pattern, mode, type });
  assert.equal(e.ok, true, `${mode} ${pattern}: ${e.error}`);
  return e;
};
const SOA = { mname: 'ns1.example.com', rname: 'hostmaster.example.com', serial: 2026100801, refresh: 7200, retry: 900, expire: 1209600, minimum: 300 };
/** A row as Global DNS keeps it: answer values, the DoH response, when it answered. */
const row = (values, { ttl = 300, soaTtl = 3600, at = T0, ...over } = {}) => {
  const empty = values.length === 1 && EXPECT_SPECIALS.includes(values[0]);
  const response = {
    ok: !values.includes('ERROR'),
    rcode: values[0] === 'NXDOMAIN' ? 'NXDOMAIN' : /^[A-Z]+$/.test(values[0]) && !empty && values[0] !== 'ERROR' ? values[0] : 'NOERROR',
    answers: empty ? [] : values.filter((v) => !v.startsWith('CNAME ')).map((v) => ({ type: 'A', ttl, text: v })),
    authorities: empty ? [{ name: 'example.com', type: 'SOA', ttl: soaTtl, data: SOA }] : []
  };
  return { key: `r${Math.random()}`, pending: false, values, response, at, ...over };
};

describe('parseExpected', () => {
  test('exact values: addresses and names split on commas and spaces, MX on commas, the rest whole', () => {
    assert.deepEqual(exp('192.0.2.10, 192.0.2.11  198.51.100.7').values, ['192.0.2.10', '192.0.2.11', '198.51.100.7']);
    assert.deepEqual(exp('2001:DB8:0::1', 'exact', 'AAAA').values, ['2001:db8::1'], 'canonical IPv6');
    assert.deepEqual(exp('New-LB.Example.NET.', 'exact', 'CNAME').values, ['new-lb.example.net']);
    assert.deepEqual(exp('10 mx1.example.com., mx2.example.com', 'exact', 'MX').values, ['10 mx1.example.com', 'mx2.example.com']);
    assert.deepEqual(exp('v=spf1 include:_spf.example.com, -all', 'exact', 'TXT').values, ['v=spf1 include:_spf.example.com, -all'], 'a TXT value is one, commas and all');
    assert.deepEqual(exp('0 issue "letsencrypt.org"', 'exact', 'CAA').values, ['0 issue letsencrypt.org']);
  });

  test('NXDOMAIN and NODATA are specials of the exact mode; contains keeps them as text', () => {
    assert.equal(exp('nxdomain').special, 'NXDOMAIN');
    assert.equal(exp('NODATA', 'exact', 'AAAA').special, 'NODATA');
    assert.equal(exp('nxdomain', 'contains').special, null);
  });

  test('refused: nothing typed, a pattern that does not compile, too long; an unknown mode is exact', () => {
    assert.deepEqual(parseExpected({ pattern: '  ' }), { ok: false, error: 'empty', mode: 'exact', pattern: '' });
    assert.equal(parseExpected({ pattern: ' , ', type: 'A' }).error, 'empty');
    const bad = parseExpected({ pattern: '(unclosed', mode: 'regex' });
    assert.equal(bad.error, 'regex');
    assert.ok(bad.detail.length > 0, 'the engine says why');
    assert.equal(parseExpected({ pattern: 'x'.repeat(EXPECT_MAX_LENGTH + 1), mode: 'contains' }).error, 'long');
    assert.equal(parseExpected({ pattern: '192.0.2.10', mode: 'nope' }).mode, 'exact');
    assert.deepEqual([...EXPECT_MODES], ['exact', 'contains', 'regex']);
    assert.deepEqual([...EXPECT_ERRORS], ['empty', 'regex', 'long']);
  });

  test('canonValue: addresses canonical, TXT strings joined and unescaped, names without the trailing dot', () => {
    assert.equal(canonValue('AAAA', '2001:0db8:0000::0001'), '2001:db8::1');
    assert.equal(canonValue('TXT', '"v=spf1 " "include:_spf.example.com -all"'), 'v=spf1 include:_spf.example.com -all');
    assert.equal(canonValue('TXT', '"a\\"b\\059c"'), 'a"b;c');
    assert.equal(canonValue('MX', '10 MX.Example.com.'), '10 mx.example.com');
    assert.equal(canonValue('HTTPS', '1 . alpn="h2,h3"'), '1 . alpn="h2,h3"', 'the root name stays');
  });
});

describe('matchExpected', () => {
  test('exact: the record set, in any order; the CNAME chain is not a record', () => {
    const e = exp('192.0.2.11, 192.0.2.10');
    assert.equal(matchExpected(['192.0.2.10', '192.0.2.11'], e), true);
    assert.equal(matchExpected(['192.0.2.10'], e), false, 'one missing');
    assert.equal(matchExpected(['192.0.2.10', '192.0.2.11', '192.0.2.12'], e), false, 'one too many');
    assert.equal(matchExpected(['192.0.2.10', '192.0.2.11', 'CNAME lb.example.net'], e), true, 'through an alias');
    assert.equal(matchExpected(['NODATA'], e), false);
    assert.equal(matchExpected(['NXDOMAIN'], e), false);
  });

  test('exact NXDOMAIN / NODATA: a deleted name, a removed record type', () => {
    assert.equal(matchExpected(['NXDOMAIN'], exp('NXDOMAIN')), true);
    assert.equal(matchExpected(['NODATA'], exp('NXDOMAIN')), false, 'the name still exists');
    assert.equal(matchExpected(['NODATA'], exp('nodata', 'exact', 'AAAA')), true);
    assert.equal(matchExpected(['192.0.2.10'], exp('NXDOMAIN')), false, 'still the old record');
  });

  test('exact MX and CAA may leave out the leading number', () => {
    const mx = exp('mx1.example.com, mx2.example.com', 'exact', 'MX');
    assert.equal(matchExpected(['10 mx1.example.com.', '20 mx2.example.com.'], mx), true);
    assert.equal(matchExpected(['10 mx1.example.com.'], mx), false);
    assert.equal(matchExpected(['10 mx1.example.com.', '20 mx2.example.com.'], exp('10 mx1.example.com, 30 mx2.example.com', 'exact', 'MX')), false, 'a preference typed is compared');
    assert.equal(matchExpected(['0 issue "letsencrypt.org"'], exp('issue letsencrypt.org', 'exact', 'CAA')), true);
  });

  test('exact TXT: one record of a set never equals the set; contains finds it', () => {
    const values = ['"google-site-verification=abc123"', '"v=spf1 include:_spf.example.com -all"'];
    assert.equal(matchExpected(values, exp('v=spf1 include:_spf.example.com -all', 'exact', 'TXT')), false);
    assert.equal(matchExpected(values, exp('include:_spf.example.com', 'contains', 'TXT')), true);
    assert.equal(matchExpected(['"v=spf1 include:_spf.example.com -all"'], exp('"v=spf1 include:_spf.example.com -all"', 'exact', 'TXT')), true, 'quotes typed or not');
  });

  test('contains: any answer, the CNAME chain included, case aside', () => {
    const values = ['192.0.2.10', 'CNAME edge.Example.net', 'CNAME d1.cdn.example.org'];
    assert.equal(matchExpected(values, exp('cdn.example.org', 'contains')), true);
    assert.equal(matchExpected(values, exp('EDGE.example.net', 'contains')), true);
    assert.equal(matchExpected(values, exp('198.51.100', 'contains')), false);
    assert.equal(matchExpected(['NXDOMAIN'], exp('nxdomain', 'contains')), true);
  });

  test('regex: case-insensitive, any answer value, the chain targets without trailing dots', () => {
    const values = ['198.51.100.20', 'CNAME new-lb.example.net'];
    assert.equal(matchExpected(values, exp('^198\\.51\\.100\\.\\d+$', 'regex')), true);
    assert.equal(matchExpected(values, exp('^NEW-LB\\.example\\.net$', 'regex')), true);
    assert.equal(matchExpected(values, exp('^192\\.0\\.2\\.', 'regex')), false);
  });

  test('a failure never matches, whatever the pattern', () => {
    for (const values of [['ERROR'], ['SERVFAIL'], ['REFUSED'], []]) {
      assert.equal(matchExpected(values, exp('.*', 'regex')), false, values.join());
    }
    assert.equal(matchExpected(['192.0.2.10'], { ok: false }), false);
  });

  test('answerValues as Global DNS shows them', () => {
    const res = {
      ok: true, rcode: 'NOERROR', name: 'www.example.com', answers: [
        { name: 'www.example.com', type: 'CNAME', typeNum: 5, data: 'new-lb.example.net', text: 'new-lb.example.net.' },
        { name: 'new-lb.example.net', type: 'A', typeNum: 1, data: '198.51.100.20', text: '198.51.100.20' }
      ]
    };
    const values = answerValues(res, 'A');
    assert.equal(matchExpected(values, exp('198.51.100.20')), true);
    assert.equal(matchExpected(values, exp('new-lb.example.net', 'contains')), true);
    assert.equal(matchExpected(answerValues(res, 'CNAME'), exp('new-lb.example.net', 'exact', 'CNAME')), true);
  });
});

describe('verdicts and counts', () => {
  test('match, mismatch, failed; nothing to judge while pending, skipped, not asked or blocked', () => {
    const e = exp('198.51.100.20');
    assert.equal(expectedVerdict(row(['198.51.100.20']), e), 'match');
    assert.equal(expectedVerdict(row(['192.0.2.10']), e), 'mismatch');
    assert.equal(expectedVerdict(row(['SERVFAIL']), e), 'failed');
    assert.equal(expectedVerdict(row(['ERROR']), e), 'failed');
    assert.equal(expectedVerdict({ pending: true, values: null }, e), null);
    assert.equal(expectedVerdict(row(['ERROR'], { skipped: true }), e), null, 'not readable in browsers');
    assert.equal(expectedVerdict({ pending: false, notAsked: true, values: [] }, e), null);
    assert.equal(expectedVerdict(row(['0.0.0.0'], { filtered: true }), e), null, 'a filter’s block is its policy');
    assert.equal(expectedVerdict(row(['198.51.100.20']), null), null, 'no expected value');
    assert.deepEqual([...EXPECT_VERDICTS], ['match', 'mismatch', 'failed']);
  });

  test('the tally: done once every source that answered serves it', () => {
    const e = exp('198.51.100.20');
    const rows = [row(['198.51.100.20']), row(['198.51.100.20']), row(['192.0.2.10']), row(['SERVFAIL']), { pending: true }];
    assert.deepEqual(expectedTally(rows, e), { match: 2, mismatch: 1, failed: 1, judged: 3, done: false });
    assert.equal(expectedTally(rows.filter((r) => r.values && r.values[0] !== '192.0.2.10'), e).done, true);
    assert.equal(expectedTally([row(['SERVFAIL'])], e).done, false, 'nothing that answered matches');
    assert.deepEqual(expectedTally(null, e), { match: 0, mismatch: 0, failed: 0, judged: 0, done: false });
  });
});

describe('how long an answer stays cached', () => {
  test('negativeTtl: min(SOA TTL, SOA minimum) of the authority SOA', () => {
    assert.equal(negativeTtl({ authorities: [{ type: 'SOA', ttl: 3600, data: SOA }] }), 300);
    assert.equal(negativeTtl({ authorities: [{ type: 'SOA', ttl: 120, data: SOA }] }), 120, 'a counted-down SOA');
    assert.equal(negativeTtl({ authorities: [] }), null);
    assert.equal(negativeTtl(null), null);
  });

  test('cachedTtl: the longest TTL of the answer, the negative TTL of an empty one, a row’s own TTL', () => {
    const r = row(['192.0.2.10']);
    r.response.answers = [{ type: 'CNAME', ttl: 3600, text: 'lb.example.net.' }, { type: 'A', ttl: 60, text: '192.0.2.10' }];
    assert.equal(cachedTtl(r), 3600, 'no part of the old answer outlives it');
    assert.equal(cachedTtl(row(['NXDOMAIN'], { soaTtl: 900 })), 300);
    assert.equal(cachedTtl(row(['NODATA'], { soaTtl: 120 })), 120);
    assert.equal(cachedTtl({ ttl: 1500, values: ['192.0.2.10'] }), 1500, 'an ISP resolver’s own TTL');
    assert.equal(cachedTtl(row(['ERROR'])), null);
    assert.equal(cachedTtl(null), null);
  });

  test('cacheEnd: when it answered plus that TTL, or an ISP row’s expiry', () => {
    assert.equal(cacheEnd(row(['192.0.2.10'], { ttl: 300 })), T0 + 300000);
    assert.equal(cacheEnd(row(['192.0.2.10'], { at: new Date(T0) })), T0 + 300000);
    assert.equal(cacheEnd({ expiresAt: new Date(T0 + 1500000).toISOString(), values: ['192.0.2.10'] }), T0 + 1500000);
    assert.equal(cacheEnd(row(['192.0.2.10'], { at: null })), null);
    assert.equal(cacheEnd(row(['ERROR'])), null);
  });
});

describe('the worst-case wait', () => {
  test('worstCaseEta: the highest TTL over the name servers; the negative-cache time for a name that did not exist', () => {
    assert.equal(worstCaseEta({ ttls: [900, 3600] }), 3600, 'multi-provider zones differ: the longest wins');
    assert.equal(worstCaseEta({ ttls: [300], negativeTtl: 900, negative: true }), 900);
    assert.equal(worstCaseEta({ ttls: [300], negativeTtl: 900, negative: false }), 300, 'a changed value: the negative time does not count');
    assert.equal(worstCaseEta({ ttls: [], negativeTtl: 900, negative: true }), 900);
    assert.equal(worstCaseEta({ ttls: [null, NaN, -5] }), null);
    assert.equal(worstCaseEta(), null);
  });

  test('expectedEta: the old answers’ highest TTL read as the zone TTL; the latest cached copy here', () => {
    const e = exp('198.51.100.20');
    const rows = [
      row(['198.51.100.20']),
      row(['192.0.2.10'], { ttl: 3412, at: T0 }),
      row(['192.0.2.10'], { ttl: 120, at: T0 + 5000 }),
      row(['SERVFAIL'])
    ];
    const eta = expectedEta(rows, e);
    assert.deepEqual(eta, {
      mismatched: 2, positive: 2, negative: 0, observedTtl: 3412, recordTtl: 3600, negativeTtl: null, negativeFrom: null, seconds: 3600, last: T0 + 3412000
    });
  });

  test('a new name: the old answers are NXDOMAIN; the negative-cache time from their SOA, or the name server’s', () => {
    const e = exp('198.51.100.20');
    const rows = [row(['198.51.100.20']), row(['NXDOMAIN'], { soaTtl: 3500 }), row(['NODATA'], { soaTtl: 200 })];
    const fromAnswers = expectedEta(rows, e);
    assert.equal(fromAnswers.negative, 2);
    assert.equal(fromAnswers.negativeTtl, 300, 'the SOA minimum (exact) caps the counted-down SOA TTL read up');
    assert.equal(fromAnswers.negativeFrom, 'answers');
    assert.equal(fromAnswers.seconds, 300);
    const probed = expectedEta(rows, e, { authoritative: { negativeTtl: 900 } });
    assert.equal(probed.negativeTtl, 900);
    assert.equal(probed.negativeFrom, 'name-server');
    assert.equal(probed.seconds, 900, 'the name server’s own value wins');
  });

  test('a Route 53 style SOA: TTL 900, minimum 86400 — the negative time is the TTL, not a day', () => {
    const big = { ...SOA, minimum: 86400 };
    const r = row(['NXDOMAIN']);
    r.response.authorities = [{ name: 'example.com', type: 'SOA', ttl: 850, data: big }];
    const eta = expectedEta([r], exp('198.51.100.20'));
    assert.equal(eta.negativeTtl, 900, 'min(likely SOA TTL 900, minimum 86400)');
  });

  test('everything matches: no wait; no expected value: nothing judged', () => {
    const e = exp('198.51.100.20');
    const done = expectedEta([row(['198.51.100.20'])], e);
    assert.equal(done.mismatched, 0);
    assert.equal(done.seconds, null);
    assert.equal(done.last, null);
    assert.equal(expectedEta([row(['192.0.2.10'])], null).mismatched, 0);
  });
});

describe('shared TTL helpers and links', () => {
  test('likelyTtl rounds a counted-down TTL up to a common one (re-exported by lib/cutover.js)', () => {
    assert.equal(likelyTtl(3412), 3600);
    assert.equal(likelyTtl(60), 60);
    assert.equal(likelyTtl(700000), 700000);
    assert.equal(likelyTtl(0), null);
    assert.equal(likelyTtl(null), null);
    assert.equal(cutover.likelyTtl, likelyTtl);
    assert.equal(cutover.COMMON_TTLS, COMMON_TTLS);
    assert.equal(cutover.FLUSH_LINKS, FLUSH_LINKS);
  });

  test('the cache-flush pages: Google Public DNS and Cloudflare 1.1.1.1, https links', () => {
    assert.deepEqual(FLUSH_LINKS.map((l) => l.id), ['google', 'cloudflare']);
    for (const l of FLUSH_LINKS) assert.match(l.url, /^https:\/\/[a-z0-9.-]+\//);
    assert.ok(Object.isFrozen(FLUSH_LINKS) && FLUSH_LINKS.every(Object.isFrozen));
  });
});
