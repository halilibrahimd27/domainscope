/**
 * lib/density.js: DNS Lookup's answer layout (NODATA types folded into one line, what every
 * answer shares said once) and IP Intel's zero-count stat folding.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import { isNoData, lookupLayout, foldZeroStats, LOOKUP_FLAGS } from '../../assets/js/lib/density.js';
import { decodeMessage } from '../../assets/js/lib/dnswire.js';

const FIX_DIR = new URL('../fixtures/dns/', import.meta.url);

/** A captured DoH answer as lib/doh.js returns it (DnsResponse). */
function captured(id, resolver = 'cloudflare') {
  const m = decodeMessage(new Uint8Array(readFileSync(new URL(`${id}.bin`, FIX_DIR))));
  const q = m.questions[0];
  return {
    name: q.name, type: q.type, resolver, ok: true, rcode: m.rcodeName, flags: m.flags,
    answers: m.answers, authorities: m.authorities, ede: (m.edns && m.edns.ede) || [], error: null
  };
}

/** A made-up DnsResponse. */
function resp(type, { answers = [], rcode = 'NOERROR', resolver = 'cloudflare', flags = { qr: true, rd: true, ra: true }, nsid, ede = [], ok = true } = {}) {
  return ok
    ? { name: 'example.com', type, resolver, ok, rcode, flags, answers, authorities: [], ede, nsid: nsid || null }
    : { name: 'example.com', type, resolver, ok: false, rcode: null, flags: {}, answers: [], authorities: [], ede: [], error: 'HTTP 429', errorKind: 'rate-limit' };
}
const rec = (type, data) => ({ name: 'example.com', type, ttl: 300, data, text: String(data) });

describe('isNoData', () => {
  test('captured answers: NODATA with a DNSSEC denial proof is NODATA; records, a chain, NXDOMAIN and SERVFAIL are not', () => {
    assert.equal(isNoData(captured('cf-nodata-cloudflare.com-nsec-do')), true);
    assert.equal(isNoData(captured('cf-a-example.com')), false);
    assert.equal(isNoData(captured('cf-a-cname-chain')), false, 'an alias chain');
    assert.equal(isNoData(captured('cf-nxdomain')), false);
    assert.equal(isNoData(captured('cf-servfail-dnssec-bogus')), false);
  });

  test('made-up edge cases', () => {
    assert.equal(isNoData(resp('CAA')), true);
    assert.equal(isNoData(resp('CAA', { ede: [{ code: 18, name: 'Prohibited', text: '' }] })), false, 'an Extended DNS Error is worth a card');
    assert.equal(isNoData(resp('CAA', { ok: false })), false, 'a failed query');
    assert.equal(isNoData(resp('TXT', { answers: [rec('RRSIG', 'x')] })), false, 'anything in the answer section');
    assert.equal(isNoData(null), false);
  });
});

describe('lookupLayout', () => {
  test('NODATA types fold into one list; records, errors and failures keep their cards, in query order', () => {
    const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'CAA', 'HTTPS', 'DS'];
    const responses = [
      resp('A', { answers: [rec('A', '192.0.2.1')] }),
      resp('AAAA'),
      resp('CNAME'),
      resp('MX', { answers: [rec('MX', { preference: 0, exchange: '.' })] }),
      null,
      resp('CAA'),
      resp('HTTPS', { ok: false }),
      resp('DS', { rcode: 'SERVFAIL' })
    ];
    const l = lookupLayout(types, responses);
    assert.deepEqual(l.cards, ['A', 'MX', 'TXT', 'HTTPS', 'DS']);
    assert.deepEqual(l.noRecords, ['AAAA', 'CNAME', 'CAA']);
    assert.deepEqual(l.failed, ['HTTPS']);
    assert.deepEqual(l.pending, ['TXT']);
    assert.deepEqual(Object.keys(l.own), ['A', 'MX', 'DS'], 'own meta only for cards with a DNS answer');
  });

  test('what every answer shares is said once: resolver, PoP, flags', () => {
    const types = ['A', 'MX', 'CAA'];
    const f = { qr: true, rd: true, ra: true, ad: true };
    const l = lookupLayout(types, [
      resp('A', { answers: [rec('A', '192.0.2.1')], flags: f, nsid: 'fra01' }),
      resp('MX', { answers: [rec('MX', { preference: 10, exchange: 'mx.example.com' })], flags: f, nsid: 'fra01' }),
      resp('CAA', { flags: f, nsid: 'fra01' })
    ]);
    assert.deepEqual(l.shared, { resolver: 'cloudflare', nsid: 'fra01', flags: { aa: false, tc: false, rd: true, ra: true, ad: true, cd: false } });
    assert.deepEqual(l.own, { A: { resolver: false, nsid: false, flags: false }, MX: { resolver: false, nsid: false, flags: false } });
    assert.deepEqual(Object.keys(l.shared.flags), [...LOOKUP_FLAGS]);
  });

  test('a card repeats only what differs (failover to another resolver, other flags, no PoP)', () => {
    const l = lookupLayout(['A', 'AAAA', 'TXT'], [
      resp('A', { answers: [rec('A', '192.0.2.1')], nsid: 'fra01' }),
      resp('AAAA', { answers: [rec('AAAA', '2001:db8::1')], resolver: 'google' }),
      resp('TXT', { answers: [rec('TXT', ['v=spf1 -all'])], flags: { qr: true, rd: true, ra: true, tc: true } })
    ]);
    assert.deepEqual(l.shared, { resolver: null, nsid: null, flags: null });
    assert.deepEqual(l.own, {
      A: { resolver: true, nsid: true, flags: true },
      AAAA: { resolver: true, nsid: false, flags: true },
      TXT: { resolver: true, nsid: false, flags: true }
    });
    // A folded NODATA answer still counts for what is shared.
    const m = lookupLayout(['A', 'CAA'], [resp('A', { answers: [rec('A', '192.0.2.1')] }), resp('CAA', { resolver: 'google' })]);
    assert.equal(m.shared.resolver, null);
    assert.deepEqual(m.own.A, { resolver: true, nsid: false, flags: false });
  });

  test('nothing answered yet, or only failures: no shared meta', () => {
    assert.deepEqual(lookupLayout(['A'], [null]).shared, { resolver: null, nsid: null, flags: null });
    const f = lookupLayout(['A', 'MX'], [resp('A', { ok: false }), resp('MX', { ok: false })]);
    assert.deepEqual([f.cards, f.failed, f.shared.resolver, f.own], [['A', 'MX'], ['A', 'MX'], null, {}]);
    assert.deepEqual(lookupLayout(null, null), { cards: [], noRecords: [], failed: [], pending: [], shared: { resolver: null, nsid: null, flags: null }, own: {} });
  });

  test('a typical apex (captured Cloudflare answers): the SOA and the NODATA fold, the flags are shared', () => {
    const types = ['A', 'AAAA', 'MX', 'SOA', 'TXT'];
    const l = lookupLayout(types, [
      captured('cf-a-example.com'), captured('cf-aaaa-example.com'), captured('cf-mx-null-example.com'), captured('cf-soa-example.com'),
      { ...captured('cf-nodata-cloudflare.com-nsec-do'), type: 'TXT' }
    ]);
    assert.deepEqual(l.noRecords, ['TXT']);
    assert.deepEqual(l.cards, ['A', 'AAAA', 'MX', 'SOA']);
    assert.equal(l.shared.resolver, 'cloudflare');
  });
});

describe('foldZeroStats', () => {
  test('only foldable zero counts fold; order is kept', () => {
    const stats = [{ id: 'ips', value: 3 }, { id: 'cdn', value: 0 }, { id: 'mine', value: 1 }, { id: 'priv', value: 0 }, { id: 'nets', value: 0 }];
    assert.deepEqual(foldZeroStats(stats, { foldable: ['cdn', 'mine', 'priv'] }), { shown: ['ips', 'mine', 'nets'], folded: ['cdn', 'priv'] });
    assert.deepEqual(foldZeroStats(stats), { shown: ['ips', 'cdn', 'mine', 'priv', 'nets'], folded: [] });
    assert.deepEqual(foldZeroStats([{ id: 'cdn', value: null }, null, { value: 0 }], { foldable: ['cdn'] }), { shown: ['cdn'], folded: [] }, 'an unknown count is not zero');
    assert.deepEqual(foldZeroStats(undefined), { shown: [], folded: [] });
  });
});
