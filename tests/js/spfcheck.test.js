/**
 * lib/health.js — the SPF check of one address (DNS Lookup › Explain, ROADMAP P1.5): the RFC 7208
 * §7 macro expander (the RFC's own §7.4 examples), a policy expanded for an address (`%{i}`, `%{v}`,
 * `ptr`), `spfCheckHost`, and the pieces Domain Health now shares with the Explain panel
 * (`spfTreeChecks`, `findDmarc`). Documentation names and addresses only.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  expandSpfMacros, spfLookupCount, spfEvaluate, spfCheckHost, spfTreeChecks, findDmarc, parseSpf,
  SPF_MACRO_NEEDS, SPF_CHECK_MAX_MX_HOSTS
} from '../../assets/js/lib/health.js';
import { zoneDns } from './zone-dns.mjs';

describe('expandSpfMacros', () => {
  // RFC 7208 §7.4: sender strong-bad@email.example.com, client 192.0.2.3, <domain> email.example.com.
  const ctx = { domain: 'email.example.com', sender: 'strong-bad@email.example.com', ip: '192.0.2.3' };
  const text = (spec, c = ctx) => expandSpfMacros(spec, c).text;

  test('the RFC 7208 §7.4 examples', () => {
    assert.equal(text('%{s}'), 'strong-bad@email.example.com');
    assert.equal(text('%{o}'), 'email.example.com');
    assert.equal(text('%{d}'), 'email.example.com');
    assert.equal(text('%{d4}'), 'email.example.com');
    assert.equal(text('%{d3}'), 'email.example.com');
    assert.equal(text('%{d2}'), 'example.com');
    assert.equal(text('%{d1}'), 'com');
    assert.equal(text('%{dr}'), 'com.example.email');
    assert.equal(text('%{d2r}'), 'example.email');
    assert.equal(text('%{l}'), 'strong-bad');
    assert.equal(text('%{l-}'), 'strong.bad');
    assert.equal(text('%{lr}'), 'strong-bad');
    assert.equal(text('%{lr-}'), 'bad.strong');
    assert.equal(text('%{l1r-}'), 'strong');
    assert.equal(text('%{ir}.%{v}._spf.%{d2}'), '3.2.0.192.in-addr._spf.example.com');
    assert.equal(text('%{lr-}.lp._spf.%{d2}'), 'bad.strong.lp._spf.example.com');
    assert.equal(text('%{lr-}.lp.%{ir}.%{v}._spf.%{d2}'), 'bad.strong.lp.3.2.0.192.in-addr._spf.example.com');
    assert.equal(text('%{ir}.%{v}.%{l1r-}.lp._spf.%{d2}'), '3.2.0.192.in-addr.strong.lp._spf.example.com');
    assert.equal(text('%{d2}.trusted-domains.example.net'), 'example.com.trusted-domains.example.net');
    // IPv6 2001:db8::cb01: 32 nibbles, here reversed.
    assert.equal(text('%{ir}.%{v}._spf.%{d2}', { ...ctx, ip: '2001:db8::cb01' }),
      '1.0.b.c.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6._spf.example.com');
  });

  test('escapes, an upper-case letter URL-escapes, the R transformer, a mapped address, the 253-character cut', () => {
    assert.equal(text('%%%_%-'), '% %20');
    assert.equal(text('%{S}', { ...ctx, sender: 'a+b@example.com' }), 'a%2Bb%40example.com');
    assert.equal(text('%{iR}.x.example.com'), '3.2.0.192.x.example.com');
    assert.equal(text('%{i}.x.example.com', { ...ctx, ip: '::ffff:192.0.2.3' }), '192.0.2.3.x.example.com', 'a mapped address is its IPv4 address');
    const long = `${'a'.repeat(60)}.${'b'.repeat(60)}.${'c'.repeat(60)}.${'d'.repeat(60)}`;
    const cut = expandSpfMacros(`%{d}.example.com`, { domain: long });
    assert.ok(cut.text.length <= 253 && cut.text.endsWith('.example.com') && !cut.text.startsWith('a'), cut.text);
  });

  test('what cannot be expanded is named; %{o} defaults to the checked domain; ipBound marks the address-bound ones', () => {
    const none = { domain: 'sub.example.com', senderDomain: 'example.com' };
    assert.deepEqual(expandSpfMacros('%{i}._spf.example.com', none), { name: null, text: null, macro: true, missing: ['i'], ipBound: true });
    assert.deepEqual(expandSpfMacros('%{l}.%{h}.%{p}.example.com', none).missing, ['l', 'h', 'p']);
    assert.equal(expandSpfMacros('%{o}.x.example.net', none).name, 'example.com.x.example.net');
    assert.equal(expandSpfMacros('%{d}.x.example.net', none).name, 'sub.example.com.x.example.net');
    const bound = expandSpfMacros('%{v}.%{d}.example.net', { ...none, ip: '198.51.100.7' });
    assert.deepEqual([bound.name, bound.ipBound, bound.missing], ['in-addr.sub.example.com.example.net', true, []]);
    assert.equal(expandSpfMacros('%{h}.example.net', { ...none, helo: 'MX1.Example.ORG.' }).name, 'mx1.example.org.example.net');
    assert.equal(expandSpfMacros('%{l}.example.net', { ...none, sender: 'example.org' }).name, 'postmaster.example.net', 'no local part: postmaster');
    assert.deepEqual(expandSpfMacros('_spf.example.net', none), { name: '_spf.example.net', text: '_spf.example.net', macro: false, missing: [], ipBound: false });
    assert.equal(SPF_MACRO_NEEDS.i, 'ip');
    assert.equal(SPF_MACRO_NEEDS.s, 'sender');
    assert.ok(Object.isFrozen(SPF_MACRO_NEEDS));
  });
});

/** A zone with address-bound terms: a per-address allow list, a per-address include and a ptr. */
const ZONE = {
  'example.com': {
    TXT: 'v=spf1 exists:%{i}._allow.example.com include:%{ir}.%{v}._spf.example.net ptr:mail.example.com mx -all',
    MX: [{ preference: 10, exchange: 'mx1.example.com' }]
  },
  'mx1.example.com': { A: '203.0.113.25', AAAA: '2001:db8:25::25' },
  '192.0.2.10._allow.example.com': { A: '127.0.0.2' },
  '20.2.0.192.in-addr._spf.example.net': { TXT: 'v=spf1 ip4:192.0.2.20 -all' },
  '30.2.0.192.in-addr.arpa': { PTR: ['out.mail.example.com', 'spoof.mail.example.com'] },
  'out.mail.example.com': { A: '192.0.2.30' },
  'spoof.mail.example.com': { A: '198.51.100.99' },
  '40.2.0.192.in-addr.arpa': { PTR: 'host.example.org' },
  'host.example.org': { A: '192.0.2.40' }
};

describe('a policy expanded for one address', () => {
  test('spfLookupCount with ip: %{i} / %{v} asked for that address, ptr evaluated, the terms marked forIp', async () => {
    const dns = zoneDns(ZONE);
    const r = await spfLookupCount('example.com', { dns, ip: '192.0.2.30' });
    const [exists, inc, ptr] = r.tree.terms;
    assert.deepEqual([exists.target, exists.forIp, exists.void], ['192.0.2.30._allow.example.com', '192.0.2.30', true]);
    assert.deepEqual([inc.target, inc.forIp], ['30.2.0.192.in-addr._spf.example.net', '192.0.2.30']);
    assert.equal(inc.error, 'no-record', 'that address has no per-address policy');
    assert.deepEqual([ptr.target, ptr.ptrNames, ptr.ptrFailed], ['mail.example.com', ['out.mail.example.com'], []], 'only the name that resolves back');
    assert.equal(r.count, 4, 'the lookups are the same whatever the address');
    assert.ok(dns.calls.some((c) => c.name === '30.2.0.192.in-addr.arpa' && c.type === 'PTR'));
    // Without an address nothing address-bound is asked.
    const plain = zoneDns(ZONE);
    const p = await spfLookupCount('example.com', { dns: plain });
    assert.deepEqual(p.tree.terms.slice(0, 3).map((t) => [t.target, t.missing || []]), [[null, ['i']], [null, ['i', 'v']], ['mail.example.com', []]]);
    assert.ok(!plain.calls.some((c) => c.type === 'PTR'));
    await assert.rejects(spfLookupCount('example.com', { dns, ip: 'not an address' }), TypeError);
  });

  test('spfEvaluate decides the address-bound terms for that address only', async () => {
    const r = await spfLookupCount('example.com', { dns: zoneDns(ZONE), ip: '192.0.2.10' });
    const mxAddresses = new Map([['mx1.example.com', { addresses: ['203.0.113.25', '2001:db8:25::25'] }]]);
    const v = spfEvaluate(r.tree, '192.0.2.10', { mxAddresses });
    assert.deepEqual([v.result, v.term], ['pass', 'exists:%{i}._allow.example.com']);
    // The same tree for another address: the exists answer was for 192.0.2.10, so it cannot be told …
    const other = spfEvaluate(r.tree, '198.51.100.1', { mxAddresses });
    assert.deepEqual([other.result, other.reason, other.term], ['unknown', 'macro', 'exists:%{i}._allow.example.com']);
    // … unless what decides could only agree with it: the mx host passes either way.
    assert.equal(spfEvaluate(r.tree, '203.0.113.25', { mxAddresses }).result, 'pass');
  });
});

describe('spfCheckHost', () => {
  const check = (ip, opts = {}) => spfCheckHost('example.com', ip, { dns: zoneDns(ZONE), ...opts });

  test('passes through each address-bound term, the mx, and fails the rest', async () => {
    const allow = await check('192.0.2.10');
    assert.deepEqual([allow.verdict.result, allow.verdict.term, allow.ip], ['pass', 'exists:%{i}._allow.example.com', '192.0.2.10']);
    const inc = await check('192.0.2.20');
    assert.deepEqual([inc.verdict.result, inc.verdict.term, inc.verdict.holder], ['pass', 'ip4:192.0.2.20', '20.2.0.192.in-addr._spf.example.net']);
    // The included per-address policy exists only for 192.0.2.20: for this address it is no SPF record, a permerror.
    const ptr = await check('192.0.2.30');
    assert.deepEqual([ptr.verdict.result, ptr.verdict.reason], ['permerror', 'no-record']);
    const mx = await check('2001:db8:25::25');
    assert.equal(mx.verdict.result, 'permerror', 'no per-address include for it either');
  });

  test('ptr: a forward-confirmed reverse name under the target matches; one elsewhere does not', async () => {
    const zone = {
      ...ZONE,
      'example.com': { TXT: 'v=spf1 ptr:mail.example.com -all' }
    };
    const pass = await spfCheckHost('example.com', '192.0.2.30', { dns: zoneDns(zone) });
    assert.deepEqual([pass.verdict.result, pass.verdict.via], ['pass', { host: 'out.mail.example.com', address: '192.0.2.30' }]);
    const elsewhere = await spfCheckHost('example.com', '192.0.2.40', { dns: zoneDns(zone) });
    assert.equal(elsewhere.verdict.result, 'fail', 'host.example.org is not under mail.example.com');
    const noPtr = await spfCheckHost('example.com', '192.0.2.50', { dns: zoneDns(zone) });
    assert.equal(noPtr.verdict.result, 'fail', 'no reverse name: no match');
    const failing = await spfCheckHost('example.com', '192.0.2.30', { dns: zoneDns(zone, { fail: { 'out.mail.example.com|A': 'timeout' } }) });
    assert.deepEqual([failing.verdict.result, failing.verdict.reason], ['unknown', 'lookup-failed'], 'a forward lookup that failed here cannot be told');
  });

  test('mx hosts are resolved; the sender and HELO macros expand once given; what is missing is listed', async () => {
    const zone = {
      'example.org': { TXT: 'v=spf1 mx exists:%{l}.%{o}._u.example.org exists:%{h}._h.example.org ~all', MX: [{ preference: 5, exchange: 'mx1.example.org' }] },
      'mx1.example.org': { A: '198.51.100.25' },
      'alice.example.org._u.example.org': { A: '127.0.0.2' },
      'mta.example.net._h.example.org': { A: '127.0.0.2' }
    };
    const viaMx = await spfCheckHost('example.org', '198.51.100.25', { dns: zoneDns(zone) });
    assert.deepEqual([viaMx.verdict.result, viaMx.verdict.via], ['pass', { host: 'mx1.example.org', address: '198.51.100.25' }]);
    assert.deepEqual([...viaMx.mxAddresses.keys()], ['mx1.example.org']);
    const unknown = await spfCheckHost('example.org', '192.0.2.99', { dns: zoneDns(zone) });
    assert.deepEqual([unknown.verdict.result, unknown.verdict.reason], ['unknown', 'macro'], 'the sender macro could have passed it');
    assert.deepEqual(unknown.missing, ['l', 'h']);
    const sender = await spfCheckHost('example.org', '192.0.2.99', { dns: zoneDns(zone), sender: 'alice@example.org' });
    assert.deepEqual([sender.verdict.result, sender.verdict.term, sender.sender], ['pass', 'exists:%{l}.%{o}._u.example.org', 'alice@example.org']);
    const helo = await spfCheckHost('example.org', '192.0.2.99', { dns: zoneDns(zone), sender: 'bob@example.org', helo: 'mta.example.net' });
    assert.deepEqual([helo.verdict.result, helo.verdict.term, helo.missing], ['pass', 'exists:%{h}._h.example.org', []]);
    const softfail = await spfCheckHost('example.org', '192.0.2.99', { dns: zoneDns(zone), sender: 'bob@example.org', helo: 'other.example.net' });
    assert.equal(softfail.verdict.result, 'softfail');
  });

  test('a record already read is not asked again; a mapped address is checked as IPv4; a bad address throws', async () => {
    const dns = zoneDns({});
    const r = await spfCheckHost('example.net', '::ffff:192.0.2.1', { dns, record: 'v=spf1 ip4:192.0.2.0/24 -all' });
    assert.deepEqual([r.verdict.result, r.ip, dns.calls.length], ['pass', '192.0.2.1', 0]);
    await assert.rejects(spfCheckHost('example.net', '192.0.2', { dns }), TypeError);
    assert.ok(SPF_CHECK_MAX_MX_HOSTS >= 10);
  });
});

describe('what Domain Health shares with the Explain panel', () => {
  test('spfTreeChecks: the findings of an expanded policy, a syntax error first', async () => {
    const zone = { 'example.com': { TXT: 'v=spf1 ip4:192.0.2.0/24 bogus ~all' } };
    const record = 'v=spf1 ip4:192.0.2.0/24 bogus ~all';
    const parsed = parseSpf(record);
    const lookups = await spfLookupCount('example.com', { dns: zoneDns(zone), record });
    const ids = spfTreeChecks('example.com', parsed, lookups).map((c) => c.id);
    assert.deepEqual(ids, ['spf.syntax', 'spf.all-softfail', 'spf.lookups-ok']);
    const nullMx = spfTreeChecks('example.com', parseSpf('v=spf1 ~all'), { count: 0, voidCount: 0, tree: { domain: 'example.com', record: 'v=spf1 ~all', terms: [{ term: '~all', mechanism: 'all', qualifier: '~' }] }, errors: [] }, { nullMx: true });
    assert.ok(nullMx.some((c) => c.id === 'spf.null-mx'));
  });

  test('findDmarc: the name\'s own record, the organizational domain\'s, none, a failed question, a known first answer', async () => {
    const zone = {
      '_dmarc.example.com': { TXT: 'v=DMARC1; p=reject; sp=quarantine' },
      '_dmarc.example.org': { TXT: ['v=DMARC1; p=none', 'v=DMARC1; p=reject'] }
    };
    const own = await findDmarc('example.com', { dns: zoneDns(zone) });
    assert.deepEqual([own.records, own.foundAt, own.inherited, own.error], [['v=DMARC1; p=reject; sp=quarantine'], 'example.com', false, null]);
    const sub = await findDmarc('mail.example.com', { dns: zoneDns(zone) });
    assert.deepEqual([sub.foundAt, sub.inherited], ['example.com', true]);
    const none = await findDmarc('example.net', { dns: zoneDns(zone) });
    assert.deepEqual([none.records, none.foundAt], [[], null]);
    const many = await findDmarc('example.org', { dns: zoneDns(zone) });
    assert.equal(many.records.length, 2);
    const failed = await findDmarc('mail.example.com', { dns: zoneDns(zone, { fail: { '_dmarc.example.com|TXT': 'timeout' } }) });
    assert.deepEqual([failed.error, failed.records], ['_dmarc.example.com: timeout', []], 'unknown whether a policy is inherited');
    const dns = zoneDns(zone);
    const first = await dns.query('_dmarc.example.com', 'TXT');
    const again = await findDmarc('example.com', { dns, first });
    assert.equal(again.foundAt, 'example.com');
    assert.equal(dns.calls.length, 1, 'the known answer was not asked again');
  });
});
