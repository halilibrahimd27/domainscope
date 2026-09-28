// Unit tests for assets/js/lib/changecheck.js — the "is it done?" link and its verdicts. Pure, no
// network: a fake DohClient answers from a table. Documentation names and addresses only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECK_RESOLVERS, CHECK_LIMITS, CHECK_TIMING, CHECK_VERDICTS, CHECK_HEADLINES, CHECK_STOPS, PENDING_REASONS, checkFromRequest, encodeCheck,
  decodeCheck, linkEncode, linkQuery, judgeAnswer, checkRound, checkState, nextCheck, pairKey
} from '../../assets/js/lib/changecheck.js';
import { buildChange, changeRequest, normalizeValue } from '../../assets/js/lib/fixes.js';
import { CASES, caseRequest } from '../fixtures/fixes/gen-fixes-golden.mjs';

const ans = (name, type, data, ttl = 300) => ({ name, type, ttl, data });
const res = (answers = [], { rcode = 'NOERROR', authorities = [] } = {}) => ({ ok: true, rcode, answers, authorities });
const SOA = (minimum, ttl = 900) => ({ name: 'example.com', type: 'SOA', ttl, data: { mname: 'ns1.example.com', rname: 'h.example.com', serial: 1, refresh: 1, retry: 1, expire: 1, minimum } });
const exp = (over) => ({ name: 'www.example.com', type: 'A', mode: 'is', family: null, values: ['192.0.2.10'], old: null, maxTtl: null, ...over });

describe('the link', () => {
  test('every golden case round-trips exactly (the goldens pin the text)', () => {
    for (const c of CASES) {
      const check = checkFromRequest(caseRequest(c));
      const enc = encodeCheck(check);
      if (!enc.ok) continue;
      const dec = decodeCheck(enc.query);
      assert.ok(dec.ok, `${c.id}: ${JSON.stringify(dec)}`);
      assert.deepEqual(dec.check, check, c.id);
      assert.deepEqual(decodeCheck(`?${enc.query}`).check, check, 'a leading ? is fine');
      assert.deepEqual(decodeCheck(new URLSearchParams(enc.query)).check, check, 'as the router passes it');
    }
  });

  test('the link is readable: presentation form, relative names, @ : / ; = kept, | and ^ escaped inside values', () => {
    const req = buildChange('record', { name: 'www.example.com', type: 'TXT', values: 'a|b^c; d=e @f:/g' });
    const { query } = encodeCheck(checkFromRequest(req));
    assert.equal(query, 'z=example.com&r=is+www+TXT+%22a%5C124b%5C094c;+d=e+@f:/g%22');
    assert.equal(linkEncode('a b@c:d/e;f=g"h|i^j&k#l'), 'a+b@c:d/e;f=g%22h%7Ci%5Ej%26k%23l');
    const dec = decodeCheck(query);
    assert.deepEqual(dec.check.sets[0].values.map((v) => v.join('')), ['a|b^c; d=e @f:/g']);
  });

  test('what the link carries: the zone, and per set the mode, the TTL bound, the values and the old ones', () => {
    const req = changeRequest({ zone: 'example.com', rrsets: [
      { name: 'www.example.com', type: 'A', ttl: 300, values: ['192.0.2.10'], before: ['192.0.2.10'], maxTtl: 300 },
      { name: '_acme-challenge.example.com', type: 'TXT', mode: 'has', values: ['tok'], before: [] },
      { name: 'old.example.com', type: 'MX', mode: 'none', before: [{ preference: 10, exchange: 'mail.example.com' }] }
    ] });
    const { query } = encodeCheck(checkFromRequest(req));
    assert.deepEqual(new URLSearchParams(query).getAll('r'), ['is/300 www A 192.0.2.10^192.0.2.10', 'has _acme-challenge TXT "tok"^', 'none old MX ^10 mail.example.com.']);
    const { check } = decodeCheck(query);
    assert.deepEqual(check.sets.map((s) => [s.mode, s.maxTtl, s.old ? s.old.length : null]), [['is', 300, 1], ['has', null, 0], ['none', null, 1]]);
  });

  test('a family is read from the values (or from the old ones for a deletion)', () => {
    const q = 'z=example.com&r=is+@+TXT+%22v=spf1+-all%22&r=none+@+TXT+^%22v=DMARC1;+p=none%22';
    const { check } = decodeCheck(q);
    assert.deepEqual(check.sets.map((s) => s.family), ['spf1', 'dmarc1']);
  });

  test('a family the values would read wrong is named in the type: TXT:* (every TXT record), TXT:spf1', () => {
    // "Delete every TXT record of www" after a read that found only an SPF record there.
    const cur = { 'www.example.com|TXT': { status: 'ok', values: [['v=spf1 -all']], ttl: 300, cname: null } };
    const req = buildChange('record', { name: 'www.example.com', type: 'TXT', action: 'delete' }, { current: cur });
    assert.equal(req.rrsets[0].family, null);
    const check = checkFromRequest(req);
    const { query } = encodeCheck(check);
    assert.equal(query, 'z=example.com&r=none+www+TXT:*+%5E%22v=spf1+-all%22');
    assert.deepEqual(decodeCheck(query).check, check, 'exact inverse');
    const unread = { zone: 'example.com', sets: [{ name: 'example.com', type: 'TXT', mode: 'none', family: 'spf1', values: [], old: null, maxTtl: null }] };
    assert.equal(encodeCheck(unread).query, 'z=example.com&r=none+@+TXT:spf1');
    assert.deepEqual(decodeCheck(encodeCheck(unread).query).check, unread);
    // A family the values give is never written twice.
    assert.equal(encodeCheck(checkFromRequest(buildChange('record', { name: 'www.example.com', type: 'TXT', values: 'v=spf1 -all' }))).query, 'z=example.com&r=is+www+TXT+%22v=spf1+-all%22');
    const err = (q) => decodeCheck(q).error;
    assert.equal(err('z=example.com&r=none+www+A:*'), 'set', 'a family on another type');
    assert.equal(err('z=example.com&r=none+www+TXT:nope'), 'set', 'an unknown family');
  });

  test('the length limit counts the link as written, also when the router hands over its URLSearchParams', () => {
    // A long link full of ; = : / @ , — the characters URLSearchParams.toString() percent-encodes.
    const tail = '; rua=mailto:dmarc@example.com,mailto:d2@example.net; ruf=mailto:f@example.com; fo=1:d:s; adkim=s; aspf=s'.repeat(3);
    const values = [];
    let query = null;
    for (let n = 1; n < 40; n++) {
      values.push(`v=DMARC1; p=quarantine; pct=${n}${tail}`);
      const enc = encodeCheck({ zone: 'example.com', sets: [{ name: '_dmarc.example.com', type: 'TXT', mode: 'has', family: null, values: values.map((v) => normalizeValue('TXT', v)), old: null, maxTtl: null }] });
      if (!enc.ok) break;
      query = enc.query;
    }
    assert.ok(query.length > CHECK_LIMITS.chars - 200 && query.length <= CHECK_LIMITS.chars, `near the limit: ${query.length}`);
    assert.ok(new URLSearchParams(query).toString().length > CHECK_LIMITS.chars, 'its own serialization would be over the limit');
    assert.equal(linkQuery(new URLSearchParams(query)), query, 'linkQuery writes it back as it was');
    assert.ok(decodeCheck(query).ok);
    assert.ok(decodeCheck(new URLSearchParams(query)).ok, 'a link the builder made is never too long for the page');
    assert.deepEqual(decodeCheck(new URLSearchParams(query)).check, decodeCheck(query).check);
  });

  test('refused: too long, too many sets or values, another version, no zone, no set, a name outside the zone, a value that does not parse', () => {
    const many = changeRequest({ zone: 'example.com', rrsets: Array.from({ length: 21 }, (_, i) => ({ name: `h${i}.example.com`, type: 'A', values: ['192.0.2.1'] })) });
    const manySets = { zone: 'example.com', sets: Array.from({ length: 21 }, (_, i) => ({ name: `h${i}.example.com`, type: 'A', mode: 'is', values: ['192.0.2.1'], old: null })) };
    assert.equal(many.rrsets.length, 20, 'a request is capped before a link is made');
    assert.equal(encodeCheck(manySets).reason, 'too-many');
    const long = { zone: 'example.com', sets: [{ name: 'x.example.com', type: 'TXT', mode: 'is', values: [normalizeValue('TXT', 'a'.repeat(3990))], old: null }] };
    const enc = encodeCheck(long);
    assert.deepEqual([enc.ok, enc.reason, enc.length > CHECK_LIMITS.chars], [false, 'too-long', true]);
    assert.equal(encodeCheck({ zone: 'example.com', sets: [] }).reason, 'empty');
    assert.equal(encodeCheck({ zone: '192.0.2.1', sets: manySets.sets.slice(0, 1) }).reason, 'zone');
    const err = (q) => decodeCheck(q).error;
    assert.equal(err(`z=example.com&r=${'a'.repeat(CHECK_LIMITS.chars)}`), 'too-long');
    assert.equal(err(`z=example.com${'&r=is+a+A+192.0.2.1'.repeat(21)}`), 'too-many');
    assert.equal(err(`z=example.com&r=is+a+A+${Array.from({ length: 41 }, (_, i) => `192.0.2.${i + 1}`).join('%7C')}`), 'too-many');
    assert.equal(err('v=2&z=example.com&r=is+a+A+192.0.2.1'), 'version');
    assert.equal(err('z=localhost&r=is+a+A+192.0.2.1'), 'zone');
    assert.equal(err('z=example.com'), 'empty');
    assert.equal(err('z=example.com&r=is+www.example.net.+A+192.0.2.1'), 'set', 'an absolute name: outside the zone');
    assert.equal(decodeCheck('z=example.com&r=is+www.example.net+A+192.0.2.1').check.sets[0].name, 'www.example.net.example.com', 'names are relative, as in a zone file');
    assert.equal(err('z=example.com&r=is+www+A+not-an-ip'), 'set');
    assert.equal(err('z=example.com&r=is+www+NS+ns1.example.com.'), 'set');
    assert.equal(err('z=example.com&r=maybe+www+A+192.0.2.1'), 'set');
    assert.equal(err('z=example.com&r=is+www+A'), 'set', 'is without a value');
    assert.equal(err('z=example.com&r=none+www+A+192.0.2.1'), 'set', 'none with a value');
    assert.ok(decodeCheck('v=1&z=example.com&r=is+www+A+192.0.2.1').ok, 'v=1 is fine');
  });
});

describe('verdicts', () => {
  test('done: exactly the values (is), at least them (has), none left (none)', () => {
    assert.equal(judgeAnswer(exp(), res([ans('www.example.com', 'A', '192.0.2.10')])).verdict, 'done');
    assert.equal(judgeAnswer(exp({ mode: 'has', type: 'TXT', values: [['tok']] }), res([ans('x', 'TXT', ['old']), ans('x', 'TXT', ['tok'])])).verdict, 'done');
    assert.equal(judgeAnswer(exp({ mode: 'none', values: [] }), res([], { rcode: 'NXDOMAIN' })).verdict, 'done');
  });

  test('pending: missing, the old value, another value without the old ones known, a partial has, the old TTL', () => {
    const j = (e, r) => { const x = judgeAnswer(e, r); return `${x.verdict}:${x.reason}`; };
    assert.equal(j(exp(), res([], { rcode: 'NXDOMAIN' })), 'pending:missing');
    assert.equal(j(exp(), res([])), 'pending:missing');
    assert.equal(j(exp({ old: ['198.51.100.5'] }), res([ans('www.example.com', 'A', '198.51.100.5')])), 'pending:old');
    assert.equal(j(exp(), res([ans('www.example.com', 'A', '198.51.100.5')])), 'pending:other');
    assert.equal(j(exp({ mode: 'has', type: 'TXT', values: [['a'], ['b']] }), res([ans('x', 'TXT', ['a'])])), 'pending:partial');
    assert.equal(j(exp({ maxTtl: 300 }), res([ans('www.example.com', 'A', '192.0.2.10', 3600)])), 'pending:ttl');
    assert.equal(j(exp({ maxTtl: 300 }), res([ans('www.example.com', 'A', '192.0.2.10', 280)])), 'done:null');
    assert.equal(j(exp({ mode: 'none', values: [] }), res([ans('www.example.com', 'A', '192.0.2.1')])), 'pending:present');
    for (const r of ['missing', 'old', 'other', 'partial', 'ttl', 'present']) assert.ok(PENDING_REASONS.includes(r));
  });

  test('wrong: a value that is neither the new nor the known old one', () => {
    const e = exp({ old: ['198.51.100.5'] });
    const out = judgeAnswer(e, res([ans('www.example.com', 'A', '203.0.113.9')]));
    assert.deepEqual([out.verdict, out.seen], ['wrong', ['203.0.113.9']]);
    assert.equal(judgeAnswer(exp({ mode: 'none', values: [], old: ['198.51.100.5'] }), res([ans('www.example.com', 'A', '203.0.113.9')])).verdict, 'wrong');
  });

  test('error: no answer, or SERVFAIL / REFUSED', () => {
    assert.deepEqual(judgeAnswer(exp(), { ok: false, errorKind: 'timeout' }), { verdict: 'error', reason: 'timeout', seen: [], ttl: null });
    assert.equal(judgeAnswer(exp(), res([], { rcode: 'SERVFAIL' })).reason, 'SERVFAIL');
    assert.equal(judgeAnswer(exp(), null).verdict, 'error');
  });

  test('a family set looks at its own kind only; TXT chunking does not matter', () => {
    const e = exp({ name: 'example.com', type: 'TXT', family: 'spf1', values: [['v=spf1 -all']], old: [['v=spf1 ~all']] });
    const others = [ans('example.com', 'TXT', ['site-verification=1'])];
    assert.equal(judgeAnswer(e, res([...others, ans('example.com', 'TXT', ['v=spf1 ', '-all'])])).verdict, 'done');
    assert.equal(judgeAnswer(e, res([...others, ans('example.com', 'TXT', ['v=spf1 ~all'])])).reason, 'old');
    assert.equal(judgeAnswer(e, res([...others, ans('example.com', 'TXT', ['v=spf1 ~all']), ans('example.com', 'TXT', ['v=spf1 -all'])])).verdict, 'wrong', 'two SPF records');
  });

  test('through a CNAME chain for other types (what a CA sees); a CNAME set by its own name', () => {
    const chain = res([ans('_acme-challenge.example.com', 'CNAME', 'x.auth.example.net'), ans('x.auth.example.net', 'TXT', ['tok'])]);
    assert.equal(judgeAnswer(exp({ name: '_acme-challenge.example.com', type: 'TXT', mode: 'has', values: [['tok']] }), chain).verdict, 'done');
    const cname = exp({ name: '_acme-challenge.example.com', type: 'CNAME', values: ['x.auth.example.net'] });
    assert.equal(judgeAnswer(cname, chain).verdict, 'done');
    assert.equal(judgeAnswer(cname, res([ans('other.example.com', 'CNAME', 'x.auth.example.net')])).reason, 'missing');
  });

  test('the TTL of an empty answer is the negative TTL of the SOA (RFC 2308)', () => {
    assert.equal(judgeAnswer(exp(), res([], { rcode: 'NXDOMAIN', authorities: [SOA(300, 900)] })).ttl, 300);
    assert.equal(judgeAnswer(exp(), res([], { authorities: [SOA(3600, 120)] })).ttl, 120);
    assert.equal(judgeAnswer(exp(), res([])).ttl, null);
    assert.equal(judgeAnswer(exp(), res([ans('www.example.com', 'A', '198.51.100.5', 77), ans('www.example.com', 'A', '198.51.100.6', 90)])).ttl, 77);
    assert.deepEqual(CHECK_VERDICTS, ['done', 'pending', 'wrong', 'error']);
  });
});

describe('rounds, state and timing', () => {
  const check = decodeCheck('z=example.com&r=is+www+A+192.0.2.10^198.51.100.5&r=has+_acme-challenge+TXT+%22tok%22').check;

  test('checkRound asks every resolver for every set, uncached, per resolver, and reports as they come', async () => {
    const log = [];
    const dns = {
      async query(name, type, opts) {
        log.push(`${name} ${type} ${opts.resolver} ${opts.noCache} ${opts.retries}`);
        if (opts.resolver === 'cznic') return { ok: false, errorKind: 'timeout' };
        if (type === 'A') return res([ans(name, 'A', opts.resolver === 'google' ? '198.51.100.5' : '192.0.2.10')]);
        return res([ans(name, 'TXT', ['tok'])]);
      }
    };
    const seen = [];
    const out = await checkRound(check, { dns, now: () => 1000, onResult: (r) => seen.push(r.resolver) });
    assert.equal(out.length, 8);
    assert.equal(seen.length, 8);
    assert.ok(log.every((l) => / true 0$/.test(l)), 'noCache, no retries');
    assert.deepEqual(CHECK_RESOLVERS, ['cloudflare', 'google', 'dnssb', 'cznic']);
    const latest = new Map(out.map((r) => [pairKey(r.set, r.resolver), r]));
    const st = checkState(check, latest);
    assert.deepEqual([st.headline, st.sets.map((s) => s.state), st.counts], ['pending', ['pending', 'done'], { done: 5, pending: 1, wrong: 0, error: 2, waiting: 0 }]);
    const only = await checkRound(check, { dns, only: new Set([pairKey(0, 'google')]), now: () => 2000 });
    assert.deepEqual(only.map((r) => `${r.set}|${r.resolver}|${r.verdict}`), ['0|google|pending']);
  });

  test('checkState: waiting before anything answers, done-partial when a resolver never answers', () => {
    assert.equal(checkState(check, new Map()).headline, 'unknown');
    const all = (verdict, skip = null) => new Map(check.sets.flatMap((_, s) => CHECK_RESOLVERS.map((r) => [pairKey(s, r), { set: s, resolver: r, verdict: r === skip ? 'error' : verdict }])));
    assert.equal(checkState(check, all('done')).headline, 'done');
    assert.equal(checkState(check, all('done', 'cznic')).headline, 'done-partial');
    assert.ok(checkState(check, all('done', 'cznic')).settled);
    assert.equal(checkState(check, all('wrong')).headline, 'wrong');
    assert.equal(checkState(check, all('error')).headline, 'no-answer', 'nobody answered');
    const oneSet = new Map([...all('done')].map(([k, v]) => [k, k.startsWith('1|') ? { ...v, verdict: 'error' } : v]));
    const st = checkState(check, oneSet);
    assert.deepEqual([st.headline, st.sets.map((s) => s.state)], ['no-answer', ['done', 'unknown']], 'one set with no answer at all');
    const waiting = new Map([[pairKey(0, 'cloudflare'), { verdict: 'error' }]]);
    assert.equal(checkState(check, waiting).headline, 'unknown', 'still asking');
    assert.ok(CHECK_HEADLINES.includes('no-answer'));
  });

  test('nextCheck: no answer from any resolver three rounds in a row stops as failed, never as done', async () => {
    const t0 = 7_000_000;
    // A DohClient that always fails (DoH blocked by a firewall, offline mid-check, rate-limited everywhere).
    const down = { async query() { return { ok: false, errorKind: 'network' }; } };
    const latest = new Map();
    let errorRounds = 0;
    let n = null;
    for (let round = 1; round <= 3; round++) {
      const out = await checkRound(check, { dns: down, only: n ? new Set(n.pairs) : null, now: () => t0 + round * 1000 });
      for (const r of out) latest.set(pairKey(r.set, r.resolver), r);
      errorRounds = out.some((r) => r.verdict === 'error') ? errorRounds + 1 : 0;
      n = nextCheck({ latest, check, round, startedAt: t0, now: t0 + round * 1000, errorRounds });
      assert.equal(checkState(check, latest).headline, 'no-answer', `round ${round}`);
      if (round < 3) assert.deepEqual([n.stop, n.pairs.length], [null, 8], `round ${round}: asked again`);
    }
    assert.deepEqual([n.stop, n.at, n.pairs], ['failed', null, []]);
    assert.ok(CHECK_STOPS.includes('failed'));
    // Every resolver failed for one set, the other is done: failed too.
    const mixed = new Map(check.sets.flatMap((_, s) => CHECK_RESOLVERS.map((r) => [pairKey(s, r), { verdict: s === 1 ? 'error' : 'done', at: t0 }])));
    assert.equal(nextCheck({ latest: mixed, check, round: 3, startedAt: t0, now: t0, errorRounds: 3 }).stop, 'failed');
    // One resolver failed for both sets, the others answered: done (the headline says done-partial).
    const partial = new Map(check.sets.flatMap((_, s) => CHECK_RESOLVERS.map((r) => [pairKey(s, r), { verdict: r === 'cznic' ? 'error' : 'done', at: t0 }])));
    assert.equal(nextCheck({ latest: partial, check, round: 3, startedAt: t0, now: t0, errorRounds: 3 }).stop, 'done');
    assert.equal(checkState(check, partial).headline, 'done-partial');
  });

  test('nextCheck: a growing backoff, never before a cached copy expires, and a stop', () => {
    const t0 = 1_000_000;
    const pending = (ttl, at = t0) => new Map(check.sets.flatMap((_, s) => CHECK_RESOLVERS.map((r) => [pairKey(s, r), { set: s, resolver: r, verdict: s === 0 ? 'pending' : 'done', ttl, at }])));
    const n0 = nextCheck({ latest: pending(0), check, round: 0, startedAt: t0, now: t0 });
    assert.deepEqual([n0.stop, n0.at - t0, n0.pairs.length], [null, CHECK_TIMING.base, 4]);
    const n3 = nextCheck({ latest: pending(0), check, round: 3, startedAt: t0, now: t0 });
    assert.equal(n3.at - t0, Math.round(CHECK_TIMING.base * CHECK_TIMING.factor ** 3));
    assert.equal(nextCheck({ latest: pending(0), check, round: 20, startedAt: t0, now: t0 }).at - t0, CHECK_TIMING.max);
    // A resolver cached the old answer for 600 s more: asking before then changes nothing.
    const ttl = nextCheck({ latest: pending(600), check, round: 0, startedAt: t0, now: t0 });
    assert.equal(ttl.at - t0, 601_000);
    // Cached past the two-hour stop: nothing can change before then.
    const cached = nextCheck({ latest: pending(86400), check, round: 0, startedAt: t0, now: t0 });
    assert.deepEqual([cached.stop, cached.cachedUntil - t0], ['cached', 86_401_000]);
    assert.equal(nextCheck({ latest: pending(0), check, round: 5, startedAt: t0, now: t0 + CHECK_TIMING.stopAfter }).stop, 'timeout');
    const done = new Map(check.sets.flatMap((_, s) => CHECK_RESOLVERS.map((r) => [pairKey(s, r), { verdict: 'done', at: t0 }])));
    assert.equal(nextCheck({ latest: done, check, round: 1, startedAt: t0, now: t0 }).stop, 'done');
  });

  test('nextCheck: only the pairs that are ready; a resolver that keeps failing is given up after three rounds', () => {
    const t0 = 5_000_000;
    const latest = new Map([
      [pairKey(0, 'cloudflare'), { verdict: 'pending', ttl: 10, at: t0 }], [pairKey(0, 'google'), { verdict: 'pending', ttl: 3000, at: t0 }],
      [pairKey(0, 'dnssb'), { verdict: 'done', at: t0 }], [pairKey(0, 'cznic'), { verdict: 'error', ttl: null, at: t0 }],
      [pairKey(1, 'cloudflare'), { verdict: 'done', at: t0 }], [pairKey(1, 'google'), { verdict: 'done', at: t0 }],
      [pairKey(1, 'dnssb'), { verdict: 'done', at: t0 }], [pairKey(1, 'cznic'), { verdict: 'error', ttl: null, at: t0 }]
    ]);
    const n = nextCheck({ latest, check, round: 0, startedAt: t0, now: t0 });
    assert.deepEqual([n.at - t0, n.pairs.sort()], [CHECK_TIMING.base, [pairKey(0, 'cloudflare'), pairKey(0, 'cznic'), pairKey(1, 'cznic')].sort()]);
    const giveUp = nextCheck({ latest, check, round: 4, startedAt: t0, now: t0, errorRounds: 3 });
    assert.deepEqual(giveUp.pairs.sort(), [pairKey(0, 'cloudflare')].sort());
  });
});
