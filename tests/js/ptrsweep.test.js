// Unit tests for assets/js/lib/ptrsweep.js — the reverse-DNS sweep with forward confirmation.
// No network: the sweep and FCrDNS cases drive a real DohClient whose fetchImpl decodes the
// RFC 8484 `?dns=` query and answers with wire-format messages built by dnswire.encodeMessage
// (as doh.test.js and dane.test.js do), so PTR, CNAME (RFC 2317) and A / AAAA answers travel
// the same path as in a browser. RIPEstat answers are small hand-made documents in the shape
// the live API returns (verified 2026-09-27). Documentation data only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as P from '../../assets/js/lib/ptrsweep.js';
import { DohClient } from '../../assets/js/lib/doh.js';
import { decodeMessage, encodeMessage, base64UrlDecode } from '../../assets/js/lib/dnswire.js';
import { parseInventory, buildIpIndex } from '../../assets/js/lib/inventory.js';
import { HttpError } from '../../assets/js/lib/util.js';

/* ------------------------------------------------------------------------ */
/* Mock DoH                                                                 */
/* ------------------------------------------------------------------------ */

/**
 * A DoH server answering from `zone`: keys `name|TYPE` → { rcode, answers } or a function of the
 * call; unknown names get NXDOMAIN. `fail` names answer HTTP 503 (a transport failure for the
 * client). Every call is recorded; `delayMs` slows each answer (cancel tests).
 */
function zoneFetch(zone, { fail = [], delayMs = 0 } = {}) {
  const calls = [];
  let inFlight = 0;
  let maxInFlight = 0;
  const fetchImpl = async (url, init = {}) => {
    const query = decodeMessage(base64UrlDecode(new URL(url).searchParams.get('dns')));
    const q = query.questions[0];
    calls.push({ name: q.name, type: q.type });
    inFlight += 1;
    maxInFlight = Math.max(maxInFlight, inFlight);
    try {
      if (delayMs) {
        await new Promise((resolve, reject) => {
          const timer = setTimeout(resolve, delayMs);
          init.signal?.addEventListener('abort', () => { clearTimeout(timer); reject(init.signal.reason); }, { once: true });
        });
      }
      if (fail.includes(q.name)) return new Response('busy', { status: 503 });
      const node = zone[`${q.name}|${q.type}`] || { rcode: 'NXDOMAIN', answers: [] };
      const bytes = encodeMessage({
        id: 0,
        flags: { qr: true, rd: true, ra: true },
        rcode: node.rcode || 'NOERROR',
        questions: [{ name: q.name, type: q.type }],
        answers: (node.answers || []).map((a) => ({ ttl: 300, ...a })),
        edns: {}
      });
      return new Response(bytes, { status: 200, headers: { 'content-type': 'application/dns-message' } });
    } finally {
      inFlight -= 1;
    }
  };
  return { fetchImpl, calls, get maxInFlight() { return maxInFlight; } };
}

const client = (zone, opts = {}) => {
  const f = zoneFetch(zone, opts);
  const dns = new DohClient({
    chain: ['cloudflare'], balancePool: ['cloudflare'], fetchImpl: f.fetchImpl, cache: false, retries: 0, baseDelayMs: 1, timeoutMs: 2000,
    concurrency: opts.concurrency || 12
  });
  return { dns, f };
};

const rev = (ip) => `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
const ptr = (ip, ...names) => ({ [`${rev(ip)}|PTR`]: { answers: names.map((data) => ({ name: rev(ip), type: 'PTR', data })) } });
const a = (name, ...ips) => ({ [`${name}|A`]: { answers: ips.map((data) => ({ name, type: 'A', data })) } });
const rcode = (name, type, code) => ({ [`${name}|${type}`]: { rcode: code, answers: [] } });

/* ------------------------------------------------------------------------ */
/* Target parsing                                                           */
/* ------------------------------------------------------------------------ */

describe('parseAsn', () => {
  test('AS-prefixed numbers only, 1 … 2^32-1', () => {
    assert.equal(P.parseAsn('AS64496'), 64496);
    assert.equal(P.parseAsn(' as64497 '), 64497);
    assert.equal(P.parseAsn('ASN 64498'), 64498);
    assert.equal(P.parseAsn('AS4294967295'), 4294967295);
    for (const bad of ['64496', 'AS0', 'AS4294967296', 'AS-1', 'ASx', '', null, 'AS 64496 1']) assert.equal(P.parseAsn(bad), null, String(bad));
  });
});

describe('parseSweepTarget', () => {
  test('empty input: nothing to say yet', () => {
    const t = P.parseSweepTarget('  \n# a comment\n');
    assert.equal(t.kind, 'empty');
    assert.deepEqual(t.issues, []);
    assert.equal(t.ok, false);
  });

  test('a /28 network: 16 addresses in order, the network and broadcast addresses included', () => {
    const t = P.parseSweepTarget('192.0.2.0/28');
    assert.equal(t.kind, 'addresses');
    assert.equal(t.ok, true);
    assert.equal(t.total, 16);
    assert.equal(t.addresses.length, 16);
    assert.equal(t.addresses[0], '192.0.2.0');
    assert.equal(t.addresses[15], '192.0.2.15');
    assert.equal(t.label, '192.0.2.0/28');
    assert.deepEqual(t.blocks.map((b) => [b.kind, b.label, b.count]), [['cidr', '192.0.2.0/28', 16]]);
  });

  test('host bits are masked and said (info only)', () => {
    const t = P.parseSweepTarget('192.0.2.77/30');
    assert.deepEqual(t.addresses, ['192.0.2.76', '192.0.2.77', '192.0.2.78', '192.0.2.79']);
    const hb = t.issues.find((i) => i.code === 'host-bits');
    assert.deepEqual(hb, { code: 'host-bits', severity: 'info', params: { input: '192.0.2.77/30', cidr: '192.0.2.76/30' } });
    assert.equal(t.ok, true);
  });

  test('ranges: the full and the short form; a reversed range is dropped with a warning', () => {
    const t = P.parseSweepTarget('198.51.100.10-198.51.100.12\n203.0.113.250-252');
    assert.deepEqual(t.addresses, ['198.51.100.10', '198.51.100.11', '198.51.100.12', '203.0.113.250', '203.0.113.251', '203.0.113.252']);
    assert.deepEqual(t.blocks.map((b) => b.label), ['198.51.100.10-198.51.100.12', '203.0.113.250-203.0.113.252']);
    const r = P.parseSweepTarget('198.51.100.20-10, 198.51.100.5');
    assert.deepEqual(r.addresses, ['198.51.100.5']);
    assert.equal(r.issues.find((i) => i.code === 'reversed').params.items, '198.51.100.20-10');
    assert.equal(P.parseSweepTarget('198.51.100.9-9').blocks[0].kind, 'ip');
  });

  test('single IPv4 and IPv6 addresses (brackets, mapped IPv4, duplicates)', () => {
    const t = P.parseSweepTarget('[2001:DB8::5], 192.0.2.1 ::ffff:192.0.2.2 192.0.2.1 2001:db8:0:0::5');
    assert.deepEqual(t.addresses, ['2001:db8::5', '192.0.2.1', '192.0.2.2']);
    assert.equal(P.parseSweepTarget('2001:db8::7/128').addresses[0], '2001:db8::7');
    // the label names each address once
    assert.equal(P.parseSweepTarget('2001:db8::1, 2001:db8::1, 2001:db8::1').label, '2001:db8::1');
    assert.equal(P.parseSweepTarget('2001:db8::1 192.0.2.0/30 2001:db8::1 192.0.2.0/30').label, '2001:db8::1, 192.0.2.0/30');
  });

  test('IPv6 networks and ranges are never swept: a warning, and an error when nothing else is left', () => {
    const only = P.parseSweepTarget('2001:db8::/64');
    assert.deepEqual(only.issues.map((i) => i.code), ['v6-range', 'nothing']);
    assert.equal(only.ok, false);
    const mixed = P.parseSweepTarget('2001:db8::/48 2001:db8::1-2001:db8::9 192.0.2.1');
    assert.deepEqual(mixed.addresses, ['192.0.2.1']);
    assert.equal(mixed.issues[0].code, 'v6-range');
    assert.equal(mixed.issues[0].params.count, 2);
    assert.equal(mixed.ok, true);
  });

  test('a network over the cap is an error with its first /22 as the suggestion', () => {
    const t = P.parseSweepTarget('192.0.0.0/20');
    assert.equal(t.ok, false);
    assert.deepEqual(t.addresses, []);
    assert.deepEqual(t.issues, [{
      code: 'too-large', severity: 'error', params: { input: '192.0.0.0/20', count: 4096, max: 1024, suggestion: '192.0.0.0/22', kind: 'cidr', skipped: '' }
    }]);
    assert.equal(P.parseSweepTarget('192.0.2.0/24', { max: 64 }).issues[0].params.suggestion, '192.0.2.0/26');
    const big = P.parseSweepTarget('192.0.2.0-192.0.2.255', { max: 100 });
    assert.equal(big.issues[0].code, 'too-large');
    assert.deepEqual([big.issues[0].params.suggestion, big.issues[0].params.kind], ['', 'range'], 'a range gets no network suggestion');
  });

  test('a network over the cap that is wholly private or reserved says so, and nothing is suggested', () => {
    const params = (text) => P.parseSweepTarget(text).issues[0].params;
    for (const [text, skipped] of [['10.0.0.0/8', 'private'], ['198.18.0.0/16', 'private'], ['172.16.0.0/12', 'private'],
      ['198.18.0.0-198.18.7.255', 'private'], ['224.0.0.0/4', 'reserved'], ['224.0.0.0/3', 'reserved']]) {
      assert.deepEqual([params(text).skipped, params(text).suggestion], [skipped, ''], text);
    }
    // part private, part public: said as too large, but its first /22 (all in 0.0.0.0/8) is no suggestion
    assert.deepEqual([params('0.0.0.0/1').skipped, params('0.0.0.0/1').suggestion, params('0.0.0.0/1').kind], ['', '', 'cidr']);
    // a block whose ends are private but in two ranges, with public space between, is not private
    assert.deepEqual([params('10.0.0.0-127.0.0.1').skipped, params('10.0.0.0-127.0.0.1').kind], ['', 'range']);
  });

  test('the cap applies to the distinct addresses of everything together (over-cap); overlaps count once', () => {
    const t = P.parseSweepTarget('192.0.2.0/24 198.51.100.0/22');
    assert.deepEqual(t.issues.map((i) => i.code), ['over-cap']);
    assert.deepEqual(t.issues[0].params, { count: 1280, max: 1024 });
    assert.deepEqual([t.addresses, t.skipped], [[], { private: 0, reserved: 0 }]);
    assert.equal(P.parseSweepTarget('192.0.2.0/28', { max: 8 }).issues[0].params.suggestion, '192.0.2.0/29');
    // a network and one inside it, the same network twice, a range across both: 1,024 and 256 distinct addresses
    const nested = P.parseSweepTarget('192.0.2.0/22 192.0.2.0/24');
    assert.deepEqual([nested.total, nested.ok, nested.issues.map((i) => i.code)], [1024, true, ['host-bits', 'private']]);
    assert.equal(nested.addresses.length, 768, 'the private 192.0.0.0/24 left out, nothing twice');
    const twice = P.parseSweepTarget('192.0.2.0/24 192.0.2.0/24 192.0.2.10-192.0.2.20 192.0.2.7');
    assert.deepEqual([twice.total, twice.addresses.length, twice.ok], [256, 256, true]);
    assert.equal(P.parseSweepTarget('192.0.2.0/24 198.51.100.0/24 203.0.113.0/24 192.0.2.0/24 198.51.100.0/24').total, 768);
  });

  test('the cap counts the addresses a sweep looks up: private and reserved ones are left out first', () => {
    // 1,280 addresses typed, 256 looked up: the private /22 and /23s never reach a resolver
    for (const text of ['10.0.0.0/22 192.0.2.0/24', '192.0.2.0/24 198.18.0.0/23 198.19.0.0/23']) {
      const t = P.parseSweepTarget(text);
      assert.deepEqual([t.ok, t.total, t.addresses.length, t.skipped, t.issues.map((i) => i.code)], [true, 1280, 256, { private: 1024, reserved: 0 }, ['private']], text);
    }
    const reserved = P.parseSweepTarget('224.0.0.0/22 239.255.255.0/24 192.0.2.0/24');
    assert.deepEqual([reserved.ok, reserved.addresses.length, reserved.skipped], [true, 256, { private: 0, reserved: 1280 }]);
    // a block across a private boundary is counted address by address; overlaps once
    const across = P.parseSweepTarget('192.0.0.0/22 192.0.0.0/24 192.0.0.128/25 10.0.0.0/30 10.0.0.1');
    assert.deepEqual([across.ok, across.total, across.addresses.length, across.skipped], [true, 1028, 768, { private: 260, reserved: 0 }]);
    assert.ok(across.addresses.every((ip) => !P.skipReason(ip)) && across.addresses.includes('192.0.2.0'), 'the public part only');
    // IPv6 exact addresses count one by one
    assert.deepEqual(P.parseSweepTarget('fe80::1 fe80::2 ff02::1 2001:db8::1').skipped, { private: 2, reserved: 1 });
    // over the cap only once the addresses to look up are
    assert.deepEqual(P.parseSweepTarget('10.0.0.0/24 192.0.2.0/24 198.51.100.0/24', { max: 300 }).issues.map((i) => [i.code, i.params.count]), [['over-cap', 512]]);
    assert.equal(P.parseSweepTarget('10.0.0.0/24 192.0.2.0/24', { max: 300 }).ok, true);
  });

  test('"AS 64496" / "ASN 64496" and ranges typed with spaces or an en dash are one token', () => {
    for (const text of ['AS 64496', 'ASN 64496', 'asn  64496 ', '# peer\nAS\t64496']) {
      const t = P.parseSweepTarget(text);
      assert.deepEqual([t.kind, t.asn, t.issues], ['asn', 64496, []], JSON.stringify(text));
    }
    for (const text of ['192.0.2.10 - 192.0.2.20', '192.0.2.10 -192.0.2.20', '192.0.2.10 – 192.0.2.20', '192.0.2.10–20', '192.0.2.10 - 20']) {
      const t = P.parseSweepTarget(text);
      assert.deepEqual([t.blocks.map((b) => b.label), t.issues], [['192.0.2.10-192.0.2.20'], []], text);
    }
    const v6 = P.parseSweepTarget('2001:db8::1 - 2001:db8::9');
    assert.deepEqual(v6.issues.map((i) => i.code), ['v6-range', 'nothing']);
    // two networks around a dash are no range: both are kept, the dash is ignored
    const nets = P.parseSweepTarget('192.0.2.0/24 - 198.51.100.0/24');
    assert.deepEqual([nets.blocks.map((b) => b.label), nets.issues.map((i) => [i.code, i.params.items])], [['192.0.2.0/24', '198.51.100.0/24'], [['invalid', '-']]]);
    assert.deepEqual(P.parseSweepTarget('192.0.2.0/28 – 198.51.100.7').blocks.map((b) => b.label), ['192.0.2.0/28', '198.51.100.7']);
    assert.deepEqual(P.parseSweepTarget('www.example.com - 192.0.2.9').blocks.map((b) => b.label), ['192.0.2.9']);
    // a dash before a word that is no address keeps the address before it
    const note = P.parseSweepTarget('192.0.2.1 - 2nd server');
    assert.deepEqual([note.addresses, note.issues.map((i) => i.code)], [['192.0.2.1'], ['invalid']]);
    // a list stays a list: no dash, or a dash at a line start (a bullet)
    assert.equal(P.parseSweepTarget('192.0.2.10 192.0.2.20').addresses.length, 2);
    assert.deepEqual(P.parseSweepTarget('- 192.0.2.10\n- 192.0.2.20').addresses, ['192.0.2.10', '192.0.2.20']);
  });

  test('private and reserved addresses are left out and counted', () => {
    const t = P.parseSweepTarget('10.0.0.0/30 192.0.2.1 224.0.0.1 fe80::1 ff02::1 fd00::1');
    assert.deepEqual(t.addresses, ['192.0.2.1']);
    assert.deepEqual(t.skipped, { private: 6, reserved: 2 });
    assert.deepEqual(t.issues.map((i) => [i.code, i.severity, i.params.count]), [['private', 'warn', 6], ['reserved', 'warn', 2]]);
    const none = P.parseSweepTarget('10.0.0.0/29');
    assert.deepEqual(none.issues.map((i) => i.code), ['private', 'nothing']);
    assert.equal(none.ok, false);
  });

  test('invalid tokens are dropped with a warning; only invalid input is an error', () => {
    const t = P.parseSweepTarget('www.example.com 192.0.2.300 192.0.2.1 192.0.2.0/33');
    assert.deepEqual(t.addresses, ['192.0.2.1']);
    assert.equal(t.issues[0].code, 'invalid');
    assert.equal(t.issues[0].params.items, 'www.example.com, 192.0.2.300, 192.0.2.0/33');
    assert.deepEqual(P.parseSweepTarget('nonsense').issues.map((i) => i.code), ['invalid', 'nothing']);
  });

  test('an AS number: kind asn, alone only', () => {
    const t = P.parseSweepTarget('AS64496');
    assert.equal(t.kind, 'asn');
    assert.equal(t.asn, 64496);
    assert.equal(t.label, 'AS64496');
    assert.equal(t.ok, true);
    assert.deepEqual(P.parseSweepTarget('AS64496 AS64497').issues.map((i) => i.code), ['asn-many']);
    assert.deepEqual(P.parseSweepTarget('AS64496 192.0.2.0/24').issues.map((i) => i.code), ['asn-mixed']);
    assert.equal(P.parseSweepTarget('AS64496 192.0.2.0/24').ok, false);
  });

  test('every issue code has a severity', () => {
    for (const code of P.TARGET_ISSUES) assert.ok(['error', 'warn', 'info'].includes(P.TARGET_ISSUE_SEVERITY[code]), code);
  });
});

describe('prefix helpers', () => {
  test('prefixSize, canonicalCidr, firstSubnet, skipReason', () => {
    assert.equal(P.prefixSize('192.0.2.0/24'), 256);
    assert.equal(P.prefixSize('2001:db8::/64'), 2 ** 64);
    assert.equal(P.prefixSize('nope'), null);
    assert.equal(P.canonicalCidr('192.0.2.77/24'), '192.0.2.0/24');
    assert.equal(P.canonicalCidr('2001:DB8:0::/48'), '2001:db8::/48');
    assert.equal(P.firstSubnet('198.18.0.0/15'), '198.18.0.0/22');
    assert.equal(P.firstSubnet('192.0.2.0/24'), '192.0.2.0/24');
    assert.equal(P.skipReason('192.0.2.1'), null);
    assert.equal(P.skipReason('172.16.0.1'), 'private');
    assert.equal(P.skipReason('240.0.0.1'), 'reserved');
    assert.equal(P.skipReason('ff05::2'), 'reserved');
    assert.equal(P.skipReason('2001:db8::1'), null);
    assert.equal(P.skipReason('bogus'), 'reserved');
  });
});

/* ------------------------------------------------------------------------ */
/* RIPEstat announced prefixes                                              */
/* ------------------------------------------------------------------------ */

const WINDOW = { query_starttime: '2026-09-13T08:00:00', query_endtime: '2026-09-27T08:00:00' };
const tl = (endtime = WINDOW.query_endtime) => [{ starttime: WINDOW.query_starttime, endtime }];
const ripe = (prefixes, extra = {}) => ({
  status: 'ok', status_code: 200, messages: [['info', 'Results exclude routes with very low visibility.']],
  data: { prefixes, resource: '64496', ...WINDOW, latest_time: WINDOW.query_endtime, ...extra }
});

describe('announced prefixes', () => {
  test('the URL carries the AS number and sourceapp only', () => {
    assert.equal(P.announcedPrefixesUrl('AS64496'), 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64496&sourceapp=domainscope');
    assert.equal(P.announcedPrefixesUrl(64497), 'https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64497&sourceapp=domainscope');
    assert.throws(() => P.announcedPrefixesUrl('64496'), TypeError);
    assert.throws(() => P.announcedPrefixesUrl(0), TypeError);
  });

  test('parse: IPv4 first in address order, sizes, sweepable, the /22 part of a big prefix, current, duplicates', () => {
    const r = P.parseAnnouncedPrefixes(ripe([
      { prefix: '2001:db8::/32', timelines: tl() },
      { prefix: '203.0.113.0/24', timelines: tl() },
      { prefix: '198.18.0.0/15', timelines: tl() },
      { prefix: '192.0.2.0/24', timelines: tl('2026-09-20T08:00:00') },
      { prefix: '198.51.100.0/24', timelines: tl() },
      { prefix: '198.51.100.0/24', timelines: tl('2026-09-14T00:00:00') },
      { prefix: 'garbage', timelines: [] },
      { prefix: '192.0.2.1', timelines: tl() }
    ]), { asn: 64496 });
    assert.equal(r.asn, 64496);
    assert.deepEqual(r.prefixes.map((p) => p.prefix), ['192.0.2.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32']);
    const by = Object.fromEntries(r.prefixes.map((p) => [p.prefix, p]));
    assert.equal(by['192.0.2.0/24'].current, false, 'withdrawn before the window ended');
    assert.equal(by['198.51.100.0/24'].current, true, 'one timeline reaching the end is enough');
    // a wholly private prefix is listed, never swept, and offers no part of it
    assert.deepEqual([by['198.18.0.0/15'].size, by['198.18.0.0/15'].sweepable, by['198.18.0.0/15'].skipped, by['198.18.0.0/15'].part], [131072, false, 'private', null]);
    assert.deepEqual([by['203.0.113.0/24'].sweepable, by['203.0.113.0/24'].skipped, by['203.0.113.0/24'].part], [true, null, null]);
    assert.deepEqual([by['2001:db8::/32'].version, by['2001:db8::/32'].sweepable, by['2001:db8::/32'].skipped, by['2001:db8::/32'].part], [6, false, null, null]);
    assert.deepEqual([r.v4, r.v6, r.v4Addresses, r.sweepable], [4, 1, 131072 + 768, 3]);
  });

  test('parse: private and reserved prefixes are not sweepable; a large public one offers its first /22 with something to sweep', () => {
    const r = P.parseAnnouncedPrefixes(ripe(['100.64.0.0/24', '192.0.0.0/24', '224.0.0.0/24', '192.0.0.0/20', '192.0.0.0/23', '198.51.100.0/24']
      .map((prefix) => ({ prefix, timelines: tl() }))));
    const by = Object.fromEntries(r.prefixes.map((p) => [p.prefix, [p.sweepable, p.skipped, p.part]]));
    assert.deepEqual(by, {
      '100.64.0.0/24': [false, 'private', null], '192.0.0.0/24': [false, 'private', null], '224.0.0.0/24': [false, 'reserved', null],
      '192.0.0.0/20': [false, null, '192.0.0.0/22'], '192.0.0.0/23': [true, null, null], '198.51.100.0/24': [true, null, null]
    });
    assert.equal(r.sweepable, 2);
    // a picked private prefix is never swept
    assert.deepEqual(P.prefixSelection(r.prefixes, ['100.64.0.0/24', '198.51.100.0/24']).cidrs, ['198.51.100.0/24']);
    assert.equal(r.queryEnd, WINDOW.query_endtime);
  });

  test('parse: an unknown AS is an empty list; an error document throws', () => {
    const r = P.parseAnnouncedPrefixes(ripe([], { resource: '64511' }));
    assert.deepEqual([r.asn, r.prefixes, r.v4, r.v6], [64511, [], 0, 0]);
    assert.throws(() => P.parseAnnouncedPrefixes({ status: 'error', messages: [['error', 'ASx is of an unsupported resource type.']], data: {} }), /unsupported resource type/);
    assert.throws(() => P.parseAnnouncedPrefixes({ status: 'ok', data: {} }), SyntaxError);
    assert.throws(() => P.parseAnnouncedPrefixes(null), SyntaxError);
  });

  test('announcedPrefixes: one GET, retried once on a 5xx, HttpError on a 400', async () => {
    const calls = [];
    let n = 0;
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), accept: new Headers(init.headers).get('accept') });
      n += 1;
      if (n === 1) return new Response('oops', { status: 502 });
      return new Response(JSON.stringify(ripe([{ prefix: '192.0.2.0/24', timelines: tl() }])), { status: 200 });
    };
    const r = await P.announcedPrefixes('AS64496', { fetchImpl });
    assert.equal(r.prefixes.length, 1);
    assert.equal(calls.length, 2);
    assert.equal(calls[0].url, P.announcedPrefixesUrl(64496));
    assert.equal(calls[0].accept, 'application/json');
    const bad = async () => new Response(JSON.stringify({ status: 'error', messages: [['error', 'unsupported']], data: {} }), { status: 400 });
    await assert.rejects(P.announcedPrefixes(64496, { fetchImpl: bad }), (e) => e instanceof HttpError && e.status === 400);
  });

  test('announcedPrefixes: an aborted signal rejects before any request', async () => {
    const ctl = new AbortController();
    ctl.abort();
    let called = 0;
    await assert.rejects(P.announcedPrefixes(64496, { signal: ctl.signal, fetchImpl: async () => { called += 1; } }), { name: 'AbortError' });
    assert.equal(called, 0);
  });

  test('prefixSelection: sweepable picks only, sum against the cap', () => {
    const r = P.parseAnnouncedPrefixes(ripe(['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '198.18.0.0/15', '2001:db8::/32'].map((prefix) => ({ prefix, timelines: tl() }))));
    const s = P.prefixSelection(r.prefixes, ['192.0.2.0/24', '198.18.0.0/15', '2001:db8::/32', '198.51.100.0/24']);
    assert.deepEqual(s, { cidrs: ['192.0.2.0/24', '198.51.100.0/24'], count: 2, addresses: 512, over: false, max: 1024 });
    assert.equal(P.prefixSelection(r.prefixes, ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'], { max: 512 }).over, true);
  });

  test('prefixSelection: a prefix and a more specific one inside it count their addresses once', () => {
    const r = P.parseAnnouncedPrefixes(ripe(['192.0.2.0/24', '192.0.2.0/25', '192.0.2.128/26', '198.51.100.0/24', '203.0.113.0/24'].map((prefix) => ({ prefix, timelines: tl() }))));
    const all = P.prefixSelection(r.prefixes, r.prefixes.map((p) => p.prefix), { max: 512 });
    assert.deepEqual([all.count, all.addresses, all.over], [5, 768, true]);
    const nested = P.prefixSelection(r.prefixes, ['192.0.2.0/24', '192.0.2.0/25', '192.0.2.128/26'], { max: 512 });
    assert.deepEqual([nested.count, nested.addresses, nested.over], [3, 256, false]);
  });
});

/* ------------------------------------------------------------------------ */
/* FCrDNS                                                                   */
/* ------------------------------------------------------------------------ */

describe('ptrOutcome / forwardOutcome / fcrdnsVerdict (pure)', () => {
  const Q = rev('192.0.2.5');
  test('PTR answers: names (RFC 2317 chain followed), NODATA, NXDOMAIN, SERVFAIL, other rcodes, transport errors', () => {
    const chain = P.ptrOutcome({
      ok: true, rcode: 'NOERROR', answers: [
        { name: Q, type: 'CNAME', data: '5.0-25.2.0.192.in-addr.arpa' },
        { name: '5.0-25.2.0.192.in-addr.arpa', type: 'PTR', data: 'Mail.Example.COM.' },
        { name: 'elsewhere.in-addr.arpa', type: 'PTR', data: 'ignored.example.net' }
      ]
    }, Q);
    assert.deepEqual(chain, { state: 'names', names: ['mail.example.com'], rcode: 'NOERROR', error: null, delegated: '5.0-25.2.0.192.in-addr.arpa' });
    assert.equal(P.ptrOutcome({ ok: true, rcode: 'NOERROR', answers: [] }, Q).state, 'no-ptr');
    assert.equal(P.ptrOutcome({ ok: true, rcode: 'NXDOMAIN', answers: [] }, Q).state, 'nxdomain');
    assert.equal(P.ptrOutcome({ ok: true, rcode: 'SERVFAIL', answers: [] }, Q).state, 'servfail');
    assert.deepEqual(P.ptrOutcome({ ok: true, rcode: 'REFUSED', answers: [] }, Q), { state: 'error', names: [], rcode: 'REFUSED', error: 'REFUSED', delegated: null });
    assert.deepEqual(P.ptrOutcome({ ok: false, error: 'timeout' }, Q).error, 'timeout');
    assert.equal(P.ptrOutcome(null, Q).state, 'error');
  });

  test('forward answers: match through a CNAME, other addresses, NODATA, NXDOMAIN, failures; AAAA for IPv6', () => {
    const viaAlias = P.forwardOutcome({
      ok: true, rcode: 'NOERROR', answers: [
        { name: 'mail.example.com', type: 'CNAME', data: 'mx.example.net' },
        { name: 'mx.example.net', type: 'A', data: '192.0.2.5' },
        { name: 'unrelated.example.org', type: 'A', data: '198.51.100.1' }
      ]
    }, 'mail.example.com', '192.0.2.5');
    assert.deepEqual(viaAlias, { state: 'match', addresses: ['192.0.2.5'], rcode: 'NOERROR', error: null });
    assert.equal(P.forwardOutcome({ ok: true, rcode: 'NOERROR', answers: [{ name: 'x.example.com', type: 'A', data: '192.0.2.9' }] }, 'x.example.com', '192.0.2.5').state, 'other');
    assert.equal(P.forwardOutcome({ ok: true, rcode: 'NOERROR', answers: [] }, 'x.example.com', '192.0.2.5').state, 'nodata');
    assert.equal(P.forwardOutcome({ ok: true, rcode: 'NXDOMAIN', answers: [] }, 'x.example.com', '192.0.2.5').state, 'nxdomain');
    assert.equal(P.forwardOutcome({ ok: true, rcode: 'SERVFAIL', answers: [] }, 'x.example.com', '192.0.2.5').state, 'error');
    assert.equal(P.forwardOutcome({ ok: false, error: 'down' }, 'x.example.com', '192.0.2.5').error, 'down');
    const v6 = P.forwardOutcome({ ok: true, rcode: 'NOERROR', answers: [{ name: 'v6.example.com', type: 'AAAA', data: '2001:DB8::5' }, { name: 'v6.example.com', type: 'A', data: '192.0.2.5' }] }, 'v6.example.com', '2001:db8::5');
    assert.deepEqual(v6.addresses, ['2001:db8::5']);
    assert.equal(v6.state, 'match');
  });

  test('verdicts: any match confirms; all definite misses mismatch; a failed forward lookup is an error', () => {
    const names = { state: 'names', names: ['a.example.com', 'b.example.com'], rcode: 'NOERROR', error: null, delegated: null };
    const v = (forward) => P.fcrdnsVerdict({ ip: '192.0.2.5', ptr: names, forward });
    assert.deepEqual(v([{ name: 'a.example.com', state: 'other', addresses: ['192.0.2.9'] }, { name: 'b.example.com', state: 'match', addresses: ['192.0.2.5'] }]).confirmed, ['b.example.com']);
    assert.equal(v([{ name: 'a.example.com', state: 'nxdomain', addresses: [] }, { name: 'b.example.com', state: 'nodata', addresses: [] }]).status, 'mismatch');
    const err = v([{ name: 'a.example.com', state: 'other', addresses: ['192.0.2.9'] }, { name: 'b.example.com', state: 'error', addresses: [], error: 'SERVFAIL' }]);
    assert.deepEqual([err.status, err.stage, err.error], ['error', 'forward', 'SERVFAIL']);
    const base = P.fcrdnsVerdict({ ip: '192.0.2.5', ptr: { state: 'servfail', names: [], rcode: 'SERVFAIL', error: null, delegated: null } });
    assert.deepEqual([base.status, base.stage, base.query, base.version], ['servfail', 'ptr', '5.2.0.192.in-addr.arpa', 4]);
    assert.equal(P.fcrdnsVerdict({ ip: '192.0.2.5', ptr: null }).status, 'error');
  });
});

describe('checkFcrdns (DohClient over a mock DoH)', () => {
  const zone = {
    ...ptr('192.0.2.1', 'mail.example.com'),
    ...a('mail.example.com', '192.0.2.1'),
    ...ptr('192.0.2.2', 'www.example.com'),
    ...a('www.example.com', '198.51.100.20'),
    ...ptr('192.0.2.3', 'gone.example.com'),
    ...ptr('192.0.2.4', 'first.example.com', 'second.example.com', 'third.example.com'),
    ...a('first.example.com', '198.51.100.1'),
    ...a('second.example.com', '192.0.2.4'),
    ...a('third.example.com', '192.0.2.4'),
    ...rcode(rev('192.0.2.5'), 'PTR', 'SERVFAIL'),
    [`${rev('192.0.2.6')}|PTR`]: { rcode: 'NOERROR', answers: [] },
    [`5.8.b.d.0.1.0.0.2.ip6.arpa|PTR`]: { answers: [] },
    ...ptr('192.0.2.8', 'flaky.example.com')
  };
  const v6rev = '5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa';
  zone[`${v6rev}|PTR`] = { answers: [{ name: v6rev, type: 'PTR', data: 'v6.example.com' }] };
  zone['v6.example.com|AAAA'] = { answers: [{ name: 'v6.example.com', type: 'AAAA', data: '2001:db8::5' }] };

  test('confirmed, mismatch (other address, NXDOMAIN), SERVFAIL, NODATA, NXDOMAIN, IPv6, forward failure', async () => {
    const { dns, f } = client(zone, { fail: ['flaky.example.com'] });
    const r = {};
    for (const ip of ['192.0.2.1', '192.0.2.2', '192.0.2.3', '192.0.2.5', '192.0.2.6', '192.0.2.7', '2001:db8::5', '192.0.2.8']) r[ip] = await P.checkFcrdns(ip, { dns });
    assert.deepEqual([r['192.0.2.1'].status, r['192.0.2.1'].confirmed, r['192.0.2.1'].resolver], ['confirmed', ['mail.example.com'], 'cloudflare']);
    assert.deepEqual([r['192.0.2.2'].status, r['192.0.2.2'].forward[0].state, r['192.0.2.2'].forward[0].addresses], ['mismatch', 'other', ['198.51.100.20']]);
    assert.deepEqual([r['192.0.2.3'].status, r['192.0.2.3'].forward[0].state], ['mismatch', 'nxdomain']);
    assert.deepEqual([r['192.0.2.5'].status, r['192.0.2.5'].rcode, r['192.0.2.5'].stage], ['servfail', 'SERVFAIL', 'ptr']);
    assert.equal(r['192.0.2.6'].status, 'no-ptr');
    assert.equal(r['192.0.2.7'].status, 'nxdomain');
    assert.deepEqual([r['2001:db8::5'].status, r['2001:db8::5'].version, r['2001:db8::5'].query], ['confirmed', 6, v6rev]);
    assert.deepEqual([r['192.0.2.8'].status, r['192.0.2.8'].stage], ['error', 'forward']);
    assert.ok(f.calls.some((c) => c.name === 'v6.example.com' && c.type === 'AAAA'), 'AAAA for an IPv6 address');
    assert.ok(!f.calls.some((c) => c.name === 'v6.example.com' && c.type === 'A'), 'never A for an IPv6 address');
  });

  test('stops at the first name that confirms; the rest are counted unchecked; maxNames caps the lookups', async () => {
    const { dns, f } = client(zone);
    const r = await P.checkFcrdns('192.0.2.4', { dns });
    assert.equal(r.status, 'confirmed');
    assert.deepEqual(r.confirmed, ['second.example.com']);
    assert.deepEqual(r.forward.map((x) => x.name), ['first.example.com', 'second.example.com']);
    assert.equal(r.unchecked, 1);
    assert.ok(!f.calls.some((c) => c.name === 'third.example.com'));
    const capped = await P.checkFcrdns('192.0.2.4', { dns, maxNames: 1 });
    assert.deepEqual([capped.status, capped.unchecked], ['mismatch', 2]);
  });

  test('input validation and abort', async () => {
    const { dns } = client(zone);
    await assert.rejects(P.checkFcrdns('192.0.2.1', {}), TypeError);
    await assert.rejects(P.checkFcrdns('not-an-ip', { dns }), TypeError);
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(P.checkFcrdns('192.0.2.1', { dns, signal: ctl.signal }), { name: 'AbortError' });
    assert.equal((await P.checkFcrdns('::ffff:192.0.2.1', { dns })).ip, '192.0.2.1', 'mapped IPv4 is looked up as IPv4');
  });

  test('a client-like object without a DohClient (lib/health adapter shape) works too', async () => {
    const calls = [];
    const fake = {
      async query(name, type) {
        calls.push(`${name}|${type}`);
        if (type === 'PTR') return { ok: true, rcode: 'NOERROR', answers: [{ name, type: 'PTR', data: 'mx.example.com.' }] };
        return { ok: true, rcode: 'NOERROR', answers: [{ name, type: 'A', data: '192.0.2.25' }] };
      }
    };
    const r = await P.checkFcrdns('192.0.2.25', { dns: fake });
    assert.equal(r.status, 'confirmed');
    assert.deepEqual(calls, ['25.2.0.192.in-addr.arpa|PTR', 'mx.example.com|A']);
  });
});

/* ------------------------------------------------------------------------ */
/* Templates and classification                                             */
/* ------------------------------------------------------------------------ */

describe('ptrTemplate', () => {
  const cases = [
    ['192-0-2-7.dyn.isp.example.net', '192.0.2.7', 'embedded', '{ip}.dyn.isp.example.net'],
    ['ip-192-0-2-7.isp.example.net', '192.0.2.7', 'embedded', 'ip-{ip}.isp.example.net'],
    ['7.2.0.192.bc.googleusercontent.com', '192.0.2.7', 'embedded', '{ip}.bc.googleusercontent.com'],
    ['192.0.2.7.static.isp.example.net', '192.0.2.7', 'embedded', '{ip}.static.isp.example.net'],
    ['host192000002007.isp.example.net', '192.0.2.7', 'embedded', 'host{ip}.isp.example.net'],
    ['c0000207.isp.example.net', '192.0.2.7', 'embedded', '{ip}.isp.example.net'],
    ['3221225991.isp.example.net', '192.0.2.7', 'embedded', '{ip}.isp.example.net'],
    ['ec2-198-51-100-7.compute-1.amazonaws.com', '198.51.100.7', 'embedded', 'ec2-{ip}.compute-1.amazonaws.com'],
    ['cpe-51-100-7.res.isp.example.net', '198.51.100.7', 'embedded', 'cpe-{ip}.res.isp.example.net'],
    ['host-2001-db8--5.isp.example.net', '2001:db8::5', 'embedded', 'host-{ip}.isp.example.net'],
    ['20010db8000000000000000000000005.v6.isp.example.net', '2001:db8::5', 'embedded', '{ip}.v6.isp.example.net'],
    ['dsl-pool-4471.isp.example.net', '192.0.2.7', 'generic', 'dsl-pool-{n}.isp.example.net'],
    ['c-2-7.cust.isp.example.net', '192.0.2.7', 'generic', 'c-{n}-{n}.cust.isp.example.net'],
    ['dynamic12.example.net', '192.0.2.7', 'generic', 'dynamic{n}.example.net']
  ];
  for (const [name, ip, kind, template] of cases) {
    test(`${name} → ${kind} ${template}`, () => {
      const t = P.ptrTemplate(name, ip);
      assert.ok(t, 'templated');
      assert.equal(t.kind, kind);
      assert.equal(t.template, template);
      assert.equal(t.key, `${kind}:${template}`);
    });
  }

  test('names a person chose are not templates', () => {
    for (const [name, ip] of [
      ['mail.example.com', '192.0.2.7'], ['web10.example.com', '192.0.2.10'], ['web02.example.com', '192.0.2.2'],
      ['node-12.cluster.example.net', '192.0.2.12'], ['static.example.com', '192.0.2.7'], ['pool.example.com', '192.0.2.7'],
      ['srv-192-0-2-70.example.net', '192.0.2.7'], ['x1192-0-2-77.example.net', '192.0.2.7'], ['', '192.0.2.7'], ['mail.example.com', 'nope']
    ]) assert.equal(P.ptrTemplate(name, ip), null, name);
    assert.equal(P.isTemplatedPtr('192-0-2-7.isp.example.net', '192.0.2.7'), true);
    assert.equal(P.isTemplatedPtr('mail.example.com', '192.0.2.7'), false);
  });

  test('the same template for every address of a block', () => {
    const keys = new Set(['192.0.2.7', '192.0.2.8', '192.0.2.200'].map((ip) => P.ptrTemplate(`${ip.replace(/\./g, '-')}.dyn.isp.example.net`, ip).key));
    assert.equal(keys.size, 1);
  });
});

describe('sweepClassification', () => {
  test('a provider range, a PTR under a provider domain, a plain address', () => {
    const cf = P.sweepClassification('104.16.1.1', []);
    assert.equal(cf.kind, 'cloudflare');
    const cloudfront = P.sweepClassification('192.0.2.15', ['server-192-0-2-15.fra50.r.cloudfront.net']);
    assert.deepEqual([cloudfront.kind, cloudfront.provider.id, cloudfront.via, cloudfront.reasonKey], ['cdn', 'cloudfront', 'ptr', 'ptr.op.cdn']);
    const plain = P.sweepClassification('192.0.2.1', ['mail.example.com']);
    assert.deepEqual([plain.kind, plain.provider], ['direct', null]);
  });
});

/* ------------------------------------------------------------------------ */
/* The sweep, rows, summary, exports and hand-offs                          */
/* ------------------------------------------------------------------------ */

function sweepZone() {
  const z = {
    ...ptr('192.0.2.1', 'mail.example.com'), ...a('mail.example.com', '192.0.2.1'),
    ...ptr('192.0.2.2', 'www.example.com'), ...a('www.example.com', '198.51.100.20'),
    ...ptr('192.0.2.3', 'host.example.net'), ...a('host.example.net', '192.0.2.3'),
    ...rcode(rev('192.0.2.5'), 'PTR', 'SERVFAIL'),
    [`${rev('192.0.2.6')}|PTR`]: { rcode: 'NOERROR', answers: [] },
    ...ptr('192.0.2.15', 'server-192-0-2-15.fra50.r.cloudfront.net'), ...a('server-192-0-2-15.fra50.r.cloudfront.net', '192.0.2.15')
  };
  for (let i = 7; i <= 14; i += 1) {
    const name = `192-0-2-${i}.dyn.isp.example.net`;
    Object.assign(z, ptr(`192.0.2.${i}`, name), a(name, `192.0.2.${i}`));
  }
  return z;
}

describe('runPtrSweep', () => {
  test('a /28: every address once, results in address order, streamed, templates and operators', async () => {
    const { dns, f } = client(sweepZone());
    const target = P.parseSweepTarget('192.0.2.0/28');
    const streamed = [];
    const { results, aborted } = await P.runPtrSweep(target.addresses, { dns, concurrency: 4, onResult: (r) => streamed.push(r.ip) });
    assert.equal(aborted, false);
    assert.equal(results.length, 16);
    assert.deepEqual(results.map((r) => r.ip), target.addresses);
    assert.deepEqual(new Set(streamed).size, 16);
    const by = Object.fromEntries(results.map((r) => [r.ip, r]));
    assert.equal(by['192.0.2.1'].status, 'confirmed');
    assert.equal(by['192.0.2.2'].status, 'mismatch');
    assert.equal(by['192.0.2.4'].status, 'nxdomain');
    assert.equal(by['192.0.2.5'].status, 'servfail');
    assert.equal(by['192.0.2.6'].status, 'no-ptr');
    assert.equal(by['192.0.2.9'].template.template, '{ip}.dyn.isp.example.net');
    assert.equal(by['192.0.2.15'].classification.provider.id, 'cloudfront');
    assert.equal(by['192.0.2.1'].template, null);
    assert.equal(f.calls.filter((c) => c.type === 'PTR').length, 16, 'one PTR query per address (no retries configured)');
  });

  test('concurrency: at most `concurrency` addresses in flight', async () => {
    const { dns, f } = client(sweepZone(), { delayMs: 5, concurrency: 32 });
    await P.runPtrSweep(P.parseSweepTarget('192.0.2.0/28').addresses, { dns, concurrency: 3 });
    assert.ok(f.maxInFlight <= 3, `max in flight ${f.maxInFlight}`);
  });

  test('cancel: resolves with aborted and the finished results only', async () => {
    const { dns } = client(sweepZone(), { delayMs: 30 });
    const ctl = new AbortController();
    const done = [];
    const p = P.runPtrSweep(P.parseSweepTarget('192.0.2.0/28').addresses, {
      dns, concurrency: 2, signal: ctl.signal, onResult: (r) => { done.push(r.ip); if (done.length === 3) ctl.abort(); }
    });
    const { results, aborted } = await p;
    assert.equal(aborted, true);
    assert.ok(results.length >= 3 && results.length < 16, `results ${results.length}`);
    assert.deepEqual(results.map((r) => r.ip), [...results.map((r) => r.ip)].sort((x, y) => Number(x.split('.')[3]) - Number(y.split('.')[3])));
  });

  test('an observer that throws never stops the sweep; a client is required', async () => {
    const { dns } = client(sweepZone());
    const { results } = await P.runPtrSweep(['192.0.2.1', '192.0.2.2'], { dns, onResult: () => { throw new Error('observer'); } });
    assert.equal(results.length, 2);
    await assert.rejects(P.runPtrSweep(['192.0.2.1'], {}), TypeError);
  });
});

describe('rows, summary, exports and hand-offs', async () => {
  const { dns } = client(sweepZone());
  const { results } = await P.runPtrSweep(P.parseSweepTarget('192.0.2.0/28').addresses, { dns });
  const index = buildIpIndex(parseInventory('web01 192.0.2.1\ndb01 192.0.2.3').servers);

  test('sweepRows: focus first, then named hosts, one pattern row, no name, failures', () => {
    const rows = P.sweepRows(results, { focus: 'example.com', index });
    assert.deepEqual(rows.map((r) => r.key), [
      '192.0.2.1', '192.0.2.2', // focus (example.com)
      '192.0.2.3', // named (example.net)
      'pattern:embedded:{ip}.dyn.isp.example.net', '192.0.2.15', // templated: the pattern, a lone template
      '192.0.2.0', '192.0.2.4', '192.0.2.6', // no reverse DNS
      '192.0.2.5' // SERVFAIL
    ]);
    const pattern = rows[3];
    assert.equal(pattern.type, 'pattern');
    assert.equal(pattern.members.length, 8);
    assert.equal(pattern.counts.confirmed, 8);
    assert.equal(pattern.template, '{ip}.dyn.isp.example.net');
    assert.equal(rows[0].focus, true);
    assert.deepEqual(rows[0].servers, [{ serverId: 'web01', name: 'web01', ip: '192.0.2.1' }]);
    assert.deepEqual(rows[2].servers.map((s) => s.name), ['db01']);
  });

  test('sweepRows: no focus → focus names rank as named; collapse off → one row per address; minPattern', () => {
    const plain = P.sweepRows(results);
    assert.deepEqual(plain.slice(0, 3).map((r) => r.key), ['192.0.2.1', '192.0.2.2', '192.0.2.3']);
    assert.ok(plain.every((r) => r.focus === false));
    assert.equal(P.sweepRows(results, { collapse: false }).length, 16);
    assert.ok(!P.sweepRows(results, { minPattern: 9 }).some((r) => r.type === 'pattern'));
  });

  test('a templated name under the focus domain is never collapsed', () => {
    const rows = P.sweepRows(results, { focus: 'isp.example.net' });
    assert.ok(!rows.some((r) => r.type === 'pattern'));
    assert.equal(rows.filter((r) => r.focus).length, 8);
  });

  test('sweepRowMatches: every filter', () => {
    const rows = P.sweepRows(results, { focus: 'example.com' });
    const keys = (f) => rows.filter((r) => P.sweepRowMatches(r, f)).map((r) => r.key);
    assert.equal(keys('all').length, rows.length);
    assert.deepEqual(keys('focus'), ['192.0.2.1', '192.0.2.2']);
    assert.deepEqual(keys('mismatch'), ['192.0.2.2']);
    assert.deepEqual(keys('none'), ['192.0.2.0', '192.0.2.4', '192.0.2.6']);
    assert.deepEqual(keys('failed'), ['192.0.2.5']);
    assert.ok(keys('confirmed').includes('pattern:embedded:{ip}.dyn.isp.example.net'));
    assert.ok(!keys('ptr').includes('192.0.2.4'));
    for (const f of P.SWEEP_FILTERS) assert.ok(Array.isArray(keys(f)));
  });

  test('sweepRowResults: a pattern row gives only the members that pass the filter and the search on their own', async () => {
    // one of the eight templated names does not resolve back
    const zone = { ...sweepZone(), ...a('192-0-2-10.dyn.isp.example.net', '198.51.100.10') };
    const { results: swept } = await P.runPtrSweep(P.parseSweepTarget('192.0.2.0/28').addresses, { dns: client(zone).dns });
    const rows = P.sweepRows(swept, { focus: 'example.com' });
    const pattern = rows.find((r) => r.type === 'pattern');
    assert.deepEqual([pattern.members.length, pattern.counts.confirmed, pattern.counts.mismatch], [8, 7, 1]);
    const exported = (filter, match = null) => rows.filter((r) => P.sweepRowMatches(r, filter))
      .flatMap((r) => P.sweepRowResults(r, filter, { match })).map((r) => r.ip);
    assert.deepEqual(exported('mismatch'), ['192.0.2.2', '192.0.2.10'], 'not the 7 confirmed members');
    assert.equal(exported('confirmed').length, 10);
    assert.ok(!exported('confirmed').includes('192.0.2.10'));
    assert.equal(exported('ptr').length, 12);
    assert.equal(exported('all').length, 16);
    assert.deepEqual(exported('focus'), ['192.0.2.1', '192.0.2.2']);
    assert.deepEqual(exported('none'), ['192.0.2.0', '192.0.2.4', '192.0.2.6']);
    // the search narrows a pattern to the members it names
    assert.deepEqual(exported('all', (r) => r.ip === '192.0.2.10'), ['192.0.2.10']);
    assert.deepEqual(P.sweepRowResults(pattern, 'all', { match: (r) => r.ip === '192.0.2.9' }).map((r) => r.ip), ['192.0.2.9']);
    assert.deepEqual(P.sweepRowResults(pattern, 'focus'), []);
    const single = rows.find((r) => r.key === '192.0.2.2');
    assert.deepEqual([P.sweepRowResults(single, 'mismatch').length, P.sweepRowResults(single, 'confirmed').length, P.sweepRowResults(single, 'mismatch', { match: () => false }).length], [1, 0, 0]);
    // the JSON export of the 'mismatch' filter: exactly those two addresses, the whole sweep's summary
    const j = P.sweepExportJson(swept, { exported: swept.filter((r) => ['192.0.2.2', '192.0.2.10'].includes(r.ip)), filter: { show: 'mismatch', search: '' } });
    assert.deepEqual([j.exported, j.results.map((r) => r.status), j.summary.byStatus.mismatch, j.summary.done], [2, ['mismatch', 'mismatch'], 2, 16]);
  });

  test('sweepResultMatches: one address against every filter', () => {
    const byIp = Object.fromEntries(results.map((r) => [r.ip, r]));
    const pass = (ip, focus = null) => P.SWEEP_FILTERS.filter((f) => P.sweepResultMatches(byIp[ip], f, { focus }));
    assert.deepEqual(pass('192.0.2.1', 'example.com'), ['all', 'ptr', 'focus', 'confirmed']);
    assert.deepEqual(pass('192.0.2.1'), ['all', 'ptr', 'confirmed'], 'no focus domain');
    assert.deepEqual(pass('192.0.2.2', 'example.com'), ['all', 'ptr', 'focus', 'mismatch']);
    assert.deepEqual(pass('192.0.2.0'), ['all', 'none']);
    assert.deepEqual(pass('192.0.2.6'), ['all', 'none']);
    assert.deepEqual(pass('192.0.2.5'), ['all', 'failed']);
  });

  test('sweepSummary', () => {
    const s = P.sweepSummary(results, { focus: 'example.com' });
    assert.deepEqual(s.byStatus, { confirmed: 11, mismatch: 1, 'no-ptr': 1, nxdomain: 2, servfail: 1, error: 0 });
    assert.deepEqual([s.done, s.withPtr, s.noReverse, s.failed, s.templated, s.patterns, s.focus, s.names, s.v6], [16, 12, 3, 1, 9, 1, 2, 12, 0]);
  });

  test('sweepExportRows / SWEEP_CSV_COLUMNS', () => {
    const rows = P.sweepExportRows(results, { focus: 'example.com', index });
    assert.equal(rows.length, 16);
    assert.deepEqual(Object.keys(rows[0]), [...P.SWEEP_CSV_COLUMNS]);
    const mail = rows.find((r) => r.ip === '192.0.2.1');
    assert.deepEqual(mail, {
      ip: '192.0.2.1', status: 'confirmed', ptr: 'mail.example.com', confirmed: 'mail.example.com',
      forward: 'mail.example.com=match:192.0.2.1', template: '', operator: '', servers: 'web01', focus: 'yes', error: ''
    });
    assert.equal(rows.find((r) => r.ip === '192.0.2.15').operator, 'Amazon CloudFront');
    assert.equal(rows.find((r) => r.ip === '192.0.2.2').forward, 'www.example.com=other:198.51.100.20');
  });

  test('sweepExportJson', () => {
    const j = P.sweepExportJson(results, {
      target: '192.0.2.0/28', focus: 'example.com', startedAt: new Date('2026-09-27T10:00:00Z'), finishedAt: new Date('2026-09-27T10:00:03Z'), index, version: '1.0.0'
    });
    assert.equal(j.schema, 'domainscope.ptr-sweep/1');
    assert.equal(j.results.length, 16);
    assert.equal(j.planned, 16);
    assert.equal(j.finishedAt, '2026-09-27T10:00:03.000Z');
    assert.deepEqual(j.results[1].servers, ['web01']);
    assert.deepEqual(j.results[15].operator, { id: 'cloudfront', name: 'Amazon CloudFront', via: 'ptr' });
    assert.deepEqual(j.results[9].template, { template: '{ip}.dyn.isp.example.net', kind: 'embedded' });
    assert.equal(JSON.parse(JSON.stringify(j)).summary.byStatus.confirmed, 11);
    assert.deepEqual([j.filter, j.exported], [null, 16]);
  });

  test('sweepExportJson of a filtered table: the summary still counts the whole sweep, the filter is recorded', () => {
    const shown = results.filter((r) => r.names.length); // the view's default filter, 'ptr'
    const j = P.sweepExportJson(results, { exported: shown, filter: { show: 'ptr', search: '' }, target: '192.0.2.0/28', planned: 16 });
    assert.deepEqual([j.planned, j.aborted, j.exported, j.results.length], [16, false, 12, 12]);
    assert.deepEqual(j.filter, { show: 'ptr', search: '' });
    assert.deepEqual([j.summary.done, j.summary.byStatus.nxdomain, j.summary.noReverse, j.summary.failed], [16, 2, 3, 1], 'not the 12 exported');
    assert.ok(j.results.every((r) => r.names.length));
    const searched = P.sweepExportJson(results, { exported: results.slice(0, 1), filter: { show: 'all', search: ' mail ' } });
    assert.deepEqual([searched.filter, searched.exported, searched.summary.done], [{ show: 'all', search: 'mail' }, 1, 16]);
    assert.equal(P.sweepExportJson(results, { filter: { show: 'all', search: '' } }).filter, null, 'nothing filtered out');
    assert.equal(P.sweepExportJson(results, { filter: { show: 'bogus' } }).filter, null);
  });

  test('sweepNames: templates left out unless asked for; focus only; confirmed only (sortHostnames order)', () => {
    assert.deepEqual(P.sweepNames(results), ['mail.example.com', 'www.example.com', 'host.example.net']);
    assert.equal(P.sweepNames(results, { templated: true }).length, 12);
    assert.deepEqual(P.sweepNames(results, { focus: 'example.com', onlyFocus: true }), ['mail.example.com', 'www.example.com']);
    assert.deepEqual(P.sweepNames(results, { confirmedOnly: true }), ['mail.example.com', 'host.example.net']);
  });

  test('inventoryAdditions: confirmed, not templated, neither an address nor a name the list already has', () => {
    const adds = P.inventoryAdditions(results, { index: buildIpIndex(parseInventory('web01 192.0.2.1').servers) });
    assert.deepEqual(adds, [{ name: 'host.example.net', ips: ['192.0.2.3'] }]);
    assert.deepEqual(P.inventoryAdditions(results).map((x) => x.name), ['mail.example.com', 'host.example.net']);
    assert.deepEqual(P.inventoryAdditions(results, { servers: parseInventory('web01 192.0.2.1').servers }), adds, 'the index is built from the servers');
    // a name the list has (on another address, or as an alias) is not added a second time
    assert.deepEqual(P.inventoryAdditions(results, { servers: parseInventory('HOST.example.net 198.51.100.9').servers }).map((x) => x.name), ['mail.example.com']);
    assert.deepEqual(P.inventoryAdditions(results, { servers: parseInventory('198.51.100.9 mail01 mail.example.com').servers }).map((x) => x.name), ['host.example.net']);
  });

  const DAY = new Date('2026-09-27T12:00:00Z');
  const ADDS = [{ name: 'mail.example.com', ips: ['192.0.2.1'] }, { name: 'vpn.example.com', ips: ['192.0.2.6', '2001:db8::6'] }];
  const serversOf = (text) => parseInventory(text).servers.map((s) => [s.name.toLowerCase(), s.ips]);
  /** The draft of `base` must read back as the old servers plus ADDS, and add nothing on a second click. */
  const drafted = (base, extra = {}) => {
    const out = P.inventoryDraft(base, ADDS, { label: '192.0.2.0/28', date: DAY });
    assert.equal(out.reason, null, `${out.format}: ${out.reason}`);
    assert.deepEqual(serversOf(out.text), [...serversOf(base), ...ADDS.map((a) => [a.name, a.ips])], out.text);
    assert.ok(parseInventory(out.text).warnings.length <= parseInventory(base).warnings.length, 'no new warning');
    const again = P.inventoryAdditions([
      { status: 'confirmed', ip: '192.0.2.1', names: ['mail.example.com'], confirmed: ['mail.example.com'] }
    ], { servers: parseInventory(out.text).servers });
    assert.deepEqual(again, [], 'a second click adds nothing');
    assert.deepEqual(out.lines, ['mail.example.com 192.0.2.1', 'vpn.example.com 192.0.2.6 2001:db8::6']);
    for (const [k, v] of Object.entries(extra)) assert.equal(out[k], v, k);
    return out;
  };

  test('inventoryDraft: plain lines, an empty list and a hosts file keep their line format', () => {
    const plain = drafted('web01 192.0.2.10\n\n', { format: 'lines', group: null });
    assert.equal(plain.text, 'web01 192.0.2.10\n\n# reverse DNS sweep of 192.0.2.0/28 (2026-09-27): forward-confirmed hosts\n'
      + 'mail.example.com 192.0.2.1\nvpn.example.com 192.0.2.6 2001:db8::6\n');
    assert.equal(drafted('', { format: 'empty' }).text, '# reverse DNS sweep of 192.0.2.0/28 (2026-09-27): forward-confirmed hosts\n'
      + 'mail.example.com 192.0.2.1\nvpn.example.com 192.0.2.6 2001:db8::6\n');
    const hosts = drafted('192.0.2.10 web01 web01.example.org\n192.0.2.11 web02', { format: 'lines' });
    assert.match(hosts.text, /\n192\.0\.2\.1 mail\.example\.com\n192\.0\.2\.6 vpn\.example\.com\n2001:db8::6 vpn\.example\.com\n$/);
    // the label is one comment line whatever the user typed
    const odd = P.inventoryDraft('', ADDS, { label: '192.0.2.0/28\n[web]\r\nx', date: DAY });
    assert.equal(odd.text.split('\n')[0], '# reverse DNS sweep of 192.0.2.0/28 [web] x (2026-09-27): forward-confirmed hosts');
    assert.equal(P.inventoryDraft('web01 192.0.2.10', []).text, 'web01 192.0.2.10\n');
  });

  test('inventoryDraft: Ansible INI gets its own [reverse_dns] group, never the last group of the file', () => {
    const base = '[web]\nweb01 ansible_host=192.0.2.10\n\n[db]\ndb01 ansible_host=192.0.2.11\n';
    const out = drafted(base, { format: 'ini', group: 'reverse_dns' });
    assert.match(out.text, /\n\[reverse_dns\]\nmail\.example\.com ansible_host=192\.0\.2\.1\nvpn\.example\.com ansible_host=192\.0\.2\.6\nvpn\.example\.com ansible_host=2001:db8::6\n$/);
    const groups = Object.fromEntries(parseInventory(out.text).servers.map((s) => [s.name, s.groups]));
    assert.deepEqual(groups, { web01: ['web'], db01: ['db'], 'mail.example.com': ['reverse_dns'], 'vpn.example.com': ['reverse_dns'] });
    assert.equal(out.newGroup, true);
    // a second addition repeats the header (Ansible merges the sections): the group is not new
    const again = P.inventoryDraft(out.text, [{ name: 'ns1.example.org', ips: ['198.51.100.1'] }], { date: DAY });
    assert.deepEqual([again.reason, again.group, again.newGroup], [null, 'reverse_dns', false]);
    assert.deepEqual(parseInventory(again.text).servers.find((s) => s.name === 'ns1.example.org').groups, ['reverse_dns']);
  });

  test('inventoryDraft: JSON arrays get elements (with the array’s own keys), JSON Lines get lines', () => {
    const pretty = drafted('[\n  {"hostname": "web01", "address": "192.0.2.10"},\n  {"hostname": "web02", "address": "192.0.2.11"}\n]', { format: 'json' });
    assert.equal(pretty.text, '[\n  {"hostname": "web01", "address": "192.0.2.10"},\n  {"hostname": "web02", "address": "192.0.2.11"},\n'
      + '  {"hostname":"mail.example.com","address":"192.0.2.1"},\n  {"hostname":"vpn.example.com","address":["192.0.2.6","2001:db8::6"]}\n]\n');
    assert.deepEqual(JSON.parse(pretty.text).length, 4, 'still one JSON document');
    const inline = drafted('[{"name":"web01","ip":"192.0.2.10"}]', { format: 'json' });
    assert.equal(inline.text, '[{"name":"web01","ip":"192.0.2.10"}, {"name":"mail.example.com","ip":"192.0.2.1"}, {"name":"vpn.example.com","ip":["192.0.2.6","2001:db8::6"]}]\n');
    assert.equal(JSON.parse(drafted('[]').text).length, 2);
    const lines = drafted('{"name":"web01","ip":"192.0.2.10"}\n{"name":"web02","ip":"192.0.2.11"}', { format: 'jsonl' });
    assert.ok(lines.text.split('\n').filter(Boolean).every((l) => JSON.parse(l)), 'every line is JSON');
    // records that hold their addresses as a list get a list, even for one address
    const listed = drafted('[{"name": "web01", "ips": ["192.0.2.10"]}]', { format: 'json' });
    assert.deepEqual(JSON.parse(listed.text).slice(1), [{ name: 'mail.example.com', ips: ['192.0.2.1'] }, { name: 'vpn.example.com', ips: ['192.0.2.6', '2001:db8::6'] }]);
    // JSON Lines keep the first line's keys; one host record alone on a line is JSON Lines too
    const keyed = drafted('{"host": "web01", "address": "192.0.2.10"}\n{"host": "web02", "address": "192.0.2.11"}', { format: 'jsonl' });
    assert.deepEqual(keyed.text.trim().split('\n').slice(2).map((l) => JSON.parse(l)), [
      { host: 'mail.example.com', address: '192.0.2.1' }, { host: 'vpn.example.com', address: ['192.0.2.6', '2001:db8::6'] }
    ]);
    const single = drafted('{"name": "web01", "ip": "192.0.2.10"}', { format: 'json' });
    assert.equal(single.text, '{"name": "web01", "ip": "192.0.2.10"}\n{"name":"mail.example.com","ip":"192.0.2.1"}\n{"name":"vpn.example.com","ip":["192.0.2.6","2001:db8::6"]}\n');
    // an object that is no host record (a map of names) is still left alone
    assert.equal(P.inventoryDraft('{"web01": "192.0.2.10"}', ADDS, { date: DAY }).reason, 'format');
  });

  test('inventoryDraft: CSV rows follow the header’s column order and delimiter', () => {
    const out = drafted('hostname,ip,role\nweb01,192.0.2.10,web\nweb02,192.0.2.11,web', { format: 'csv' });
    assert.match(out.text, /\nweb02,192\.0\.2\.11,web\nmail\.example\.com,192\.0\.2\.1,\nvpn\.example\.com,192\.0\.2\.6 2001:db8::6,\n$/);
    const semi = drafted('IP;Sunucu Adı;Rol\n192.0.2.10;web01;web', { format: 'csv' });
    assert.match(semi.text, /\n192\.0\.2\.1;mail\.example\.com;\n192\.0\.2\.6 2001:db8::6;vpn\.example\.com;\n$/);
    assert.ok(!/#/.test(out.text), 'no comment row in a CSV file');
  });

  test('inventoryDraft: YAML — an Ansible inventory gets a reverse_dns group, a list gets items', () => {
    const ansible = drafted('all:\n  children:\n    web:\n      hosts:\n        web01:\n          ansible_host: 192.0.2.10\n', { format: 'yaml', group: 'reverse_dns' });
    assert.match(ansible.text, /\nreverse_dns:\n {2}hosts:\n {4}mail\.example\.com:\n {6}ansible_host: 192\.0\.2\.1\n {4}vpn\.example\.com:\n {6}ansible_host: 192\.0\.2\.6\n {6}ips: \[192\.0\.2\.6, "2001:db8::6"\]\n$/);
    assert.equal(ansible.newGroup, true);
    const list = drafted('- name: web01\n  ip: 192.0.2.10\n- name: web02\n  ip: 192.0.2.11\n', { format: 'yaml', group: null });
    assert.match(list.text, /\n- name: mail\.example\.com\n {2}ip: 192\.0\.2\.1\n- name: vpn\.example\.com\n {2}ip: \[192\.0\.2\.6, "2001:db8::6"\]\n$/);
    const listed = drafted('- name: web01\n  ips: [192.0.2.10]\n', { format: 'yaml' });
    assert.match(listed.text, /\n- name: mail\.example\.com\n {2}ips: \[192\.0\.2\.1\]\n/);
  });

  test('inventoryDraft: YAML — a second addition goes under the reverse_dns group the first one wrote', () => {
    const NS = [{ name: 'ns1.example.org', ips: ['198.51.100.1'] }];
    const groupsOf = (text) => Object.fromEntries(parseInventory(text).servers.map((s) => [s.name, [s.ips.join(' '), s.groups.join(' ')]]));
    const first = drafted('all:\n  hosts:\n    web01:\n      ansible_host: 198.51.100.10\n', { group: 'reverse_dns', newGroup: true });
    const second = P.inventoryDraft(first.text, NS, { label: '198.51.100.0/28', date: DAY });
    assert.deepEqual([second.reason, second.group, second.newGroup], [null, 'reverse_dns', false]);
    assert.equal(second.text, `${first.text.replace(/\n$/, '')}\n    # reverse DNS sweep of 198.51.100.0/28 (2026-09-27): forward-confirmed hosts\n    ns1.example.org:\n      ansible_host: 198.51.100.1\n`);
    assert.deepEqual(groupsOf(second.text), {
      web01: ['198.51.100.10', ''], 'mail.example.com': ['192.0.2.1', 'reverse_dns'], 'vpn.example.com': ['192.0.2.6 2001:db8::6', 'reverse_dns'],
      'ns1.example.org': ['198.51.100.1', 'reverse_dns']
    });
    // wherever the group is, whatever the indentation; a group with vars only gets a hosts key
    const before = (group) => `${group}\nall:\n    hosts:\n        web01:\n            ansible_host: 198.51.100.10\n`;
    const moved = P.inventoryDraft(before('reverse_dns:\n    hosts:\n        old.example.com:\n            ansible_host: 192.0.2.9\n    vars:\n        ansible_user: ops'), NS, { date: DAY });
    assert.equal(moved.reason, null);
    assert.match(moved.text, /\n {8}old\.example\.com:\n {12}ansible_host: 192\.0\.2\.9\n {8}# reverse DNS sweep \(2026-09-27\): forward-confirmed hosts\n {8}ns1\.example\.org:\n {12}ansible_host: 198\.51\.100\.1\n {4}vars:\n/);
    const vars = P.inventoryDraft(before('reverse_dns:\n    vars:\n        ansible_user: ops'), NS, { date: DAY });
    assert.match(vars.text, /^reverse_dns:\n {4}vars:\n {8}ansible_user: ops\n {4}hosts:\n {8}# reverse DNS sweep/);
    assert.deepEqual(groupsOf(vars.text)['ns1.example.org'], ['198.51.100.1', 'reverse_dns']);
    // a flow value cannot take a host: the next free group name does
    const flow = P.inventoryDraft('all:\n  hosts:\n    web01:\n      ansible_host: 198.51.100.10\nreverse_dns:\n  hosts: {}\nreverse_dns_2:\n  hosts: {}\n', NS, { date: DAY });
    assert.deepEqual([flow.reason, flow.group, flow.newGroup], [null, 'reverse_dns_3', true]);
    assert.deepEqual(groupsOf(flow.text)['ns1.example.org'], ['198.51.100.1', 'reverse_dns_3']);
  });

  test('inventoryDraft: a shape it does not write, or an addition that would not read back, leaves the text alone', () => {
    const untouched = (base, format, reason, adds = ADDS) => {
      const out = P.inventoryDraft(base, adds, { date: DAY });
      assert.deepEqual([out.text, out.format, out.reason, out.group], [null, format, reason, null], base);
      assert.deepEqual(out.lines, adds.map((a) => `${a.name} ${a.ips.join(' ')}`));
    };
    untouched('{"web01": "192.0.2.10", "web02": "192.0.2.11"}', 'json', 'format'); // a map (or Terraform / ansible-inventory output)
    untouched('[["web01", "192.0.2.10"]]', 'json', 'format');
    untouched('servers:\n  web01: 192.0.2.10\n  web02: 192.0.2.11\n', 'yaml', 'format');
    untouched('ip,role\n192.0.2.10,web', 'csv', 'format'); // no name column to put the host name in
    // an address the list has already: a DUPLICATE_IP warning; a name it has: the servers merge
    untouched('web01 192.0.2.10', 'lines', 'check', [{ name: 'mail.example.com', ips: ['192.0.2.10'] }]);
    untouched('mail.example.com 192.0.2.10', 'lines', 'check', [{ name: 'mail.example.com', ips: ['192.0.2.1'] }]);
  });

  test('scanHandoff: the focus domain and its names, else the most frequent registrable domains', () => {
    assert.deepEqual(P.scanHandoff(results, { focus: 'Example.COM' }), { names: ['mail.example.com', 'www.example.com'], domains: ['example.com'], moreDomains: 0 });
    assert.deepEqual(P.scanHandoff(results), { names: ['mail.example.com', 'www.example.com', 'host.example.net'], domains: ['example.com', 'example.net'], moreDomains: 0 });
    assert.deepEqual(P.scanHandoff(results, { maxDomains: 1 }).moreDomains, 1);
    assert.deepEqual(P.scanHandoff(results, { focus: 'example.org' }), { names: [], domains: [], moreDomains: 0 });
  });

  test('isFocusName', () => {
    assert.equal(P.isFocusName('mail.example.com', 'example.com'), true);
    assert.equal(P.isFocusName('example.com', 'EXAMPLE.com.'), true);
    assert.equal(P.isFocusName('badexample.com', 'example.com'), false);
    assert.equal(P.isFocusName('mail.example.com', null), false);
  });
});
