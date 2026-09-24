// Unit tests for assets/js/lib/dnswire.js — no network access.
// Real-world coverage comes from binary DoH responses captured by
// tests/live/capture-dns-fixtures.mjs into tests/fixtures/dns/ (see manifest.json).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import {
  TYPES, RCODES, CLASSES, EDE_CODES, SVC_PARAM_KEYS,
  typeToNumber, typeToName, classToName, rcodeToName,
  encodeQuery, encodeName, encodeMessage, decodeMessage, computeKeyTag,
  DnsWireError, base64UrlEncode, base64UrlDecode, base64Encode, base64Decode, hexEncode, hexDecode
} from '../../assets/js/lib/dnswire.js';

const FIX_DIR = new URL('../fixtures/dns/', import.meta.url);
const MANIFEST = JSON.parse(readFileSync(new URL('manifest.json', FIX_DIR), 'utf8'));
const fixtureBytes = (id) => new Uint8Array(readFileSync(new URL(`${id}.bin`, FIX_DIR)));
const fixture = (id) => decodeMessage(fixtureBytes(id));

const hex = (s) => hexDecode(s.replace(/\s+/g, ''));

/** Deterministic PRNG (mulberry32) for fuzzing. */
function prng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Deep "subset" match: objects → every expected key matches; arrays → every expected item is included. */
function subsetMatch(actual, expected) {
  if (expected === null || typeof expected !== 'object') return Object.is(actual, expected);
  if (Array.isArray(expected)) {
    return Array.isArray(actual) && expected.every((e) => actual.some((a) => subsetMatch(a, e)));
  }
  if (actual === null || typeof actual !== 'object') return false;
  return Object.entries(expected).every(([k, v]) => subsetMatch(actual[k], v));
}

// ---------------------------------------------------------------------------
describe('type / class / rcode helpers', () => {
  test('TYPES contains every contract type with the right number', () => {
    const contract = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28, SRV: 33, NAPTR: 35, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50, TLSA: 52, SVCB: 64, HTTPS: 65, CAA: 257, ANY: 255 };
    for (const [k, v] of Object.entries(contract)) assert.equal(TYPES[k], v, k);
  });

  test('RCODES has the standard names', () => {
    assert.equal(RCODES[0], 'NOERROR');
    assert.equal(RCODES[2], 'SERVFAIL');
    assert.equal(RCODES[3], 'NXDOMAIN');
    assert.equal(RCODES[5], 'REFUSED');
    assert.equal(RCODES[16], 'BADVERS');
    assert.equal(rcodeToName(12), 'RCODE12');
  });

  test('typeToNumber accepts mnemonics, TYPEnnn, numeric strings and numbers', () => {
    assert.equal(typeToNumber('AAAA'), 28);
    assert.equal(typeToNumber('aaaa'), 28);
    assert.equal(typeToNumber(' https '), 65);
    assert.equal(typeToNumber('TYPE65'), 65);
    assert.equal(typeToNumber('type65280'), 65280);
    assert.equal(typeToNumber('28'), 28);
    assert.equal(typeToNumber(257), 257);
    assert.equal(typeToNumber('FOO'), null);
    assert.equal(typeToNumber('TYPE70000'), null);
    assert.equal(typeToNumber(-1), null);
    assert.equal(typeToNumber(1.5), null);
    assert.equal(typeToNumber(null), null);
  });

  test('typeToName maps numbers and normalizes names; unknown → TYPEnnn', () => {
    assert.equal(typeToName(1), 'A');
    assert.equal(typeToName(65), 'HTTPS');
    assert.equal(typeToName(123), 'TYPE123');
    assert.equal(typeToName('mx'), 'MX');
    assert.equal(typeToName(41), 'OPT');
  });

  test('classToName', () => {
    assert.equal(classToName(1), 'IN');
    assert.equal(classToName(3), 'CH');
    assert.equal(classToName(42), 'CLASS42');
    assert.equal(CLASSES.IN, 1);
  });
});

// ---------------------------------------------------------------------------
describe('base64 / hex helpers', () => {
  const enc = new TextEncoder();
  test('RFC 4648 test vectors', () => {
    const vectors = [['', ''], ['f', 'Zg=='], ['fo', 'Zm8='], ['foo', 'Zm9v'], ['foob', 'Zm9vYg=='], ['fooba', 'Zm9vYmE='], ['foobar', 'Zm9vYmFy']];
    for (const [plain, b64] of vectors) {
      assert.equal(base64Encode(enc.encode(plain)), b64);
      assert.equal(base64UrlEncode(enc.encode(plain)), b64.replace(/=+$/, ''));
      assert.deepEqual(base64Decode(b64), enc.encode(plain));
      assert.deepEqual(base64UrlDecode(b64.replace(/=+$/, '')), enc.encode(plain));
    }
  });

  test('base64url uses - and _ and round-trips binary data', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    const s = base64UrlEncode(bytes);
    assert.ok(!/[+/=]/.test(s));
    assert.ok(s.includes('-') && s.includes('_'));
    assert.deepEqual(base64UrlDecode(s), bytes);
    assert.deepEqual(base64Decode(base64Encode(bytes)), bytes);
  });

  test('base64Decode rejects garbage', () => {
    assert.throws(() => base64Decode('ab$d'), DnsWireError);
    assert.throws(() => base64Decode('abcde'), DnsWireError);
  });

  test('hex helpers', () => {
    assert.equal(hexEncode(new Uint8Array([0, 15, 255])), '000fff');
    assert.deepEqual(hexDecode('00:0F ff'), new Uint8Array([0, 15, 255]));
    assert.throws(() => hexDecode('abc'), DnsWireError);
    assert.throws(() => hexDecode('zz'), DnsWireError);
  });
});

// ---------------------------------------------------------------------------
describe('encodeName', () => {
  test('encodes labels, accepts trailing dot and root', () => {
    assert.deepEqual(encodeName('example.com'), hex('07 6578616d706c65 03 636f6d 00'));
    assert.deepEqual(encodeName('example.com.'), encodeName('example.com'));
    assert.deepEqual(encodeName('.'), new Uint8Array([0]));
    assert.deepEqual(encodeName(''), new Uint8Array([0]));
    assert.deepEqual(encodeName('_dmarc.xn--mnchen-3ya.de'), hex('06 5f646d617263 0e 786e2d2d6d6e6368656e2d337961 02 6465 00'));
  });

  test('presentation escapes: \\. inside a label and \\DDD', () => {
    assert.deepEqual(encodeName('a\\.b.c'), hex('03 612e62 01 63 00'));
    assert.deepEqual(encodeName('\\065x'), hex('02 4178 00'));
    assert.deepEqual(encodeName('a\\\\b'), hex('03 615c62 00'));
  });

  test('length limits: label 63 ok / 64 rejected; name 255 octets ok / 256 rejected', () => {
    const l63 = 'a'.repeat(63);
    assert.equal(encodeName(`${l63}.com`).length, 63 + 1 + 3 + 1 + 1);
    assert.throws(() => encodeName(`${'a'.repeat(64)}.com`), /63/);
    // 3 × (63+1) + (61+1) + 1 = 255 octets on the wire
    const max = [l63, l63, l63, 'b'.repeat(61)].join('.');
    assert.equal(encodeName(max).length, 255);
    assert.throws(() => encodeName(`${max}b`), /255/);
  });

  test('rejects empty labels, whitespace, control and non-ASCII characters, bad escapes', () => {
    for (const bad of ['a..b', '.a', 'a b.com', 'a\tb', 'münchen.de', 'exämple.com', 'abc\\', 'a\\256b', '\u0000x']) {
      assert.throws(() => encodeName(bad), DnsWireError, bad);
    }
    assert.throws(() => encodeName(42), DnsWireError);
  });
});

// ---------------------------------------------------------------------------
describe('encodeQuery', () => {
  test('exact bytes: example.com A with defaults (id 0, RD+AD, EDNS 1232)', () => {
    const q = encodeQuery('example.com', 'A');
    assert.deepEqual(q, hex(`
      0000 0120 0001 0000 0000 0001
      07 6578616d706c65 03 636f6d 00 0001 0001
      00 0029 04d0 00 00 0000 0000`));
  });

  test('matches the RFC 8484 §4.1.1 example once the OPT record is removed', () => {
    const q = encodeQuery('www.example.com', 'A', { ad: false });
    const noOpt = q.slice(0, q.length - 11);
    noOpt[11] = 0; // ARCOUNT
    assert.equal(base64UrlEncode(noOpt), 'AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB');
  });

  test('header flags, id, DO bit, UDP size, class', () => {
    const q = decodeMessage(encodeQuery('Example.COM', 'MX', { id: 0xbeef, rd: false, cd: true, ad: false, dnssecOk: true, udpSize: 4096, qclass: 3 }));
    assert.equal(q.id, 0xbeef);
    assert.deepEqual(
      { qr: q.flags.qr, rd: q.flags.rd, cd: q.flags.cd, ad: q.flags.ad, opcode: q.flags.opcode },
      { qr: false, rd: false, cd: true, ad: false, opcode: 0 });
    assert.equal(q.edns.dnssecOk, true);
    assert.equal(q.edns.udpSize, 4096);
    assert.equal(q.edns.version, 0);
    assert.deepEqual(q.questions, [{ name: 'example.com', type: 'MX', typeNum: 15, class: 3, className: 'CH' }]);
    assert.equal(q.additionals.length, 0, 'OPT is exposed as edns, not as an additional RR');
  });

  test('always adds exactly one OPT record', () => {
    const bytes = encodeQuery('a.b', 'TXT');
    assert.equal((bytes[10] << 8) | bytes[11], 1);
    assert.ok(decodeMessage(bytes).edns);
  });

  test('ECS IPv4 /24 (RFC 7871 wire layout)', () => {
    const q = encodeQuery('x.com', 'A', { ecs: '198.51.100.77/24' });
    assert.deepEqual(q.slice(-11), hex('0008 0007 0001 18 00 c63364'));
    const m = decodeMessage(q);
    assert.deepEqual(m.edns.ecs, { family: 1, sourcePrefix: 24, scopePrefix: 0, address: '198.51.100.0', subnet: '198.51.100.0/24' });
  });

  test('ECS truncates to ceil(prefix/8) bytes and zeroes host bits', () => {
    const opt = (ecs) => {
      const m = decodeMessage(encodeQuery('x.com', 'A', { ecs }));
      return { ecs: m.edns.ecs, data: hexEncode(m.edns.options.find((o) => o.code === 8).data) };
    };
    assert.equal(opt('10.105.255.77/22').data, '00011600' + '0a69fc');
    assert.equal(opt('10.105.255.77/22').ecs.address, '10.105.252.0');
    assert.equal(opt('10.1.2.3/32').data, '00012000' + '0a010203');
    assert.equal(opt('10.1.2.3/0').data, '00010000');
    assert.equal(opt('10.1.2.3/1').data, '00010100' + '00');
    assert.equal(opt('203.0.113.9').data, '00011800' + 'cb0071', 'IPv4 default /24');
    assert.equal(opt({ address: '198.51.100.7', sourcePrefix: 20 }).data, '00011400' + 'c63360');
    assert.equal(opt({ address: '198.51.100.7', prefix: 16 }).data, '00011000' + 'c633');
    assert.equal(opt({ subnet: '198.51.100.0/24' }).data, '00011800' + 'c63364');
  });

  test('ECS IPv6 including default /56 and odd prefixes', () => {
    const data = (ecs) => {
      const m = decodeMessage(encodeQuery('x.com', 'AAAA', { ecs }));
      return { hex: hexEncode(m.edns.options.find((o) => o.code === 8).data), ecs: m.edns.ecs };
    };
    const a = data('2001:db8:abcd:12ff::1/56');
    assert.equal(a.hex, '00023800' + '20010db8abcd12');
    assert.deepEqual(a.ecs, { family: 2, sourcePrefix: 56, scopePrefix: 0, address: '2001:db8:abcd:1200::', subnet: '2001:db8:abcd:1200::/56' });
    assert.equal(data('2a02:ff0::/29').hex, '00021d00' + '2a020ff0');
    assert.equal(data('2a02:ff7f::/29').hex, '00021d00' + '2a02ff78');
    assert.equal(data('2001:db8::').hex, '00023800' + '20010db8000000', 'IPv6 default /56');
    assert.equal(data('::ffff:1.2.3.4/128').hex, '00028000' + '00000000000000000000ffff01020304');
  });

  test('ECS input validation', () => {
    for (const bad of ['1.2.3/24', '1.2.3.4/33', '1.2.3.4/-1', '1.2.3.4/x', '256.1.1.1/24', '01.2.3.4/24', '2001:db8::/129', 'nope', { address: 'x' }, 42]) {
      assert.throws(() => encodeQuery('x.com', 'A', { ecs: bad }), DnsWireError, String(bad));
    }
  });

  test('NSID request option', () => {
    const m = decodeMessage(encodeQuery('x.com', 'A', { nsid: true }));
    assert.deepEqual(m.edns.options.map((o) => [o.code, o.data.length]), [[3, 0]]);
  });

  test('invalid type / name / id', () => {
    assert.throws(() => encodeQuery('x.com', 'BOGUS'), DnsWireError);
    assert.throws(() => encodeQuery('x..com', 'A'), DnsWireError);
    for (const badName of [42, null, undefined, {}, ['a']]) assert.throws(() => encodeQuery(badName, 'A'), DnsWireError, String(badName));
    assert.throws(() => encodeMessage({ answers: [{ name: 7, type: 'A', data: '1.2.3.4' }] }), DnsWireError);
    assert.throws(() => encodeQuery('x.com', 'A', { id: 70000 }), DnsWireError);
    assert.throws(() => encodeQuery('x.com', 'A', { udpSize: 70000 }), DnsWireError);
  });

  test('numeric and TYPEnnn query types', () => {
    assert.equal(decodeMessage(encodeQuery('x.com', 65)).questions[0].type, 'HTTPS');
    assert.equal(decodeMessage(encodeQuery('x.com', 'TYPE65280')).questions[0].type, 'TYPE65280');
  });
});

// ---------------------------------------------------------------------------
describe('decodeMessage — real captured DoH responses', () => {
  test('manifest lists fixtures that exist', () => {
    assert.ok(MANIFEST.fixtures.length >= 40);
    for (const f of MANIFEST.fixtures) assert.ok(fixtureBytes(f.id).length === f.size, f.id);
  });

  for (const f of MANIFEST.fixtures) {
    test(`fixture ${f.id} (${f.resolver} ${f.query.type} ${f.query.name})`, () => {
      const m = fixture(f.id);
      const e = f.expect;
      if (e.rcode) assert.equal(m.rcodeName, e.rcode);
      assert.equal(m.rcodeName, rcodeToName(m.rcode));
      assert.equal(m.id, 0);
      if (e.flags) assert.ok(subsetMatch(m.flags, e.flags), `flags ${JSON.stringify(m.flags)}`);
      assert.equal(m.truncated, false);
      assert.equal(m.questions.length, 1);
      assert.ok(subsetMatch(m.questions[0], e.question), JSON.stringify(m.questions[0]));
      if (e.edns) {
        assert.ok(m.edns, 'edns present');
        const { nsid, ...rest } = e.edns;
        assert.ok(subsetMatch(m.edns, rest), JSON.stringify(m.edns));
        if (nsid) assert.ok(typeof m.edns.nsid === 'string' && m.edns.nsid.length > 0, 'nsid');
      }
      for (const [section, spec] of Object.entries(e.sections || {})) {
        const rrs = m[section];
        if (spec.types) assert.deepEqual([...new Set(rrs.map((r) => r.type))].sort(), [...spec.types].sort(), `${section} types`);
        if (spec.min !== undefined) assert.ok(rrs.length >= spec.min, `${section} count ${rrs.length} >= ${spec.min}`);
        if (spec.max !== undefined) assert.ok(rrs.length <= spec.max, `${section} count ${rrs.length} <= ${spec.max}`);
        if (spec.names) assert.deepEqual([...new Set(rrs.map((r) => r.name))].sort(), [...spec.names].sort(), `${section} names`);
      }
      for (const r of e.records || []) {
        const candidates = m[r.section].filter((rr) => rr.type === r.type && (!r.name || rr.name === r.name));
        const ok = candidates.some((rr) =>
          (r.data === undefined || subsetMatch(rr.data, r.data)) &&
          (r.text === undefined || rr.text === r.text) &&
          (r.textRe === undefined || new RegExp(r.textRe).test(rr.text)));
        assert.ok(ok, `no ${r.section} ${r.type} matching ${JSON.stringify(r)} in ${JSON.stringify(candidates.map((c) => c.text))}`);
      }
      if (e.ecs) {
        const { scopePrefixMin, ...rest } = e.ecs;
        assert.ok(m.edns?.ecs, 'ECS echoed');
        assert.ok(subsetMatch(m.edns.ecs, rest), JSON.stringify(m.edns.ecs));
        if (scopePrefixMin !== undefined) assert.ok(m.edns.ecs.scopePrefix >= scopePrefixMin, `scope ${m.edns.ecs.scopePrefix}`);
      }
      for (const x of e.ede || []) assert.ok(m.edns?.ede.some((d) => d.code === x.code), `EDE ${x.code} in ${JSON.stringify(m.edns?.ede)}`);
      if (e.chain) {
        let cur = f.query.name;
        const answers = m.answers;
        let i = 0;
        while (i < answers.length && answers[i].type === 'CNAME') {
          assert.equal(answers[i].name, cur, 'CNAME chain order');
          cur = answers[i].data;
          i++;
        }
        assert.ok(i >= 1, 'at least one CNAME');
        for (; i < answers.length; i++) assert.equal(answers[i].name, cur, 'final records owned by chain target');
      }
      if (e.txtMultiString) {
        const spf = m.answers.find((rr) => rr.type === 'TXT' && rr.data[0].startsWith('v=spf1'));
        assert.ok(spf.data.length > 1, 'SPF split across character-strings');
        assert.ok(spf.data.join('').length > 255);
      }
      // generic invariants for every record
      for (const rr of [...m.answers, ...m.authorities, ...m.additionals]) {
        assert.equal(typeof rr.text, 'string');
        assert.equal(rr.error, undefined, `${rr.type} decoded without error`);
        assert.equal(rr.class, 1);
        assert.equal(rr.className, 'IN');
        assert.ok(rr.ttl >= 0 && rr.ttl <= 0x7fffffff);
        assert.equal(rr.typeNum, typeToNumber(rr.type));
        assert.ok(rr.rdata instanceof Uint8Array);
        assert.ok(!rr.name.endsWith('.') || rr.name === '.', 'owner has no trailing dot');
        assert.equal(rr.name, rr.name.toLowerCase());
      }
    });
  }

  test('Google JSON API oracle agrees with our presentation text', () => {
    const norm = (s) => s.replace(/"/g, '');
    const withOracle = MANIFEST.fixtures.filter((f) => f.oracle);
    assert.ok(withOracle.length >= 10);
    for (const f of withOracle) {
      const m = fixture(f.id);
      const ours = m.answers.filter((rr) => rr.type !== 'RRSIG').map((rr) => {
        if (rr.type === 'TXT') return rr.data.join('');
        if (rr.type === 'DS' || rr.type === 'TLSA') return rr.text.toLowerCase();
        return norm(rr.text);
      }).sort();
      const theirs = f.oracle.answers.map((a) => {
        if (a.type === TYPES.DS || a.type === TYPES.TLSA) return a.data.toLowerCase();
        return a.type === TYPES.TXT ? a.data : norm(a.data);
      }).sort();
      assert.deepEqual(ours, theirs, f.id);
    }
  });

  test('Cloudflare and Google fixtures decode to the same stable RRsets', () => {
    const stable = ['mx-google.com', 'mx-null-example.com', 'txt-spf-long', 'ns-google.com', 'caa-google.com', 'ds-cloudflare.com-do', 'dnskey-cloudflare.com-do', 'https-cloudflare.com', 'srv-jabber', 'ptr-8.8.8.8', 'tlsa-ietf', 'naptr-sip2sip'];
    for (const s of stable) {
      const texts = (id) => fixture(id).answers.filter((rr) => rr.type !== 'RRSIG').map((rr) => `${rr.name} ${rr.type} ${rr.text}`).sort();
      assert.deepEqual(texts(`cf-${s}`), texts(`gg-${s}`), s);
    }
  });

  test('SOA details and mailbox conversion', () => {
    const soa = fixture('cf-nxdomain').authorities[0];
    assert.equal(soa.type, 'SOA');
    assert.equal(soa.data.mname, 'ns1.google.com');
    assert.equal(soa.data.rname, 'dns-admin.google.com');
    assert.equal(soa.data.email, 'dns-admin@google.com');
    for (const k of ['serial', 'refresh', 'retry', 'expire', 'minimum']) assert.equal(typeof soa.data[k], 'number');
    assert.equal(soa.text, `ns1.google.com. dns-admin.google.com. ${soa.data.serial} ${soa.data.refresh} ${soa.data.retry} ${soa.data.expire} ${soa.data.minimum}`);
  });

  test('HTTPS SvcParams from a real Cloudflare record', () => {
    const rr = fixture('gg-https-cloudflare.com').answers[0];
    assert.equal(rr.data.priority, 1);
    assert.equal(rr.data.target, '.');
    assert.deepEqual(rr.data.params.alpn, ['h3', 'h2']);
    assert.ok(rr.data.params.ipv4hint.every((ip) => /^\d+\.\d+\.\d+\.\d+$/.test(ip)));
    assert.ok(rr.data.params.ipv6hint.every((ip) => ip.startsWith('2606:4700:')));
  });

  test('SVCB DDR records: port, hints, dohpath', () => {
    const cf = fixture('cf-svcb-ddr').answers.find((rr) => rr.data.priority === 1);
    assert.equal(cf.data.params.port, 443);
    assert.deepEqual(cf.data.params.ipv4hint, ['1.1.1.1', '1.0.0.1']);
    assert.deepEqual(cf.data.params.ipv6hint, ['2606:4700:4700::1111', '2606:4700:4700::1001']);
    assert.equal(cf.data.params.dohpath, '/dns-query{?dns}');
    const gg = fixture('gg-svcb-ddr');
    assert.equal(gg.edns, null, 'Google DDR answer carries no OPT');
    assert.deepEqual(gg.additionals.map((rr) => rr.text).sort(), ['2001:4860:4860::8844', '2001:4860:4860::8888', '8.8.4.4', '8.8.8.8']);
  });

  test('NSEC (Cloudflare compact denial) and NSEC3 (.com) type bitmaps', () => {
    const nsec = fixture('cf-nodata-cloudflare.com-nsec-do').authorities.find((rr) => rr.type === 'NSEC');
    assert.ok(nsec.data.nextDomain.startsWith('\\000.'), nsec.data.nextDomain);
    assert.ok(nsec.data.types.includes('NSEC') && nsec.data.types.includes('RRSIG'));
    assert.ok(nsec.text.startsWith(`${nsec.data.nextDomain}. `));
    const nsec3 = fixture('gg-nxdomain-com-nsec3-do').authorities.filter((rr) => rr.type === 'NSEC3');
    assert.ok(nsec3.length >= 2);
    for (const rr of nsec3) {
      assert.equal(rr.data.hashAlgorithm, 1);
      assert.equal(rr.data.salt, '');
      assert.equal(rr.data.optOut, true);
      assert.match(rr.data.nextHashedOwner, /^[0-9a-v]{32}$/);
      assert.match(rr.name, /^[0-9a-v]{32}\.com$/);
      assert.ok(rr.data.types.includes('NS'));
    }
  });

  test('Extended DNS Errors carry code, name and text', () => {
    const cf = fixture('cf-servfail-dnssec-bogus').edns.ede[0];
    assert.equal(cf.code, 9);
    assert.equal(cf.name, 'DNSKEY Missing');
    assert.match(cf.text, /dnssec-failed\.org/);
    assert.equal(fixture('cff-blocked-ede').edns.ede[0].name, EDE_CODES[16]);
    assert.equal(fixture('q9-blocked-ede').edns.ede[0].name, 'Filtered');
    assert.equal(fixture('cf-any-notimp').edns.ede[0].code, 21);
  });

  test('ECS scope from Google for an IPv4 and an IPv6 source', () => {
    const v4 = fixture('gg-ecs-v4-amazon').edns.ecs;
    assert.equal(v4.subnet, '85.105.0.0/24');
    assert.ok(v4.scopePrefix > 0);
    const v6 = fixture('gg-ecs-v6').edns.ecs;
    assert.equal(v6.family, 2);
    assert.equal(v6.subnet, '2a01:cb00::/32');
  });
});

// ---------------------------------------------------------------------------
describe('DNSSEC data from real fixtures', () => {
  const concat = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };
  const u16 = (v) => new Uint8Array([v >>> 8, v & 255]);
  const u32 = (v) => new Uint8Array([v >>> 24, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]);
  const cmp = (a, b) => {
    for (let i = 0; i < Math.min(a.length, b.length); i++) if (a[i] !== b[i]) return a[i] - b[i];
    return a.length - b.length;
  };

  /** Canonical RDATA (RFC 4034 §6.2): re-encode types whose RDATA may contain compressed names. */
  function canonicalRdata(rr) {
    if (rr.type === 'SOA') {
      const d = rr.data;
      return concat(encodeName(d.mname), encodeName(d.rname), u32(d.serial), u32(d.refresh), u32(d.retry), u32(d.expire), u32(d.minimum));
    }
    return rr.rdata;
  }

  /** RFC 4034 §3.1.8.1 signed data for an RRSIG over `rrset`. */
  function signedData(sig, rrset) {
    const d = sig.data;
    const owner = (name) => {
      const labels = name === '.' ? [] : name.split('.');
      return encodeName(labels.length > d.labels ? `*.${labels.slice(-d.labels).join('.')}` : name);
    };
    const rrs = rrset.map((rr) => ({ rdata: canonicalRdata(rr), owner: owner(rr.name), typeNum: rr.typeNum }))
      .sort((a, b) => cmp(a.rdata, b.rdata))
      .map((rr) => concat(rr.owner, u16(rr.typeNum), u16(1), u32(d.originalTtl), u16(rr.rdata.length), rr.rdata));
    return concat(sig.rdata.subarray(0, 18), encodeName(d.signerName), ...rrs);
  }

  function p256Key(dnskey) {
    const raw = base64Decode(dnskey.data.publicKey);
    assert.equal(raw.length, 64);
    return createPublicKey({ key: { kty: 'EC', crv: 'P-256', x: base64UrlEncode(raw.subarray(0, 32)), y: base64UrlEncode(raw.subarray(32)) }, format: 'jwk' });
  }

  function verifySig(sig, rrset, dnskey) {
    assert.equal(sig.data.algorithm, 13);
    assert.equal(sig.data.keyTag, dnskey.data.keyTag);
    return cryptoVerify('sha256', signedData(sig, rrset), { key: p256Key(dnskey), dsaEncoding: 'ieee-p1363' }, base64Decode(sig.data.signature));
  }

  for (const p of ['cf', 'gg']) {
    test(`${p}: DNSKEY key tags, DS digest match, RRSIG(DNSKEY) verifies with the KSK`, () => {
      const keys = fixture(`${p}-dnskey-cloudflare.com-do`);
      const dnskeys = keys.answers.filter((rr) => rr.type === 'DNSKEY');
      const ksk = dnskeys.find((k) => k.data.sep);
      const zsk = dnskeys.find((k) => !k.data.sep);
      assert.equal(ksk.data.keyTag, 2371);
      assert.equal(zsk.data.keyTag, 34505);
      assert.equal(computeKeyTag(ksk.rdata), 2371);
      const ds = fixture(`${p}-ds-cloudflare.com-do`).answers.find((rr) => rr.type === 'DS');
      assert.equal(ds.data.keyTag, ksk.data.keyTag);
      const digest = createHash('sha256').update(concat(encodeName('cloudflare.com'), ksk.rdata)).digest('hex');
      assert.equal(ds.data.digest, digest, 'DS = SHA-256(owner | DNSKEY RDATA)');
      const sig = keys.answers.find((rr) => rr.type === 'RRSIG');
      assert.equal(sig.data.typeCovered, 'DNSKEY');
      assert.ok(sig.data.expiration instanceof Date && sig.data.inception instanceof Date);
      assert.ok(sig.data.expiration > sig.data.inception);
      assert.ok(verifySig(sig, dnskeys, ksk), 'RRSIG over the DNSKEY RRset verifies');
    });
  }

  test('RRSIGs made by the ZSK verify: HINFO (ANY), SOA and NSEC (compact denial)', () => {
    const zsk = fixture('cf-dnskey-cloudflare.com-do').answers.find((rr) => rr.type === 'DNSKEY' && !rr.data.sep);
    const check = (msg, section, type) => {
      const rrset = msg[section].filter((rr) => rr.type === type);
      const sig = msg[section].find((rr) => rr.type === 'RRSIG' && rr.data.typeCovered === type);
      assert.ok(rrset.length && sig, type);
      assert.ok(verifySig(sig, rrset, zsk), `RRSIG(${type}) verifies`);
    };
    check(fixture('gg-any-cloudflare.com-do'), 'answers', 'HINFO');
    const nodata = fixture('cf-nodata-cloudflare.com-nsec-do');
    check(nodata, 'authorities', 'SOA');
    check(nodata, 'authorities', 'NSEC');
  });

  test('a tampered record fails verification (sanity check of the harness)', () => {
    const keys = fixture('gg-dnskey-cloudflare.com-do');
    const dnskeys = keys.answers.filter((rr) => rr.type === 'DNSKEY');
    const sig = keys.answers.find((rr) => rr.type === 'RRSIG');
    const ksk = dnskeys.find((k) => k.data.sep);
    const tampered = { ...sig, data: { ...sig.data, originalTtl: sig.data.originalTtl + 1 } };
    assert.equal(verifySig(tampered, dnskeys, ksk), false);
  });

  test('RRSIG presentation text uses YYYYMMDDHHmmSS timestamps', () => {
    const sig = fixture('cf-ds-cloudflare.com-do').answers.find((rr) => rr.type === 'RRSIG');
    assert.match(sig.text, /^DS 13 2 \d+ \d{14} \d{14} \d+ com\. [A-Za-z0-9+/]+=*$/);
    const exp = sig.text.split(' ')[4];
    assert.equal(exp, sig.data.expiration.toISOString().replace(/[-:T]/g, '').slice(0, 14));
  });
});

// ---------------------------------------------------------------------------
describe('computeKeyTag', () => {
  test('RFC 4034 §5.4 example: key tag 60485 and its SHA-1 DS digest', () => {
    const publicKey = 'AQOeiiR0GOMYkDshWoSKz9XzfwJr1AYtsmx3TGkJaNXVbfi/2pHm822aJ5iI9BMzNXxeYCmZDRD99WYwYqUSdjMmmAphXdvxegXd/M5+X7OrzKBaMbCVdFLUUh6DhweJBjEVv5f2wwjM9XzcnOf+EPbtG9DMBmADjFDc2w/rljwvFw==';
    const m = decodeMessage(encodeMessage({
      flags: { qr: true },
      answers: [{ name: 'dskey.example.com', type: 'DNSKEY', ttl: 86400, data: { flags: 256, protocol: 3, algorithm: 5, publicKey } }]
    }));
    const rr = m.answers[0];
    assert.equal(rr.data.keyTag, 60485);
    assert.equal(rr.data.publicKey, publicKey);
    assert.equal(rr.data.zoneKey, true);
    assert.equal(rr.data.sep, false);
    assert.equal(rr.text, `256 3 5 ${publicKey}`);
    const sha1 = createHash('sha1').update(Buffer.concat([encodeName('dskey.example.com'), rr.rdata])).digest('hex');
    assert.equal(sha1, '2bb183af5f22588179a53b0a98631fad1a292118');
  });

  test('algorithm 1 (RSA/MD5) uses the modulus bytes', () => {
    const rdata = new Uint8Array([0x01, 0x00, 3, 1, 1, 3, 0xaa, 0xbb, 0xcc, 0xde, 0xad, 0x01]);
    assert.equal(computeKeyTag(rdata), 0xdead);
  });

  test('odd-length RDATA and ArrayBuffer input', () => {
    const rdata = new Uint8Array([1, 1, 3, 8, 0xff]);
    // 0x0101 + 0x0308 + 0xff00 = 0x1_0309 → fold carry → 0x030a
    assert.equal(computeKeyTag(rdata.buffer), 0x030a);
  });
});

// ---------------------------------------------------------------------------
describe('encodeMessage ↔ decodeMessage round trips (every supported RR type)', () => {
  const pub = base64Encode(new Uint8Array(64).map((_, i) => i * 3));
  const cases = [
    ['A', '192.0.2.1', '192.0.2.1'],
    ['AAAA', '2001:0db8:0000:0000:0000:ff00:0042:8329', '2001:db8::ff00:42:8329'],
    ['AAAA', '2001:db8:0:0:1:0:0:1', '2001:db8::1:0:0:1'],
    ['AAAA', '2001:0:0:1:0:0:0:1', '2001:0:0:1::1'],
    ['AAAA', '2001:db8:0:1:1:1:1:1', '2001:db8:0:1:1:1:1:1'],
    ['AAAA', '::', '::'],
    ['AAAA', '::1', '::1'],
    ['AAAA', '::ffff:192.0.2.128', '::ffff:192.0.2.128'],
    ['AAAA', 'fe80::1:2', 'fe80::1:2'],
    ['NS', 'Ns1.Example.COM', 'ns1.example.com.', 'ns1.example.com'],
    ['CNAME', 'target.example.net', 'target.example.net.'],
    ['PTR', 'dns.google', 'dns.google.'],
    ['DNAME', 'new.example', 'new.example.'],
    ['MX', { preference: 10, exchange: 'mx.example.com' }, '10 mx.example.com.'],
    ['MX', { preference: 0, exchange: '.' }, '0 .'],
    ['TXT', ['v=spf1 -all'], '"v=spf1 -all"'],
    ['TXT', ['a', 'b c', ''], '"a" "b c" ""'],
    ['TXT', ['say "hi" \\ bye'], '"say \\"hi\\" \\\\ bye"'],
    ['TXT', ['Türkçe ğüşiöç'], '"Türkçe ğüşiöç"'],
    ['TXT', ['tab\there\n'], '"tab\\009here\\010"'],
    ['SPF', ['v=spf1 ~all'], '"v=spf1 ~all"'],
    ['HINFO', { cpu: 'RFC8482', os: '' }, '"RFC8482" ""'],
    ['SOA', { mname: 'ns.example.com', rname: 'host\\.master.example.com', serial: 2024010101, refresh: 7200, retry: 3600, expire: 1209600, minimum: 300 },
      'ns.example.com. host\\.master.example.com. 2024010101 7200 3600 1209600 300',
      { mname: 'ns.example.com', rname: 'host\\.master.example.com', serial: 2024010101, email: 'host.master@example.com' }],
    ['SOA', { mname: 'a.example', rname: 'hostmaster@example.org', serial: 4294967295 },
      'a.example. hostmaster.example.org. 4294967295 0 0 0 0', { rname: 'hostmaster.example.org', email: 'hostmaster@example.org', serial: 4294967295 }],
    ['SRV', { priority: 10, weight: 60, port: 5060, target: 'sip.example.com' }, '10 60 5060 sip.example.com.'],
    ['SRV', { priority: 0, weight: 0, port: 0, target: '.' }, '0 0 0 .'],
    ['NAPTR', { order: 100, preference: 10, flags: 'u', services: 'E2U+sip', regexp: '!^.*$!sip:info@example.com!', replacement: '.' },
      '100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .'],
    ['CAA', { flags: 0, tag: 'issue', value: 'letsencrypt.org' }, '0 issue "letsencrypt.org"', { critical: false }],
    ['CAA', { flags: 128, tag: 'iodef', value: 'mailto:security@example.com' }, '128 iodef "mailto:security@example.com"', { critical: true }],
    ['CAA', { flags: 0, tag: 'issuewild', value: ';' }, '0 issuewild ";"'],
    ['DS', { keyTag: 2371, algorithm: 13, digestType: 2, digest: 'ABCDEF0123' }, '2371 13 2 ABCDEF0123', { digest: 'abcdef0123' }],
    ['CDS', { keyTag: 1, algorithm: 8, digestType: 4, digest: '00ff' }, '1 8 4 00FF'],
    ['DNSKEY', { flags: 257, protocol: 3, algorithm: 13, publicKey: pub }, `257 3 13 ${pub}`, { sep: true, zoneKey: true, revoked: false }],
    ['CDNSKEY', { flags: 385, protocol: 3, algorithm: 15, publicKey: pub }, `385 3 15 ${pub}`, { revoked: true }],
    ['TLSA', { usage: 3, selector: 1, matchingType: 1, data: 'deadbeef' }, '3 1 1 DEADBEEF'],
    ['SMIMEA', { usage: 3, selector: 0, matchingType: 0, data: '00' }, '3 0 0 00'],
    ['SSHFP', { algorithm: 4, fpType: 2, fingerprint: 'AABB' }, '4 2 AABB', { fingerprint: 'aabb' }],
    ['URI', { priority: 10, weight: 1, target: 'https://example.com/' }, '10 1 "https://example.com/"'],
    ['NSEC', { nextDomain: 'b.example.com', types: ['A', 'MX', 'RRSIG', 'NSEC', 'TYPE1234', 'CAA'] },
      'b.example.com. A MX RRSIG NSEC CAA TYPE1234'],
    ['RRSIG', {
      typeCovered: 'A', algorithm: 13, labels: 2, originalTtl: 300,
      expiration: new Date('2026-10-01T12:00:00Z'), inception: new Date('2026-09-01T00:00:05Z'),
      keyTag: 34505, signerName: 'example.com', signature: 'AQID'
    }, 'A 13 2 300 20261001120000 20260901000005 34505 example.com. AQID'],
    ['SVCB', { priority: 0, target: 'svc.example.net', params: {} }, '0 svc.example.net.'],
    ['HTTPS', {
      priority: 1, target: '.',
      params: {
        mandatory: ['alpn', 'port'], alpn: ['h3', 'h2', 'weird,one\\'], 'no-default-alpn': true, port: 8443,
        ipv4hint: ['192.0.2.1', '192.0.2.2'], ech: 'AEX+DQBB', ipv6hint: ['2001:db8::1'],
        dohpath: '/q{?dns}', ohttp: true, 'tls-supported-groups': [29, 23], key65000: 'c0ffee'
      }
    }, '1 . mandatory=alpn,port alpn="h3,h2,weird\\\\,one\\\\\\\\" no-default-alpn port=8443 ipv4hint=192.0.2.1,192.0.2.2 ech=AEX+DQBB ipv6hint=2001:db8::1 dohpath="/q{?dns}" ohttp tls-supported-groups=29,23 key65000="\\192\\255\\238"']
  ];

  for (const [type, data, text, expectData] of cases) {
    test(`${type}: ${text}`, () => {
      const bytes = encodeMessage({
        id: 7, flags: { qr: true, rd: true, ra: true },
        questions: [{ name: 'q.example', type }],
        answers: [{ name: 'Owner.Example', type, ttl: 3600, data }]
      });
      const m = decodeMessage(bytes);
      assert.equal(m.answers.length, 1);
      const rr = m.answers[0];
      assert.equal(rr.error, undefined, rr.error);
      assert.equal(rr.name, 'owner.example');
      assert.equal(rr.type, type);
      assert.equal(rr.ttl, 3600);
      assert.equal(rr.text, text);
      if (expectData !== undefined) {
        assert.ok(subsetMatch(rr.data, expectData), `${JSON.stringify(rr.data)} ⊇ ${JSON.stringify(expectData)}`);
      } else if (typeof data === 'object' && !Array.isArray(data)) {
        assert.ok(subsetMatch(rr.data, data), JSON.stringify(rr.data));
      }
      // decode → encode → decode is stable (the decoder's data shape is valid encoder input).
      const again = decodeMessage(encodeMessage({ answers: [{ name: rr.name, type, ttl: 1, data: rr.data }] })).answers[0];
      assert.deepEqual(again.data, rr.data, 're-encoded data');
      assert.equal(again.text, rr.text, 're-encoded text');
    });
  }

  test('AAAA text is identical to netinfo.normalizeIP (IP strings are compared across modules)', async (t) => {
    let netinfo;
    try {
      netinfo = await import('../../assets/js/lib/netinfo.js');
    } catch {
      t.skip('netinfo.js not available');
      return;
    }
    const rnd = prng(7);
    const samples = ['::', '::1', '::ffff:1.2.3.4', '2001:db8::', '2001:db8:0:0:1:0:0:1', 'fe80::', '64:ff9b::1.2.3.4', '1::', '0:1::'];
    for (let i = 0; i < 2000; i++) {
      samples.push(Array.from({ length: 8 }, () => (rnd() < 0.45 ? '0' : Math.floor(rnd() * 65536).toString(16))).join(':'));
    }
    for (const s of samples) {
      const ours = decodeMessage(encodeMessage({ answers: [{ name: 'x', type: 'AAAA', data: s }] })).answers[0].data;
      assert.equal(ours, netinfo.normalizeIP(s), s);
    }
  });

  test('HTTPS params decode to the documented data shape', () => {
    const rr = decodeMessage(encodeMessage({
      answers: [{
        name: 'x.example', type: 'HTTPS', data: {
          priority: 1, target: 'pool.example',
          params: { alpn: ['h2'], 'no-default-alpn': true, port: 443, ipv4hint: ['1.2.3.4'], ech: 'AAEC', ipv6hint: ['::1'], mandatory: ['ipv4hint'], key9999: '' }
        }
      }]
    })).answers[0];
    assert.deepEqual(rr.data, {
      priority: 1, target: 'pool.example',
      params: { mandatory: ['ipv4hint'], alpn: ['h2'], 'no-default-alpn': true, port: 443, ipv4hint: ['1.2.3.4'], ech: 'AAEC', ipv6hint: ['::1'], key9999: '' }
    });
    assert.equal(rr.text, '1 pool.example. mandatory=ipv4hint alpn="h2" no-default-alpn port=443 ipv4hint=1.2.3.4 ech=AAEC ipv6hint=::1 key9999');
  });

  test('unknown types use RFC 3597 generic encoding', () => {
    const m = decodeMessage(encodeMessage({
      answers: [
        { name: 'x.example', type: 'TYPE65280', data: '0a000001' },
        { name: 'x.example', type: 65281, rdata: new Uint8Array(0) },
        { name: 'x.example', type: 'LOC', rdata: hex('00 12 16 13 89 17 2d d0 70 be 15 f0 00 98 8d 20') }
      ]
    }));
    assert.deepEqual(m.answers.map((rr) => [rr.type, rr.data, rr.text]), [
      ['TYPE65280', '0a000001', '\\# 4 0A000001'],
      ['TYPE65281', '', '\\# 0'],
      ['LOC', '0012161389172dd070be15f000988d20', '\\# 16 0012161389172DD070BE15F000988D20']
    ]);
  });

  test('TXT: invalid UTF-8 falls back to Latin-1 in data and \\DDD in text', () => {
    const m = decodeMessage(encodeMessage({ answers: [{ name: 'x', type: 'TXT', rdata: hex('04 41ff fe42 03 c3a7 21') }] }));
    const rr = m.answers[0];
    assert.deepEqual(rr.data, ['AÿþB', 'ç!']);
    assert.equal(rr.text, '"A\\255\\254B" "ç!"');
  });

  test('TXT/CAA text escapes bidi, zero-width and C1 control characters (untrusted data)', () => {
    const m = decodeMessage(encodeMessage({
      answers: [
        { name: 'x', type: 'TXT', data: ['safe‮evil​\u0085﻿!'] },
        { name: 'x', type: 'CAA', data: { flags: 0, tag: 'issue', value: 'ca⁦.example' } }
      ]
    }));
    assert.equal(m.answers[0].text, '"safe\\226\\128\\174evil\\226\\128\\139\\194\\133\\239\\187\\191!"');
    assert.equal(m.answers[0].data[0], 'safe‮evil​\u0085﻿!', 'data keeps the raw string');
    assert.equal(m.answers[1].text, '0 issue "ca\\226\\129\\166.example"');
  });

  test('a malformed EDNS option keeps the answer and reports edns.error', () => {
    const good = encodeMessage({ flags: { qr: true }, answers: [{ name: 'x', type: 'A', data: '1.2.3.4' }], edns: { nsid: 'ab' } });
    const bad = good.slice();
    bad[bad.length - 3] = 9; // NSID option length 2 → 9 (runs past the OPT RDATA)
    const m = decodeMessage(bad);
    assert.equal(m.answers[0].data, '1.2.3.4');
    assert.match(m.edns.error, /runs past/);
    assert.equal(m.edns.nsid, null);
    const short = encodeMessage({ additionals: [{ name: '.', type: 'OPT', class: 512, ttl: 0, rdata: hex('0003') }] });
    assert.match(decodeMessage(short).edns.error, /truncated/);
    assert.equal(decodeMessage(good).edns.error, undefined);
  });

  test('names: escaping of special bytes and lowercasing on decode', () => {
    const m = decodeMessage(encodeMessage({
      questions: [{ name: 'A\\.B.Ex\\032ample.', type: 'A' }],
      answers: [{ name: 'WWW.EXAMPLE.COM', type: 'CNAME', data: 'we\\"ird\\;x.example' }, { name: '.', type: 'NS', data: 'a.root-servers.net' }]
    }));
    assert.equal(m.questions[0].name, 'a\\.b.ex\\032ample');
    assert.equal(m.answers[0].name, 'www.example.com');
    assert.equal(m.answers[0].data, 'we\\"ird\\;x.example');
    assert.equal(m.answers[1].name, '.');
    // decoded escaped names re-encode to the same wire bytes
    assert.deepEqual(encodeName(m.questions[0].name), encodeName('a\\.b.ex\\032ample'));
  });

  test('rcode by name, extended rcode via EDNS, flags', () => {
    let m = decodeMessage(encodeMessage({ rcode: 'NXDOMAIN', flags: { qr: true, aa: true, ra: true, ad: true, cd: true, tc: false, opcode: 0 } }));
    assert.equal(m.rcode, 3);
    assert.equal(m.rcodeName, 'NXDOMAIN');
    assert.deepEqual(m.flags, { qr: true, opcode: 0, aa: true, tc: false, rd: false, ra: true, z: false, ad: true, cd: true });
    m = decodeMessage(encodeMessage({ rcode: 16 }));
    assert.equal(m.rcode, 16);
    assert.equal(m.rcodeName, 'BADVERS');
    assert.equal(m.edns.extendedRcode, 1);
    m = decodeMessage(encodeMessage({ rcode: 23, edns: { udpSize: 512 } }));
    assert.equal(m.rcodeName, 'BADCOOKIE');
    m = decodeMessage(encodeMessage({ flags: { opcode: 5, z: true } }));
    assert.equal(m.flags.opcode, 5);
    assert.equal(m.flags.z, true);
    assert.throws(() => encodeMessage({ rcode: 'WHAT' }), DnsWireError);
  });

  test('EDNS options: ECS echo with scope, EDE with/without text, NSID, unknown options', () => {
    const m = decodeMessage(encodeMessage({
      edns: {
        udpSize: 1400, dnssecOk: true,
        ecs: { address: '198.51.100.0', sourcePrefix: 24, scopePrefix: 17 },
        ede: [{ code: 15, text: 'blocked by policy' }, { code: 29 }, { code: 999, text: 'x' }],
        nsid: 'ist07',
        options: [{ code: 65001, data: 'beef' }]
      }
    }));
    assert.equal(m.edns.udpSize, 1400);
    assert.equal(m.edns.dnssecOk, true);
    assert.deepEqual(m.edns.ecs, { family: 1, sourcePrefix: 24, scopePrefix: 17, address: '198.51.100.0', subnet: '198.51.100.0/24' });
    assert.deepEqual(m.edns.ede, [
      { code: 15, name: 'Blocked', text: 'blocked by policy' },
      { code: 29, name: 'Synthesized', text: '' },
      { code: 999, name: 'EDE999', text: 'x' }
    ]);
    assert.equal(m.edns.nsid, 'ist07');
    assert.deepEqual(m.edns.options.map((o) => o.name), ['OPT65001', 'NSID', 'ECS', 'EDE', 'EDE', 'EDE']);
  });

  test('binary NSID is shown as hex; EDE text NUL terminator is stripped', () => {
    const m = decodeMessage(encodeMessage({
      edns: { options: [{ code: 3, data: '00ff10' }, { code: 15, data: '0006' + hexEncode(new TextEncoder().encode('bogus\0')) }] }
    }));
    assert.equal(m.edns.nsid, '00ff10');
    assert.deepEqual(m.edns.ede, [{ code: 6, name: 'DNSSEC Bogus', text: 'bogus' }]);
  });

  test('malformed ECS payloads do not throw', () => {
    const decodeEcs = (data) => decodeMessage(encodeMessage({ edns: { options: [{ code: 8, data }] } })).edns.ecs;
    assert.equal(decodeEcs('0001'), null, 'too short');
    assert.deepEqual(decodeEcs('0003 1000 aabb'.replace(/ /g, '')), { family: 3, sourcePrefix: 16, scopePrefix: 0, address: null, subnet: null });
    assert.equal(decodeEcs('0001 2000 0102030405'.replace(/ /g, '')).address, null, 'address longer than family size');
    assert.equal(decodeEcs('0002 3000 20010db8'.replace(/ /g, '')).address, '2001:db8::');
  });

  test('encodeMessage input validation', () => {
    assert.throws(() => encodeMessage({ answers: [{ name: 'x', type: 'A', data: '1.2.3' }] }), DnsWireError);
    assert.throws(() => encodeMessage({ answers: [{ name: 'x', type: 'AAAA', data: '1::2::3' }] }), DnsWireError);
    assert.throws(() => encodeMessage({ answers: [{ name: 'x', type: 'NOPE', data: '' }] }), DnsWireError);
    assert.throws(() => encodeMessage({ answers: [{ name: 'x', type: 'TXT', data: 'x'.repeat(256) }] }), DnsWireError);
    assert.throws(() => encodeMessage({ answers: [{ name: 'x', type: 'HTTPS', data: { priority: 1, target: '.', params: { bogus: 1 } } }] }), DnsWireError);
    assert.throws(() => encodeMessage({ answers: [{ name: 'x', type: 'A', ttl: -1, data: '1.2.3.4' }] }), DnsWireError);
    assert.throws(() => encodeMessage({ id: -1 }), DnsWireError);
  });
});

// ---------------------------------------------------------------------------
describe('decodeMessage — hardening', () => {
  // Hand-built response with nested compression:
  // Q: www.example.com A; AN1: www.example.com CNAME cdn.<ptr example.com>; AN2: <ptr cdn...> A 93.184.216.34
  const COMPRESSED = hex(`
    1234 8180 0001 0002 0000 0000
    03 777777 07 6578616d706c65 03 636f6d 00 0001 0001
    c00c 0005 0001 0000012c 0006 03 63646e c010
    c02d 0001 0001 0000003c 0004 5db8d822`);

  test('follows (nested) compression pointers', () => {
    const m = decodeMessage(COMPRESSED);
    assert.equal(m.id, 0x1234);
    assert.deepEqual(m.answers.map((rr) => [rr.name, rr.type, rr.data, rr.ttl]), [
      ['www.example.com', 'CNAME', 'cdn.example.com', 300],
      ['cdn.example.com', 'A', '93.184.216.34', 60]
    ]);
    assert.equal(m.answers[0].text, 'cdn.example.com.');
  });

  test('accepts ArrayBuffer, DataView, Buffer and rejects non-bytes', () => {
    assert.equal(decodeMessage(COMPRESSED.buffer.slice(0)).answers.length, 2);
    assert.equal(decodeMessage(new DataView(COMPRESSED.buffer)).answers.length, 2);
    assert.equal(decodeMessage(Buffer.from(COMPRESSED)).answers.length, 2);
    const offset = new Uint8Array(COMPRESSED.length + 5);
    offset.set(COMPRESSED, 5);
    assert.equal(decodeMessage(offset.subarray(5)).answers.length, 2, 'non-zero byteOffset views');
    for (const bad of ['abc', null, undefined, 42, {}]) assert.throws(() => decodeMessage(bad), DnsWireError);
  });

  const header = (qd = 1, an = 0) => hex(`0000 8180 ${qd.toString(16).padStart(4, '0')} ${an.toString(16).padStart(4, '0')} 0000 0000`);
  const msg = (...parts) => {
    const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
  };

  test('pointer loops are detected', () => {
    // name at 12 points to itself
    assert.throws(() => decodeMessage(msg(header(), hex('c00c 0001 0001'))), /loop|255/);
    // two pointers pointing at each other
    assert.throws(() => decodeMessage(msg(header(), hex('c00e c00c 0001 0001'))), /loop|255/);
    // label followed by a pointer back to itself: grows until the 255-octet limit
    assert.throws(() => decodeMessage(msg(header(), hex('01 61 c00c 0001 0001'))), /255|loop/);
  });

  test('pointer / label errors', () => {
    assert.throws(() => decodeMessage(msg(header(), hex('c0ff 0001 0001'))), /out of range/);
    assert.throws(() => decodeMessage(msg(header(), hex('40 61 00 0001 0001'))), /label type/);
    assert.throws(() => decodeMessage(msg(header(), hex('80 61 00 0001 0001'))), /label type/);
    assert.throws(() => decodeMessage(msg(header(), hex('0a 6162 '))), DnsWireError);
    assert.throws(() => decodeMessage(msg(header(), hex('c0'))), DnsWireError);
  });

  test('names longer than 255 octets built from pointers are rejected', () => {
    // four 63-byte labels via a pointer chain: label(63) → label(63) → ... exceeds 255
    const l = (n) => msg(new Uint8Array([63]), new Uint8Array(63).fill(0x61 + n));
    const body = msg(l(0), hex('c00c'));
    assert.throws(() => decodeMessage(msg(header(), body, hex('0001 0001'))), /255|loop/);
  });

  test('forward pointers are allowed when they terminate', () => {
    // question name = pointer to a name stored after the question (inside an answer RDATA)
    const m = decodeMessage(msg(header(1, 1),
      hex('c01d 0001 0001'), // qname → offset 29
      hex('00 0005 0001 00000001 0005'), // answer at 18: owner root, CNAME, rdlen 5 → RDATA at 29
      hex('01 78 01 79 00')));
    assert.equal(m.questions[0].name, 'x.y');
    assert.equal(m.answers[0].data, 'x.y');
  });

  test('header / count / length checks', () => {
    assert.throws(() => decodeMessage(new Uint8Array(11)), /12-byte header/);
    assert.throws(() => decodeMessage(hex('0000 8180 ffff ffff ffff ffff')), /counts exceed/);
    assert.throws(() => decodeMessage(msg(header(1, 1), hex('00 0001 0001'), hex('00 0001 0001 00000001 0010 01020304'))), /truncated/);
  });

  test('every truncation of real fixtures throws DnsWireError', () => {
    for (const id of ['gg-dnskey-cloudflare.com-do', 'cf-svcb-ddr', 'gg-ecs-v4-amazon', 'cf-servfail-dnssec-bogus', 'gg-nxdomain-com-nsec3-do']) {
      const full = fixtureBytes(id);
      for (let len = 0; len < full.length; len++) {
        assert.throws(() => decodeMessage(full.subarray(0, len)), DnsWireError, `${id} truncated to ${len}`);
      }
    }
  });

  test('TC=1 responses that stop at a record boundary decode as truncated', () => {
    const bytes = encodeMessage({ flags: { qr: true, tc: true }, questions: [{ name: 'x', type: 'TXT' }], answers: [{ name: 'x', type: 'TXT', data: ['a'] }] });
    const cut = bytes.slice();
    cut[7] = 3; // claim 3 answers, only 1 present
    const m = decodeMessage(cut);
    assert.equal(m.truncated, true);
    assert.equal(m.answers.length, 1);
    assert.equal(m.flags.tc, true);
  });

  test('TC=1 responses cut inside a record keep the complete records', () => {
    const bytes = encodeMessage({
      flags: { qr: true, tc: true }, questions: [{ name: 'x', type: 'A' }],
      answers: [{ name: 'x', type: 'A', data: '1.2.3.4' }, { name: 'x', type: 'A', data: '5.6.7.8' }]
    });
    const m = decodeMessage(bytes.subarray(0, bytes.length - 6));
    assert.equal(m.truncated, true);
    assert.deepEqual(m.answers.map((rr) => rr.data), ['1.2.3.4']);
    const noTc = bytes.slice(0, bytes.length - 6);
    noTc[2] &= ~0x02;
    assert.throws(() => decodeMessage(noTc), DnsWireError, 'without TC the same bytes are malformed');
  });

  test('malformed RDATA of a known type degrades to generic form with error', () => {
    const m = decodeMessage(encodeMessage({
      answers: [
        { name: 'x', type: 'A', rdata: hex('010203') },
        { name: 'x', type: 'AAAA', rdata: hex('00') },
        { name: 'x', type: 'MX', rdata: hex('000a 05 61') },
        { name: 'x', type: 'HTTPS', rdata: hex('0001 00 0003 0002 01bb 0001 0003 026832') }, // keys out of order
        { name: 'x', type: 'HTTPS', rdata: hex('0001 00 0001 0001 00') }, // empty alpn-id
        { name: 'x', type: 'CAA', rdata: hex('00 00') },
        { name: 'x', type: 'NSEC', rdata: hex('00 00 21') }, // bitmap length 33
        { name: 'x', type: 'TXT', rdata: hex('05 6162') },
        { name: 'x', type: 'A', rdata: hex('01020304 05') }
      ]
    }));
    assert.equal(m.answers.length, 9);
    for (const rr of m.answers) {
      assert.ok(rr.error, `${rr.type} should carry an error`);
      assert.match(rr.text, /^\\# \d+( [0-9A-F]+)?$/);
      assert.equal(rr.data, hexEncode(rr.rdata));
    }
    assert.equal(m.answers[0].text, '\\# 3 010203');
  });

  test('TTL with the high bit set is treated as 0 (RFC 2181 §8)', () => {
    const m = decodeMessage(encodeMessage({ answers: [{ name: 'x', type: 'A', ttl: 0x80000000, data: '1.2.3.4' }, { name: 'x', type: 'A', ttl: 0x7fffffff, data: '1.2.3.5' }] }));
    assert.deepEqual(m.answers.map((rr) => rr.ttl), [0, 0x7fffffff]);
  });

  test('OPT handling: first OPT wins, OPT outside additional section / non-root owner rejected', () => {
    const opt = (udp) => ({ name: '.', type: 'OPT', class: udp, ttl: 0, rdata: new Uint8Array(0) });
    const m = decodeMessage(encodeMessage({ additionals: [opt(1000), opt(2000), { name: 'x', type: 'A', data: '1.2.3.4' }] }));
    assert.equal(m.edns.udpSize, 1000);
    assert.deepEqual(m.additionals.map((rr) => rr.type), ['A']);
    assert.throws(() => decodeMessage(encodeMessage({ answers: [opt(512)] })), /OPT/);
    assert.throws(() => decodeMessage(encodeMessage({ additionals: [{ ...opt(512), name: 'x' }] })), /root/);
  });

  test('fuzz: random mutations of real fixtures only ever throw DnsWireError', () => {
    const rnd = prng(0xd15ea5e);
    const ids = MANIFEST.fixtures.map((f) => f.id);
    let decoded = 0;
    let rejected = 0;
    for (let i = 0; i < 4000; i++) {
      const src = fixtureBytes(ids[i % ids.length]);
      const buf = src.slice();
      const flips = 1 + Math.floor(rnd() * 6);
      for (let k = 0; k < flips; k++) {
        const pos = Math.floor(rnd() * buf.length);
        buf[pos] = rnd() < 0.3 ? 0xc0 | Math.floor(rnd() * 64) : Math.floor(rnd() * 256);
      }
      try {
        const m = decodeMessage(buf);
        for (const rr of [...m.answers, ...m.authorities, ...m.additionals]) assert.equal(typeof rr.text, 'string');
        decoded++;
      } catch (err) {
        if (!(err instanceof DnsWireError)) throw new Error(`non-DnsWireError on mutation ${i}: ${err.stack}`);
        rejected++;
      }
    }
    assert.ok(decoded > 100 && rejected > 100, `decoded ${decoded}, rejected ${rejected}`);
  });

  test('fuzz: random garbage only ever throws DnsWireError', () => {
    const rnd = prng(42);
    for (let i = 0; i < 3000; i++) {
      const buf = new Uint8Array(Math.floor(rnd() * 300)).map(() => Math.floor(rnd() * 256));
      if (buf.length > 12 && rnd() < 0.7) { buf[4] = 0; buf[5] = 1; buf[6] = 0; buf[7] = Math.floor(rnd() * 4); buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 1; }
      try {
        decodeMessage(buf);
      } catch (err) {
        if (!(err instanceof DnsWireError)) throw new Error(`non-DnsWireError: ${err.stack}`);
      }
    }
  });

  test('DnsWireError carries name and offset', () => {
    try {
      decodeMessage(new Uint8Array(3));
      assert.fail('should throw');
    } catch (err) {
      assert.ok(err instanceof DnsWireError);
      assert.ok(err instanceof Error);
      assert.equal(err.name, 'DnsWireError');
      assert.equal(err.offset, 0);
    }
  });

  test('SVC_PARAM_KEYS registry names', () => {
    assert.equal(SVC_PARAM_KEYS[1], 'alpn');
    assert.equal(SVC_PARAM_KEYS[5], 'ech');
    assert.equal(SVC_PARAM_KEYS[7], 'dohpath');
  });
});
