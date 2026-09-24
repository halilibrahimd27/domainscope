// Unit tests for assets/js/lib/resolvers.js — static data checks, no network.
// Live verification of the same data: node tests/live/verify-resolvers.mjs [--browser]
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  RESOLVERS, DEFAULT_CHAIN, GEO_VANTAGES, DEFAULT_GEO_RESOLVER, RESOLVERS_VERIFIED,
  getResolver, getVantage, flagEmoji
} from '../../assets/js/lib/resolvers.js';
import { encodeQuery, decodeMessage } from '../../assets/js/lib/dnswire.js';

const SPEC_IDS = ['cloudflare', 'cloudflare-family', 'google', 'quad9', 'quad9-ecs', 'controld', 'dnssb', 'iij', 'cleanbrowsing', 'tiar', 'seby', 'cznic'];

describe('RESOLVERS', () => {
  test('exactly the 12 resolvers verified in spec §3, unique ids', () => {
    assert.deepEqual(RESOLVERS.map((r) => r.id).sort(), [...SPEC_IDS].sort());
    assert.equal(new Set(RESOLVERS.map((r) => r.id)).size, RESOLVERS.length);
    assert.equal(new Set(RESOLVERS.map((r) => r.url)).size, RESOLVERS.length);
  });

  test('endpoint URLs are exactly the verified ones', () => {
    const urls = Object.fromEntries(RESOLVERS.map((r) => [r.id, r.url]));
    assert.deepEqual(urls, {
      cloudflare: 'https://cloudflare-dns.com/dns-query',
      'cloudflare-family': 'https://family.cloudflare-dns.com/dns-query',
      google: 'https://dns.google/dns-query',
      quad9: 'https://dns.quad9.net/dns-query',
      'quad9-ecs': 'https://dns11.quad9.net/dns-query',
      controld: 'https://freedns.controld.com/p0',
      dnssb: 'https://doh.dns.sb/dns-query',
      iij: 'https://public.dns.iij.jp/dns-query',
      cleanbrowsing: 'https://doh.cleanbrowsing.org/doh/security-filter/',
      tiar: 'https://doh.tiar.app/dns-query',
      seby: 'https://doh.seby.io/dns-query',
      cznic: 'https://odvr.nic.cz/doh'
    });
  });

  test('every entry has the contract shape', () => {
    for (const r of RESOLVERS) {
      assert.match(r.id, /^[a-z0-9-]+$/, r.id);
      for (const k of ['name', 'operator', 'location']) assert.ok(typeof r[k] === 'string' && r[k].length > 0, `${r.id}.${k}`);
      const u = new URL(r.url);
      assert.equal(u.protocol, 'https:');
      assert.ok(!u.search, 'URL must not carry a query string (callers append ?dns=)');
      assert.ok(r.countryCode === null || /^[A-Z]{2}$/.test(r.countryCode), `${r.id}.countryCode`);
      assert.equal(r.location === 'Anycast', r.countryCode === null, `${r.id}: anycast ⇔ no country`);
      assert.equal(typeof r.ecs, 'boolean');
      assert.equal(typeof r.dnssecValidating, 'boolean');
      assert.ok([null, 'malware', 'security', 'family'].includes(r.filtering), `${r.id}.filtering`);
      assert.equal(new URL(r.homepage).protocol, 'https:');
      // extensions
      for (const k of ['ecsEcho', 'nsid', 'browserReliable']) assert.equal(typeof r[k], 'boolean', `${r.id}.${k}`);
      assert.ok(r.issue === null || r.issue === 'h3-no-cors');
      assert.equal(r.browserReliable, r.issue === null);
    }
  });

  test('verified behaviour flags (2026-09-23)', () => {
    const by = Object.fromEntries(RESOLVERS.map((r) => [r.id, r]));
    assert.ok(RESOLVERS.every((r) => r.dnssecValidating), 'all 12 returned SERVFAIL for dnssec-failed.org and AD for cloudflare.com');
    assert.deepEqual(RESOLVERS.filter((r) => r.ecs).map((r) => r.id).sort(), ['google', 'quad9-ecs']);
    assert.equal(by.google.ecsEcho, true);
    assert.deepEqual(RESOLVERS.filter((r) => r.filtering).map((r) => `${r.id}:${r.filtering}`).sort(),
      ['cleanbrowsing:security', 'cloudflare-family:family', 'quad9-ecs:malware', 'quad9:malware']);
    assert.deepEqual(RESOLVERS.filter((r) => !r.browserReliable).map((r) => r.id).sort(), ['quad9', 'quad9-ecs']);
    assert.deepEqual(
      Object.fromEntries(RESOLVERS.filter((r) => r.countryCode).map((r) => [r.id, r.countryCode])),
      { iij: 'JP', tiar: 'SG', seby: 'AU', cznic: 'CZ' });
  });

  test('data is frozen', () => {
    assert.ok(Object.isFrozen(RESOLVERS));
    assert.ok(RESOLVERS.every((r) => Object.isFrozen(r)));
    assert.throws(() => { RESOLVERS[0].url = 'https://evil.example/'; }, TypeError);
    assert.ok(Object.isFrozen(DEFAULT_CHAIN));
    assert.ok(Object.isFrozen(GEO_VANTAGES));
  });

  test('RESOLVERS_VERIFIED is an ISO date', () => {
    assert.match(RESOLVERS_VERIFIED, /^\d{4}-\d{2}-\d{2}$/);
  });
});

describe('DEFAULT_CHAIN / DEFAULT_GEO_RESOLVER / getResolver', () => {
  test('DEFAULT_CHAIN: known, browser-readable, unfiltered, DNSSEC-validating resolvers', () => {
    // Quad9 was dropped (browsers cannot read it: HTTP/3 without CORS; and it filters malware).
    assert.deepEqual([...DEFAULT_CHAIN], ['cloudflare', 'google', 'dnssb', 'cznic']);
    for (const id of DEFAULT_CHAIN) {
      const r = getResolver(id);
      assert.ok(r, id);
      assert.equal(r.browserReliable, true, `${id} browserReliable`);
      assert.equal(r.filtering, null, `${id} unfiltered`);
      assert.equal(r.dnssecValidating, true, `${id} validates`);
    }
    assert.ok(Object.isFrozen(DEFAULT_CHAIN));
  });

  test('the geo resolver honours and echoes ECS', () => {
    const g = getResolver(DEFAULT_GEO_RESOLVER);
    assert.ok(g && g.ecs && g.ecsEcho && g.browserReliable);
  });

  test('getResolver', () => {
    assert.equal(getResolver('google').url, 'https://dns.google/dns-query');
    assert.equal(getResolver('nope'), undefined);
    assert.equal(getResolver(undefined), undefined);
  });
});

describe('GEO_VANTAGES', () => {
  const REQUIRED = ['TR', 'AZ', 'DE', 'NL', 'GB', 'FR', 'IT', 'ES', 'PL', 'SE', 'RU', 'UA', 'US', 'CA', 'BR', 'MX', 'AR', 'IN', 'SG', 'JP', 'KR', 'AU', 'ZA', 'AE', 'EG', 'HK', 'ID'];

  test('covers every required country', () => {
    const have = new Set(GEO_VANTAGES.map((g) => g.countryCode));
    for (const cc of REQUIRED) assert.ok(have.has(cc), cc);
    assert.ok(GEO_VANTAGES.length >= 25 && GEO_VANTAGES.length <= 35, `count ${GEO_VANTAGES.length}`);
  });

  test('Türkiye has at least two different ISPs; US has east and west', () => {
    const tr = GEO_VANTAGES.filter((g) => g.countryCode === 'TR');
    assert.ok(new Set(tr.map((g) => g.isp)).size >= 2, 'TR ISPs');
    assert.ok(new Set(tr.map((g) => g.asn)).size >= 2, 'TR ASNs');
    assert.ok(tr.some((g) => g.isp === 'Türk Telekom'));
    assert.ok(getVantage('us-east') && getVantage('us-west'));
    assert.equal(getVantage('us-east').countryCode, 'US');
    assert.equal(getVantage('us-west').countryCode, 'US');
  });

  test('every vantage has the contract shape and a normalized /24', () => {
    const ids = new Set();
    const subnets = new Set();
    for (const g of GEO_VANTAGES) {
      assert.match(g.id, /^[a-z]{2}(-[a-z]+)+$/, g.id);
      assert.ok(!ids.has(g.id), `duplicate id ${g.id}`);
      ids.add(g.id);
      assert.match(g.countryCode, /^[A-Z]{2}$/);
      assert.equal(g.verifiedCountry, g.countryCode, `${g.id} verified country`);
      assert.ok(g.city === null || (typeof g.city === 'string' && g.city.length > 0));
      assert.ok(g.nameTr && g.nameEn && g.isp, g.id);
      assert.ok(Number.isInteger(g.asn) && g.asn > 0 && g.asn < 4294967296, `${g.id} asn`);
      assert.ok(['EU', 'AS', 'NA', 'SA', 'AF', 'OC'].includes(g.continent), `${g.id} continent`);
      const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.0\/24$/.exec(g.subnet);
      assert.ok(m, `${g.id} subnet ${g.subnet}`);
      assert.ok(m.slice(1).every((o) => Number(o) <= 255));
      assert.ok(!subnets.has(g.subnet), `duplicate subnet ${g.subnet}`);
      subnets.add(g.subnet);
      // Must not be private / reserved space (ECS with such a source is useless).
      const [a, b] = m.slice(1).map(Number);
      assert.ok(!(a === 10 || a === 127 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127) || a >= 224 || a === 0), `${g.id} public`);
    }
  });

  test('every subnet encodes as an RFC 7871 ECS option (3 address bytes, /24)', () => {
    for (const g of GEO_VANTAGES) {
      const m = decodeMessage(encodeQuery('www.example.com', 'A', { ecs: g.subnet }));
      assert.equal(m.edns.ecs.subnet, g.subnet);
      assert.equal(m.edns.options.find((o) => o.code === 8).data.length, 4 + 3);
    }
  });

  test('getVantage', () => {
    assert.equal(getVantage('tr-ist-tt').countryCode, 'TR');
    assert.equal(getVantage('xx'), undefined);
  });
});

describe('flagEmoji', () => {
  test('regional indicator pairs', () => {
    assert.equal(flagEmoji('TR'), '\u{1F1F9}\u{1F1F7}');
    assert.equal(flagEmoji('tr'), '\u{1F1F9}\u{1F1F7}');
    assert.equal(flagEmoji('AZ'), '\u{1F1E6}\u{1F1FF}');
    assert.equal(flagEmoji('US'), '\u{1F1FA}\u{1F1F8}');
  });

  test('anything else → globe', () => {
    for (const bad of [null, undefined, '', 'T', 'TUR', '12', 'T1', 42, {}, 'ÇĞ']) assert.equal(flagEmoji(bad), '\u{1F310}', String(bad));
  });

  test('every resolver / vantage country renders as a 2-code-point flag', () => {
    for (const cc of [...RESOLVERS.map((r) => r.countryCode), ...GEO_VANTAGES.map((g) => g.countryCode)]) {
      const f = flagEmoji(cc);
      assert.equal([...f].length, cc ? 2 : 1);
    }
  });
});
