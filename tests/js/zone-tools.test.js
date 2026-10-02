// Unit tests for assets/js/ui/zone-tools.js — the Zone File's Compare and Convert tabs. The module is
// DOM-free at import time; its pure helpers word a comparison row and a conversion pitfall. No network.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { parseZone } from '../../assets/js/lib/zoneparse.js';
import { diffZones } from '../../assets/js/lib/zonediff.js';
import { convertZone, CONVERT_TARGETS } from '../../assets/js/lib/zoneconvert.js';

let Z;
let i18n;
const bind = (text) => parseZone(`$ORIGIN example.com.\n$TTL 300\n${text}\n`, { format: 'bind' });

before(async () => {
  i18n = await import('../../assets/js/i18n.js');
  Z = await import('../../assets/js/ui/zone-tools.js');
  i18n.setLang('en');
});
after(() => i18n.setLang('en'));

describe('zone-tools', () => {
  test('every key it builds from a library code exists in English and Turkish, with the same placeholders', () => {
    const en = new Set(i18n.listKeys('en'));
    const tr = new Set(i18n.listKeys('tr'));
    const keys = Z.generatedKeys();
    assert.ok(keys.length > 60, `${keys.length} keys`);
    assert.deepEqual(keys.filter((k) => !en.has(k) || !tr.has(k)), []);
  });

  test('a row\'s note: its reasons, TTLs and proxy flags on both sides, then what an option hid', () => {
    const a = bind('www 300 A 192.0.2.10 ; cf_tags=cf-proxied:true\n@ TXT "v=spf1 " "-all"\nttl 300 A 192.0.2.60');
    const b = bind('www 3600 A 192.0.2.11 ; cf_tags=cf-proxied:false\n@ TXT "v=spf1 -all"\nttl 600 A 192.0.2.60');
    const rows = Object.fromEntries(diffZones(a, b, { ignoreTtl: false }).rows.map((r) => [r.key, r]));
    assert.equal(Z.rowNote(rows['www|A']), 'Values differ. The TTL differs: 300 → 3,600. Cloudflare’s proxy differs: proxied → DNS only.');
    assert.equal(Z.rowNote(rows['@|TXT']), 'The same text, split into strings differently.');
    const quiet = Object.fromEntries(diffZones(a, b, { ignoreTtl: true }).rows.map((r) => [r.key, r]));
    assert.equal(Z.rowNote(quiet['ttl|A']), 'The TTL differs (300 → 600), ignored.');
    i18n.setLang('tr');
    assert.equal(Z.rowNote(rows['www|A']), 'Değerler farklı. TTL farklı: 300 → 3.600. Cloudflare proxy’si farklı: proxy’li → yalnızca DNS.');
    i18n.setLang('en');
  });

  test('a pitfall\'s text names the target, the types, flags, tags and keys it is about', () => {
    const z = bind([
      '@ CAA 1 policy "x"', 'u URI 10 1 "https://www.example.com/"', 'geo LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m',
      'doh SVCB 1 doh.example.net. alpn=h2 dohpath=/dns-query{?dns} ohttp', 'split TXT "v=spf1 " "-all"', 'www ANAME lb.example.net.'
    ].join('\n'));
    for (const target of CONVERT_TARGETS) {
      for (const p of convertZone(z, target).pitfalls) {
        for (const lang of ['en', 'tr']) {
          i18n.setLang(lang);
          const text = Z.pitfallText(p, target);
          assert.ok(text && !text.startsWith('zconv.'), `${lang} ${target} ${p.code}: ${text}`);
          assert.ok(!/\{\w+\}/.test(text), `${lang} ${target} ${p.code}: a placeholder left: ${text}`);
        }
        i18n.setLang('en');
      }
    }
    const text = (target, code) => Z.pitfallText(convertZone(z, target).pitfalls.find((p) => p.code === code), target);
    assert.equal(text('route53', 'unsupported-type'), 'URI, LOC, ANAME records: Route 53 does not support them; left out.');
    assert.equal(text('route53', 'caa-flags'), 'CAA flags other than 0 or 128 (1): many providers accept only these two.');
    assert.match(text('dnscontrol', 'caa-tag'), /^CAA tag policy: DNSControl accepts only issue, .* kept as a comment\.$/);
    assert.equal(text('octodns', 'by-hand'), 'LOC records: octoDNS has them, but DomainScope cannot write them from this file; left out, add them by hand.');
    assert.match(text('octodns', 'svc-key'), /^HTTPS \/ SVCB parameters written by number, each value as its wire bytes \(dohpath, ohttp: key5 for ech, key7 for dohpath …\): .* The records are the same on the wire\.$/);
    assert.match(text('dnscontrol', 'txt-split'), /: DNSControl keeps the joined text and splits it again/);
    assert.match(text('dnscontrol', 'alias-record'), /^ALIAS \/ ANAME records: written as ALIAS\(…\)/);
    i18n.setLang('tr');
    assert.equal(text('octodns', 'by-hand'), 'LOC kayıtları: octoDNS bunları destekler, ama DomainScope onları bu dosyadan yazamıyor; dışarıda bırakıldı, elle ekleyin.');
    i18n.setLang('en');
    assert.match(Z.pitfallText({ code: 'alias-zone-id', params: {} }, 'route53'), /replace HOSTED_ZONE_ID_OF_THE_TARGET with it/);
  });

  test('the second zone: named as typed, as the file names it, or after this zone when the file only guesses and every name fits', () => {
    const zone = bind('@ A 192.0.2.1');
    const parse = (files, { origin }) => parseZone(files[0].text, { origin, filename: files[0].name });
    const batch = (name) => [{ name: 'pasted', text: JSON.stringify({ Changes: [{ Action: 'UPSERT', ResourceRecordSet: { Name: name, Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.10' }] } }] }) }];
    const pick = (z) => [z.origin, z.originSource, z.originConfidence];
    assert.deepEqual(pick(parse(batch('www.example.com.'), { origin: null })), ['www.example.com', 'records', 'low'], 'alone, a one-record batch is named after its record');
    assert.deepEqual(pick(Z.readOther(batch('www.example.com.'), { zone, parse })), ['example.com', 'user', 'high'], 'every name fits under this zone: its name');
    assert.deepEqual(pick(Z.readOther(batch('www.example.com.'), { zone, typed: ' www.example.com ', parse })), ['www.example.com', 'user', 'high'], 'a typed name wins');
    assert.deepEqual(pick(Z.readOther(batch('www.example.net.'), { zone, parse })), ['www.example.net', 'records', 'low'], 'names of another zone keep their guess');
    assert.deepEqual(pick(Z.readOther([{ name: 'db', text: 'www 300 IN A 192.0.2.1\n' }], { zone, parse })), ['example.com', 'user', 'high'], 'a file that names no zone at all');
    const header = [{ name: 'p', text: JSON.stringify({ result: [{ id: '1', zone_name: 'example.org', name: 'example.org', type: 'A', content: '192.0.2.1', ttl: 1, proxied: false }], success: true }) }];
    assert.equal(Z.readOther(header, { zone, parse }).origin, 'example.org', 'a name the file states is kept');
    // A batch that only deletes: its DELETE names choose too.
    const cleanup = (name) => [{ name: 'pasted', text: JSON.stringify({ Changes: [{ Action: 'DELETE', ResourceRecordSet: { Name: name, Type: 'A', TTL: 300, ResourceRecords: [{ Value: '192.0.2.10' }] } }] }) }];
    assert.deepEqual(pick(Z.readOther(cleanup('old.example.com.'), { zone, parse })), ['example.com', 'user', 'high'], 'its DELETEs fit under this zone');
    assert.deepEqual(pick(Z.readOther(cleanup('old.example.net.'), { zone, parse })), ['old.example.net', 'records', 'low'], 'another zone\'s DELETEs keep their guess');
  });

  test('the notes of a change batch and an incomplete export, in English and Turkish', () => {
    const row = (notes) => ({ reasons: [], notes, a: null, b: null });
    assert.equal(Z.rowNote(row(['not-in-batch'])), 'Not in the change batch: it does not change this set, so this is no difference.');
    assert.equal(Z.rowNote(row(['batch-delete', 'partial'])), 'The change batch deletes this set. The file without this set is incomplete: the set may be in the part that is missing.');
    i18n.setLang('tr');
    assert.equal(Z.rowNote(row(['not-in-batch'])), 'Değişiklik paketinde yok: paket bu kümeyi değiştirmiyor, yani bu bir fark değil.');
    assert.equal(Z.rowNote(row(['batch-delete', 'partial'])), 'Değişiklik paketi bu kümeyi siliyor. Bu kümenin olmadığı dosya eksik: küme, dosyanın eksik kısmında olabilir.');
    i18n.setLang('en');
  });

  test('the preview stops at PREVIEW_LINES lines', () => {
    assert.equal(Z.PREVIEW_LINES, 400);
  });
});
