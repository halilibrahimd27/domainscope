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

  test('a pitfall\'s text names the target, the types, flags and tags it is about', () => {
    const z = bind('@ CAA 1 policy "x"\nu URI 10 1 "https://www.example.com/"');
    for (const target of CONVERT_TARGETS) {
      for (const p of convertZone(z, target).pitfalls) {
        const text = Z.pitfallText(p, target);
        assert.ok(text && !text.startsWith('zconv.'), `${target} ${p.code}: ${text}`);
        assert.ok(!/\{\w+\}/.test(text), `${target} ${p.code}: a placeholder left: ${text}`);
      }
    }
    const r53 = convertZone(z, 'route53');
    assert.equal(Z.pitfallText(r53.pitfalls.find((p) => p.code === 'unsupported-type'), 'route53'), 'URI: Route 53 does not support this record type; left out.');
    assert.equal(Z.pitfallText(r53.pitfalls.find((p) => p.code === 'caa-flags'), 'route53'), 'CAA flags other than 0 or 128 (1): many providers accept only these two.');
    assert.match(Z.pitfallText({ code: 'alias-zone-id', params: {} }, 'route53'), /replace HOSTED_ZONE_ID_OF_THE_TARGET with it/);
  });

  test('the preview stops at PREVIEW_LINES lines', () => {
    assert.equal(Z.PREVIEW_LINES, 400);
  });
});
