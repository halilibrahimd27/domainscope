// Unit tests for assets/js/lib/zonediff.js — the semantic diff of two zones (Zone File › Compare).
// No network. Golden case: tests/fixtures/zonediff/ (a BIND file and its move to Route 53), plus small
// zones written inline; documentation data only (example.com / .net / .org, 192.0.2.0/24 …).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseZone } from '../../assets/js/lib/zoneparse.js';
import {
  diffZones, diffFilter, diffCsv, diffJson, diffSummaryFacts, hasDifferences, canonicalName, relativeName, valueKey, recordSets,
  DIFF_STATUSES, DIFF_REASONS, DIFF_NOTES, DIFF_DEFAULTS, DIFF_OPTIONS, DIFF_FILTERS, DIFF_CSV_COLUMNS
} from '../../assets/js/lib/zonediff.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIX = join(ROOT, 'tests', 'fixtures', 'zonediff');
const read = (f) => readFileSync(join(FIX, f), 'utf8').replace(/\r\n/g, '\n');
const before = () => parseZone(read('before.zone.txt'), { filename: 'before.zone.txt' });
const after = () => parseZone(read('after.route53.json'), { filename: 'after.route53.json' });
const bind = (text, origin = 'example.com') => parseZone(`$ORIGIN ${origin}.\n$TTL 300\n${text}\n`, { format: 'bind' });
/** Rows as `status rel TYPE reasons|notes` lines (the golden form). */
const lines = (res) => res.rows.map((r) => `${r.status} ${r.rel} ${r.type} ${r.reasons.join(',')}|${r.notes.join(',')}`);

describe('vocabulary', () => {
  test('statuses, reasons, notes, options and filters', () => {
    assert.deepEqual(DIFF_STATUSES, ['added', 'removed', 'changed', 'same', 'ignored']);
    assert.deepEqual(DIFF_REASONS, ['values', 'ttl', 'proxied', 'routing', 'soa-names', 'soa-serial', 'soa-timers']);
    assert.deepEqual(DIFF_NOTES, ['ttl-ignored', 'txt-split', 'soa-ignored', 'apex-ns']);
    assert.deepEqual(DIFF_DEFAULTS, { ignoreTtl: false, joinTxt: true, ignoreSoa: false, ignoreApexNs: false });
    assert.deepEqual(DIFF_OPTIONS, ['ignoreTtl', 'joinTxt', 'ignoreSoa', 'ignoreApexNs']);
    assert.deepEqual(DIFF_FILTERS, ['diff', 'added', 'removed', 'changed', 'same', 'ignored', 'all']);
    for (const list of [DIFF_STATUSES, DIFF_REASONS, DIFF_NOTES, DIFF_DEFAULTS, DIFF_FILTERS]) assert.ok(Object.isFrozen(list));
  });
});

describe('names', () => {
  test('canonical: case, trailing dot, decimal escapes of plain characters, the root', () => {
    assert.equal(canonicalName('WWW.Example.COM.'), 'www.example.com');
    assert.equal(canonicalName('\\042.wild.example.com'), '*.wild.example.com', '\\042 and * are the same wire label');
    assert.equal(canonicalName('\\097pi.example.com'), 'api.example.com');
    assert.equal(canonicalName('a\\032b.example.com'), 'a\\032b.example.com', 'a space stays escaped');
    assert.equal(canonicalName('a\\\\042.example.com'), 'a\\\\042.example.com', 'an escaped backslash before digits is no escape');
    assert.equal(canonicalName('dot\\.label.example.com.'), 'dot\\.label.example.com');
    assert.equal(canonicalName('trailing\\.'), 'trailing\\.', 'an escaped final dot is part of the label');
    assert.equal(canonicalName('.'), '');
  });

  test('relative: @, the labels below, an absolute name with its dot outside, an escaped dot is no boundary', () => {
    assert.equal(relativeName('example.com', 'example.com'), '@');
    assert.equal(relativeName('WWW.example.com.', 'example.com'), 'www');
    assert.equal(relativeName('*.apps.example.com', 'example.com'), '*.apps');
    assert.equal(relativeName('mail.example.net', 'example.com'), 'mail.example.net.');
    assert.equal(relativeName('notexample.com', 'example.com'), 'notexample.com.');
    assert.equal(relativeName('a\\.example.com', 'example.com'), 'a\\.example.com.', 'one label "a.example", then com');
    assert.equal(relativeName('', 'example.com'), '.');
    assert.equal(relativeName('www.example.com', null), 'www.example.com.');
  });
});

describe('values', () => {
  const rec = (text, origin = 'example.com') => bind(text, origin).records[0];

  test('MX / SRV fields, not spacing; IPv6 in its compressed form; CAA tag and issuer in lowercase', () => {
    assert.equal(valueKey(rec('@ MX 10    mail')), valueKey(rec('@ MX 10 mail.example.com.')));
    assert.equal(valueKey(rec('_s._tcp SRV 1 2   443 host')), valueKey(rec('_s._tcp SRV 1 2 443 host.example.com.')));
    assert.equal(valueKey(rec('v6 AAAA 2001:DB8:0:0:0:0:0:1')), valueKey(rec('v6 AAAA 2001:db8::1')));
    assert.equal(valueKey(rec('@ CAA 0 ISSUE "LetsEncrypt.org; validationmethods=dns-01"')), valueKey(rec('@ CAA 0 issue "letsencrypt.org;validationmethods=dns-01"')));
    assert.notEqual(valueKey(rec('@ CAA 0 iodef "mailto:A@example.com"')), valueKey(rec('@ CAA 0 iodef "mailto:a@example.com"')), 'only an issuer domain is case-insensitive');
    assert.notEqual(valueKey(rec('@ CAA 128 issue "ca.example.net"')), valueKey(rec('@ CAA 0 issue "ca.example.net"')), 'flags count');
  });

  test('TXT: joined text with joinTxt, the strings themselves without', () => {
    const split = rec('@ TXT "v=spf1 mx " "-all"');
    const whole = rec('@ TXT "v=spf1 mx -all"');
    assert.equal(valueKey(split), valueKey(whole));
    assert.notEqual(valueKey(split, { joinTxt: false }), valueKey(whole, { joinTxt: false }));
  });

  test('names inside RDATA relative to their zone: a copy under another name compares equal', () => {
    assert.equal(valueKey(rec('www CNAME @'), { origin: 'example.com' }), valueKey(rec('www CNAME @', 'example.net'), { origin: 'example.net' }));
    assert.notEqual(valueKey(rec('www CNAME other.example.org.'), { origin: 'example.com' }), valueKey(rec('www CNAME @'), { origin: 'example.com' }));
  });

  test('SOA: every field, or its names only with ignoreSoa; an alias by its target; undecoded data by its text', () => {
    const a = rec('@ SOA ns1 host 1 2 3 4 5');
    const b = rec('@ SOA ns1 host 2 2 3 4 6');
    assert.notEqual(valueKey(a, { origin: 'example.com' }), valueKey(b, { origin: 'example.com' }));
    assert.equal(valueKey(a, { origin: 'example.com', ignoreSoa: true }), valueKey(b, { origin: 'example.com', ignoreSoa: true }));
    const alias = { type: 'A', alias: { target: 'D111.cloudfront.net' }, data: null, text: '' };
    assert.equal(valueKey(alias), 'alias d111.cloudfront.net.');
    assert.equal(valueKey({ type: 'LOC', data: null, text: ' 52 22  N ' }), 'text 52 22 N');
  });

  test('record sets: one per owner and type, duplicates folded, TTLs, proxy flags and routing collected', () => {
    const z = bind('www 300 A 192.0.2.1 ; cf_tags=cf-proxied:true\nwww 600 A 192.0.2.2 ; cf_tags=cf-proxied:false\nwww A 192.0.2.1\nwww AAAA 2001:db8::1');
    const sets = recordSets(z);
    assert.deepEqual([...sets.keys()], ['www|A', 'www|AAAA']);
    const a = sets.get('www|A');
    assert.deepEqual([a.values.size, a.ttls, a.proxied], [2, [300, 600], [false, true]]);
  });
});

describe('golden: a zone moved from BIND to Route 53 (tests/fixtures/zonediff)', () => {
  test('default options: names, case, escapes, spacing, IPv6 and TXT chunks normalised; real differences found', () => {
    const res = diffZones(before(), after());
    assert.deepEqual(res.counts, { added: 1, removed: 1, changed: 4, same: 8, ignored: 0, total: 14 });
    assert.deepEqual(lines(res), [
      'changed @ SOA soa-names,soa-serial,soa-timers,ttl|',
      'changed @ NS values,ttl|',
      'same @ A |',
      'same @ MX |',
      'same @ TXT |txt-split',
      'same @ CAA |',
      'changed api A values|',
      'same ipv6 AAAA |',
      'same mail A |',
      'added new A |',
      'removed old A |',
      'changed ttl A ttl|',
      'same *.wild A |',
      'same www CNAME |'
    ]);
    const api = res.rows.find((r) => r.key === 'api|A');
    assert.deepEqual([api.added, api.removed, api.a.values, api.b.values], [['192.0.2.16'], ['192.0.2.15'], ['192.0.2.14', '192.0.2.15'], ['192.0.2.14', '192.0.2.16']]);
    const ttl = res.rows.find((r) => r.key === 'ttl|A');
    assert.deepEqual([ttl.a.ttl, ttl.b.ttl, ttl.added, ttl.removed], [300, 3600, [], []]);
    assert.deepEqual(res.a, { origin: 'example.com', format: 'bind', dialect: 'generic', records: 15, rrsets: 13 });
    assert.equal(res.b.format, 'route53');
    assert.equal(res.relative, false);
    assert.equal(hasDifferences(res), true);
  });

  test('every option on: TTLs, the SOA serial / timers and the apex NS hidden, each said on its row', () => {
    const res = diffZones(before(), after(), { ignoreTtl: true, ignoreSoa: true, ignoreApexNs: true });
    assert.deepEqual(res.counts, { added: 1, removed: 1, changed: 2, same: 9, ignored: 1, total: 14 });
    assert.deepEqual(lines(res).slice(0, 2), ['changed @ SOA soa-names|soa-ignored', 'ignored @ NS |apex-ns'],
      'the SOA still names another server and mailbox; the apex NS is left out');
    assert.equal(lines(res).find((l) => l.startsWith('same ttl A')), 'same ttl A |ttl-ignored');
    assert.deepEqual(res.options, { ignoreTtl: true, joinTxt: true, ignoreSoa: true, ignoreApexNs: true });
  });

  test('joinTxt off: strings split differently are a change of values', () => {
    const res = diffZones(before(), after(), { joinTxt: false });
    assert.equal(lines(res).find((l) => l.includes(' TXT ')), 'changed @ TXT values|');
    assert.deepEqual(res.counts, { added: 1, removed: 1, changed: 5, same: 7, ignored: 0, total: 14 });
  });

  test('the same zone against itself: nothing differs, in either direction', () => {
    for (const z of [before(), after()]) {
      const res = diffZones(z, z);
      assert.equal(hasDifferences(res), false);
      assert.equal(res.counts.same, res.counts.total);
    }
    const back = diffZones(after(), before());
    assert.deepEqual([back.counts.added, back.counts.removed, back.counts.changed], [1, 1, 4], 'swapped: added and removed trade places');
    assert.ok(lines(back).includes('added old A |') && lines(back).includes('removed new A |'));
  });
});

describe('more cases', () => {
  test('Cloudflare proxy flags: a flipped flag is a change, a provider without flags never is', () => {
    const cf = bind('www A 192.0.2.10 ; cf_tags=cf-proxied:true\napi A 192.0.2.14 ; cf_tags=cf-proxied:false');
    const flipped = bind('www A 192.0.2.10 ; cf_tags=cf-proxied:false\napi A 192.0.2.14 ; cf_tags=cf-proxied:false');
    const plain = bind('www A 192.0.2.10\napi A 192.0.2.14');
    const res = diffZones(cf, flipped);
    assert.deepEqual(lines(res), ['same api A |', 'changed www A proxied|']);
    assert.deepEqual([res.rows[1].a.proxied, res.rows[1].b.proxied], [true, false]);
    assert.equal(hasDifferences(diffZones(cf, plain)), false, 'no flag on one side: nothing to compare');
  });

  test('a mixed proxy set reads as mixed', () => {
    const z = bind('m A 192.0.2.1 ; cf_tags=cf-proxied:true\nm A 192.0.2.2 ; cf_tags=cf-proxied:false');
    const one = bind('m A 192.0.2.1 ; cf_tags=cf-proxied:true\nm A 192.0.2.2 ; cf_tags=cf-proxied:true');
    const res = diffZones(z, one);
    assert.deepEqual([res.rows[0].status, res.rows[0].reasons, res.rows[0].a.proxied], ['changed', ['proxied'], 'mixed']);
  });

  test('two copies under different names: compared relative to each, targets too; the result says so', () => {
    const a = bind('@ A 192.0.2.10\nwww CNAME @\n@ MX 10 mail\nmail A 192.0.2.25');
    const b = bind('@ A 192.0.2.10\nwww CNAME @\n@ MX 10 mail\nmail A 192.0.2.26', 'example.net');
    const res = diffZones(a, b);
    assert.equal(res.relative, true);
    assert.deepEqual(lines(res).filter((l) => !l.startsWith('same')), ['changed mail A values|']);
  });

  test('a type on one side only: removed and added, never matched across types', () => {
    const res = diffZones(bind('www CNAME host.example.net.'), bind('www A 192.0.2.10'));
    assert.deepEqual(lines(res), ['added www A |', 'removed www CNAME |']);
  });

  test('routing variants: a different policy or set of variants is a change', () => {
    const r53 = (weight) => parseZone(JSON.stringify({ ResourceRecordSets: [
      { Name: 'app.example.com.', Type: 'A', TTL: 60, SetIdentifier: 'one', Weight: weight, ResourceRecords: [{ Value: '192.0.2.21' }] }
    ] }), { origin: 'example.com' });
    assert.deepEqual(lines(diffZones(r53(10), r53(20))), ['changed app A routing|']);
    assert.equal(hasDifferences(diffZones(r53(10), r53(10))), false);
  });

  test('a fatal zone is refused', () => {
    assert.throws(() => diffZones(parseZone(''), bind('@ A 192.0.2.1')), TypeError);
    assert.throws(() => diffZones(null, null), TypeError);
  });
});

describe('filters and exports', () => {
  test('filters: diff = added + removed + changed; all; one status', () => {
    const res = diffZones(before(), after(), { ignoreApexNs: true });
    const n = (f) => res.rows.filter((r) => diffFilter(r, f)).length;
    assert.deepEqual(DIFF_FILTERS.map((f) => [f, n(f)]), [['diff', 5], ['added', 1], ['removed', 1], ['changed', 3], ['same', 8], ['ignored', 1], ['all', 14]]);
  });

  test('CSV: the columns, absolute names, values separated by " | ", a redaction applied', () => {
    const res = diffZones(before(), after());
    const csv = diffCsv(res.rows.filter((r) => diffFilter(r, 'diff')), { redact: (values) => values.map((v) => (v === '192.0.2.15' ? '[origin hidden]' : v)) });
    const rows = csv.replace(/^﻿/, '').trim().split('\r\n');
    assert.equal(rows[0], DIFF_CSV_COLUMNS.join(','));
    assert.deepEqual(DIFF_CSV_COLUMNS, ['status', 'name', 'type', 'ttl_a', 'ttl_b', 'values_a', 'values_b', 'added', 'removed', 'reasons', 'notes']);
    assert.ok(rows.includes('changed,api.example.com,A,3600,3600,192.0.2.14 | [origin hidden],192.0.2.14 | 192.0.2.16,192.0.2.16,[origin hidden],values,'), rows.join('\n'));
    assert.ok(rows.includes('added,new.example.com,A,,3600,,192.0.2.70,192.0.2.70,,,'));
    assert.ok(rows.includes('changed,example.com,NS,3600,172800,ns1.example.com. | ns2.example.com.,ns-1.awsdns-01.org. | ns-2.awsdns-02.co.uk.,ns-1.awsdns-01.org. | ns-2.awsdns-02.co.uk.,ns1.example.com. | ns2.example.com.,values ttl,'));
    assert.equal(rows.length, 1 + 6);
  });

  test('JSON: both zones, the options, the counts and the rows given', () => {
    const res = diffZones(before(), after());
    const doc = JSON.parse(diffJson(res, res.rows.filter((r) => r.status === 'added')));
    assert.deepEqual(Object.keys(doc), ['a', 'b', 'relative', 'options', 'counts', 'rows']);
    assert.deepEqual(doc.rows, [{ status: 'added', name: 'new.example.com', relative: 'new', type: 'A', ttl_a: null, ttl_b: 3600, values_a: [], values_b: ['192.0.2.70'],
      added: ['192.0.2.70'], removed: [], proxied_a: null, proxied_b: null, reasons: [], notes: [] }]);
    assert.equal(JSON.parse(diffJson(res)).rows.length, 14, 'every row by default');
  });

  test('summary facts: names and types of the first differences, the options on, never a value', () => {
    const res = diffZones(before(), after(), { ignoreTtl: true });
    const facts = diffSummaryFacts(res, { max: 2, formatA: 'BIND zone file', formatB: 'AWS Route 53 (JSON)' });
    assert.deepEqual(facts, {
      a: { origin: 'example.com', format: 'BIND zone file' }, b: { origin: 'example.com', format: 'AWS Route 53 (JSON)' }, relative: false,
      counts: { added: 1, removed: 1, changed: 3, same: 9, ignored: 0, total: 14 }, options: ['ignoreTtl', 'joinTxt'],
      differences: [{ status: 'changed', name: '@', type: 'SOA', reasons: ['soa-names', 'soa-serial', 'soa-timers'] }, { status: 'changed', name: '@', type: 'NS', reasons: ['values'] }],
      more: 3
    });
    assert.ok(!JSON.stringify(facts).includes('192.0.2.'), 'no value');
  });
});
