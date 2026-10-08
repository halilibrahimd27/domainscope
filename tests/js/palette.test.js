/**
 * lib/palette.js — the command palette's search: Turkish-safe folding, word matching, what a
 * typed text is about, the fill-only routes of its actions and the order of the entries.
 * Documentation data only (example.com, 192.0.2.0/24, 198.51.100.0/24, 2001:db8::/32, AS64496).
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  foldText, foldWithMap, matchWord, queryWords, scoreFields, highlightRanges, parseSubject, actionRoute, paletteResults,
  PALETTE_ACTIONS, ACTION_IDS, SUBJECT_KINDS, ENTRY_TYPES, TOOL_KEYWORDS, MAX_ENTRIES, MAX_RECENT
} from '../../assets/js/lib/palette.js';
import { VIEWS } from '../../assets/js/app.js';
import { TARGET_ROUTES, isFillOnly } from '../../assets/js/lib/session.js';

const TOOLS = [
  { id: 'subdomains', title: 'Subdomains', altTitle: 'Subdomain Tarama', desc: 'Discover the subdomains of a domain from DNS, CT logs and passive DNS.' },
  { id: 'lookup', title: 'DNS Lookup', altTitle: 'DNS Sorgulama', desc: 'Query any record type with DNSSEC status.' },
  { id: 'ip', title: 'IP Intel', altTitle: 'IP Bilgisi', desc: 'Reverse DNS, ASN, owner, location and CDN detection for IP addresses.' },
  { id: 'ptr', title: 'Reverse DNS', altTitle: 'Ters DNS', desc: 'Look up the reverse DNS (PTR) of every address in a network.' },
  { id: 'health', title: 'Domain Health', altTitle: 'Alan Adı Sağlığı', desc: 'NS, SOA, MX, SPF, DMARC, DKIM, CAA, DNSSEC and registration checks.' },
  { id: 'about', title: 'About', altTitle: 'Hakkında', desc: 'Where to start, how it works, data sources and quotas.' }
];
const keys = (r) => r.entries.map((e) => e.key);
const results = (query, extra = {}) => paletteResults({ query, tools: TOOLS, ...extra });

describe('foldText — one letter for every i, no diacritics, the same in Turkish and English', () => {
  test('the four i letters fold to i; ç ğ ö ş ü lose their marks', () => {
    assert.equal(foldText('İSTANBUL Istanbul ıstanbul istanbul'), 'istanbul istanbul istanbul istanbul');
    assert.equal(foldText('Alan Adı Sağlığı'), 'alan adi sagligi');
    assert.equal(foldText('ÇĞÖŞÜ çğöşü'), 'cgosu cgosu');
    assert.equal(foldText('IP Bilgisi'), 'ip bilgisi', 'not "ıp" as a Turkish lower case would give');
    assert.equal(foldText(null), '');
    assert.equal(foldText(42), '42');
  });

  test('the map points each folded character back to the original text', () => {
    const { folded, map } = foldWithMap('Sağİ');
    assert.equal(folded, 'sagi');
    assert.deepEqual(map, [0, 1, 2, 3, 4]);
    const combining = foldWithMap('i̇x'); // an i with a combining dot above, decomposed
    assert.equal(combining.folded, 'ix');
    assert.deepEqual(combining.map, [0, 2, 3]);
  });

  test('highlightRanges marks the original characters, merged where they touch', () => {
    assert.deepEqual(highlightRanges('Alan Adı Sağlığı', [9, 10, 11]), [[9, 12]]);
    assert.deepEqual(highlightRanges('DNS Lookup', [0, 1, 2, 4]), [[0, 3], [4, 5]]);
    assert.deepEqual(highlightRanges('DNS', [7]), [], 'out of range');
    assert.deepEqual(highlightRanges('DNS', []), []);
  });
});

describe('matchWord and scoreFields — how a word matches a text', () => {
  test('start of the text, start of a word, inside a word, letters in order', () => {
    assert.equal(matchWord('dns', 'dns lookup').score, 1);
    assert.equal(matchWord('look', 'dns lookup').score, 0.85);
    assert.deepEqual(matchWord('look', 'dns lookup').positions, [4, 5, 6, 7]);
    assert.equal(matchWord('ook', 'dns lookup').score, 0.6);
    assert.equal(matchWord('dlk', 'dns lookup'), null, 'no fuzzy match unless asked');
    const fuzzy = matchWord('dlk', 'dns lookup', { fuzzy: true });
    assert.ok(fuzzy && fuzzy.score > 0.3 && fuzzy.score <= 0.55, JSON.stringify(fuzzy));
    assert.deepEqual(fuzzy.positions, [0, 4, 7]);
    assert.equal(matchWord('xyz', 'dns lookup', { fuzzy: true }), null);
  });

  test('a fuzzy match that skips to a word start falls back to the earliest letters', () => {
    const m = matchWord('abd', 'xab d a', { fuzzy: true });
    assert.ok(m, 'a(1) b(2) d(4)');
    assert.deepEqual(m.positions, [1, 2, 4]);
  });

  test('a one-letter word matches only the start of a word', () => {
    assert.equal(matchWord('l', 'dns lookup').score, 0.85);
    assert.equal(matchWord('o', 'dns lookup'), null);
    assert.equal(matchWord('o', 'dns lookup', { fuzzy: true }), null);
  });

  test('every word must match a field; titles count more than descriptions', () => {
    const tool = { title: 'Reverse DNS', altTitle: 'Ters DNS', desc: 'The PTR of every address' };
    assert.ok(scoreFields(['ters'], tool).score > scoreFields(['ptr'], tool).score, 'a title beats a description');
    assert.equal(scoreFields(['ters', 'nothing'], tool), null);
    assert.deepEqual(scoreFields(['rev'], tool).title, [0, 1, 2], 'the matched title letters');
    assert.deepEqual(scoreFields(['ters'], tool).title, [], 'the other language’s title is not highlighted');
  });

  test('queryWords folds, splits and drops repeats', () => {
    assert.deepEqual(queryWords('  DNS  dns İp '), ['dns', 'ip']);
    assert.deepEqual(queryWords(''), []);
  });
});

describe('parseSubject — what the text is about', () => {
  test('domains, host names and URLs', () => {
    assert.deepEqual(parseSubject('example.com'), { subject: { kind: 'domain', value: 'example.com' }, words: [] });
    assert.deepEqual(parseSubject('https://www.Example.com/login').subject, { kind: 'host', value: 'www.example.com' });
    assert.deepEqual(parseSubject('_dmarc.example.com').subject, { kind: 'domain', value: 'example.com' });
    assert.deepEqual(parseSubject('MX example.com'), { subject: { kind: 'domain', value: 'example.com' }, words: ['mx'] });
  });

  test('IP addresses, networks and AS numbers', () => {
    assert.deepEqual(parseSubject('192.0.2.10').subject, { kind: 'ip', value: '192.0.2.10' });
    assert.deepEqual(parseSubject('[2001:db8::1]:443').subject, { kind: 'ip', value: '2001:db8::1' });
    assert.deepEqual(parseSubject('198.51.100.7/24').subject, { kind: 'cidr', value: '198.51.100.7/24' }, 'as typed: Reverse DNS reports host bits');
    assert.deepEqual(parseSubject('2001:DB8::/48').subject, { kind: 'cidr', value: '2001:db8::/48' });
    assert.deepEqual(parseSubject('AS64496').subject, { kind: 'asn', value: 'AS64496' });
    assert.deepEqual(parseSubject('asn 64496').subject, { kind: 'asn', value: 'AS64496' });
    assert.deepEqual(parseSubject('sweep as64496'), { subject: { kind: 'asn', value: 'AS64496' }, words: ['sweep'] });
    assert.equal(parseSubject('AS0').subject, null, 'reserved');
    assert.equal(parseSubject('198.51.100.0/33').subject, null);
  });

  test('a pasted certificate is the whole text; a private key is no subject', () => {
    const pem = '-----BEGIN CERTIFICATE-----MIIBszCCAVmgAwIBAgIU-----END CERTIFICATE-----';
    assert.deepEqual(parseSubject(` ${pem} `), { subject: { kind: 'cert', value: pem }, words: [] });
    assert.equal(parseSubject('-----BEGIN PRIVATE KEY-----MIIE-----END PRIVATE KEY-----').subject, null);
  });

  test('words, single labels and public suffixes are no subject', () => {
    for (const text of ['health', 'dns lookup', 'localhost', 'com', 'co.uk', '', '   ', 'ip 1.2']) {
      assert.equal(parseSubject(text).subject, null, JSON.stringify(text));
    }
    assert.deepEqual(parseSubject('Domain HEALTH').words, ['domain', 'health']);
  });
});

describe('actions — fill-only routes into the tools', () => {
  test('every action names a tool, takes known subjects, and has a label key', () => {
    const ids = new Set(VIEWS.map((v) => v.id));
    for (const a of PALETTE_ACTIONS) {
      assert.ok(ids.has(a.view), a.id);
      assert.ok(a.kinds.length && a.kinds.every((k) => SUBJECT_KINDS.includes(k)), a.id);
      if (!a.param && a.id !== 'cert') assert.ok(TARGET_ROUTES[a.view], `${a.id}: a TARGET_ROUTES tool or its own param`);
    }
    assert.deepEqual(ACTION_IDS, PALETTE_ACTIONS.map((a) => a.id));
    assert.equal(new Set(ACTION_IDS).size, ACTION_IDS.length);
    assert.deepEqual(ENTRY_TYPES, ['action', 'tool', 'recent', 'target']);
  });

  test('a domain opens its tools with the domain in the box and run=0', () => {
    const subject = { kind: 'domain', value: 'example.com' };
    const route = (id) => actionRoute(PALETTE_ACTIONS.find((a) => a.id === id), subject);
    assert.deepEqual(route('subdomains'), { domain: 'example.com', run: '0' });
    assert.deepEqual(route('domain'), { name: 'example.com', run: '0' });
    assert.deepEqual(route('health'), { domain: 'example.com', run: '0' });
    assert.deepEqual(route('lookupMx'), { name: 'example.com', run: '0', type: 'MX' });
    assert.deepEqual(route('lookupCaa'), { name: 'example.com', run: '0', type: 'CAA' });
    assert.deepEqual(route('global'), { name: 'example.com', run: '0' });
    assert.deepEqual(route('renew'), { names: 'example.com', run: '0' });
    assert.equal(route('ip'), null, 'IP Intel takes no domain');
  });

  test('an address, a network and an AS number', () => {
    const ip = { kind: 'ip', value: '192.0.2.10' };
    const route = (id, subject) => actionRoute(PALETTE_ACTIONS.find((a) => a.id === id), subject);
    assert.deepEqual(route('ip', ip), { ips: '192.0.2.10', run: '0' });
    assert.deepEqual(route('reverseIp', ip), { ips: '192.0.2.10', run: '0' });
    assert.deepEqual(route('ptr', ip), { target: '192.0.2.10', run: '0' });
    assert.deepEqual(route('retire', ip), { ips: '192.0.2.10', run: '0' }, 'Retire an IP: the address box');
    assert.deepEqual(route('sweep', { kind: 'cidr', value: '198.51.100.0/24' }), { target: '198.51.100.0/24', run: '0' });
    assert.deepEqual(route('sweep', { kind: 'asn', value: 'AS64496' }), { target: 'AS64496', run: '0' });
    assert.equal(route('cert', { kind: 'cert', value: '-----BEGIN CERTIFICATE-----' }), null, 'no route: the panel reads it');
  });

  test('every route an action builds only fills the form', () => {
    for (const text of ['example.com', 'www.example.com', '192.0.2.10', '2001:db8::10', '198.51.100.0/24', 'AS64496']) {
      for (const e of results(text).entries.filter((x) => x.type === 'action')) {
        assert.ok(isFillOnly(e.params), `${text} → ${e.id}`);
      }
    }
  });
});

describe('paletteResults — the entries, best first', () => {
  test('an empty box: the current target, the recent domains, then every tool in registry order', () => {
    const recent = ['example.com', 'www.example.org', 'example.net', 'a.example.com', 'b.example.com', 'c.example.com', 'd.example.com'];
    const r = results('', { recent, target: { value: 'www.example.org', kind: 'host' } });
    assert.deepEqual(keys(r), [
      'target:www.example.org',
      'recent:example.com', 'recent:example.net', 'recent:a.example.com', 'recent:b.example.com', 'recent:c.example.com',
      ...TOOLS.map((tool) => `tool:${tool.id}`)
    ], 'the target once, then five recent domains');
    assert.equal(r.subject, null);
    assert.equal(MAX_RECENT, 5);
  });

  test('a domain: its actions in order, nothing else', () => {
    const r = results('example.com', { recent: ['example.com'] });
    assert.deepEqual(r.subject, { kind: 'domain', value: 'example.com' });
    assert.deepEqual(keys(r), ['action:subdomains', 'action:domain', 'action:health', 'action:lookupMx', 'action:lookupTxt',
      'action:lookupCaa', 'action:global', 'action:renew']);
  });

  test('words next to a domain rank its actions: the record type, the label, the tool', () => {
    assert.equal(keys(results('mx example.com'))[0], 'action:lookupMx');
    assert.equal(keys(results('example.com caa', { actionLabels: { lookupCaa: ['CAA records of', 'kayıtları'] } }))[0], 'action:lookupCaa');
    const labels = { health: ['Check the health of', 'için alan adı sağlığını kontrol et'] };
    assert.equal(keys(results('example.com sağlığını', { actionLabels: labels }))[0], 'action:health', 'the Turkish label');
    assert.equal(keys(results('example.com health'))[0], 'action:health', 'the tool’s title');
    assert.equal(results('mx example.com').entries.length, 8, 'the other actions stay, after it');
  });

  test('an address offers IP Intel, its domains, Reverse DNS and Retire an IP; a network or an AS the sweep', () => {
    assert.deepEqual(keys(results('192.0.2.10')), ['action:ip', 'action:reverseIp', 'action:ptr', 'action:retire']);
    assert.deepEqual(keys(results('198.51.100.0/24')), ['action:sweep']);
    assert.deepEqual(keys(results('AS64496')), ['action:sweep']);
    const cert = results('-----BEGIN CERTIFICATE-----MIIB-----END CERTIFICATE-----');
    assert.deepEqual(keys(cert), ['action:cert']);
    assert.equal(cert.entries[0].params, null);
  });

  test('words find tools by their titles in either language, then by their descriptions', () => {
    assert.deepEqual(keys(results('ters')), ['tool:ptr']);
    assert.deepEqual(keys(results('TERS dns')), ['tool:ptr']);
    assert.equal(keys(results('dns'))[0], 'tool:lookup', 'a title that starts with the word first');
    assert.equal(keys(results('alan adı'))[0], 'tool:health');
    assert.equal(keys(results('ALAN ADI'))[0], 'tool:health', 'İ/I/ı fold alike');
    assert.equal(keys(results('hlth'))[0], 'tool:health', 'letters in order');
    assert.deepEqual(keys(results('ptr')), ['tool:ptr'], 'keywords and the description');
    assert.deepEqual(keys(results('reverse')), ['tool:ptr', 'tool:ip'], 'a title, then a description');
    assert.deepEqual(keys(results('zzzz')), []);
  });

  test('words also offer the recent domains that contain them, after the tools', () => {
    const r = results('exa', { recent: ['example.com', 'example.net', 'other.example'], target: { value: 'example.com', kind: 'domain' } });
    assert.deepEqual(keys(r), ['recent:example.com', 'recent:example.net', 'recent:other.example']);
    assert.ok(!keys(results('ip', { recent: ['example.com'] })).includes('recent:example.com'));
    assert.deepEqual(keys(results('', { recent: [null, '', 42, 'example.com', 'example.com'] })).filter((k) => k.startsWith('recent:')),
      ['recent:example.com'], 'bad and repeated entries are skipped');
  });

  test('at most `max` entries', () => {
    assert.equal(results('', { max: 3 }).entries.length, 3);
    assert.equal(results('', { max: -1 }).entries.length, 0);
    assert.equal(MAX_ENTRIES, 40);
    assert.deepEqual(paletteResults().entries, []);
  });

  test('every tool of the registry has keywords; the registry is searchable as the panel builds it', () => {
    for (const v of VIEWS) assert.equal(typeof TOOL_KEYWORDS[v.id], 'string', v.id);
    const tools = VIEWS.map((v) => ({ id: v.id, title: v.id }));
    assert.equal(paletteResults({ query: '', tools }).entries.length, VIEWS.length);
  });
});
