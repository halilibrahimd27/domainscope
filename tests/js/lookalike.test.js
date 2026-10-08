/**
 * lookalike.test.js — lib/lookalike.js: punycode, the candidate techniques (exact outputs for small
 * labels, the keyboards, the Turkish, Cyrillic and Greek lookalike letters), the budget's
 * round-robin, the user's own domains, the DNS / RDAP / crt.sh checks with fakes, the risk score,
 * the order and the CSV. Documentation names and addresses only; nothing reaches the network.
 */

import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  punycodeEncode, punycodeDecode, labelToAscii, nameToUnicode, lookalikeTarget, adjacentKeys, generateLookalikes,
  checkCandidate, checkLookalikes, lookupRegistration, lookupCertificates, parseCrtshRows, crtshLookalikeUrl, targetFootprint,
  scoreLookalike, sortLookalikes, lookalikeCsv, lookalikeExportRow, lookalikeState,
  LOOKALIKE_TECHNIQUES, LOOKALIKE_LEVELS, LOOKALIKE_REASONS, LOOKALIKE_STATES, LOOKALIKE_DEFAULT_BUDGET, LOOKALIKE_MAX_BUDGET,
  LOOKALIKE_CSV_COLUMNS, RISK_WEIGHTS, TLD_SWAPS, HOMOGLYPHS
} from '../../assets/js/lib/lookalike.js';
import { clearRdapCache, IANA_BOOTSTRAP } from '../../assets/js/lib/rdap.js';

const DAY = 86400000;
const NOW = Date.parse('2026-10-08T12:00:00Z');
const names = (r) => r.candidates.map((c) => c.name);
const only = (input, technique, opts = {}) => names(generateLookalikes(input, { budget: 5000, techniques: [technique], ...opts }));

/* ------------------------------------------------------------------------ */
/* Punycode                                                                  */
/* ------------------------------------------------------------------------ */

test('punycode: RFC 3492 encodings (checked against Python\'s punycode codec) and back', () => {
  const vectors = [
    ['bücher', 'bcher-kva'], ['türkiye', 'trkiye-3ya'], ['ü', 'tda'], ['exаmple', 'exmple-4nf'], ['αb', 'b-ylb'], ['аb', 'b-7sb'],
    ['i̇stanbul', 'istanbul-o0e'], ['ğüşıöç', '7ca3ar3ltdxm']
  ];
  for (const [u, p] of vectors) {
    assert.equal(punycodeEncode(u), p, u);
    assert.equal(punycodeDecode(p), u, p);
  }
  assert.equal(punycodeEncode('example'), 'example-');
  assert.equal(punycodeDecode('example-'), 'example');
  assert.equal(punycodeDecode('a!b'), null, 'not a punycode digit');
  assert.equal(punycodeDecode('kva'.repeat(1)), punycodeDecode('kva'));
});

test('labelToAscii: ASCII as is, Unicode as xn--, refuses what no label can be', () => {
  assert.equal(labelToAscii('example'), 'example');
  assert.equal(labelToAscii('bücher'), 'xn--bcher-kva');
  assert.equal(labelToAscii('bücher'), 'xn--bcher-kva', 'NFC first');
  for (const bad of ['', '-ab', 'ab-', 'ab--cd', 'a_b', 'a.b', '̇ab', 'Ğab', 'a'.repeat(64)]) assert.equal(labelToAscii(bad), null, bad);
  assert.equal(nameToUnicode('xn--bcher-kva.example.com'), 'bücher.example.com');
  assert.equal(nameToUnicode('xn--!!.example'), 'xn--!!.example', 'undecodable label kept');
});

/* ------------------------------------------------------------------------ */
/* Candidates                                                                */
/* ------------------------------------------------------------------------ */

test('lookalikeTarget: the registrable domain, its label (an IDN decoded) and its suffix', () => {
  assert.deepEqual(lookalikeTarget('https://www.example.com.tr/path'), { domain: 'example.com.tr', label: 'example', suffix: 'com.tr' });
  assert.deepEqual(lookalikeTarget('xn--trkiye-3ya.com'), { domain: 'xn--trkiye-3ya.com', label: 'türkiye', suffix: 'com' });
  assert.deepEqual(lookalikeTarget('Türkiye.com'), { domain: 'xn--trkiye-3ya.com', label: 'türkiye', suffix: 'com' });
  for (const bad of ['192.0.2.1', 'com.tr', '', 'not a domain', null]) assert.equal(lookalikeTarget(bad), null, String(bad));
});

test('keyboards: neighbouring keys on QWERTY and on the Turkish Q layout', () => {
  assert.deepEqual(adjacentKeys('q'), ['1', '2', 'w', 'a']);
  assert.deepEqual(adjacentKeys('s'), ['w', 'e', 'a', 'd', 'z', 'x']);
  assert.deepEqual(adjacentKeys('m'), ['j', 'k', 'n']);
  assert.deepEqual(adjacentKeys('p'), ['0', 'o', 'l']);
  assert.deepEqual(adjacentKeys('i', 'tr-q'), ['ğ', 'ü', 'ş'], 'the dotted i sits right of ş');
  assert.deepEqual(adjacentKeys('ı', 'tr-q'), ['8', '9', 'u', 'o', 'j', 'k'], 'the dotless ı where QWERTY has i');
  assert.deepEqual(adjacentKeys('l', 'tr-q'), ['o', 'p', 'k', 'ş', 'ö', 'ç']);
  assert.deepEqual(adjacentKeys('ş'), [], 'no ş on QWERTY');
});

test('techniques: exact outputs for a two-letter label', () => {
  assert.deepEqual(only('ab.com', 'omission'), ['b.com', 'a.com']);
  assert.deepEqual(only('ab.com', 'repetition'), ['aab.com', 'abb.com']);
  assert.deepEqual(only('ab.com', 'transposition'), ['ba.com']);
  assert.deepEqual(only('aab.com', 'transposition'), ['aba.com'], 'no swap of two equal letters');
  assert.deepEqual(only('ab.com', 'hyphenation'), ['a-b.com']);
  assert.deepEqual(only('ab.com', 'vowel-swap'), ['eb.com', 'ib.com', 'ob.com', 'ub.com']);
  assert.deepEqual(only('ab.com', 'replacement'), ['qb.com', 'wb.com', 'sb.com', 'zb.com', 'ag.com', 'ah.com', 'av.com', 'an.com']);
  assert.deepEqual(only('ab.com', 'bitsquatting'), ['cb.com', 'eb.com', 'ib.com', 'qb.com', 'ac.com', 'af.com', 'aj.com', 'ar.com']);
  assert.deepEqual(only('ab.com', 'insertion').slice(0, 4), ['qab.com', 'aqb.com', 'wab.com', 'awb.com']);
  assert.equal(only('ab.com', 'addition').length, 36);
  assert.deepEqual(only('ab.com', 'addition').slice(0, 2), ['aba.com', 'abb.com']);
  assert.deepEqual(only('ab.com', 'dictionary').slice(0, 2), ['login-ab.com', 'loginab.com']);
  assert.ok(only('ab.com', 'dictionary').includes('ab-support.com'));
  assert.deepEqual(only('ab.com', 'tld-swap'), TLD_SWAPS.filter((s) => s !== 'com').map((s) => `ab.${s}`));
  assert.deepEqual(only('ab.com.tr', 'tld-swap').slice(0, 3), ['ab.com', 'ab.net', 'ab.org'], '.com.tr → .com first');
  const sub = generateLookalikes('abc.com', { techniques: ['subdomain'] }).candidates;
  assert.deepEqual(sub.map((c) => [c.name, c.registrable]), [['a.bc.com', 'bc.com'], ['ab.c.com', 'c.com']]);
  assert.deepEqual(only('xcom.tr', 'subdomain'), ['xc.om.tr', 'xco.m.tr'], 'x.com.tr: a split that leaves a bare suffix holds no domain');
});

test('homoglyphs: ASCII lookalikes and letter pairs, Turkish letters, Cyrillic and Greek as punycode', () => {
  const ascii = only('modl.com', 'homoglyph').filter((n) => !n.startsWith('xn--'));
  assert.deepEqual(ascii, ['nodl.com', 'm0dl.com', 'mobl.com', 'mod1.com', 'modi.com', 'rnodl.com', 'mocll.com', 'nnodl.com']);
  // each Turkish letter in place of its plain one, as Python's punycode codec writes it
  const turkish = generateLookalikes('sigcou.com', { budget: 5000, techniques: ['homoglyph'] }).candidates;
  const tr = { 'şigcou.com': 'xn--igcou-idb.com', 'sıgcou.com': 'xn--sgcou-n4a.com', 'si̇gcou.com': 'xn--sigcou-qyd.com', 'siğcou.com': 'xn--sicou-l1a.com',
    'sigçou.com': 'xn--sigou-0ra.com', 'sigcöu.com': 'xn--sigcu-mua.com', 'sigcoü.com': 'xn--sigco-ova.com' };
  for (const [u, a] of Object.entries(tr)) {
    const c = turkish.find((x) => x.unicode === u);
    assert.ok(c, u);
    assert.equal(c.name, a, u);
    assert.equal(c.idn, true);
  }
  const ex = generateLookalikes('example.com', { budget: 5000, techniques: ['homoglyph'] }).candidates;
  assert.equal(ex.find((c) => c.unicode === 'exаmple.com').name, 'xn--exmple-4nf.com', 'Cyrillic а');
  assert.ok(ex.some((c) => c.unicode === 'exαmple.com'), 'Greek α');
  // a label with Turkish letters: the plain letters first (türkiye → turkiye)
  const fold = generateLookalikes('türkiye.com', { budget: 3, techniques: ['homoglyph'] }).candidates;
  assert.equal(fold[0].name, 'turkiye.com');
  assert.equal(fold[0].idn, false);
});

test('punycode correctness: every IDN candidate is what the URL parser (UTS #46) makes of its Unicode form', () => {
  for (const input of ['example.com', 'sigcou.com.tr', 'türkiye.com', 'paypal.co']) {
    const list = generateLookalikes(input, { budget: LOOKALIKE_MAX_BUDGET }).candidates.filter((c) => c.idn);
    assert.ok(list.length > 5, input);
    for (const c of list) assert.equal(new URL(`http://${c.unicode}/`).hostname, c.name, `${input}: ${c.unicode}`);
  }
  // every lookalike letter is lower case and one a label may hold
  for (const cls of Object.values(HOMOGLYPHS)) {
    for (const glyphs of Object.values(cls)) for (const g of glyphs) assert.ok(labelToAscii(`a${g}b`), g);
  }
});

test('the list: deduplicated (the first technique keeps a name), never the domain itself, round-robin under the budget', () => {
  const all = generateLookalikes('www.example.com', { budget: LOOKALIKE_MAX_BUDGET });
  assert.deepEqual(all.target, { domain: 'example.com', label: 'example', suffix: 'com' });
  assert.equal(new Set(names(all)).size, all.candidates.length, 'no name twice');
  assert.ok(!names(all).includes('example.com'));
  assert.equal(all.total, Object.values(all.byTechnique).reduce((a, b) => a + b, 0));
  assert.deepEqual(Object.keys(all.byTechnique), [...LOOKALIKE_TECHNIQUES]);
  // 'dxample' is a QWERTY slip and a bit flip: the earlier technique keeps it
  assert.equal(all.candidates.find((c) => c.name === 'dxample.com').technique, 'replacement');
  const small = generateLookalikes('example.com', { budget: 13 });
  assert.deepEqual(small.candidates.map((c) => c.technique), [...LOOKALIKE_TECHNIQUES], 'one of each technique first');
  assert.deepEqual(names(small), names(generateLookalikes('example.com', { budget: 50 })).slice(0, 13), 'a larger budget adds to the list');
  assert.deepEqual(small.candidates.map((c) => c.index), [...Array(13).keys()]);
  assert.equal(generateLookalikes('example.com').candidates.length <= LOOKALIKE_DEFAULT_BUDGET, true);
  const long = generateLookalikes('internationalbusinessmachines.com', { budget: 500 });
  assert.deepEqual([long.candidates.length, long.total > 500], [500, true], 'the budget caps the list');
  const huge = generateLookalikes('internationalbusinessmachines.com', { budget: 1e9 });
  assert.equal(huge.candidates.length, Math.min(huge.total, LOOKALIKE_MAX_BUDGET), 'at most every candidate, at most the maximum');
  assert.equal(generateLookalikes('192.0.2.7'), null);
});

test('the user\'s own domains are marked own (never checked, never flagged)', () => {
  const r = generateLookalikes('example.com', { own: ['example.net', 'https://shop.example.org/', 'not a domain'] });
  const own = r.candidates.filter((c) => c.own).map((c) => c.name);
  assert.deepEqual(own, ['example.net', 'example.org']);
  assert.equal(r.own, 2);
  assert.deepEqual(scoreLookalike({ candidate: r.candidates.find((c) => c.own), dns: null }), { level: 'own', score: null, reasons: [] });
});

/* ------------------------------------------------------------------------ */
/* Checks                                                                    */
/* ------------------------------------------------------------------------ */

/** A fake DohClient: `zone[name][type]` = data list; a name not in it is NXDOMAIN; `fail[name|type]` a failure. */
function fakeDns(zone, fail = {}) {
  const calls = [];
  return {
    calls,
    async query(name, type, { signal } = {}) {
      calls.push(`${name}|${type}`);
      if (signal && signal.aborted) throw Object.assign(new Error('Aborted'), { name: 'AbortError' });
      const f = fail[`${name}|${type}`];
      if (f === 'transport') return { ok: false, rcode: null, answers: [], authorities: [], error: 'Network error', errorKind: 'network' };
      if (f) return { ok: true, rcode: f, answers: [], authorities: [] };
      const node = zone[name];
      if (!node) return { ok: true, rcode: 'NXDOMAIN', answers: [], authorities: [] };
      return { ok: true, rcode: 'NOERROR', answers: (node[type] || []).map((data) => ({ name, type, ttl: 300, data })), authorities: [] };
    }
  };
}

const cand = (name, extra = {}) => ({ name, unicode: name, technique: 'omission', registrable: name, idn: false, own: false, index: 0, ...extra });

test('checkCandidate: NXDOMAIN asks nothing more; a name in DNS gets A, AAAA and MX; failures are statuses', async () => {
  const dns = fakeDns({
    'exmple.com': { NS: ['ns1.example.net.', 'NS2.example.net'], A: ['192.0.2.10'], AAAA: ['2001:db8::10'], MX: [{ preference: 10, exchange: 'mx.exmple.com.' }] },
    'nullmx.com': { NS: ['ns1.example.net'], MX: [{ preference: 0, exchange: '' }] },
    'nodeleg.com': { A: ['192.0.2.11'] }
  }, { 'servfail.com|NS': 'SERVFAIL', 'down.com|NS': 'transport', 'exmple.com|MX': 'SERVFAIL' });
  const now = () => NOW;
  const free = await checkCandidate(cand('xample.com'), { dns, now });
  assert.equal(free.state, 'free');
  assert.deepEqual(dns.calls, ['xample.com|NS'], 'one question for a name not in DNS');
  assert.equal((await checkCandidate(cand('nodeleg.com'), { dns, now })).state, 'free', 'no delegation: not registered');
  const reg = await checkCandidate(cand('exmple.com'), { dns, now });
  assert.equal(reg.state, 'registered');
  assert.deepEqual(reg.ns, ['ns1.example.net', 'ns2.example.net']);
  assert.deepEqual(reg.addresses, ['192.0.2.10', '2001:db8::10']);
  assert.deepEqual(reg.mx, [], 'the MX question failed');
  assert.deepEqual(reg.failures.map((f) => [f.lookup, f.source, f.rcode]), [['mx', 'doh', 'SERVFAIL']]);
  const nm = await checkCandidate(cand('nullmx.com'), { dns, now });
  assert.deepEqual([nm.state, nm.mx, nm.nullMx, nm.addresses], ['registered', [], true, []]);
  const sf = await checkCandidate(cand('servfail.com'), { dns, now });
  assert.deepEqual([sf.state, sf.failures[0].lookup, sf.failures[0].rcode], ['failed', 'ns', 'SERVFAIL']);
  const down = await checkCandidate(cand('down.com'), { dns, now });
  assert.deepEqual([down.state, down.failures[0].errorKind, down.failures[0].at], ['failed', 'network', NOW]);
  // a dot split: NS of the registrable domain, A / AAAA / MX of the whole name
  dns.calls.length = 0;
  await checkCandidate(cand('ex.mple.com', { registrable: 'exmple.com', technique: 'subdomain' }), { dns, now });
  assert.deepEqual(dns.calls, ['exmple.com|NS', 'ex.mple.com|A', 'ex.mple.com|AAAA', 'ex.mple.com|MX']);
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(checkCandidate(cand('exmple.com'), { dns, signal: ctl.signal }), { name: 'AbortError' });
});

test('targetFootprint: the domain\'s own name servers and addresses; a failure leaves them empty', async () => {
  const dns = fakeDns({ 'example.com': { NS: ['ns1.example.net'], A: ['192.0.2.1'], AAAA: ['2001:db8::1'] } }, { 'example.org|NS': 'transport' });
  assert.deepEqual(await targetFootprint('example.com', { dns }), { ns: ['ns1.example.net'], addresses: ['192.0.2.1', '2001:db8::1'] });
  assert.deepEqual(await targetFootprint('example.org', { dns }), { ns: [], addresses: [] });
});

const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const RDAP_BASE = 'https://rdap.example.net/';
const rdapBody = (name, created) => ({
  objectClassName: 'domain', ldhName: name.toUpperCase(), status: ['active'],
  events: [{ eventAction: 'registration', eventDate: created }],
  entities: [{ objectClassName: 'entity', roles: ['registrar'], vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'Example Registrar, Inc.']]] }]
});
function fakeRdapFetch(domains, { status = {} } = {}) {
  const calls = [];
  const fetchImpl = async (input) => {
    const url = String(input);
    calls.push(url);
    if (url === IANA_BOOTSTRAP.dns) return json({ services: [[['com', 'net', 'org'], [RDAP_BASE]]] });
    if (url.startsWith(RDAP_BASE)) {
      const name = decodeURIComponent(url.split('/domain/')[1]);
      if (status[name]) return json({ errorCode: status[name] }, status[name]);
      return domains[name] ? json(rdapBody(name, domains[name])) : json({ errorCode: 404 }, 404);
    }
    throw new TypeError(`unexpected ${url}`);
  };
  return { fetchImpl, calls };
}

beforeEach(() => clearRdapCache());

test('lookupRegistration: the registration date and registrar; 404 not found; a TLD without RDAP; a failure with its status', async () => {
  const { fetchImpl } = fakeRdapFetch({ 'exmple.com': '2026-09-30T08:00:00Z' }, { status: { 'broken.com': 503 } });
  const ok = await lookupRegistration('exmple.com', { fetchImpl });
  assert.equal(ok.state, 'ok');
  assert.equal(ok.created.toISOString(), '2026-09-30T08:00:00.000Z');
  assert.equal(ok.registrar, 'Example Registrar, Inc.');
  assert.equal((await lookupRegistration('xample.com', { fetchImpl })).state, 'not-found');
  assert.equal((await lookupRegistration('example.tr', { fetchImpl })).state, 'unsupported');
  const bad = await lookupRegistration('broken.com', { fetchImpl });
  assert.equal(bad.state, 'failed');
  assert.equal(bad.failure.source, 'rdap');
});

test('checkLookalikes: own candidates skipped, RDAP once per registrable domain as each lands in DNS, abort rejects', async () => {
  const dns = fakeDns({
    'exmple.com': { NS: ['ns1.example.net'], A: ['192.0.2.20'] },
    'examp1e.com': { NS: ['ns1.example.net'], MX: [{ preference: 10, exchange: 'mx.example.net' }] }
  });
  const { fetchImpl, calls } = fakeRdapFetch({ 'exmple.com': '2026-09-30T08:00:00Z', 'examp1e.com': '2001-01-01T00:00:00Z' });
  const list = [cand('exmple.com'), cand('examp1e.com'), cand('ex.mple.com', { registrable: 'exmple.com' }), cand('xample.com'), cand('example.net', { own: true })];
  const seenDns = [];
  const seenRdap = [];
  const counts = await checkLookalikes(list, {
    dns, fetchImpl, concurrency: 2, now: () => NOW,
    onDns: (c, r) => seenDns.push(`${c.name}:${r.state}`), onRdap: (c, r) => seenRdap.push(`${c.name}:${r.state}`)
  });
  assert.deepEqual(counts, { checked: 4, registered: 3, failed: 0 });
  assert.deepEqual(seenDns.sort(), ['ex.mple.com:registered', 'examp1e.com:registered', 'exmple.com:registered', 'xample.com:free']);
  assert.deepEqual(seenRdap.sort(), ['ex.mple.com:ok', 'examp1e.com:ok', 'exmple.com:ok']);
  assert.equal(calls.filter((u) => u.startsWith(`${RDAP_BASE}domain/`)).length, 2, 'one RDAP request per registrable domain');
  assert.ok(!dns.calls.some((c) => c.startsWith('example.net')), 'own: never asked');
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(checkLookalikes(list, { dns, fetchImpl, signal: ctl.signal }), { name: 'AbortError' });
});

test('lookupCertificates: one crt.sh search, rows deduplicated, the newest and the issuers; failures are statuses', async () => {
  assert.equal(crtshLookalikeUrl('xn--exmple-4nf.com'), 'https://crt.sh/?q=xn--exmple-4nf.com&output=json&exclude=expired&deduplicate=Y');
  const rows = [
    { issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R11", serial_number: '01', not_before: '2026-10-01T10:00:00' },
    { issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R11", serial_number: '01', not_before: '2026-10-01T10:00:00' },
    { issuer_ca_id: 2, issuer_name: 'C=US, O="Example CA, Inc.", CN=Example CA', serial_number: '02', not_before: '2026-09-01T00:00:00' },
    { issuer_ca_id: 1, issuer_name: "C=US, O=Let's Encrypt, CN=R10", serial_number: '03', not_before: '2026-08-01T00:00:00' }
  ];
  const parsed = parseCrtshRows(rows);
  assert.equal(parsed.count, 3);
  assert.equal(parsed.newest.toISOString(), '2026-10-01T10:00:00.000Z');
  assert.deepEqual(parsed.issuers, ["Let's Encrypt", 'Example CA, Inc.']);
  assert.equal(parseCrtshRows({}), null);
  const urls = [];
  const ok = await lookupCertificates('exmple.com', { fetchImpl: async (u) => { urls.push(String(u)); return json(rows); } });
  assert.deepEqual([ok.state, ok.count], ['ok', 3]);
  assert.deepEqual(urls, [crtshLookalikeUrl('exmple.com')]);
  const down = await lookupCertificates('exmple.com', { fetchImpl: async () => new Response('Bad Gateway', { status: 502 }), now: () => NOW });
  assert.deepEqual([down.state, down.failure.source, down.failure.status, down.failure.at], ['failed', 'crtsh', 502, NOW]);
  const garbage = await lookupCertificates('exmple.com', { fetchImpl: async () => json({ error: 'x' }) });
  assert.deepEqual([garbage.state, garbage.failure.errorKind], ['failed', 'parse']);
  const ctl = new AbortController();
  ctl.abort();
  await assert.rejects(lookupCertificates('exmple.com', { fetchImpl: async () => json(rows), signal: ctl.signal }), { name: 'AbortError' });
});

/* ------------------------------------------------------------------------ */
/* Score, order, export                                                      */
/* ------------------------------------------------------------------------ */

const regDns = (extra = {}) => ({ state: 'registered', ns: ['ns1.example.net'], addresses: [], mx: [], nullMx: false, failures: [], ...extra });

test('scoreLookalike: MX, a web host, a new registration, a certificate and an IDN raise it; the same name servers or addresses lower it', () => {
  const c = cand('exmple.com');
  const target = { ns: ['ns1.example.org'], addresses: ['198.51.100.1'] };
  assert.deepEqual(scoreLookalike({ candidate: c, dns: null }), { level: 'pending', score: null, reasons: [] });
  assert.deepEqual(scoreLookalike({ candidate: c, dns: { state: 'free', ns: [], addresses: [], mx: [], failures: [] } }), { level: 'none', score: 0, reasons: [] });
  assert.deepEqual(scoreLookalike({ candidate: c, dns: { state: 'failed', ns: [], addresses: [], mx: [], failures: [{}] } }).level, 'unknown');
  assert.deepEqual(scoreLookalike({ candidate: c, dns: regDns() }, { target }), { level: 'low', score: 10, reasons: [] });
  const mail = { candidate: c, dns: regDns({ mx: ['mx.example.net'], addresses: ['192.0.2.30'] }) };
  assert.deepEqual(scoreLookalike(mail, { target, now: NOW }), { level: 'high', score: 60, reasons: ['mx', 'web'] });
  const fresh = { ...mail, rdap: { state: 'ok', created: new Date(NOW - 5 * DAY), registrar: 'Example Registrar, Inc.' }, ct: { state: 'ok', count: 2 } };
  assert.deepEqual(scoreLookalike(fresh, { target, now: NOW }), { level: 'high', score: 100, reasons: ['mx', 'web', 'new', 'cert'] });
  const recent = { candidate: c, dns: regDns({ addresses: ['192.0.2.30'] }), rdap: { state: 'ok', created: new Date(NOW - 60 * DAY) } };
  assert.deepEqual(scoreLookalike(recent, { target, now: NOW }), { level: 'medium', score: 45, reasons: ['web', 'recent'] });
  const old = { ...recent, rdap: { state: 'ok', created: new Date(NOW - 400 * DAY) } };
  assert.deepEqual(scoreLookalike(old, { target, now: NOW }).reasons, ['web']);
  const defensive = { candidate: { ...c, idn: true }, dns: regDns({ ns: ['ns1.example.org'], addresses: ['198.51.100.1'] }) };
  assert.deepEqual(scoreLookalike(defensive, { target, now: NOW }), { level: 'low', score: 1, reasons: ['web', 'idn', 'same-ns', 'same-ip'] });
  assert.deepEqual(Object.keys(RISK_WEIGHTS).filter((k) => k !== 'registered'), [...LOOKALIKE_REASONS]);
});

test('sortLookalikes: worst first, then the score, then the list order; lookalikeState', () => {
  const rows = [
    { candidate: cand('free.com', { index: 0 }), dns: { state: 'free', ns: [], addresses: [], mx: [], failures: [] } },
    { candidate: cand('own.com', { index: 1, own: true }), dns: null },
    { candidate: cand('low.com', { index: 2 }), dns: regDns() },
    { candidate: cand('high.com', { index: 3 }), dns: regDns({ mx: ['mx.example.net'], addresses: ['192.0.2.5'] }) },
    { candidate: cand('failed.com', { index: 4 }), dns: { state: 'failed', ns: [], addresses: [], mx: [], failures: [{ lookup: 'ns' }] } },
    { candidate: cand('pending.com', { index: 5 }), dns: null },
    { candidate: cand('medium.com', { index: 6 }), dns: regDns({ mx: ['mx.example.net'] }) },
    { candidate: cand('low2.com', { index: 7 }), dns: regDns() }
  ];
  assert.deepEqual(sortLookalikes(rows).map((r) => r.candidate.name), ['high.com', 'medium.com', 'low.com', 'low2.com', 'failed.com', 'free.com', 'pending.com', 'own.com']);
  assert.deepEqual(rows.map(lookalikeState), ['free', 'own', 'registered', 'registered', 'failed', 'pending', 'registered', 'registered']);
  assert.deepEqual([...LOOKALIKE_STATES].sort(), ['failed', 'free', 'own', 'pending', 'registered']);
  assert.deepEqual([...LOOKALIKE_LEVELS], ['high', 'medium', 'low', 'unknown', 'none', 'pending', 'own']);
});

test('lookalikeCsv: worst first, a failed lookup says n/a, one never made stays empty, cells are formula-safe', () => {
  const rows = [
    { candidate: cand('xample.com', { index: 0 }), dns: { state: 'free', ns: [], addresses: [], mx: [], failures: [] } },
    {
      candidate: cand('xn--exmple-4nf.com', { index: 1, unicode: 'exаmple.com', technique: 'homoglyph', idn: true }),
      dns: regDns({ addresses: ['192.0.2.40'], failures: [{ lookup: 'mx', source: 'doh', rcode: 'SERVFAIL' }] }),
      rdap: { state: 'failed', created: null, registrar: null, failure: { source: 'rdap' } },
      ct: { state: 'ok', count: 1, newest: new Date('2026-10-01T00:00:00Z'), issuers: ["Let's Encrypt"] }
    },
    { candidate: cand('down.com', { index: 2 }), dns: { state: 'failed', ns: [], addresses: [], mx: [], failures: [{ lookup: 'ns' }] } }
  ];
  const csv = lookalikeCsv(rows, { now: NOW });
  const lines = csv.replace(/^﻿/, '').trim().split('\r\n');
  assert.equal(lines[0], LOOKALIKE_CSV_COLUMNS.join(','));
  assert.equal(lines.length, 4);
  assert.ok(lines[1].startsWith('xn--exmple-4nf.com,exаmple.com,homoglyph,registered,medium,45,'), lines[1]);
  const idn = lookalikeExportRow(rows[1], { now: NOW });
  assert.deepEqual([idn.mx, idn.addresses, idn.registered, idn.registrar, idn.certificates, idn.newestCertificate], ['n/a', '192.0.2.40', 'n/a', 'n/a', 1, '2026-10-01']);
  assert.deepEqual(idn.reasons, 'web cert idn');
  const down = lookalikeExportRow(rows[2], { now: NOW });
  assert.deepEqual([down.state, down.risk, down.ns, down.addresses, down.mx, down.registered, down.certificates], ['failed', 'unknown', 'n/a', 'n/a', 'n/a', '', '']);
  assert.ok(lines[2].startsWith('down.com,'), 'failed (unknown) before free (none)');
  assert.ok(lines[3].startsWith('xample.com,xample.com,omission,free,none,0'));
});
