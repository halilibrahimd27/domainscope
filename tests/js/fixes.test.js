// Unit tests for assets/js/lib/fixes.js — pure, no network (a fake DohClient where a read is
// needed). Every template in every format is pinned by the goldens of
// tests/fixtures/fixes/gen-fixes-golden.mjs; the rest checks the pieces one by one.
// Documentation names and addresses only.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FIX_TYPES, FIX_FORMATS, FIX_LIMITS, FIX_CAS, FIX_FIELDS, FIX_I18N, CHANGE_TEMPLATES, TEMPLATE_IDS, CLOUDFLARE_VARS, CHANGE_LINT_CODES,
  HEALTH_FIX_IDS, LINT_FIX_CODES, ACME_TOKEN_RE,
  absoluteName, relativeName, zoneName, txtChunks, normalizeValue, valueKey, valueText, parseValueText, txtFamily, familyOf,
  rrset, rrsetPlan, changeRequest, readPlan, readCurrent, currentEntry, applyCurrent, validateChange, afterZoneText, countSpfLookups,
  renderFix, formatNotes, changeInstructions, editSpf, mergeSpf, editDmarc, buildChange, templateInput, changeTemplate, mailtoUri,
  m365MxHost, healthFix, lintFix, caaFixFromIssuers, currentFromReport, textIn, hasErrors, unreadEdits, rrsetAction
} from '../../assets/js/lib/fixes.js';
import { LINT_I18N } from '../../assets/js/lib/zonelint.js';
import { HEALTH_CHECK_IDS, parseSpf, parseDmarc, parseCaa, checkCaaAllows } from '../../assets/js/lib/health.js';
import { parseZone } from '../../assets/js/lib/zoneparse.js';
import { lintZone } from '../../assets/js/lib/zonelint.js';
import { CASES, caseGolden, goldenPath, FIXES_DIR } from '../fixtures/fixes/gen-fixes-golden.mjs';

const TOKEN = 'gfj9Xq3Wr1Bm5zQXxZrW1zFeI6nY6cRgO0sIkWQfVbk';

/** A fake DohClient answering from a table: 'name|TYPE' → { rcode?, answers: [{ name, type, ttl, data }] }. */
function fakeDns(table, log = []) {
  return {
    async query(name, type, opts = {}) {
      log.push({ name, type, ...opts });
      const hit = table[`${name}|${type}`];
      if (hit === 'error') return { ok: false, rcode: null, answers: [], authorities: [], errorKind: 'network', error: 'down' };
      if (!hit) return { ok: true, rcode: 'NOERROR', answers: [], authorities: [] };
      return { ok: true, rcode: hit.rcode || 'NOERROR', answers: hit.answers || [], authorities: hit.authorities || [] };
    }
  };
}

/** Files reached from `entry` through static imports (as tests/js/start-route.test.js reads them). */
function staticGraph(entry) {
  const seen = new Set();
  const queue = [entry];
  while (queue.length) {
    const file = queue.shift();
    if (seen.has(file)) continue;
    seen.add(file);
    const src = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    for (const m of src.matchAll(/(?:^|[;\n])\s*(?:import|export)\s[^;'"]*?\bfrom\s*(['"])([^'"]+)\1/g)) queue.push(resolve(dirname(file), m[2]));
  }
  return [...seen].map((f) => f.split(/[\\/]/).slice(-2).join('/'));
}

describe('what lib/fixes.js loads', () => {
  test('the shared string helpers come from lib/zonetext.js: never the zone converter, the diff or the export library', () => {
    const graph = staticGraph(resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'assets', 'js', 'lib', 'fixes.js'));
    assert.ok(graph.includes('lib/zonetext.js'), graph.join(' '));
    assert.deepEqual(graph.filter((f) => ['lib/zoneconvert.js', 'lib/zonediff.js', 'lib/export.js'].includes(f)), []);
  });
});

describe('goldens: every template in every format and both languages', () => {
  test('each case matches its golden (node tests/fixtures/fixes/gen-fixes-golden.mjs --write after a deliberate change)', () => {
    for (const c of CASES) {
      const expected = readFileSync(goldenPath(c.id), 'utf8').replace(/\r\n/g, '\n');
      assert.equal(caseGolden(c), expected, c.id);
    }
  });

  test('every template has a golden, and no golden is left without a case', () => {
    const covered = new Set(CASES.filter((c) => c.template).map((c) => c.template));
    for (const id of TEMPLATE_IDS) assert.ok(covered.has(id), `no golden for template ${id}`);
    const files = readdirSync(join(FIXES_DIR, 'expected')).filter((f) => f.endsWith('.golden.txt')).map((f) => f.replace('.golden.txt', ''));
    assert.deepEqual(files.sort(), CASES.map((c) => c.id).sort());
  });

  test('the goldens are deterministic (built twice, the same)', () => {
    for (const c of CASES) assert.equal(caseGolden(c), caseGolden(c), c.id);
  });
});

describe('names', () => {
  test('zoneName: a host name, never an address, a single label or a service label', () => {
    assert.equal(zoneName('Example.COM.'), 'example.com');
    assert.equal(zoneName('sub.example.com'), 'sub.example.com');
    for (const bad of ['', '192.0.2.1', '[2001:db8::1]', 'localhost', '_dmarc.example.com', 'exa mple.com', null]) assert.equal(zoneName(bad), null, String(bad));
  });

  test('absoluteName: @, relative, absolute, wildcards, and a dotted name outside the zone is an error', () => {
    assert.deepEqual(absoluteName('@', 'example.com'), { name: 'example.com', error: null });
    assert.deepEqual(absoluteName('', 'example.com'), { name: 'example.com', error: null });
    assert.deepEqual(absoluteName('www', 'example.com'), { name: 'www.example.com', error: null });
    assert.deepEqual(absoluteName('_acme-challenge.www', 'example.com'), { name: '_acme-challenge.www.example.com', error: null });
    assert.deepEqual(absoluteName('WWW.Example.com.', 'example.com'), { name: 'www.example.com', error: null });
    assert.deepEqual(absoluteName('*.dev', 'example.com'), { name: '*.dev.example.com', error: null });
    assert.deepEqual(absoluteName('*.dev', 'example.com', { wildcard: false }), { name: null, error: 'invalid' });
    assert.deepEqual(absoluteName('www.example.net', 'example.com'), { name: null, error: 'outside' });
    assert.deepEqual(absoluteName('shop.eu', 'example.com'), { name: null, error: 'outside' });
    assert.deepEqual(absoluteName('mail.', 'example.com'), { name: null, error: 'outside' });
    assert.equal(absoluteName('a b', 'example.com').name, null);
  });

  test('relativeName: @ for the apex, the labels below it, a name outside kept absolute', () => {
    assert.equal(relativeName('example.com', 'example.com'), '@');
    assert.equal(relativeName('_dmarc.example.com', 'example.com'), '_dmarc');
    assert.equal(relativeName('www.example.net', 'example.com'), 'www.example.net.');
  });
});

describe('values', () => {
  test('normalizeValue per type, null for anything else', () => {
    assert.equal(normalizeValue('A', '192.0.2.1'), '192.0.2.1');
    assert.equal(normalizeValue('A', '2001:db8::1'), null);
    assert.equal(normalizeValue('AAAA', '2001:DB8:0::1'), '2001:db8::1');
    assert.equal(normalizeValue('AAAA', '192.0.2.1'), null);
    assert.equal(normalizeValue('CNAME', 'Target.Example.NET.'), 'target.example.net');
    assert.equal(normalizeValue('CNAME', '*.example.net'), null);
    assert.deepEqual(normalizeValue('MX', { preference: 0, exchange: '.' }), { preference: 0, exchange: '' });
    assert.deepEqual(normalizeValue('MX', { preference: '10', exchange: 'Mail.example.com' }), { preference: 10, exchange: 'mail.example.com' });
    assert.equal(normalizeValue('MX', { preference: 70000, exchange: 'mail.example.com' }), null);
    assert.deepEqual(normalizeValue('CAA', { flags: 0, tag: 'ISSUE', value: 'letsencrypt.org' }), { flags: 0, tag: 'issue', value: 'letsencrypt.org' });
    assert.equal(normalizeValue('CAA', { flags: 300, tag: 'issue', value: 'x' }), null);
    assert.equal(normalizeValue('CAA', { flags: 0, tag: 'is-sue', value: 'x' }), null);
    assert.equal(normalizeValue('TXT', 'x'.repeat(FIX_LIMITS.valueBytes + 1)), null);
    assert.equal(normalizeValue('NS', 'ns1.example.com'), null);
  });

  test('txtChunks: 255 bytes at most, never splitting a UTF-8 character', () => {
    assert.deepEqual(txtChunks(''), ['']);
    assert.deepEqual(txtChunks('a'.repeat(255)), ['a'.repeat(255)]);
    assert.deepEqual(txtChunks('a'.repeat(256)), ['a'.repeat(255), 'a']);
    const chunks = txtChunks(`${'a'.repeat(254)}ş${'b'.repeat(3)}`);
    assert.deepEqual(chunks, ['a'.repeat(254), `ş${'b'.repeat(3)}`], 'ş (2 bytes) does not fit in the last byte');
    for (const c of txtChunks('ğüşiöç'.repeat(100))) assert.ok(new TextEncoder().encode(c).length <= 255);
  });

  test('valueKey compares TXT by its joined text, other types as live answers do', () => {
    assert.equal(valueKey('TXT', ['ab', 'c']), valueKey('TXT', ['a', 'bc']));
    assert.equal(valueKey('MX', { preference: 0, exchange: '' }), valueKey('MX', { preference: 0, exchange: '.' }));
    assert.equal(valueKey('CNAME', 'a.example.net'), valueKey('CNAME', 'a.example.net.'));
    assert.notEqual(valueKey('CAA', { flags: 0, tag: 'issue', value: 'a' }), valueKey('CAA', { flags: 128, tag: 'issue', value: 'a' }));
  });

  test('valueText writes what the zone parser reads back, for every type', () => {
    const samples = {
      A: '192.0.2.1', AAAA: '2001:db8::1', CNAME: 'target.example.net', MX: { preference: 0, exchange: '' },
      TXT: txtChunks(`quote " back \\ semi ; ${'x'.repeat(300)} ş`), CAA: { flags: 128, tag: 'issue', value: 'letsencrypt.org; validationmethods=dns-01' }
    };
    for (const type of FIX_TYPES) {
      const text = valueText(type, samples[type]);
      const back = parseValueText(type, text, 'example.com');
      assert.equal(valueKey(type, back), valueKey(type, samples[type]), `${type}: ${text}`);
    }
    assert.equal(valueText('MX', { preference: 0, exchange: '' }), '0 .');
    assert.equal(parseValueText('A', '192.0.2.1\n@ A 192.0.2.2', 'example.com'), null, 'one line only');
    assert.equal(parseValueText('A', 'not-an-ip', 'example.com'), null);
    assert.equal(parseValueText('SOA', 'x', 'example.com'), null);
  });

  test('txtFamily / familyOf: the v= kind a TXT value (list) shares', () => {
    assert.equal(txtFamily('v=spf1 -all'), 'spf1');
    assert.equal(txtFamily(['v=DMARC1; ', 'p=none']), 'dmarc1');
    assert.equal(txtFamily('v=TLSRPTv1; rua=mailto:tls@example.com'), 'tlsrptv1');
    assert.equal(txtFamily('v=spf10'), null);
    assert.equal(txtFamily('google-site-verification=abc'), null);
    assert.equal(familyOf('TXT', ['v=spf1 -all']), 'spf1');
    assert.equal(familyOf('TXT', ['v=spf1 -all', 'other']), null);
    assert.equal(familyOf('CAA', [{}]), null);
  });

  test('mailtoUri and the Microsoft 365 MX host', () => {
    assert.equal(mailtoUri('DMARC@Example.com'), 'mailto:DMARC@example.com');
    assert.equal(mailtoUri('mailto:dmarc@example.com'), 'mailto:dmarc@example.com');
    for (const bad of ['', 'dmarc', 'a@b@example.com', 'a b@example.com', 'x@', 'x@exa mple.com']) assert.equal(mailtoUri(bad), null, bad);
    assert.equal(m365MxHost('example.com'), 'example-com.mail.protection.outlook.com');
  });
});

describe('record-set plans', () => {
  const A = (v) => rrset({ name: 'www.example.com', type: 'A', ...v });

  test('is: add what is new, remove what goes; unknown current values stay unknown', () => {
    assert.deepEqual(rrsetPlan(A({ values: ['192.0.2.1'], before: ['198.51.100.5'] })),
      { add: ['192.0.2.1'], remove: ['198.51.100.5'], keep: [], after: ['192.0.2.1'], full: ['192.0.2.1'], ttlOnly: false, rewrite: false, unchanged: false, complete: true });
    const unread = rrsetPlan(A({ values: ['192.0.2.1'] }));
    assert.equal(unread.remove, null);
    assert.deepEqual(unread.add, ['192.0.2.1']);
    assert.ok(unread.complete, 'the whole set is known: exactly these values');
  });

  test('has: keeps what is there; the full set is known only after a read', () => {
    const p = rrsetPlan(rrset({ name: 'x.example.com', type: 'TXT', mode: 'has', values: ['new'], before: ['old'] }));
    assert.deepEqual(p.add.map((v) => v.join('')), ['new']);
    assert.deepEqual(p.full.map((v) => v.join('')), ['old', 'new']);
    assert.equal(rrsetPlan(rrset({ name: 'x.example.com', type: 'TXT', mode: 'has', values: ['new'] })).complete, false);
  });

  test('none: removes the current values (unknown before a read)', () => {
    assert.deepEqual(rrsetPlan(A({ mode: 'none', before: ['192.0.2.1'] })).remove, ['192.0.2.1']);
    assert.equal(rrsetPlan(A({ mode: 'none' })).remove, null);
    assert.equal(rrsetPlan(A({ mode: 'none', before: [] })).unchanged, true, 'nothing there: nothing to delete');
  });

  test('a family set: its other TXT values are part of the full set only once read', () => {
    const r = rrset({ name: 'example.com', type: 'TXT', values: ['v=spf1 -all'], before: ['v=spf1 ~all'], others: ['site-verification=1'] });
    assert.equal(r.family, 'spf1');
    assert.deepEqual(rrsetPlan(r).full.map((v) => v.join('')), ['site-verification=1', 'v=spf1 -all']);
    assert.equal(rrsetPlan(rrset({ name: 'example.com', type: 'TXT', values: ['v=spf1 -all'] })).complete, false);
  });

  test('a TTL change counts only when asked for (maxTtl) or from the zone file; a resolver TTL never does', () => {
    assert.equal(rrsetPlan(A({ values: ['192.0.2.1'], before: ['192.0.2.1'], ttl: 300, maxTtl: 300 })).ttlOnly, true);
    assert.equal(rrsetPlan(A({ values: ['192.0.2.1'], before: ['192.0.2.1'], ttl: 300, beforeTtl: 5 })).ttlOnly, true);
    assert.equal(rrsetPlan(A({ values: ['192.0.2.1'], before: ['192.0.2.1'], ttl: 300 })).unchanged, true);
  });

  test('rrset: canonical, de-duplicated values; defaults', () => {
    const r = rrset({ name: 'WWW.example.com.', type: 'a', values: ['192.0.2.1', '192.0.2.1', 'bogus'] });
    assert.deepEqual([r.name, r.type, r.values, r.mode, r.ttl, r.before], ['www.example.com', 'A', ['192.0.2.1'], 'is', 3600, null]);
    assert.equal(rrset({ name: 'x.example.com', type: 'A', ttl: '0' }).ttl, 3600, 'TTL 0 falls back');
  });
});

describe('change requests, reads and validation', () => {
  test('changeRequest merges sets of one name, type and family, and caps them', () => {
    const req = changeRequest({ zone: 'example.com', rrsets: [
      { name: 'a.example.com', type: 'A', values: ['192.0.2.1'] }, { name: 'a.example.com', type: 'A', values: ['192.0.2.2'] }
    ] });
    assert.equal(req.rrsets.length, 1);
    assert.deepEqual(req.rrsets[0].values, ['192.0.2.1', '192.0.2.2']);
    const many = changeRequest({ zone: 'example.com', rrsets: Array.from({ length: 25 }, (_, i) => ({ name: `h${i}.example.com`, type: 'A', values: ['192.0.2.1'] })) });
    assert.equal(many.rrsets.length, FIX_LIMITS.rrsets);
    assert.ok(hasErrors(many));
  });

  test('readPlan: each set, and at its name what a CNAME would clash with', () => {
    const req = changeRequest({ zone: 'example.com', rrsets: [{ name: 'www.example.com', type: 'CNAME', values: ['t.example.net'] }, { name: 'example.com', type: 'TXT', values: ['x'] }] });
    assert.deepEqual(readPlan(req).map((q) => `${q.name} ${q.type}`), [
      'www.example.com CNAME', 'www.example.com A', 'www.example.com AAAA', 'www.example.com TXT', 'www.example.com MX', 'example.com TXT', 'example.com CNAME'
    ]);
  });

  test('readCurrent / currentEntry: the name\'s own records, a CNAME noted, NXDOMAIN and failures told apart', async () => {
    const log = [];
    const dns = fakeDns({
      'www.example.com|A': { answers: [{ name: 'www.example.com', type: 'CNAME', ttl: 60, data: 'edge.example.net' }, { name: 'edge.example.net', type: 'A', ttl: 60, data: '192.0.2.9' }] },
      'gone.example.com|A': { rcode: 'NXDOMAIN' },
      'down.example.com|A': 'error',
      'example.com|TXT': { answers: [{ name: 'example.com', type: 'TXT', ttl: 300, data: ['v=spf1 ', '-all'] }, { name: 'example.com', type: 'TXT', ttl: 200, data: ['x'] }] }
    }, log);
    const cur = await readCurrent([{ name: 'www.example.com', type: 'A' }, { name: 'gone.example.com', type: 'A' }, { name: 'down.example.com', type: 'A' }, { name: 'example.com', type: 'TXT' }], { dns });
    assert.deepEqual(cur['www.example.com|A'], { status: 'nodata', values: [], ttl: null, cname: 'edge.example.net' });
    assert.equal(cur['gone.example.com|A'].status, 'nxdomain');
    assert.equal(cur['down.example.com|A'].status, 'error');
    assert.deepEqual(cur['example.com|TXT'].values.map((v) => v.join('')), ['v=spf1 -all', 'x']);
    assert.equal(cur['example.com|TXT'].ttl, 200);
    assert.ok(log.every((q) => q.noCache === true), 'a read never answers from the cache');
    assert.deepEqual(currentEntry({ ok: true, rcode: 'SERVFAIL', answers: [] }, 'x.example.com', 'A').status, 'error');
  });

  test('applyCurrent fills before / others per family, never the resolver TTL', () => {
    const req = changeRequest({ zone: 'example.com', rrsets: [{ name: 'example.com', type: 'TXT', values: ['v=spf1 -all'] }] });
    const cur = { 'example.com|TXT': { status: 'ok', values: [['v=spf1 ~all'], ['verify=1']], ttl: 77, cname: null } };
    const r = applyCurrent(req, cur).rrsets[0];
    assert.deepEqual([r.before.map((v) => v.join('')), r.others.map((v) => v.join('')), r.beforeTtl], [['v=spf1 ~all'], ['verify=1'], null]);
    assert.equal(applyCurrent(req, { 'example.com|TXT': { status: 'error', values: [] } }).rrsets[0].before, null, 'a failed read stays unknown');
  });

  test('validateChange: the zone linter over the records after the change, with what the read found at the same names', () => {
    const req = buildChange('record', { name: 'www.example.com', type: 'CNAME', values: 'edge.example.net' });
    assert.deepEqual(validateChange(req), [], 'alone, a CNAME is fine');
    const cur = { 'www.example.com|A': { status: 'ok', values: ['192.0.2.1'], ttl: 300, cname: null } };
    const probs = validateChange(req, { current: cur });
    assert.deepEqual(probs.map((p) => [p.severity, p.key]), [['error', 'zone.lint.CNAME_AND_OTHER_DATA']]);
    assert.match(afterZoneText(req, cur), /www\.example\.com\. 300 IN A 192\.0\.2\.1/);
  });

  test('validateChange: private addresses, CAA flags and tags, SPF / DMARC syntax, the SPF lookup budget, TTL bounds', () => {
    const req = changeRequest({ zone: 'example.com', rrsets: [
      { name: 'intranet.example.com', type: 'A', values: ['10.0.0.5'], ttl: 20 },
      { name: 'example.com', type: 'CAA', values: [{ flags: 1, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'isue', value: 'x' },
        { flags: 0, tag: 'issue', value: 'letsencrypt.org; validationmethods=' }, { flags: 0, tag: 'issue', value: 'letsencrypt.org; accounturi=x y' }] },
      { name: 'example.com', type: 'TXT', values: [`v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:s${i}.example.net`).join(' ')} -all`], ttl: 100000 },
      { name: '_dmarc.example.com', type: 'TXT', values: ['v=DMARC1; p=maybe'] }
    ] });
    const spfRecord = req.rrsets.find((r) => r.family === 'spf1').values[0].join('');
    const keys = validateChange(req, { spf: { 'example.com': { record: spfRecord, count: 14, exceeded: true } } }).map((p) => p.key);
    for (const k of ['zone.lint.PRIVATE_IP', 'zone.lint.CAA_FLAGS', 'zone.lint.CAA_UNKNOWN_TAG', 'zone.lint.DMARC_INVALID', 'fix.p.caa-malformed',
      'fix.p.spf-terms', 'fix.p.spf-lookups-over', 'fix.p.ttl-low', 'fix.p.ttl-high']) assert.ok(keys.includes(k), k);
    assert.ok(keys.indexOf('fix.p.ttl-low') > keys.indexOf('fix.p.spf-terms'), 'errors before info');
    for (const code of CHANGE_LINT_CODES) assert.ok(LINT_I18N.en[`zone.lint.${code}`], code);
  });

  test('countSpfLookups: the proposed record, its includes as published now', async () => {
    const req = changeRequest({ zone: 'example.com', rrsets: [{ name: 'example.com', type: 'TXT', values: ['v=spf1 include:_spf.example.net -all'] }] });
    const dns = fakeDns({ '_spf.example.net|TXT': { answers: [{ name: '_spf.example.net', type: 'TXT', ttl: 300, data: ['v=spf1 include:a.example.net include:b.example.net ~all'] }] },
      'a.example.net|TXT': { answers: [{ name: 'a.example.net', type: 'TXT', ttl: 300, data: ['v=spf1 ip4:192.0.2.0/24 ~all'] }] },
      'b.example.net|TXT': { answers: [{ name: 'b.example.net', type: 'TXT', ttl: 300, data: ['v=spf1 ip4:198.51.100.0/24 ~all'] }] } });
    const out = await countSpfLookups(req, { dns });
    assert.deepEqual(out, { 'example.com': { record: 'v=spf1 include:_spf.example.net -all', count: 3, exceeded: false, error: null } });
    assert.deepEqual(validateChange(req, { spf: out }).map((p) => [p.severity, p.key, p.params.count]), [['info', 'fix.p.spf-lookups-ok', 3]]);
  });

  test('a lookup count belongs to the record it counted: the form changed after the read asks to read again', async () => {
    const cur = { 'example.com|TXT': { status: 'ok', values: [['v=spf1 ~all']], ttl: 300, cname: null } };
    const dns = fakeDns({ '_spf.google.com|TXT': { answers: [{ name: '_spf.google.com', type: 'TXT', ttl: 300, data: ['v=spf1 include:a.example.net ~all'] }] } });
    const at = buildChange('spf', { domain: 'example.com', includes: '_spf.google.com' }, { current: cur });
    const spf = await countSpfLookups(at, { dns });
    assert.equal(spf['example.com'].count, 2);
    assert.ok(validateChange(at, { current: cur, spf }).some((p) => p.key === 'fix.p.spf-lookups-ok'), 'the record it counted');
    // Edited without a new read: an include that costs ten lookups more.
    const edited = buildChange('spf', { domain: 'example.com', includes: '_spf.google.com\nmany.example.net' }, { current: cur });
    const probs = validateChange(edited, { current: cur, spf });
    assert.ok(!probs.some((p) => p.key.startsWith('fix.p.spf-lookups-')), 'no count of another record');
    assert.deepEqual(probs.filter((p) => p.key === 'fix.p.spf-recount').map((p) => [p.severity, p.params]), [['info', { name: 'example.com' }]]);
  });
});

describe('formats', () => {
  const req = buildChange('record', { name: 'www.example.com', type: 'A', values: '192.0.2.10' });

  test('every format renders every template without throwing; an unknown format is refused', () => {
    for (const c of CASES) {
      const r = c.request ? c.request() : buildChange(c.template, c.input);
      for (const f of FIX_FORMATS) assert.equal(typeof renderFix(r, f), 'string', `${c.id} ${f}`);
    }
    assert.throws(() => renderFix(req, 'pdf'), RangeError);
  });

  test('the Cloudflare script never holds a secret: the token and zone ID come from shell variables it names', () => {
    for (const c of CASES) {
      const text = renderFix(c.request ? c.request() : buildChange(c.template, c.input), 'cloudflare');
      assert.match(text, new RegExp(`\\$\\{${CLOUDFLARE_VARS.token}:\\?`));
      assert.match(text, new RegExp(`\\$\\{${CLOUDFLARE_VARS.zone}:\\?`));
      assert.doesNotMatch(text, /Bearer [A-Za-z0-9_-]{20,}/, c.id);
      for (const l of text.split('\n').filter((x) => x.includes('--data '))) assert.match(l, /--data '[\x20-\x7e]*'$/, 'ASCII, single-quoted');
    }
  });

  test('Route 53 writes non-ASCII TXT bytes as octal escapes and splits strings over 255 bytes', () => {
    const r = buildChange('record', { name: 'x.example.com', type: 'TXT', values: `café ${'a'.repeat(300)}` });
    const batch = JSON.parse(renderFix(r, 'route53'));
    const value = batch.Changes[0].ResourceRecordSet.ResourceRecords[0].Value;
    assert.match(value, /^"caf\\303\\251 a+" "a+"$/);
  });

  test('Terraform escapes HCL interpolation and quotes; aws_route53_record splits long TXT with ""', () => {
    const r = buildChange('record', { name: 'x.example.com', type: 'TXT', values: 'a ${b} %{c} "d"' });
    assert.match(renderFix(r, 'terraform-cloudflare'), /content {2}= "a \$\$\{b\} %%\{c\} \\"d\\""/);
    const long = buildChange('record', { name: 'x.example.com', type: 'TXT', values: 'b'.repeat(300) });
    assert.match(renderFix(long, 'terraform-route53'), /records = \["b{255}\\"\\"b{45}"\]/);
  });

  test('aws_route53_record writes a TXT string as Route 53 reads it, like the change batch: " and \\ escaped, non-ASCII in octal', () => {
    const r = buildChange('record', { name: 'x.example.com', type: 'TXT', values: '"say \\"hi\\" path=C:\\\\tmp café"' });
    const batch = JSON.parse(renderFix(r, 'route53')).Changes[0].ResourceRecordSet.ResourceRecords[0].Value;
    assert.equal(batch, '"say \\"hi\\" path=C:\\\\tmp caf\\303\\251"');
    // The provider wraps the HCL string in quotes as it is and sends that: the change batch's value.
    const tf = renderFix(r, 'terraform-route53').match(/records = \[(".*")\]/)[1];
    assert.equal(`"${JSON.parse(tf)}"`, batch);
  });

  test('octoDNS escapes ; in TXT values and quotes YAML specials; the apex is \'\'', () => {
    const r = buildChange('record', { name: 'example.com', type: 'TXT', values: "v=DMARC1; p=none; it's" });
    const y = renderFix(r, 'octodns');
    assert.match(y, /^'':$/m);
    assert.match(y, /- 'v=DMARC1\\; p=none\\; it''s'$/m);
  });

  test('octoDNS: a TXT value with " " inside is noted in the file and in the notes (octoDNS deletes it as it loads it)', () => {
    const r = buildChange('record', { name: 'q.example.com', type: 'TXT', values: '"say \\"hi\\" \\"there\\""' });
    const y = renderFix(r, 'octodns');
    assert.match(y, /^ {2}# octoDNS deletes " " inside a TXT value as it loads it: [^\n]+\n(?: {2}[^\n]*\n)*? {6}- 'say "hi" "there"'$/m, y);
    assert.ok(formatNotes(r, 'octodns').some((n) => n.key === 'fix.fn.octodns-quote' && n.params.name === 'q.example.com'));
    assert.ok(!formatNotes(r, 'bind').some((n) => n.key === 'fix.fn.octodns-quote'), 'BIND takes it as it is');
    const plain = buildChange('record', { name: 'q.example.com', type: 'TXT', values: 'v=spf1 -all' });
    assert.ok(!/deletes " "/.test(renderFix(plain, 'octodns')) && !formatNotes(plain, 'octodns').some((n) => n.key === 'fix.fn.octodns-quote'));
  });

  test('octoDNS: a TXT value with ; says to load it with escaped_semicolons: true; one that starts with a quote goes in one more pair', () => {
    const y = renderFix(buildChange('record', { name: 'example.com', type: 'TXT', values: 'v=DMARC1; p=none' }), 'octodns');
    assert.match(y, /^# TXT values write ; as \\; : the YamlProvider needs escaped_semicolons: true/m);
    assert.ok(!/escaped_semicolons/.test(renderFix(buildChange('record', { name: 'example.com', type: 'TXT', values: 'v=spf1 -all' }), 'octodns')), 'no ; no line');
    assert.match(renderFix(buildChange('record', { name: 'q.example.com', type: 'TXT', values: '"\\"quoted\\""' }), 'octodns'), /^ {6}- '""quoted""'$/m, 'the text "quoted", quotes and all');
  });

  test('octoDNS: keys in its natural order (ttl, type, values; the names too), TXT as raw text, lenient where its own check refuses the text', () => {
    const y = renderFix(buildChange('record', { name: 'www.example.com', type: 'TXT', values: 'café a\\b' }), 'octodns');
    assert.match(y, /^www:\n {2}# octoDNS's check refuses this text [^\n]+\n {2}- octodns:\n {6}lenient: true\n {4}ttl: 3600\n {4}type: TXT\n {4}values:\n {6}- "caf\\xe9 a\\\\b"$/m, 'ASCII only: the é escaped');
    const plain = renderFix(buildChange('record', { name: 'www.example.com', type: 'A', values: '192.0.2.10' }), 'octodns');
    assert.match(plain, /^www:\n {2}- ttl: 3600\n {4}type: A\n {4}values:\n {6}- '192\.0\.2\.10'$/m);
    const names = renderFix(buildChange('m365', { domain: 'example.com', tenant: 'example' }), 'octodns').split('\n').filter((l) => /^\S.*:$/.test(l));
    assert.deepEqual(names, ["'':", '_dmarc:', 'autodiscover:'], '_ sorts before letters');
  });

  test('formatNotes: a whole-set format says what was not read; a Route 53 DELETE must match exactly', () => {
    const unread = buildChange('acme-txt', { name: 'example.com', tokens: TOKEN });
    assert.deepEqual(formatNotes(unread, 'route53').map((n) => n.key), ['fix.fn.incomplete']);
    assert.deepEqual(formatNotes(unread, 'bind'), []);
    const del = changeRequest({ zone: 'example.com', rrsets: [{ name: 'old.example.com', type: 'A', mode: 'none', before: ['192.0.2.1'] }] });
    assert.deepEqual(formatNotes(del, 'route53').map((n) => n.key), ['fix.fn.route53-delete']);
    const low = buildChange('record', { name: 'www.example.com', type: 'A', values: '192.0.2.1', ttl: '30' });
    assert.ok(formatNotes(low, 'cloudflare').some((n) => n.key === 'fix.fn.cloudflare-ttl'));
  });

  test('a one-for-one replacement is changed in place on Cloudflare (never two SPF records at once)', () => {
    const r = changeRequest({ zone: 'example.com', rrsets: [{ name: 'example.com', type: 'TXT', values: ['v=spf1 -all'], before: ['v=spf1 ~all'], others: [] }] });
    const text = renderFix(r, 'cloudflare');
    assert.match(text, /# 1\. Change example\.com TXT \(SPF\): "v=spf1 ~all" -> "v=spf1 -all"/);
    assert.doesNotMatch(text, /-X POST/);
    assert.match(text, /-X PATCH "\$API\/RECORD_ID"/);
  });

  test('an unchanged set is left out of BIND, Route 53, Cloudflare and the instructions', () => {
    const r = changeRequest({ zone: 'example.com', rrsets: [{ name: 'www.example.com', type: 'A', values: ['192.0.2.1'], before: ['192.0.2.1'] }] });
    assert.doesNotMatch(renderFix(r, 'bind'), /IN A/);
    assert.deepEqual(JSON.parse(renderFix(r, 'route53')).Changes, []);
    assert.doesNotMatch(renderFix(r, 'cloudflare'), /curl/);
    assert.match(changeInstructions(r), /Nothing to change/);
  });
});

describe('instructions', () => {
  test('English and Turkish: one numbered step per set, the notes, the check link', () => {
    const req = buildChange('parked', { domain: 'example.org' });
    const en = changeInstructions(req, { lang: 'en', checkUrl: 'https://example.github.io/domainscope/#/change/check?z=example.org' });
    const tr = changeInstructions(req, { lang: 'tr' });
    assert.match(en, /^DNS change request: example\.org\n/);
    assert.equal((en.match(/^\d+\. /gm) || []).length, 4);
    assert.equal((tr.match(/^\d+\. /gm) || []).length, 4);
    assert.match(tr, /^DNS değişiklik talebi: example\.org\n/);
    assert.match(en, /check\?z=example\.org\n$/);
    assert.doesNotMatch(tr, /check\?/);
    assert.equal(changeInstructions(req, { lang: 'de' }), changeInstructions(req, { lang: 'en' }), 'an unknown language writes English');
  });

  test('textIn: either language whatever the UI\'s, params filled, unknown params kept visible', () => {
    assert.equal(textIn('tr', 'fix.ins.name'), 'Ad');
    assert.equal(textIn('en', 'fix.ins.title', { zone: 'example.com' }), 'DNS change request: example.com');
    assert.equal(textIn('en', 'fix.ins.title'), 'DNS change request: {zone}');
    assert.equal(textIn('en', 'no.such.key'), 'no.such.key');
  });
});

describe('SPF and DMARC editing', () => {
  test('editSpf: an include before all / redirect, once; removal; the all qualifier', () => {
    assert.equal(editSpf('v=spf1 mx ~all', { add: ['_spf.example.net'] }).record, 'v=spf1 mx include:_spf.example.net ~all');
    assert.equal(editSpf('v=spf1 mx redirect=_spf.example.org', { add: ['a.example.net'] }).record, 'v=spf1 mx include:a.example.net redirect=_spf.example.org');
    assert.deepEqual(editSpf('v=spf1 include:A.example.net ~all', { add: ['a.example.net'] }).present, ['a.example.net']);
    const rm = editSpf('v=spf1 include:a.example.net +include:b.example.net ~all', { remove: ['b.example.net', 'c.example.net'] });
    assert.deepEqual([rm.record, rm.removed, rm.missing], ['v=spf1 include:a.example.net ~all', ['b.example.net'], ['c.example.net']]);
    assert.equal(editSpf('v=spf1 mx +all', { all: '-all' }).record, 'v=spf1 mx -all');
    assert.equal(editSpf('v=spf1 mx redirect=x.example.net', { all: '~all' }).record, 'v=spf1 mx ~all', 'an all replaces a redirect');
    assert.equal(editSpf('', { add: ['a.example.net'] }).record, 'v=spf1 include:a.example.net');
  });

  test('mergeSpf: every term once, the strictest all last', () => {
    assert.equal(mergeSpf(['v=spf1 include:a.example.net ~all', 'v=spf1 ip4:192.0.2.0/24 include:a.example.net -all']),
      'v=spf1 include:a.example.net ip4:192.0.2.0/24 -all');
    assert.equal(mergeSpf(['v=spf1 mx', 'v=spf1 redirect=_spf.example.net']), 'v=spf1 mx redirect=_spf.example.net');
    assert.equal(mergeSpf(['v=spf1 +all', 'v=spf1 a']), 'v=spf1 a +all');
    assert.ok(parseSpf(mergeSpf(['v=spf1 a -all', 'v=spf1 mx ?all'])).valid);
  });

  test('mergeSpf keeps exp= and unknown modifiers, each once (the first record\'s value)', () => {
    assert.equal(mergeSpf(['v=spf1 a exp=explain.example.com -all', 'v=spf1 mx x-note=1 ~all']), 'v=spf1 a mx -all exp=explain.example.com x-note=1');
    assert.equal(mergeSpf(['v=spf1 a exp=a.example.com X-Note=1 -all', 'v=spf1 mx exp=b.example.net x-note=2 ~all']), 'v=spf1 a mx -all exp=a.example.com X-Note=1');
    assert.equal(mergeSpf(['v=spf1 a redirect=_spf.example.net', 'v=spf1 mx -all exp=e.example.com']), 'v=spf1 a mx -all exp=e.example.com', 'an all voids the redirect, never the exp');
    assert.ok(parseSpf(mergeSpf(['v=spf1 a exp=explain.example.com -all', 'v=spf1 mx exp=other.example.com ~all'])).valid, 'one exp= only');
  });

  test('editDmarc: v first, p second, tags kept in order, null removes one', () => {
    assert.equal(editDmarc('v=DMARC1; rua=mailto:d@example.com; p=none; pct=50', { p: 'quarantine', pct: null }), 'v=DMARC1; p=quarantine; rua=mailto:d@example.com');
    assert.equal(editDmarc(null, { p: 'none', rua: 'mailto:d@example.com' }), 'v=DMARC1; p=none; rua=mailto:d@example.com');
    assert.equal(editDmarc('v=DMARC1; p=reject; sp=none', { sp: null }), 'v=DMARC1; p=reject');
    assert.ok(parseDmarc(editDmarc('v=DMARC1; p=none', { p: 'reject', adkim: 's' })).valid);
  });
});

describe('templates', () => {
  test('every template: known fields, a default TTL, texts in both languages', () => {
    assert.deepEqual(TEMPLATE_IDS, ['acme-txt', 'acme-cname', 'm365', 'google', 'caa', 'spf', 'dmarc', 'ttl', 'record', 'parked']);
    for (const t of CHANGE_TEMPLATES) {
      for (const f of t.fields) assert.ok(FIX_FIELDS[f], `${t.id}.${f}`);
      assert.ok(Number.isInteger(t.ttl));
      for (const k of [`fix.tpl.${t.id}`, `fix.tpl.${t.id}.desc`]) assert.ok(FIX_I18N.en[k] && FIX_I18N.tr[k], k);
    }
    for (const [id, f] of Object.entries(FIX_FIELDS)) {
      assert.ok(FIX_I18N.en[`fix.field.${id}`] && FIX_I18N.tr[`fix.field.${id}`], id);
      if (f.kind === 'select' && !f.literal) for (const o of f.options) assert.ok(FIX_I18N.en[`fix.opt.${id}.${o}`] && FIX_I18N.tr[`fix.opt.${id}.${o}`], `${id}.${o}`);
    }
    assert.ok(FIX_CAS.some((c) => c.id === 'letsencrypt' && c.caa === 'letsencrypt.org'));
    assert.ok(!FIX_CAS.some((c) => c.id === 'etugra'), 'no distrusted CA');
  });

  test('templateInput: defaults, booleans and lists from strings (a route\'s params)', () => {
    assert.deepEqual(templateInput('caa', { domain: 'example.com', cas: 'google,letsencrypt,nope', wild: 'bogus' }),
      { domain: 'example.com', cas: ['google', 'letsencrypt'], wild: 'unset', accountUri: '', methods: [], iodef: '', ttl: '', zone: '' });
    assert.equal(templateInput('parked', { dkim: '1' }).dkim, true);
    assert.equal(templateInput('parked', { caa: '0' }).caa, false);
    assert.equal(changeTemplate('nope'), null);
    assert.ok(hasErrors(buildChange('nope', {})));
  });

  test('the form\'s mistakes are problems, never a wrong record', () => {
    const keys = (id, input, opts) => buildChange(id, input, opts).problems.map((p) => p.key);
    assert.deepEqual(keys('acme-txt', { name: '' }), ['fix.p.name-missing']);
    assert.deepEqual(keys('acme-txt', { name: 'example.com' }), ['fix.p.tokens-missing']);
    assert.deepEqual(keys('acme-txt', { name: 'example.com', tokens: TOKEN }), []);
    assert.ok(ACME_TOKEN_RE.test(TOKEN));
    assert.deepEqual(keys('acme-txt', { name: 'example.com', tokens: 'short' }), ['fix.p.token-format']);
    assert.deepEqual(keys('record', { name: 'www.example.net', zone: 'example.com', type: 'A', values: '192.0.2.1' }), ['fix.p.outside']);
    assert.deepEqual(keys('record', { name: 'www.example.com', type: 'A', values: 'nope' }), ['fix.p.value']);
    assert.deepEqual(keys('record', { name: 'www.example.com', type: 'CNAME', values: 'a.example.net\nb.example.net' }), ['fix.p.cname-one']);
    assert.deepEqual(keys('record', { name: 'www.example.com', type: 'A', values: '192.0.2.1', ttl: 'soon' }), ['fix.p.ttl']);
    assert.deepEqual(keys('caa', { domain: 'example.com', cas: ['letsencrypt', 'google'], accountUri: 'https://acme.example.net/acct/1' }), ['fix.p.accounturi-one']);
    assert.deepEqual(keys('caa', { domain: 'example.com', cas: [] }), ['fix.p.caa-none']);
    assert.deepEqual(keys('dmarc', { domain: 'example.com', pct: '0' }), ['fix.p.read-first', 'fix.p.pct', 'fix.p.dmarc-no-rua']);
    assert.deepEqual(keys('spf', { domain: 'example.com', includes: 'bad..name' }), ['fix.p.host', 'fix.p.read-first']);
    assert.deepEqual(keys('google', { domain: 'example.com', dkimKey: 'k=rsa; p=' }), ['fix.p.dkim-key']);
    assert.deepEqual(keys('ttl', { domain: 'example.com', records: 'www\nwww A' }), ['fix.p.ttl-line', 'fix.p.ttl-read']);
    assert.deepEqual(keys('m365', { domain: '_dmarc.example.com' }), ['fix.p.domain']);
    assert.deepEqual(keys('m365', { domain: 'example.com', zone: '192.0.2.1' }), ['fix.p.zone']);
    for (const k of new Set(CASES.flatMap((c) => (c.request ? c.request() : buildChange(c.template, c.input)).problems.map((p) => p.key)))) {
      assert.ok(FIX_I18N.en[k] || LINT_I18N.en[k], k);
    }
  });

  test('an SPF include is never removed from a record that was not read; an add says what it cannot know', () => {
    const rm = buildChange('spf', { domain: 'example.com', spfAction: 'remove', includes: 'mailgun.org' });
    assert.deepEqual([rm.rrsets, rm.problems], [[], [{ severity: 'error', key: 'fix.p.spf-remove-read', params: { name: 'example.com' } }]]);
    assert.ok(hasErrors(rm));
    const add = buildChange('spf', { domain: 'example.com', includes: 'mailgun.org\n_spf.example.net' });
    assert.deepEqual(add.notes, [{ key: 'fix.n.spf-unread', params: { include: 'mailgun.org include:_spf.example.net', name: 'example.com' } }]);
    assert.ok(!add.notes.some((n) => n.key === 'fix.n.spf-new'), 'nothing was read: no word about there being no record');
    // Read, and no SPF record there: this one is new.
    const none = { 'example.com|TXT': { status: 'ok', values: [['site-verification=1']], ttl: 300, cname: null } };
    assert.deepEqual(buildChange('spf', { domain: 'example.com', includes: 'mailgun.org' }, { current: none }).notes.map((n) => n.key), ['fix.n.spf-new']);
    // The instructions and every format say it: "add or change", never "replace the SPF record".
    assert.deepEqual(unreadEdits(add).map((r) => `${r.name} ${r.family}`), ['example.com spf1']);
    const en = changeInstructions(add, { lang: 'en' });
    assert.match(en, /^1\. Add or change: SPF record \(TXT\)$/m);
    assert.doesNotMatch(en, /Replace the name’s SPF record/);
    assert.match(changeInstructions(add, { lang: 'tr' }), /^1\. Ekle ya da değiştir: SPF kaydı \(TXT\)$/m);
    for (const f of FIX_FORMATS) assert.equal(formatNotes(add, f)[0].key, 'fix.fn.unread-edit', f);
    assert.deepEqual(unreadEdits(buildChange('spf', { domain: 'example.com', includes: 'mailgun.org' }, { current: none })), [], 'read: exact');
    assert.equal(rrsetAction(add.rrsets[0]), 'replace', 'the plan itself is unchanged');
  });

  test('a DMARC step-up without a read: the tags it leaves out are named, and no policy it comes from', () => {
    const req = buildChange('dmarc', { domain: 'example.com', policy: 'reject' });
    assert.deepEqual(req.notes, [{ key: 'fix.n.dmarc-unread', params: { name: '_dmarc.example.com' } }, { key: 'fix.n.dmarc-to', params: { to: 'reject' } }]);
    assert.doesNotMatch(changeInstructions(req), /From p=none/);
    assert.match(changeInstructions(req), /keep the others \(rua, ruf, sp, pct …\)/);
    // A first DMARC record of a mail template, not read: one that is there stays.
    const m365 = buildChange('m365', { domain: 'example.com' });
    assert.ok(m365.notes.some((n) => n.key === 'fix.n.dmarc-first-unread' && n.params.name === '_dmarc.example.com'));
    assert.deepEqual(unreadEdits(m365).map((r) => r.family), ['spf1', 'dmarc1']);
  });

  test('the DMARC pct field: empty keeps the record\'s own, 100 removes it, a number sets it', () => {
    const cur = { '_dmarc.example.com|TXT': { status: 'ok', values: [['v=DMARC1; p=quarantine; pct=25; rua=mailto:d@example.com']], ttl: 300, cname: null } };
    const value = (pct) => buildChange('dmarc', { domain: 'example.com', policy: 'reject', pct }, { current: cur }).rrsets[0].values[0].join('');
    assert.equal(value(''), 'v=DMARC1; p=reject; pct=25; rua=mailto:d@example.com');
    assert.equal(value('100'), 'v=DMARC1; p=reject; rua=mailto:d@example.com');
    assert.equal(value('50'), 'v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com');
  });

  test('the ACME templates take the record name a client prints for the certificate name: the label is never doubled', () => {
    for (const name of ['_acme-challenge.example.com', '_ACME-Challenge.example.com.']) {
      const txt = buildChange('acme-txt', { name, tokens: TOKEN });
      assert.deepEqual(txt.rrsets.map((r) => r.name), ['_acme-challenge.example.com'], name);
      assert.deepEqual(txt.problems, [{ severity: 'info', key: 'fix.p.acme-name', params: { value: name, name: '_acme-challenge.example.com' } }]);
      assert.ok(!hasErrors(txt));
    }
    const sub = buildChange('acme-cname', { name: '_acme-challenge.www.example.com', target: 'x.auth.example.net' });
    assert.deepEqual([sub.zone, sub.rrsets.map((r) => `${r.name} ${r.type}`)], ['example.com', ['_acme-challenge.www.example.com CNAME']]);
    assert.equal(sub.problems[0].key, 'fix.p.acme-name');
    assert.deepEqual(buildChange('acme-txt', { name: '*.example.com', tokens: TOKEN }).problems, [], 'a plain name: no word');
  });

  test('a delegated _acme-challenge is refused: the TXT belongs at the CNAME target', () => {
    const cur = { '_acme-challenge.example.com|CNAME': { status: 'ok', values: ['x.auth.example.net'], ttl: 300, cname: null } };
    const req = buildChange('acme-txt', { name: '*.example.com', tokens: TOKEN }, { current: cur });
    assert.deepEqual(req.problems.find((p) => p.key === 'fix.p.acme-delegated').params, { name: '_acme-challenge.example.com', target: 'x.auth.example.net' });
  });

  test('the SPF of a mail template goes into the record there (after a read), never a second one', () => {
    const cur = { 'example.com|TXT': { status: 'ok', values: [['v=spf1 include:_spf.example.net ~all']], ttl: 300, cname: null } };
    const set = buildChange('google', { domain: 'example.com' }, { current: cur }).rrsets.find((r) => r.family === 'spf1');
    assert.deepEqual(set.values.map((v) => v.join('')), ['v=spf1 include:_spf.example.net include:_spf.google.com ~all']);
    const two = { 'example.com|TXT': { status: 'ok', values: [['v=spf1 -all'], ['v=spf1 a -all']], ttl: 300, cname: null } };
    assert.ok(buildChange('m365', { domain: 'example.com' }, { current: two }).problems.some((p) => p.key === 'fix.p.spf-multiple'));
  });

  test('the lowered TTLs keep the values a read found, and the check asks for the new TTL', () => {
    const cur = { 'www.example.com|A': { status: 'ok', values: ['192.0.2.1'], ttl: 86400, cname: null } };
    const req = buildChange('ttl', { domain: 'example.com', records: 'www A' }, { current: cur });
    assert.deepEqual([req.rrsets[0].values, req.rrsets[0].ttl, req.rrsets[0].maxTtl], [['192.0.2.1'], 300, 300]);
    assert.deepEqual(req.notes, [{ key: 'fix.n.ttl-wait', params: { ttl: 86400 } }]);
  });
});

describe('fixes of Domain Health checks', () => {
  const report = (over = {}) => ({
    domain: 'example.com',
    zone: 'example.com',
    records: { txt: ['v=spf1 include:_spf.example.net +all', 'site-verification=1'], mx: [{ preference: 10, exchange: 'mail.example.com' }], caa: [] },
    spf: { record: 'v=spf1 include:_spf.example.net +all', parsed: parseSpf('v=spf1 include:_spf.example.net +all'), lookups: null },
    dmarc: { record: null, parsed: null, foundAt: null, inherited: false },
    failedLookups: [],
    checks: [],
    ...over
  });

  test('every fixable id is a real check id, and has texts', () => {
    for (const id of HEALTH_FIX_IDS) assert.ok(HEALTH_CHECK_IDS.includes(id), id);
    for (const k of Object.keys(FIX_I18N.en).filter((x) => x.startsWith('fix.a.'))) assert.ok(FIX_I18N.tr[k], k);
  });

  test('dmarc.missing: a p=none record with a report address to create first', () => {
    const f = healthFix({ id: 'dmarc.missing' }, report());
    assert.equal(f.kind, 'records');
    assert.deepEqual(f.request.rrsets.map((r) => [r.name, r.values.map((v) => v.join(''))]), [['_dmarc.example.com', ['v=DMARC1; p=none; rua=mailto:dmarc-reports@example.com']]]);
    assert.deepEqual(f.advice.map((a) => a.key), ['fix.a.rua-mailbox']);
    assert.equal(f.template, 'dmarc');
    assert.equal(f.input.domain, 'example.com');
  });

  test('spf.all-pass: the same record with ~all; Route 53 keeps the other TXT values (read by the check)', () => {
    const f = healthFix({ id: 'spf.all-pass' }, report());
    const r = f.request.rrsets[0];
    assert.deepEqual([r.family, r.values.map((v) => v.join('')), r.others.map((v) => v.join(''))],
      ['spf1', ['v=spf1 include:_spf.example.net ~all'], ['site-verification=1']]);
    assert.ok(rrsetPlan(r).complete);
    assert.deepEqual(JSON.parse(renderFix(f.request, 'route53')).Changes[0].ResourceRecordSet.ResourceRecords.map((x) => x.Value),
      ['"site-verification=1"', '"v=spf1 include:_spf.example.net ~all"']);
  });

  test('spf.missing: -all without MX, the platform include for Microsoft 365, else advice only', () => {
    const noMx = healthFix({ id: 'spf.missing' }, report({ records: { txt: [], mx: [], caa: [] }, spf: {} }));
    assert.deepEqual(noMx.request.rrsets[0].values.map((v) => v.join('')), ['v=spf1 -all']);
    assert.deepEqual(noMx.advice.map((a) => a.key), ['fix.a.spf-no-mail']);
    const m365 = healthFix({ id: 'spf.missing' }, report({ records: { txt: [], mx: [{ preference: 0, exchange: 'example-com.mail.protection.outlook.com' }], caa: [] }, spf: {} }));
    assert.deepEqual(m365.request.rrsets[0].values.map((v) => v.join('')), ['v=spf1 include:spf.protection.outlook.com -all']);
    const other = healthFix({ id: 'spf.missing' }, report({ records: { txt: [], mx: [{ preference: 10, exchange: 'mail.example.com' }], caa: [] }, spf: {} }));
    assert.equal(other.kind, 'advice');
  });

  test('spf.lookups-exceeded: flattening advice naming the costliest includes, never a record', () => {
    const tree = { terms: [{ mechanism: 'include', target: 'a.example.net', child: { count: 4 } }, { mechanism: 'include', target: 'b.example.net', child: { count: 6 } }, { mechanism: 'ip4', target: null, child: null }] };
    const f = healthFix({ id: 'spf.lookups-exceeded' }, report({ spf: { record: 'x', parsed: null, lookups: { tree } } }));
    assert.equal(f.kind, 'advice');
    assert.equal(f.request, null);
    assert.deepEqual(f.advice, [{ key: 'fix.a.spf-flatten', params: { includes: 'b.example.net (7), a.example.net (5)' } }]);
  });

  test('spf.multiple: one merged record; ptr and terms after all removed', () => {
    const f = healthFix({ id: 'spf.multiple' }, report({ records: { txt: ['v=spf1 a ~all', 'v=spf1 mx -all'], mx: [], caa: [] } }));
    assert.deepEqual(f.request.rrsets[0].values.map((v) => v.join('')), ['v=spf1 a mx -all']);
    assert.deepEqual(f.request.rrsets[0].before.map((v) => v.join('')), ['v=spf1 a ~all', 'v=spf1 mx -all']);
    const ptr = 'v=spf1 ptr mx ~all ip4:192.0.2.1';
    const p = healthFix({ id: 'spf.ptr' }, report({ spf: { record: ptr, parsed: parseSpf(ptr) } }));
    assert.deepEqual(p.request.rrsets[0].values.map((v) => v.join('')), ['v=spf1 mx ~all ip4:192.0.2.1'], 'only ptr goes');
    const after = healthFix({ id: 'spf.after-all' }, report({ spf: { record: ptr, parsed: parseSpf(ptr) } }));
    assert.deepEqual(after.request.rrsets[0].values.map((v) => v.join('')), ['v=spf1 ptr mx ~all'], 'only what follows all goes');
  });

  test('caa.missing needs the CAs of the domain\'s certificates, then one issue value per CA', () => {
    const f = healthFix({ id: 'caa.missing' }, report());
    assert.equal(f.needsCt, true);
    const done = caaFixFromIssuers(f, [{ caaDomains: ['letsencrypt.org'] }, { caaDomains: ['pki.goog'] }, { caaDomains: ['ca.example.net'] }, { caaDomains: ['letsencrypt.org'] }]);
    assert.equal(done.needsCt, false);
    assert.deepEqual(done.request.rrsets[0].values.map((v) => v.value), ['letsencrypt.org', 'pki.goog', 'ca.example.net']);
    assert.ok(!done.request.problems.some((p) => p.key === 'fix.p.caa-none'));
    // The report read no CAA set there: the fix adds one (no "not read" in any format).
    assert.deepEqual([done.request.rrsets[0].before, rrsetAction(done.request.rrsets[0])], [[], 'add']);
    assert.deepEqual(formatNotes(done.request, 'route53'), []);
    // A CA the form does not list: the edit link opens the plain record with every value.
    assert.deepEqual([done.template, done.input.name, done.input.type], ['record', 'example.com', 'CAA']);
    assert.deepEqual(buildChange('record', done.input).rrsets[0].values, done.request.rrsets[0].values, 'the edit link builds the same set');
    const known = caaFixFromIssuers(f, [{ caaDomains: ['letsencrypt.org'] }, { caaDomains: ['pki.goog'] }]);
    assert.deepEqual([known.template, known.input.cas, rrsetAction(known.request.rrsets[0])], ['caa', ['letsencrypt', 'google'], 'add']);
  });

  test('mx.none: the mail lock-down without the CAA part; checks without a fix give null', () => {
    const f = healthFix({ id: 'mx.none' }, report({ records: { txt: [], mx: [], caa: [] } }));
    assert.deepEqual(f.request.rrsets.map((r) => `${r.name} ${r.type}`), ['example.com MX', 'example.com TXT', '_dmarc.example.com TXT']);
    assert.deepEqual(f.request.problems, []);
    const locked = healthFix({ id: 'mx.none' }, report({ records: { txt: ['v=spf1 -all'], mx: [], caa: [] } }));
    assert.equal(locked.kind, 'records', 'an SPF record that lets nobody send: the lock-down');
    assert.equal(healthFix({ id: 'dnssec.unsigned' }, report()), null);
    assert.equal(healthFix({ id: 'dmarc.missing' }, null), null);
  });

  test('mx.none of a domain that sends mail (no MX, an SPF record with senders): advice only, never the lock-down', () => {
    const sender = 'v=spf1 include:sendgrid.example.net ~all';
    const f = healthFix({ id: 'mx.none' }, report({ records: { txt: [sender, 'site-verification=1'], mx: [], caa: [] } }));
    assert.deepEqual([f.kind, f.request, f.template], ['advice', null, null]);
    assert.deepEqual(f.advice, [{ key: 'fix.a.no-mx-sends', params: { record: sender } }]);
    for (const rec of ['v=spf1 +all', 'v=spf1 ?all', 'v=spf1 redirect=_spf.example.net', 'v=spf1 ip4:192.0.2.0/24 -all']) {
      assert.equal(healthFix({ id: 'mx.none' }, report({ records: { txt: [rec], mx: [], caa: [] } })).kind, 'advice', rec);
    }
  });

  test('the parked lock-down after a read: an SPF record with senders is a warning; a DMARC record keeps its report addresses', () => {
    const cur = {
      'example.com|TXT': { status: 'ok', values: [['v=spf1 include:sendgrid.example.net ~all']], ttl: 300, cname: null },
      'example.com|MX': { status: 'nodata', values: [], ttl: null, cname: null },
      '_dmarc.example.com|TXT': { status: 'ok', values: [['v=DMARC1; p=none; sp=none; pct=20; rua=mailto:d@example.com']], ttl: 300, cname: null }
    };
    const req = buildChange('parked', { domain: 'example.com' }, { current: cur });
    assert.deepEqual(req.problems, [{ severity: 'warn', key: 'fix.p.parked-sends', params: { name: 'example.com', record: 'v=spf1 include:sendgrid.example.net ~all' } }]);
    assert.deepEqual(req.rrsets.find((r) => r.family === 'dmarc1').values.map((v) => v.join('')), ['v=DMARC1; p=reject; rua=mailto:d@example.com']);
    assert.deepEqual(buildChange('parked', { domain: 'example.com' }).rrsets.find((r) => r.family === 'dmarc1').values.map((v) => v.join('')), ['v=DMARC1; p=reject'], 'not read: a new record');
  });

  test('an inherited DMARC policy is fixed where it comes from: the organizational domain\'s record, its tags kept', () => {
    const org = 'v=DMARC1; p=reject; sp=none';
    const sub = (id) => healthFix({ id }, report({ domain: 'shop.example.com', dmarc: { record: org, parsed: parseDmarc(org), foundAt: 'example.com', inherited: true } }));
    const rua = sub('dmarc.rua-missing');
    assert.deepEqual(rua.request.rrsets.map((r) => [r.name, r.values.map((v) => v.join('')), r.before.map((v) => v.join(''))]),
      [['_dmarc.example.com', ['v=DMARC1; p=reject; sp=none; rua=mailto:dmarc-reports@example.com'], [org]]], 'rua added, p and sp as they are');
    assert.deepEqual(rua.advice.map((a) => a.key), ['fix.a.dmarc-inherited', 'fix.a.rua-mailbox']);
    assert.deepEqual(rua.advice[0].params, { domain: 'shop.example.com', name: '_dmarc.example.com', org: 'example.com' });
    assert.equal(rua.input.domain, 'example.com', 'the edit link opens the organizational domain');
    const none = sub('dmarc.policy-none');
    assert.deepEqual(none.request.rrsets[0].values.map((v) => v.join('')), ['v=DMARC1; p=reject; sp=quarantine'], 'the subdomain policy steps up, p stays');
    assert.ok(none.request.notes.some((n) => n.key === 'fix.n.dmarc-sp' && n.params.from === 'none' && n.params.to === 'quarantine'));
    assert.ok(!none.request.notes.some((n) => n.key === 'fix.n.dmarc-step'), 'no p step: it stays reject');
    assert.ok(!none.request.rrsets.some((r) => r.name === '_dmarc.shop.example.com'), 'no record of the subdomain with fewer tags');
  });

  test('DMARC fixes keep what they are not about: rua-missing keeps pct, policy-none steps p only', () => {
    const rec = 'v=DMARC1; p=quarantine; pct=25';
    const r = report({ dmarc: { record: rec, parsed: parseDmarc(rec), foundAt: 'example.com', inherited: false } });
    assert.deepEqual(healthFix({ id: 'dmarc.rua-missing' }, r).request.rrsets[0].values.map((v) => v.join('')), ['v=DMARC1; p=quarantine; pct=25; rua=mailto:dmarc-reports@example.com']);
    assert.deepEqual(healthFix({ id: 'dmarc.pct' }, r).request.rrsets[0].values.map((v) => v.join('')), ['v=DMARC1; p=quarantine']);
    const none = 'v=DMARC1; p=none; rua=mailto:d@example.com';
    const f = healthFix({ id: 'dmarc.policy-none' }, report({ dmarc: { record: none, parsed: parseDmarc(none), foundAt: 'example.com', inherited: false } }));
    assert.deepEqual(f.request.rrsets.map((x) => [x.name, x.values.map((v) => v.join(''))]), [['_dmarc.example.com', ['v=DMARC1; p=quarantine; rua=mailto:d@example.com']]]);
    assert.deepEqual(f.advice, []);
  });

  test('caa.cert-denied: the certificate\'s CA joins the CAA set where it was found (a parent), the listed CAs stay', () => {
    const caa = [{ flags: 0, tag: 'issue', value: 'pki.goog' }];
    const r = report({
      domain: 'www.example.com', records: { txt: [], mx: [], caa },
      caa: { foundAt: 'example.com', parsed: parseCaa(caa) }, caaCert: checkCaaAllows(parseCaa(caa), "CN=R11,O=Let's Encrypt,C=US")
    });
    assert.equal(r.caaCert.reason, 'not-listed');
    const f = healthFix({ id: 'caa.cert-denied', params: { issuer: 'Let\'s Encrypt' } }, r);
    const set = f.request.rrsets[0];
    assert.deepEqual([f.request.zone, set.name, set.values.map((v) => `${v.tag} ${v.value}`), set.before.length], ['example.com', 'example.com', ['issue pki.goog', 'issue letsencrypt.org'], 1]);
    assert.deepEqual(f.advice.map((a) => a.key), ['fix.a.caa-at', 'fix.a.caa-cert']);
    assert.deepEqual(f.advice[1].params, { issuer: 'Let\'s Encrypt', value: 'letsencrypt.org', property: 'issue' });
    assert.deepEqual([f.template, f.input.name, f.input.values], ['record', 'example.com', '0 issue "pki.goog"\n0 issue "letsencrypt.org"']);
    assert.deepEqual(buildChange('record', f.input).rrsets[0].values, set.values, 'the edit link builds the same set');
    // A wildcard certificate with an issuewild set: the CA joins issuewild.
    const wild = [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'issuewild', value: 'pki.goog' }];
    const w = healthFix({ id: 'caa.cert-denied' }, report({ records: { txt: [], mx: [], caa: wild }, caa: { foundAt: 'example.com', parsed: parseCaa(wild) },
      caaCert: checkCaaAllows(parseCaa(wild), "CN=R11,O=Let's Encrypt,C=US", { wildcard: true }) }));
    assert.deepEqual(w.request.rrsets[0].values.map((v) => `${v.tag} ${v.value}`), ['issue letsencrypt.org', 'issuewild pki.goog', 'issuewild letsencrypt.org']);
    assert.deepEqual(w.advice.map((a) => a.key), ['fix.a.caa-cert'], 'at the domain itself: no word about a parent');
    assert.equal(healthFix({ id: 'caa.cert-denied' }, report({ caaCert: { issuerDomains: [] } })), null, 'an unknown CA: no record');
  });

  test('caa.critical-unknown: the critical flag cleared on the unknown tags, as the Zone File fix does', () => {
    const caa = [{ flags: 128, tag: 'tbs', value: 'x' }, { flags: 128, tag: 'issue', value: 'letsencrypt.org' }];
    const f = healthFix({ id: 'caa.critical-unknown' }, report({ records: { txt: [], mx: [], caa }, caa: { foundAt: 'example.com', parsed: parseCaa(caa) } }));
    assert.deepEqual(f.request.rrsets[0].values.map((v) => `${v.flags} ${v.tag}`), ['0 tbs', '128 issue'], 'only the unknown tag loses it');
    assert.deepEqual(f.advice, [{ key: 'fix.a.caa-critical', params: { tags: 'tbs' } }]);
    assert.equal(rrsetPlan(f.request.rrsets[0]).remove.length, 1);
  });

  test('a report-based fix of existing records says its TTL is a default (a resolver cannot tell the zone\'s)', () => {
    const f = healthFix({ id: 'spf.all-pass' }, report());
    assert.deepEqual(f.request.notes.filter((n) => n.key === 'fix.n.report-ttl'), [{ key: 'fix.n.report-ttl', params: { ttl: 3600 } }]);
    assert.match(changeInstructions(f.request), /TTL 3600 is a default/);
    assert.ok(!healthFix({ id: 'dmarc.missing' }, report()).request.notes.some((n) => n.key === 'fix.n.report-ttl'), 'a new record: no note');
  });

  test('spf.ptr / spf.after-all keep exp= and unknown modifiers; only a redirect= an all voids goes', () => {
    const rec = 'v=spf1 ptr mx -all exp=explain.example.com x-note=1 redirect=_spf.example.net';
    const f = healthFix({ id: 'spf.ptr' }, report({ spf: { record: rec, parsed: parseSpf(rec) } }));
    assert.deepEqual(f.request.rrsets[0].values.map((v) => v.join('')), ['v=spf1 mx -all exp=explain.example.com x-note=1']);
    const noAll = 'v=spf1 ptr mx redirect=_spf.example.net';
    assert.deepEqual(healthFix({ id: 'spf.ptr' }, report({ spf: { record: noAll, parsed: parseSpf(noAll) } })).request.rrsets[0].values.map((v) => v.join('')),
      ['v=spf1 mx redirect=_spf.example.net']);
  });

  test('currentFromReport: what the report read, never a failed lookup as "none"', () => {
    const cur = currentFromReport(report({ failedLookups: ['mx'] }));
    assert.deepEqual(Object.keys(cur).sort(), ['_dmarc.example.com|TXT', 'example.com|CAA', 'example.com|TXT']);
    assert.equal(cur['example.com|CAA'].status, 'nodata');
  });

  test('currentFromReport: a CAA set found at a parent is there (none at the domain); an inherited DMARC record at the organizational domain', () => {
    const caa = [{ flags: 0, tag: 'issue', value: 'pki.goog' }];
    const org = 'v=DMARC1; p=reject';
    const cur = currentFromReport(report({ domain: 'www.example.com', records: { txt: [], mx: [], caa }, caa: { foundAt: 'example.com', parsed: parseCaa(caa) },
      dmarc: { record: org, parsed: parseDmarc(org), foundAt: 'example.com', inherited: true } }));
    assert.deepEqual([cur['example.com|CAA'].values, cur['www.example.com|CAA'].status], [caa, 'nodata']);
    assert.deepEqual([cur['_dmarc.example.com|TXT'].values.map((v) => v.join('')), cur['_dmarc.www.example.com|TXT'].status], [[org], 'nodata']);
  });
});

describe('fixes of Zone File findings', () => {
  const zone = (text) => parseZone(text, { origin: 'example.com' });
  const findingOf = (z, code) => lintZone(z).findings.find((f) => f.code === code);

  test('every fixable code is a lint code', () => {
    for (const code of LINT_FIX_CODES) assert.ok(LINT_I18N.en[`zone.lint.${code}`], code);
  });

  test('TTL_TOO_LOW: the set with TTL 300, values from the file (exact)', () => {
    const z = zone('$ORIGIN example.com.\napi 5 IN A 192.0.2.20\napi 5 IN A 192.0.2.21\n');
    const f = lintFix(findingOf(z, 'TTL_TOO_LOW'), z);
    const r = f.request.rrsets[0];
    assert.deepEqual([r.name, r.ttl, r.beforeTtl, r.values], ['api.example.com', 300, 5, ['192.0.2.20', '192.0.2.21']]);
    assert.ok(rrsetPlan(r).ttlOnly);
  });

  test('LOCALHOST_RECORD deletes the set; CAA_FLAGS sets the flags to 0; MULTIPLE_SPF merges', () => {
    const z = zone('$ORIGIN example.com.\nlocalhost 300 IN A 127.0.0.1\n@ 300 IN CAA 1 issue "letsencrypt.org"\n@ 300 IN TXT "v=spf1 a ~all"\n@ 300 IN TXT "v=spf1 mx -all"\n@ 300 IN TXT "verify=1"\n');
    const lh = lintFix(findingOf(z, 'LOCALHOST_RECORD'), z).request.rrsets[0];
    assert.deepEqual([lh.mode, rrsetPlan(lh).remove], ['none', ['127.0.0.1']]);
    const caa = lintFix(findingOf(z, 'CAA_FLAGS'), z).request.rrsets[0];
    assert.deepEqual(caa.values, [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }]);
    // A critical unknown tag: only its critical flag goes, as for the live CAA check.
    const crit = zone('$ORIGIN example.com.\n@ 300 IN CAA 0 issue "letsencrypt.org"\n@ 300 IN CAA 128 isue "letsencrypt.org"\n');
    assert.deepEqual(lintFix(findingOf(crit, 'CAA_CRITICAL_UNKNOWN_TAG'), crit).request.rrsets[0].values,
      [{ flags: 0, tag: 'issue', value: 'letsencrypt.org' }, { flags: 0, tag: 'isue', value: 'letsencrypt.org' }]);
    const spf = lintFix(findingOf(z, 'MULTIPLE_SPF'), z).request.rrsets[0];
    assert.deepEqual([spf.values.map((v) => v.join('')), spf.others.map((v) => v.join(''))], [['v=spf1 a mx -all'], ['verify=1']]);
    assert.equal(lintFix({ code: 'SINGLE_NS', name: 'example.com', type: 'NS' }, z), null);
  });

  test('the Cloudflare script keeps a zone file\'s names out of the shell: a ` $ " \\ ! in an owner or $ORIGIN is never expanded', () => {
    const texts = ['$ORIGIN ex`id`.com.\na`id`b 5 IN A 192.0.2.1\n', '$ORIGIN example.com.\na`id`b\\$x\\"c!d 5 IN A 192.0.2.1\n'];
    for (const text of texts) {
      const z = parseZone(text);
      const f = lintFix(findingOf(z, 'TTL_TOO_LOW'), z);
      const script = renderFix(f.request, 'cloudflare');
      assert.match(script, /name=a%60id%60b/, 'the name percent-encoded in the list call');
      for (const line of script.split('\n').filter((l) => l && !l.startsWith('#'))) {
        const shell = line.replace(/'[^']*'/g, "''"); // single-quoted words are literal
        assert.doesNotMatch(shell, /`|\$\(|!/, line);
        assert.equal((shell.match(/"/g) || []).length % 2, 0, `balanced double quotes: ${line}`);
        for (const m of shell.matchAll(/\$\{?([A-Za-z_]\w*)/g)) assert.ok(['API', CLOUDFLARE_VARS.token, CLOUDFLARE_VARS.zone].includes(m[1]), line);
      }
    }
  });

  test('TXT_STRING_TOO_LONG: the same text re-split into strings of 255 bytes', () => {
    const z = zone(`$ORIGIN example.com.\nk 300 IN TXT "${'a'.repeat(300)}"\n`);
    const f = lintFix(findingOf(z, 'TXT_STRING_TOO_LONG'), z);
    assert.deepEqual(f.request.rrsets[0].values[0].map((s) => s.length), [255, 45]);
    assert.match(renderFix(f.request, 'bind'), /k 300 IN TXT "a{255}" "a{45}"/);
  });
});

describe('i18n', () => {
  test('every fix.* key the module can emit exists in both languages (not only the ones the goldens reach)', () => {
    const src = readFileSync(new URL('../../assets/js/lib/fixes.js', import.meta.url), 'utf8');
    const literal = new Set([...src.matchAll(/key: '(fix\.[a-z]+\.[a-z0-9.-]+)'/g)].map((m) => m[1]));
    assert.ok(literal.size > 60, `found ${literal.size}`);
    for (const k of literal) assert.ok(FIX_I18N.en[k] && FIX_I18N.tr[k], k);
    // Built keys: formats, templates, actions.
    for (const f of FIX_FORMATS) for (const k of [`fix.fmt.${f}`, `fix.fmt.${f}.how`]) assert.ok(FIX_I18N.en[k] && FIX_I18N.tr[k], k);
    for (const a of ['add', 'replace', 'delete', 'ttl', 'rewrite', 'unchanged', 'set']) assert.ok(FIX_I18N.tr[`fix.ins.action.${a}`], a);
    for (const k of ['fix.ins.editFamily', 'fix.ins.replaceFamily', 'fix.ins.replaceAll']) assert.ok(FIX_I18N.en[k] && FIX_I18N.tr[k], k);
  });

  test('English and Turkish have the same keys and placeholders', () => {
    const holes = (s) => [...new Set([...JSON.stringify(s).matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1]))].sort().join(',');
    assert.deepEqual(Object.keys(FIX_I18N.tr).sort(), Object.keys(FIX_I18N.en).sort());
    for (const k of Object.keys(FIX_I18N.en)) assert.equal(holes(FIX_I18N.en[k]), holes(FIX_I18N.tr[k]), k);
  });
});
