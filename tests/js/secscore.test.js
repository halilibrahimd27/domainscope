/**
 * lib/secscore.js — CSC's eight domain security measures over lib/portfolio.js facts: each one a
 * lib/policy.js rule with a fixed requirement (pass, fail or "not known" with the policy's
 * evidence), the 0–8 score with measures not known, the portfolio's adoption and totals, the CSV
 * in English and Turkish, the JSON codes, and the texts. Pure Node, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  SECURITY_MEASURES, SECURITY_MAX, SECURITY_I18N, securityScore, securityScores, securityAdoption, securityTotals, scoreBand, securityCsv, securityExport
} from '../../assets/js/lib/secscore.js';
import { POLICY_I18N, POLICY_PRESETS, evaluatePolicy, parsePolicy, policyRule, presetPolicy, evidenceText } from '../../assets/js/lib/policy.js';

/** `t` over SECURITY_I18N and POLICY_I18N (plural objects: one / other / zero). */
function makeT(lang = 'en') {
  const dict = { ...POLICY_I18N[lang], ...SECURITY_I18N[lang] };
  return (key, params = {}) => {
    let s = dict[key];
    if (s === undefined) return key;
    if (typeof s === 'object') s = (params.count === 0 && s.zero) || (params.count === 1 && s.one) || s.other;
    return s.replace(/\{(\w+)\}/g, (m, k) => (k in params ? String(params[k]) : m));
  };
}
const t = makeT('en');

/** A domain that meets every measure, as lib/portfolio.js portfolioFacts derives it (only the parts read). */
function facts(over = {}) {
  return {
    domain: 'example.com',
    exists: true,
    registration: {
      state: 'ok', registrar: 'Example Brand Registrar', ianaId: '292', registrarClass: 'corporate', transferLock: true, lockLevel: 'registry', registryLock: true,
      serverLocks: ['server transfer prohibited', 'server update prohibited', 'server delete prohibited'], statuses: [], critical: []
    },
    ns: {
      state: 'ok', hosts: ['ns-1.awsdns-01.com', 'ns1.example.net'], domains: [],
      providers: { count: 2, providers: [{ id: 'route53', name: 'Amazon Route 53', known: true, hosts: [] }, { id: 'domain:example.net', name: 'example.net', known: false, hosts: [] }] }
    },
    dnssec: { state: 'signed', dsCount: 1, dnskeyFailure: null, pending: false },
    caa: { state: 'present', issuers: ['letsencrypt.org'], wildIssuers: [] },
    spf: { state: 'ok', all: '-', count: 1 },
    dkim: { state: 'found', selectors: ['selector1'], asked: 8 },
    dmarc: { state: 'ok', policy: 'reject', count: 1 },
    ...over
  };
}
const reg = (extra) => ({ registration: { ...facts().registration, ...extra } });

describe('the measures', () => {
  test('eight, in CSC\'s order, each a policy rule with its requirement; the corporate preset asks for every one alike', () => {
    assert.equal(SECURITY_MAX, 8);
    assert.deepEqual(SECURITY_MEASURES.map((m) => m.id), ['registrar', 'registryLock', 'caa', 'dnsRedundancy', 'dnssec', 'spf', 'dkim', 'dmarc']);
    for (const m of SECURITY_MEASURES) {
      assert.ok(policyRule(m.rule), m.rule);
      assert.deepEqual(parsePolicy({ [m.rule]: m.value }).errors, [], m.id);
      // the same requirement as the corporate preset: the score and the preset never disagree
      assert.ok(Object.hasOwn(POLICY_PRESETS.corporate.rules, m.rule), `${m.rule} in the corporate preset`);
      const preset = presetPolicy('corporate').rules.find((r) => r.id === m.rule);
      const own = parsePolicy({ [m.rule]: m.value }).policy.rules[0];
      assert.deepEqual([preset.op, preset.value], [own.op, own.value], m.id);
    }
  });

  test('every measure met: 8 of 8; each measure says it with the evidence of its policy cell', () => {
    const s = securityScore(facts());
    assert.deepEqual([s.domain, s.score, s.fail, s.unknown, s.max], ['example.com', 8, 0, 0, 8]);
    assert.deepEqual(s.measures.map((m) => [m.id, m.status]), SECURITY_MEASURES.map((m) => [m.id, 'pass']));
    const cells = new Map(evaluatePolicy(presetPolicy('corporate'), facts()).map((c) => [c.id, c]));
    for (const m of s.measures) assert.deepEqual(m.evidence, cells.get(m.rule).evidence, m.id);
    assert.deepEqual(s.measures.map((m) => evidenceText(m, t)), [
      'a corporate registrar: Example Brand Registrar (IANA ID 292)',
      'a registry lock: server transfer, update and delete prohibited',
      'CAA allows letsencrypt.org',
      '2 DNS providers: Amazon Route 53, example.net',
      'signed (DS), not validated by the resolver',
      'one valid SPF record',
      'DKIM selectors selector1',
      'DMARC p=reject'
    ]);
  });

  test('not met, and not known: a measure not known never counts as met, nor as failed', () => {
    const weak = securityScore(facts({
      ...reg({ registrarClass: 'retail', ianaId: '1068', registryLock: false, lockLevel: 'registry-partial', serverLocks: ['server transfer prohibited'] }),
      ns: { ...facts().ns, providers: { count: 1, providers: [{ id: 'domain:example.net', name: 'example.net', known: false, hosts: [] }] } },
      dnssec: { state: 'unsigned', dsCount: 0 },
      caa: { state: 'none' },
      dkim: { state: 'off' },
      dmarc: { state: 'ok', policy: 'none', count: 1 }
    }));
    assert.deepEqual(weak.measures.map((m) => [m.id, m.status]), [
      ['registrar', 'fail'], ['registryLock', 'fail'], ['caa', 'fail'], ['dnsRedundancy', 'fail'], ['dnssec', 'fail'], ['spf', 'pass'], ['dkim', 'unknown'], ['dmarc', 'fail']
    ]);
    assert.deepEqual([weak.score, weak.fail, weak.unknown], [1, 6, 1]);
    assert.equal(evidenceText(weak.measures[6], t), 'not checked (turned off)');
    // a registry without RDAP: the registration measures are not known, the DNS ones are read as for any domain
    const tr = securityScore(facts({ domain: 'example-test.com.tr', registration: { state: 'unsupported', tld: 'tr' } }));
    assert.deepEqual([tr.score, tr.fail, tr.unknown, tr.measures[0].status, tr.measures[1].status], [6, 0, 2, 'unknown', 'unknown']);
    assert.equal(evidenceText(tr.measures[0], t), 'the .tr registry publishes no RDAP: see its WHOIS');
    // DMARC quarantine counts; a quarantine at pct < 100 is still quarantine
    assert.equal(securityScore(facts({ dmarc: { state: 'ok', policy: 'quarantine', pct: 50 } })).measures[7].status, 'pass');
    // a domain that does not exist: its DNS measures fail with that reason
    const gone = securityScore(facts({ exists: false, ns: { state: 'nxdomain', domains: [], providers: null }, dnssec: { state: null }, caa: { state: null }, spf: { state: null }, dkim: { state: null }, dmarc: { state: null } }));
    assert.deepEqual(gone.measures.slice(2).map((m) => [m.status, m.evidence.key]), Array(6).fill(['fail', 'pol.ev.nxdomain']));
    // nothing landed yet: every measure not known, none of them failed
    const none = securityScore({ domain: 'example.com' });
    assert.deepEqual([none.score, none.fail, none.unknown], [0, 0, 8]);
  });

  test('scores of a list, in its order; a score\'s band', () => {
    const rows = securityScores([facts(), null, facts({ domain: 'example.org', caa: { state: 'none' } })]);
    assert.deepEqual(rows.map((r) => [r.domain, r.score]), [['example.com', 8], ['example.org', 7]]);
    assert.deepEqual([8, 7, 6, 5, 4, 3, 0].map(scoreBand), ['ok', 'info', 'info', 'warn', 'warn', 'error', 'error']);
  });
});

describe('the portfolio', () => {
  const rows = securityScores([
    facts(),
    facts({ domain: 'example.org', caa: { state: 'none' }, dkim: { state: 'off' } }),
    facts({ domain: 'example-test.com.tr', registration: { state: 'unsupported', tld: 'tr' }, dmarc: { state: 'none', count: 0 } })
  ]);

  test('adoption: per measure, how many domains meet it, miss it or could not be checked; the share of all', () => {
    const a = securityAdoption(rows);
    assert.deepEqual(a.map((x) => [x.id, x.pass, x.fail, x.unknown, x.total]), [
      ['registrar', 2, 0, 1, 3], ['registryLock', 2, 0, 1, 3], ['caa', 2, 1, 0, 3], ['dnsRedundancy', 3, 0, 0, 3],
      ['dnssec', 3, 0, 0, 3], ['spf', 3, 0, 0, 3], ['dkim', 2, 0, 1, 3], ['dmarc', 2, 1, 0, 3]
    ]);
    assert.equal(a[0].share, 2 / 3);
    assert.deepEqual(securityAdoption([]).map((x) => [x.total, x.share]), Array(8).fill([0, null]));
  });

  test('totals: the average score, the domains that meet all eight, the measures not known', () => {
    assert.deepEqual(securityTotals(rows), { domains: 3, average: (8 + 6 + 5) / 3, full: 1, unknownDomains: 2, unknownMeasures: 3 });
    assert.deepEqual(securityTotals([]), { domains: 0, average: null, full: 0, unknownDomains: 0, unknownMeasures: 0 });
  });

  test('CSV: a row per domain, the score, then a column per measure with its status and evidence, in English and Turkish', () => {
    const lines = securityCsv(rows, { t }).replace(/^\uFEFF/, '').trimEnd().split('\r\n');
    assert.equal(lines[0], 'Domain,Score (of 8),Not known,Corporate registrar,Registry lock,CAA,DNS redundancy,DNSSEC,SPF,DKIM,DMARC');
    assert.match(lines[1], /^example\.com,8,0,PASS · a corporate registrar: Example Brand Registrar \(IANA ID 292\),"PASS · a registry lock: server transfer, update and delete prohibited",/);
    assert.match(lines[2], /^example\.org,6,1,.*,FAIL · no CAA record: any CA may issue,.*,UNKNOWN · not checked \(turned off\),/);
    assert.match(lines[3], /^example-test\.com\.tr,5,2,UNKNOWN · the \.tr registry publishes no RDAP: see its WHOIS,/);
    const tr = securityCsv(rows, { t: makeT('tr') }).replace(/^\uFEFF/, '').split('\r\n');
    assert.equal(tr[0], 'Alan adı,Puan (8 üzerinden),Bilinmeyen,Kurumsal kayıt firması,Kayıt kuruluşu kilidi,CAA,DNS yedekliliği,DNSSEC,SPF,DKIM,DMARC');
    assert.match(tr[2], /,FAIL · CAA kaydı yok: her CA sertifika verebilir,/);
  });

  test('JSON codes: the score, the measures not known, each measure\'s status by id', () => {
    assert.deepEqual(securityExport(rows[1]), {
      score: 6, max: 8, unknown: 1,
      measures: { registrar: 'pass', registryLock: 'pass', caa: 'fail', dnsRedundancy: 'pass', dnssec: 'pass', spf: 'pass', dkim: 'unknown', dmarc: 'pass' }
    });
  });
});

describe('texts', () => {
  test('a name and what it asks for every measure, in both languages with the same placeholders', () => {
    assert.deepEqual(Object.keys(SECURITY_I18N.tr).sort(), Object.keys(SECURITY_I18N.en).sort());
    for (const m of SECURITY_MEASURES) {
      for (const k of [`sec.m.${m.id}`, `sec.d.${m.id}`]) assert.ok(SECURITY_I18N.en[k] && SECURITY_I18N.tr[k], k);
    }
    const ph = (s) => [...String(s).matchAll(/\{(\w+)\}/g)].map((x) => x[1]).sort().join();
    for (const [k, v] of Object.entries(SECURITY_I18N.en)) assert.equal(ph(SECURITY_I18N.tr[k]), ph(v), k);
  });
});
