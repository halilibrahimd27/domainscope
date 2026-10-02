/**
 * lib/policy.js — the domain policy: its parser (flat and nested, every value kind, the errors
 * that leave a rule out), the presets, the evaluator over lib/portfolio.js facts (pass, fail and
 * "not known" with the evidence), the matrix and its exports, and every text in both languages.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import {
  POLICY_RULES, POLICY_PRESETS, POLICY_PRESET_IDS, POLICY_OPS, POLICY_I18N, POLICY_ERRORS, POLICY_MAX_RULES,
  parsePolicy, policyObject, policyText, presetPolicy, evaluatePolicy, auditPortfolio, auditCsv, auditJson, evidenceText, requirementText, policyRule
} from '../../assets/js/lib/policy.js';
import { portfolioFacts } from '../../assets/js/lib/portfolio.js';
import { HEALTH_CHECK_IDS } from '../../assets/js/lib/health.js';

/** English `t` over POLICY_I18N (plural objects: one / other / zero). */
function makeT(lang = 'en') {
  const dict = POLICY_I18N[lang];
  return (key, params = {}) => {
    let s = dict[key];
    if (s === undefined) return key;
    if (typeof s === 'object') s = (params.count === 0 && s.zero) || (params.count === 1 && s.one) || s.other;
    return s.replace(/\{(\w+)\}/g, (m, k) => (k in params ? String(params[k]) : m));
  };
}
const t = makeT('en');

/** Facts as lib/portfolio.js derives them, with only the parts a test needs (the rest unknown). */
function facts(over = {}) {
  return {
    domain: 'example.com',
    exists: true,
    registration: { state: 'ok', daysLeft: 200, expires: new Date('2027-04-20T00:00:00Z'), registrar: 'Example Registrar, Inc.', transferLock: true, critical: [], statuses: ['client transfer prohibited'] },
    ns: { state: 'ok', hosts: ['ns1.example.net'], domains: [{ domain: 'example.net', own: false, state: 'ok', daysLeft: 90 }], minDaysLeft: 90 },
    dnssec: { state: 'validated' },
    caa: { state: 'present', issuers: ['letsencrypt.org'], wildIssuers: [] },
    mx: { state: 'some', hosts: ['mx.example.com'] },
    spf: { state: 'ok', all: '-', lookups: 4, lookupsState: 'ok' },
    dmarc: { state: 'ok', policy: 'quarantine', pct: 100 },
    dkim: { state: 'found', selectors: ['google'], asked: 8 },
    mtaSts: { state: 'present' },
    tlsRpt: { state: 'none' },
    parked: { parked: false },
    ...over
  };
}

const cellOf = (policy, f, id) => evaluatePolicy(policy, f).find((c) => c.id === id);
const one = (rules) => parsePolicy({ rules }).policy;

describe('parsePolicy', () => {
  test('the example of the request: flat, every value kind, rules in POLICY_RULES order', () => {
    const { policy, errors } = parsePolicy('{ "dmarc.policy": ">= quarantine", "dnssec": "signed", "caa": "present", "transferLock": true, "expiryDays": ">= 30" }');
    assert.deepEqual(errors, []);
    assert.equal(policy.name, null);
    assert.deepEqual(policy.rules.map((r) => [r.id, r.op, r.value]), [
      ['expiryDays', '>=', 30], ['transferLock', '==', true], ['dnssec', '>=', 'signed'], ['caa', '==', 'present'], ['dmarc.policy', '>=', 'quarantine']
    ]);
  });

  test('nested { name, rules }; bare numbers and levels take the rule\'s natural operator; = is ==', () => {
    const { policy, errors } = parsePolicy({
      name: '  Customer   A ', version: 1,
      rules: { expiryDays: 45, 'spf.lookups': 9, 'spf.all': '~', 'dmarc.policy': 'p=reject', registrar: 'Example Registrar', 'caa.issuers': ['letsencrypt.org', 'LetsEncrypt.org', 'sectigo.com'], dkim: 'true', spf: true, nsExpiryDays: '= 60' }
    });
    assert.deepEqual(errors, []);
    assert.equal(policy.name, 'Customer A');
    const by = Object.fromEntries(policy.rules.map((r) => [r.id, [r.op, r.value]]));
    assert.deepEqual(by.expiryDays, ['>=', 45]);
    assert.deepEqual(by['spf.lookups'], ['<=', 9]);
    assert.deepEqual(by['spf.all'], ['>=', '~all']);
    assert.deepEqual(by['dmarc.policy'], ['>=', 'reject']);
    assert.deepEqual(by.registrar, ['in', ['Example Registrar']]);
    assert.deepEqual(by['caa.issuers'], ['in', ['letsencrypt.org', 'sectigo.com']], 'case-free duplicates dropped');
    assert.deepEqual(by.dkim, ['==', true]);
    assert.deepEqual(by.spf, ['==', 'valid']);
    assert.deepEqual(by.nsExpiryDays, ['==', 60]);
  });

  test('errors: not JSON, not an object, too long, too many rules; an unknown rule or a bad value is left out, never passed', () => {
    assert.equal(parsePolicy('{ nope').errors[0].code, 'not-json');
    assert.equal(parsePolicy('[1, 2]').errors[0].code, 'not-object');
    assert.equal(parsePolicy({ rules: [1] }).errors[0].code, 'not-object');
    assert.equal(parsePolicy(`{"x":"${'a'.repeat(20000)}"}`).errors[0].code, 'too-large');
    const many = Object.fromEntries(Array.from({ length: POLICY_MAX_RULES + 1 }, (_, i) => [`r${i}`, 1]));
    assert.equal(parsePolicy(many).errors[0].code, 'too-many');
    const { policy, errors } = parsePolicy({ expiryDays: '>= thirty', dnsec: 'signed', transferLock: 'yes', caa: 'maybe', 'spf.lookups': 101, 'dmarc.policy': '>= strict', dkim: true });
    assert.deepEqual(policy.rules.map((r) => r.id), ['dkim']);
    assert.deepEqual(errors.map((e) => [e.code, e.rule]), [
      ['bad-value', 'expiryDays'], ['unknown-rule', 'dnsec'], ['bad-value', 'transferLock'], ['bad-value', 'caa'], ['bad-value', 'spf.lookups'], ['bad-value', 'dmarc.policy']
    ]);
    assert.equal(errors[0].example, '">= 30"', 'the error offers an example');
    assert.deepEqual(parsePolicy({}).errors, [{ code: 'empty' }]);
    for (const e of POLICY_ERRORS) assert.ok(POLICY_I18N.en[`pol.err.${e}`] && POLICY_I18N.tr[`pol.err.${e}`], e);
  });

  test('the file round-trips: every value written out, the same policy read back', () => {
    const p = parsePolicy({ name: 'x', rules: { expiryDays: 30, dnssec: 'signed', caa: true, registrar: 'Example Registrar' } }).policy;
    assert.deepEqual(policyObject(p), { name: 'x', version: 1, rules: { expiryDays: '>= 30', registrar: ['Example Registrar'], dnssec: '>= signed', caa: 'present' } });
    const text = policyText(p);
    assert.ok(text.endsWith('}\n'));
    assert.deepEqual(parsePolicy(text).policy, p);
  });

  test('presets: baseline, strict mail, parked domain; each parses without an error', () => {
    assert.deepEqual(POLICY_PRESET_IDS, ['baseline', 'strict-mail', 'parked']);
    for (const id of POLICY_PRESET_IDS) {
      const { errors } = parsePolicy(POLICY_PRESETS[id]);
      assert.deepEqual(errors, [], id);
      assert.ok(POLICY_I18N.en[`pol.preset.${id}`] && POLICY_I18N.tr[`pol.preset.${id}`], id);
    }
    assert.deepEqual(presetPolicy('parked').rules.map((r) => r.id), ['expiryDays', 'transferLock', 'caa', 'spf.all', 'dmarc.policy', 'mx.null']);
    assert.throws(() => presetPolicy('nope'), RangeError);
  });

  test('every rule: a label in both languages, an example its own parser takes, health check ids that exist', () => {
    for (const r of POLICY_RULES) {
      assert.ok(POLICY_I18N.en[`pol.rule.${r.id}`] && POLICY_I18N.tr[`pol.rule.${r.id}`], r.id);
      assert.deepEqual(parsePolicy({ [r.id]: r.example }).errors, [], r.id);
      for (const h of r.health) assert.ok(HEALTH_CHECK_IDS.includes(h), `${r.id}: ${h}`);
    }
    assert.deepEqual(POLICY_OPS, ['>=', '<=', '>', '<', '==', '!=']);
    assert.equal(policyRule('nope'), null);
  });
});

describe('evaluatePolicy', () => {
  test('expiry: days left against the requirement; an expired domain; a registry without RDAP is "not known"', () => {
    const p = one({ expiryDays: '>= 30' });
    assert.equal(cellOf(p, facts(), 'expiryDays').status, 'pass');
    const soon = cellOf(p, facts({ registration: { ...facts().registration, daysLeft: 12 } }), 'expiryDays');
    assert.deepEqual([soon.status, soon.actual, evidenceText(soon, t), soon.required], ['fail', 12, '12 days left (2027-04-20)', '>= 30']);
    const gone = cellOf(p, facts({ registration: { ...facts().registration, daysLeft: -3 } }), 'expiryDays');
    assert.deepEqual([gone.status, evidenceText(gone, t)], ['fail', 'expired 3 days ago (2027-04-20)']);
    const tr = cellOf(p, facts({ registration: { state: 'unsupported', tld: 'tr' } }), 'expiryDays');
    assert.deepEqual([tr.status, evidenceText(tr, t)], ['unknown', 'the .tr registry publishes no RDAP: see its WHOIS']);
    assert.equal(cellOf(p, facts({ registration: { state: 'failed' } }), 'expiryDays').status, 'unknown');
    assert.equal(evidenceText(cellOf(p, facts({ registration: { state: 'failed' } }), 'expiryDays'), t), 'RDAP lookup failed');
    assert.equal(cellOf(p, facts({ registration: { state: 'not-found' } }), 'expiryDays').status, 'fail', 'not registered: anyone can take it');
  });

  test('transfer lock, critical statuses, registrar', () => {
    const p = one({ transferLock: true, 'status.critical': false, registrar: ['Example Registrar', 'Other Registrar'] });
    assert.deepEqual(evaluatePolicy(p, facts()).map((c) => c.status), ['pass', 'pass', 'pass']);
    assert.equal(evidenceText(cellOf(p, facts(), 'transferLock'), t), 'transfers are prohibited: client transfer prohibited');
    // A registry lock alone is a transfer lock (RFC 5731: transfer requests MUST be rejected).
    const registry = cellOf(p, facts({ registration: { ...facts().registration, statuses: ['server transfer prohibited'], transferLock: true, registryLock: true } }), 'transferLock');
    assert.deepEqual([registry.status, evidenceText(registry, t)], ['pass', 'transfers are prohibited: server transfer prohibited']);
    const bad = evaluatePolicy(p, facts({ registration: { ...facts().registration, statuses: ['active'], transferLock: false, critical: ['serverHold'], registrar: 'Elsewhere Ltd' } }));
    assert.deepEqual(bad.map((c) => [c.status, evidenceText(c, t)]), [
      ['fail', 'no transfer prohibition (clientTransferProhibited or serverTransferProhibited): the domain can be transferred away'],
      ['fail', 'critical status: serverHold'],
      ['fail', 'registrar: Elsewhere Ltd']
    ]);
    assert.equal(cellOf(p, facts({ registration: { ...facts().registration, transferLock: null } }), 'transferLock').status, 'unknown', 'no status from the registry');
  });

  test('name server domains: the soonest decides; one not known leaves a pass "not known", never a fail', () => {
    const p = one({ nsExpiryDays: '>= 30' });
    assert.deepEqual([cellOf(p, facts(), 'nsExpiryDays').status, evidenceText(cellOf(p, facts(), 'nsExpiryDays'), t)], ['pass', 'name server domain example.net: 90 days left']);
    const ns = (domains) => facts({ ns: { state: 'ok', hosts: [], domains } });
    const soon = cellOf(p, ns([{ domain: 'example.net', state: 'ok', daysLeft: 10 }, { domain: 'example.org', state: 'failed', daysLeft: null }]), 'nsExpiryDays');
    assert.deepEqual([soon.status, soon.actual], ['fail', 10], 'one known to fail is enough');
    const partial = cellOf(p, ns([{ domain: 'example.net', state: 'ok', daysLeft: 300 }, { domain: 'example.org', state: 'unsupported', daysLeft: null }]), 'nsExpiryDays');
    assert.deepEqual([partial.status, evidenceText(partial, t)], ['unknown', 'the expiry of name server domain example.org is not known']);
    assert.equal(cellOf(p, facts({ ns: { state: 'failed', domains: [] } }), 'nsExpiryDays').status, 'unknown');
    assert.equal(evidenceText(cellOf(p, ns([{ domain: 'example.net', state: 'ok', daysLeft: -2 }]), 'nsExpiryDays'), t), 'name server domain example.net expired 2 days ago');
    // Name servers under the domain itself expire with it: expiryDays says that, this rule reads the others.
    const own = { domain: 'example.com', own: true, state: 'ok', daysLeft: 12 };
    const mixed = cellOf(p, ns([own, { domain: 'example.net', own: false, state: 'ok', daysLeft: 300 }]), 'nsExpiryDays');
    assert.deepEqual([mixed.status, mixed.actual, evidenceText(mixed, t)], ['pass', 300, 'name server domain example.net: 300 days left']);
    const ownOnly = cellOf(p, ns([own]), 'nsExpiryDays');
    assert.deepEqual([ownOnly.status, evidenceText(ownOnly, t)], ['pass', 'the name servers are under the domain itself: they expire with it']);
    // A name server domain the registry says is not registered: the classic takeover, a fail before any count of days.
    const gone = cellOf(p, ns([{ domain: 'example.net', state: 'ok', daysLeft: 10 }, { domain: 'example.org', state: 'not-found', daysLeft: null }]), 'nsExpiryDays');
    assert.deepEqual([gone.status, gone.evidence.key, evidenceText(gone, t)],
      ['fail', 'pol.ev.nsNotRegistered', 'name server domain example.org is not registered — anyone can register it and take over DNS']);
    assert.equal(cellOf(p, ns([{ domain: 'example.org', state: 'not-found', daysLeft: null }]), 'nsExpiryDays').status, 'fail', 'never "not known"');
  });

  test('DNSSEC as levels; DS with keys that could not be read', () => {
    const atLeast = one({ dnssec: 'signed' });
    const validated = one({ dnssec: 'validated' });
    const d = (state) => facts({ dnssec: { state } });
    assert.deepEqual(['validated', 'signed', 'unsigned'].map((s) => cellOf(atLeast, d(s), 'dnssec').status), ['pass', 'pass', 'fail']);
    assert.deepEqual(['validated', 'signed', 'unsigned'].map((s) => cellOf(validated, d(s), 'dnssec').status), ['pass', 'fail', 'fail']);
    assert.equal(cellOf(atLeast, d('failing'), 'dnssec').status, 'pass', 'signed for sure');
    assert.equal(cellOf(validated, d('failing'), 'dnssec').status, 'unknown', 'validated or not: not known');
    assert.equal(cellOf(one({ dnssec: '== unsigned' }), d('failing'), 'dnssec').status, 'fail');
    assert.equal(cellOf(atLeast, facts({ dnssec: { state: null, failure: {} } }), 'dnssec').status, 'unknown');
  });

  test('CAA: present, deny-all and the only CAs it may allow', () => {
    const present = one({ caa: 'present' });
    const deny = one({ caa: 'deny-all' });
    const only = one({ 'caa.issuers': ['letsencrypt.org'] });
    const caa = (c) => facts({ caa: c });
    assert.equal(cellOf(present, facts(), 'caa').status, 'pass');
    assert.equal(cellOf(present, caa({ state: 'none' }), 'caa').status, 'fail');
    assert.equal(evidenceText(cellOf(present, caa({ state: 'none' }), 'caa'), t), 'no CAA record: any CA may issue');
    assert.equal(cellOf(present, caa({ state: 'unrestricted' }), 'caa').status, 'fail', 'no issue property: any CA');
    assert.equal(cellOf(deny, caa({ state: 'deny-all' }), 'caa').status, 'pass');
    assert.equal(cellOf(deny, facts(), 'caa').status, 'fail');
    assert.equal(cellOf(only, facts(), 'caa.issuers').status, 'pass');
    const extra = cellOf(only, caa({ state: 'present', issuers: ['letsencrypt.org'], wildIssuers: ['sectigo.com'] }), 'caa.issuers');
    assert.deepEqual([extra.status, evidenceText(extra, t)], ['fail', 'CAA also allows sectigo.com']);
    assert.equal(cellOf(only, caa({ state: 'deny-all' }), 'caa.issuers').status, 'pass', 'nobody at all is within the list');
    assert.equal(cellOf(only, caa({ state: 'none' }), 'caa.issuers').status, 'fail');
  });

  test('SPF: valid, lookups (a partial count fails only when already over), the "all" qualifier', () => {
    const p = one({ spf: 'valid', 'spf.lookups': '<= 10', 'spf.all': '>= ~all' });
    assert.deepEqual(evaluatePolicy(p, facts()).map((c) => c.status), ['pass', 'pass', 'pass']);
    const over = evaluatePolicy(p, facts({ spf: { state: 'ok', all: '~', lookups: 12, lookupsState: 'ok' } }));
    assert.deepEqual(over.map((c) => c.status), ['pass', 'fail', 'pass']);
    assert.equal(evidenceText(over[1], t), '12 DNS lookups');
    const partial = (n) => cellOf(p, facts({ spf: { state: 'ok', all: '-', lookups: n, lookupsState: 'partial' } }), 'spf.lookups').status;
    assert.deepEqual([partial(4), partial(11)], ['unknown', 'fail']);
    const none = evaluatePolicy(p, facts({ spf: { state: 'none' } }));
    assert.deepEqual(none.map((c) => [c.status, evidenceText(c, t)]), [['fail', 'no SPF record'], ['fail', 'no SPF record'], ['fail', 'no SPF record']]);
    assert.equal(cellOf(p, facts({ spf: { state: 'ok', all: null, redirect: '_spf.example.net' } }), 'spf.all').status, 'unknown', 'redirected: the qualifier is the other record\'s');
    assert.equal(cellOf(p, facts({ spf: { state: 'ok', all: null, redirect: null } }), 'spf.all').status, 'fail', 'no all: neutral');
    assert.equal(cellOf(one({ 'spf.all': '== -all' }), facts({ spf: { state: 'ok', all: '~' } }), 'spf.all').status, 'fail');
    assert.equal(cellOf(p, facts({ spf: { state: null, failure: {} } }), 'spf').status, 'unknown');
  });

  test('DMARC as levels, a missing record fails; DKIM, MTA-STS, TLS-RPT, null MX', () => {
    const p = one({ 'dmarc.policy': '>= quarantine', dkim: true, mtaSts: true, tlsRpt: true, 'mx.null': true });
    assert.deepEqual(evaluatePolicy(p, facts()).map((c) => [c.id, c.status]), [
      ['dmarc.policy', 'pass'], ['dkim', 'pass'], ['mtaSts', 'pass'], ['tlsRpt', 'fail'], ['mx.null', 'fail']
    ]);
    const weak = cellOf(p, facts({ dmarc: { state: 'ok', policy: 'none' } }), 'dmarc.policy');
    assert.deepEqual([weak.status, evidenceText(weak, t)], ['fail', 'DMARC p=none']);
    assert.equal(evidenceText(cellOf(p, facts({ dmarc: { state: 'none' } }), 'dmarc.policy'), t), 'no DMARC record');
    assert.equal(cellOf(p, facts({ dkim: { state: 'off' } }), 'dkim').status, 'unknown', 'not checked is not "none"');
    assert.equal(evidenceText(cellOf(p, facts({ dkim: { state: 'off' } }), 'dkim'), t), 'not checked (turned off)');
    assert.equal(cellOf(p, facts({ dkim: { state: 'none', asked: 8 } }), 'dkim').status, 'fail');
    assert.equal(cellOf(p, facts({ mtaSts: { state: 'invalid' } }), 'mtaSts').status, 'fail', 'a record senders ignore');
    assert.equal(cellOf(p, facts({ mx: { state: 'null' } }), 'mx.null').status, 'pass');
  });

  test('a domain that does not exist in DNS fails its DNS rules with that reason', () => {
    const p = one({ dnssec: 'signed', 'dmarc.policy': '>= none', 'mx.null': true });
    const gone = evaluatePolicy(p, facts({ exists: false, dnssec: { state: null }, dmarc: { state: null }, mx: { state: null } }));
    assert.deepEqual(gone.map((c) => [c.status, evidenceText(c, t)]), Array(3).fill(['fail', 'the domain does not exist in DNS (NXDOMAIN)']));
  });
});

describe('the matrix', () => {
  const policy = parsePolicy({ name: 'baseline', rules: { expiryDays: '>= 30', transferLock: true, 'dmarc.policy': '>= quarantine' } }).policy;
  const list = [
    facts(),
    facts({ domain: 'example.org', registration: { ...facts().registration, daysLeft: 9, transferLock: false } }),
    facts({ domain: 'example-test.com.tr', registration: { state: 'unsupported', tld: 'tr' } })
  ];
  const audit = auditPortfolio(policy, list);

  test('one row per domain, one cell per rule; counts', () => {
    assert.deepEqual(audit.rules, [{ id: 'expiryDays', required: '>= 30' }, { id: 'transferLock', required: 'true' }, { id: 'dmarc.policy', required: '>= quarantine' }]);
    assert.deepEqual(audit.rows.map((r) => [r.domain, r.pass, r.fail, r.unknown]), [['example.com', 3, 0, 0], ['example.org', 1, 2, 0], ['example-test.com.tr', 1, 0, 2]]);
    assert.deepEqual(audit.counts, { domains: 3, failing: 1, passing: 1, unknown: 1, pass: 5, fail: 2, cells: 9 });
  });

  test('CSV: a row per domain, a column per rule with the status and the evidence', () => {
    const csv = auditCsv(audit, { t });
    const lines = csv.replace(/^﻿/, '').trimEnd().split('\r\n');
    assert.equal(lines[0], 'Domain,Failed,Not known,Passed,expiryDays (>= 30),transferLock (true),dmarc.policy (>= quarantine)');
    assert.equal(lines[2], 'example.org,2,0,1,FAIL · 9 days left (2027-04-20),FAIL · no transfer prohibition (clientTransferProhibited or serverTransferProhibited): the domain can be transferred away,PASS · DMARC p=quarantine');
    assert.match(lines[3], /^example-test\.com\.tr,0,2,1,UNKNOWN · the \.tr registry publishes no RDAP: see its WHOIS,/);
  });

  test('JSON: the policy file, the counts, every cell with its evidence worded and as its key', () => {
    const j = auditJson(audit, { t, policy, version: '1.0.0', at: new Date('2026-10-02T00:00:00Z') });
    assert.equal(j.format, 'domainscope-policy-audit');
    assert.deepEqual(j.policy.rules, { expiryDays: '>= 30', transferLock: true, 'dmarc.policy': '>= quarantine' });
    assert.deepEqual(j.rows[1].rules[0], { id: 'expiryDays', status: 'fail', required: '>= 30', actual: 9, evidence: '9 days left (2027-04-20)', key: 'pol.ev.daysLeft', params: { count: 9, date: '2027-04-20' } });
    assert.equal(j.at, '2026-10-02T00:00:00.000Z');
  });

  test('from real facts (lib/portfolio.js): nothing landed yet is "not known" everywhere', () => {
    const empty = auditPortfolio(presetPolicy('baseline'), [portfolioFacts({ domain: 'example.com' })]);
    assert.ok(empty.rows[0].cells.every((c) => c.status === 'unknown'), JSON.stringify(empty.rows[0].cells.map((c) => c.status)));
    assert.equal(requirementText({ id: 'registrar', op: 'in', value: ['Example Registrar, Inc.', 'b'] }), 'Example Registrar, Inc.; b', 'a list between semicolons: a name has commas');
  });

  test('Turkish texts: the same placeholders as English, never empty', () => {
    const ph = (s) => [...String(typeof s === 'object' ? s.other : s).matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join();
    assert.deepEqual(Object.keys(POLICY_I18N.tr).sort(), Object.keys(POLICY_I18N.en).sort());
    for (const [k, v] of Object.entries(POLICY_I18N.en)) {
      assert.equal(ph(POLICY_I18N.tr[k]), ph(v), k);
      assert.ok(String(typeof POLICY_I18N.tr[k] === 'object' ? POLICY_I18N.tr[k].other : POLICY_I18N.tr[k]).trim(), k);
    }
    assert.equal(evidenceText(cellOf(one({ expiryDays: 30 }), facts({ registration: { ...facts().registration, daysLeft: 3 } }), 'expiryDays'), makeT('tr')), '3 gün kaldı (2027-04-20)');
  });
});
