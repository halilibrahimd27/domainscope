/**
 * views/ptr.js and its hand-off into views/subdomains.js: the pure helpers (share link, issue
 * keys, the names intent and how Subdomains reads it back) and the strings every lib/ptrsweep
 * issue, status and plural renders to. Pure Node (the views are DOM-free at import time).
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';

import { setLang, t } from '../../assets/js/i18n.js';
import { parseSweepTarget, FCRDNS_STATUSES, TARGET_ISSUES } from '../../assets/js/lib/ptrsweep.js';
import { shareParams, linkText, issueKey, buildNamesIntent, confirmedHint, LINK_MAX_CHARS } from '../../assets/js/views/ptr.js';
import '../../assets/js/views/health.js'; // registers the hlt.fcrdns.* strings
import {
  namesFromIntent, handoffScanOverrides, handoffForDomains, NAMES_INTENT_MAX_AGE, NAMES_HANDOFF_MAX, ZONE_MODES
} from '../../assets/js/views/subdomains.js';

describe('Reverse DNS view helpers', () => {
  test('shareParams: comma-joined tokens, a clean focus domain, nothing for a long list', () => {
    assert.deepEqual(shareParams('192.0.2.0/24\n# a comment\n198.51.100.7, AS64496', ' Example.COM '), { target: '192.0.2.0/24,198.51.100.7,AS64496', focus: 'example.com' });
    assert.deepEqual(shareParams('192.0.2.1', 'not a domain!'), { target: '192.0.2.1', focus: null });
    assert.equal(shareParams(''), null);
    const long = Array.from({ length: 60 }, (_, i) => `192.0.2.${i}`).join('\n');
    assert.ok(long.length > LINK_MAX_CHARS);
    assert.equal(shareParams(long), null);
  });

  test('a range typed with spaces or an en dash survives the share link and the link read back', () => {
    const cases = [
      ['192.0.2.10 - 192.0.2.14', '192.0.2.10-192.0.2.14', 5],
      ['192.0.2.10 – 20', '192.0.2.10-20', 11],
      ['192.0.2.10–20\n198.51.100.7', '192.0.2.10-20,198.51.100.7', 12],
      ['AS 64496', 'AS64496', 0]
    ];
    for (const [typed, target, count] of cases) {
      assert.equal(shareParams(typed).target, target, typed);
      const back = parseSweepTarget(linkText(target));
      assert.deepEqual([back.issues, back.addresses.length], [[], count], typed);
      assert.equal(back.label, parseSweepTarget(typed).label, typed);
    }
    // a link typed by hand (spaces, an en dash) reads as the form would
    assert.equal(linkText('192.0.2.10 - 192.0.2.14, 198.51.100.7'), '192.0.2.10-192.0.2.14\n198.51.100.7');
    assert.equal(linkText('192.0.2.20 – 22'), '192.0.2.20-22');
    assert.equal(linkText(''), '');
  });

  test('issueKey: a network too large gets its first /22, or why it is not swept at all; a range has no network to suggest', () => {
    assert.equal(issueKey({ code: 'too-large', params: { suggestion: '192.0.0.0/22', kind: 'cidr', skipped: '' } }), 'ptr.issue.too-large');
    assert.equal(issueKey({ code: 'too-large', params: { suggestion: '' } }), 'ptr.issue.too-large.range');
    assert.equal(issueKey({ code: 'too-large', params: { suggestion: '', kind: 'range', skipped: '' } }), 'ptr.issue.too-large.range');
    assert.equal(issueKey({ code: 'too-large', params: { suggestion: '', kind: 'cidr', skipped: '' } }), 'ptr.issue.too-large.split');
    assert.equal(issueKey({ code: 'too-large', params: { suggestion: '', kind: 'cidr', skipped: 'private' } }), 'ptr.issue.too-large.private');
    assert.equal(issueKey({ code: 'too-large', params: { suggestion: '', kind: 'cidr', skipped: 'reserved' } }), 'ptr.issue.too-large.reserved');
    assert.equal(issueKey({ code: 'private', params: {} }), 'ptr.issue.private');
  });

  test('every issue parseSweepTarget can raise renders in both languages with its params filled', () => {
    const inputs = ['nonsense', '2001:db8::/64', '198.51.100.20-10 192.0.2.1', '192.0.0.0/20', '198.18.0.0/16', '198.18.0.0-198.18.7.255', '198.51.100.0-203.0.113.255',
      '224.0.0.0/4', '0.0.0.0/1', '192.0.2.0/24 198.51.100.0/22', 'AS64496 AS64497', 'AS64496 192.0.2.1',
      '10.0.0.0/30 224.0.0.1 192.0.2.1', '192.0.2.77/30'];
    const seen = new Set();
    const keys = new Set();
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      for (const text of inputs) {
        for (const issue of parseSweepTarget(text).issues) {
          seen.add(issue.code);
          keys.add(issueKey(issue));
          const out = t(issueKey(issue), issue.params);
          assert.ok(!/\{\w+\}/.test(out), `${lang} ${issue.code}: ${out}`);
          assert.notEqual(out, issueKey(issue));
        }
      }
    }
    assert.deepEqual([...seen].sort(), [...TARGET_ISSUES].sort());
    for (const k of ['too-large', 'too-large.range', 'too-large.split', 'too-large.private', 'too-large.reserved']) assert.ok(keys.has(`ptr.issue.${k}`), k);
  });

  test('English plurals and Turkish singular nouns after a number', () => {
    setLang('en');
    assert.equal(t('ptr.parsed.addresses', { count: 1 }), '1 address');
    assert.equal(t('ptr.parsed.addresses', { count: 1024 }), '1,024 addresses');
    assert.equal(t('ptr.issue.private', { count: 1 }), '1 private address left out: public resolvers cannot see an internal reverse zone (ask your own DNS server).');
    assert.equal(t('ptr.asn.selected', { count: 0, addresses: '0', max: '1,024' }), 'Nothing selected yet');
    assert.equal(t('ptr.asn.selected', { count: 2, addresses: '512', max: '1,024' }), 'Selected: 2 prefixes · 512 of at most 1,024 addresses');
    setLang('tr');
    assert.equal(t('ptr.parsed.addresses', { count: 5 }), '5 adres');
    assert.equal(t('ptr.pattern.count', { count: 8 }), '8 adres');
    for (const s of FCRDNS_STATUSES) {
      for (const key of [`ptr.st.${s}`, `ptr.st.${s}.title`, `hlt.fcrdns.st.${s}`]) assert.notEqual(t(key), key, key);
    }
  });

  test('confirmedHint: "every name resolves back" only when there are names and each does', () => {
    setLang('en');
    const s = (over) => ({ done: 16, withPtr: 12, forwardFailed: 0, ...over, byStatus: { confirmed: 12, mismatch: 0, ...(over.byStatus || {}) } });
    assert.equal(confirmedHint(s({})), 'every name resolves back');
    assert.equal(confirmedHint(s({ byStatus: { confirmed: 11, mismatch: 1 } })), '1 does not resolve back');
    assert.equal(confirmedHint(s({ byStatus: { confirmed: 9, mismatch: 2 }, forwardFailed: 1 })), '2 do not resolve back · 1 could not be checked');
    // no PTR name at all (an unused block), or every forward lookup failed: never "every name resolves back"
    assert.equal(confirmedHint(s({ withPtr: 0, byStatus: { confirmed: 0 } })), 'no PTR name to check');
    assert.equal(confirmedHint(s({ withPtr: 3, forwardFailed: 3, byStatus: { confirmed: 0 } })), '3 could not be checked');
    assert.equal(confirmedHint(s({ done: 0, withPtr: 0, byStatus: { confirmed: 0 } })), null, 'nothing before the first result');
    setLang('tr');
    assert.equal(confirmedHint(s({ withPtr: 0, byStatus: { confirmed: 0 } })), 'kontrol edilecek PTR adı yok');
    assert.equal(confirmedHint(s({})), 'her ad adresine geri çözülüyor');
    assert.equal(confirmedHint(s({ byStatus: { confirmed: 10, mismatch: 2 } })), '2 tanesi adresine geri çözülmüyor');
    setLang('en');
  });

  after(() => setLang('en'));
});

describe('Subdomains: names handed over by the Reverse DNS view', () => {
  const now = 1_800_000_000_000;
  const intent = (over = {}) => ({ ...buildNamesIntent({ names: ['mail.example.com', 'www.example.com'], domains: ['example.com'], label: '192.0.2.0/28', now }), ...over });

  test('a fresh intent round-trips; the names are re-validated (PTR data is untrusted)', () => {
    assert.deepEqual(namesFromIntent(intent(), now + 1000), {
      names: ['mail.example.com', 'www.example.com'], domains: ['example.com'], label: '192.0.2.0/28', source: 'ptr', mode: 'exact'
    });
    const dirty = namesFromIntent(intent({ names: ['MAIL.example.com.', 'bad name', '$(reboot).example.com', '192.0.2.1', 'ok.example.net'], label: 'a\nb' }), now);
    assert.deepEqual(dirty.names, ['mail.example.com', 'ok.example.net']);
    assert.equal(dirty.label, 'a b');
    assert.equal(namesFromIntent(intent({ mode: 'discover' }), now).mode, 'discover');
  });

  test('stale, foreign, empty or malformed intents are ignored', () => {
    assert.equal(namesFromIntent(intent(), now + NAMES_INTENT_MAX_AGE + 1), null);
    assert.equal(namesFromIntent(intent(), now - 1), null, 'from the future');
    assert.equal(namesFromIntent(intent({ target: 'scan' }), now), null);
    assert.equal(namesFromIntent(intent({ v: 2 }), now), null);
    assert.equal(namesFromIntent(intent({ names: ['not a name'] }), now), null);
    assert.equal(namesFromIntent(null, now), null);
    assert.equal(namesFromIntent('x', now), null);
  });

  test('at most NAMES_HANDOFF_MAX names', () => {
    const many = Array.from({ length: NAMES_HANDOFF_MAX + 10 }, (_, i) => `h${i}.example.com`);
    assert.equal(namesFromIntent(intent({ names: many }), now).names.length, NAMES_HANDOFF_MAX);
  });

  test('handoffScanOverrides: exact resolves the names only; discover and off change nothing', () => {
    assert.deepEqual(handoffScanOverrides({ mode: 'exact', names: ['a.example.com'] }), {
      exact: true, sources: [], bruteforce: 'off', permutationBudget: 0, recursive: false, mine: false, learnedLabels: null, customWordlist: null
    });
    assert.deepEqual(handoffScanOverrides({ mode: 'discover', names: ['a.example.com'] }), {});
    assert.deepEqual(handoffScanOverrides({ mode: 'off', names: ['a.example.com'] }), {});
    assert.deepEqual(handoffScanOverrides(null), {});
    assert.deepEqual(ZONE_MODES, ['exact', 'discover', 'off']);
  });

  test('handoffForDomains: a scan uses only the names under its domains; another domain gets none (nor exact mode)', () => {
    const ho = namesFromIntent(intent({ names: ['mail.example.com', 'www.example.com', 'ns1.example.org'], domains: ['example.com', 'example.org'] }), now);
    assert.deepEqual(handoffForDomains(ho, ['example.com']), { ...ho, names: ['mail.example.com', 'www.example.com'], total: 3 });
    assert.deepEqual(handoffForDomains(ho, ['example.com', 'example.org']).names, ['mail.example.com', 'www.example.com', 'ns1.example.org']);
    assert.deepEqual(handoffForDomains(ho, ['mail.example.com']).names, ['mail.example.com'], 'a narrower domain');
    assert.equal(handoffForDomains(ho, ['example.net']), null);
    assert.equal(handoffForDomains(ho, []), null);
    assert.equal(handoffForDomains(null, ['example.com']), null);
    // the mode is the hand-off's own (the chip changes it)
    assert.equal(handoffForDomains({ ...ho, mode: 'off' }, ['example.org']).mode, 'off');
  });
});
