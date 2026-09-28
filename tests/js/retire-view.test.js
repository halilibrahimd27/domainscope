/**
 * views/retire.js: the pure helpers (share link, the domain box filled in from the page session,
 * the known host names per domain and their cap, the "what to change" text of every action and
 * record type, the Copy summary facts) and the strings they render to in English and Turkish.
 * Pure Node (the view is DOM-free at import time); documentation data only.
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';

import { setLang, t, hasString } from '../../assets/js/i18n.js';
import {
  shareParams, linkText, prefillDomains, hostsForDomains, changeText, summaryFacts, jobGaps, gapTexts, failureList, LINK_MAX_CHARS
} from '../../assets/js/views/retire.js';
import { buildChanges, parseRetireTargets, CHANGE_ACTIONS, UNKNOWN_REASONS, RETIRE_MAX_HOSTS } from '../../assets/js/lib/retire.js';
import { buildSummary, renderMarkdown } from '../../assets/js/lib/summary.js';
import '../../assets/js/ui/summary-button.js'; // registers the sum.* strings

after(() => setLang('en'));

const change = (extra) => ({
  key: 'k', group: 'example.com', groupKind: 'domain', severity: 'live', name: 'example.com', type: 'A', value: '192.0.2.10',
  addresses: ['192.0.2.10'], blocks: ['192.0.2.10/32'], action: 'remove', verified: 'live', via: [], roles: [], sources: ['dns'],
  line: null, proxied: null, spf: null, reason: null, foundFor: ['example.com'], ...extra
});

describe('Retire an IP view helpers', () => {
  test('shareParams: comma-joined addresses and domains; nothing without an address or for a long form', () => {
    assert.deepEqual(shareParams('192.0.2.10\n# old web\n2001:db8::10', ' Example.COM\nhttps://www.example.net/x'), {
      ips: '192.0.2.10,2001:db8::10', domains: 'example.com,www.example.net'
    });
    assert.deepEqual(shareParams('192.0.2.0/28', ''), { ips: '192.0.2.0/28' });
    assert.equal(shareParams('', 'example.com'), null);
    const long = Array.from({ length: 40 }, (_, i) => `host-${i}.example.com`).join('\n');
    assert.ok(long.length > LINK_MAX_CHARS);
    assert.equal(shareParams('192.0.2.10', long), null);
    assert.equal(linkText('192.0.2.10,192.0.2.0/28'), '192.0.2.10\n192.0.2.0/28');
    assert.equal(linkText(undefined), '');
  });

  test('prefillDomains: the last scan, then the zone — each domain once, with where from', () => {
    assert.deepEqual(prefillDomains({ scanHosts: { domains: ['example.com', 'www.example.net'] }, zone: { origin: 'example.org' } }),
      { domains: ['example.com', 'www.example.net', 'example.org'], sources: ['scan', 'zone'] });
    assert.deepEqual(prefillDomains({ scanHosts: { domains: ['example.com'] }, zone: { origin: 'example.com' } }), { domains: ['example.com'], sources: ['scan'] },
      'a source that adds nothing new is not named');
    assert.deepEqual(prefillDomains({ scanHosts: { domains: 'nope' }, zone: {} }), { domains: [], sources: [] });
  });

  test('hostsForDomains: every source per domain, in order, capped for the whole check', () => {
    const { hosts, capped } = hostsForDomains(['example.com', 'example.net'], {
      scanHosts: { names: ['www.example.com', 'api.example.com', 'www.example.org'] },
      zone: { names: ['www.example.com', 'shop.example.com', 'ns1.example.net'] },
      passive: new Map([['example.net', ['forum.example.net']]]),
      discovered: new Map([['example.net', ['mail.example.net']]])
    });
    assert.equal(capped, false);
    assert.deepEqual(hosts.get('example.com'), [
      { name: 'www.example.com', source: 'scan' }, { name: 'api.example.com', source: 'scan' }, { name: 'shop.example.com', source: 'zone' }
    ]);
    assert.deepEqual(hosts.get('example.net'), [
      { name: 'ns1.example.net', source: 'zone' }, { name: 'forum.example.net', source: 'passive' }, { name: 'mail.example.net', source: 'discovered' }
    ]);
    const many = Array.from({ length: RETIRE_MAX_HOSTS + 5 }, (_, i) => `h${i}.example.com`);
    const big = hostsForDomains(['example.com', 'example.net'], { scanHosts: { names: [...many, 'www.example.net'] } });
    assert.equal(big.capped, true);
    assert.equal(big.hosts.get('example.com').length, RETIRE_MAX_HOSTS);
    assert.deepEqual(big.hosts.get('example.net'), [], 'nothing left for the next domain');
  });

  test('changeText: one text for each action and record type, every key in English and Turkish', () => {
    const cases = [
      [change({}), 'retire.act.remove.a'],
      [change({ type: 'HTTPS' }), 'retire.act.remove.https'],
      [change({ type: 'TXT', value: 'ip4:192.0.2.10', severity: 'mail', spf: { holder: 'example.com' } }), 'retire.act.remove.spf'],
      [change({ type: 'TXT', value: '-ip4:192.0.2.10', severity: 'stale', spf: { holder: 'example.com' } }), 'retire.act.remove.spfStale'],
      [change({ type: 'TXT', value: 'ip4:192.0.2.0/24', action: 'narrow', spf: { range: '192.0.2.0/24' } }), 'retire.act.narrow'],
      [change({ type: 'TXT', value: 'a:mail.example.com', action: 'follow', spf: { host: 'mail.example.com' } }), 'retire.act.follow.spf'],
      [change({ type: 'CNAME', value: 'lb.example.net', action: 'follow', via: ['www.example.com', 'lb.example.net'] }), 'retire.act.follow.cname'],
      [change({ type: 'MX', value: '10 mail.example.com', action: 'repoint' }), 'retire.act.repoint.mx'],
      [change({ type: 'NS', value: 'ns1.example.net', action: 'repoint' }), 'retire.act.repoint.ns'],
      [change({ type: 'SRV', value: 'sip.example.com', action: 'repoint', via: ['_sip._tcp.example.com', 'sip.example.com'] }), 'retire.act.repoint.other'],
      [change({ type: 'NS', value: 'ns1.example.com', action: 'glue' }), 'retire.act.glue'],
      [change({ type: 'TXT', value: 'ip4:192.0.2.0/24', action: 'provider', spf: { holder: '_spf.example.net' } }), 'retire.act.provider'],
      [change({ action: 'origin', proxied: true }), 'retire.act.origin'],
      [change({ action: 'check', sources: ['passive'], verified: 'unverified' }), 'retire.act.check.passive'],
      [change({ action: 'check', sources: ['passive'], verified: 'unknown', reason: 'lookup-failed' }), 'retire.act.check.lookup-failed'],
      [change({ type: 'TXT', value: '', action: 'check', reason: 'lookup-failed', sources: ['spf'], spf: { mechanism: 'record', holder: 'example.com' } }), 'retire.act.check.record-failed'],
      ...UNKNOWN_REASONS.map((reason) => [change({ type: 'TXT', action: 'check', reason, sources: ['spf'] }), `retire.act.check.${reason}`])
    ];
    const seen = new Set();
    for (const [c, key] of cases) {
      const got = changeText(c);
      assert.equal(got.key, key, `${c.action} ${c.type}`);
      seen.add(c.action);
      for (const lang of ['en', 'tr']) {
        assert.ok(hasString(key, lang), `${key} [${lang}]`);
        setLang(lang);
        // An SPF macro such as %{i} is text, not a placeholder.
        assert.doesNotMatch(t(key, { ...got.params, sources: 'HackerTarget' }), /(?:^|[^%])\{[a-z]+\}/, `${key} [${lang}] fills every placeholder`);
      }
    }
    assert.deepEqual([...seen].sort(), [...CHANGE_ACTIONS].sort(), 'every action has a text');
    setLang('en');
    assert.equal(t('retire.act.repoint.mx', changeText(cases[7][0]).params), 'Point the MX at a mail server that stays, or give mail.example.com its new address first. Senders queue mail for a few days, then bounce it.');
  });

  test('summaryFacts: what Copy summary says about a finished check', () => {
    const parsed = parseRetireTargets('192.0.2.10');
    const check = {
      domain: 'example.com', names: [{ name: 'example.com', status: 'NOERROR', cnames: [], ipv4: ['192.0.2.10'], ipv6: [], roles: ['apex'], sources: [] }],
      mx: { status: 'none', hosts: [] }, ns: { status: 'none', hosts: [] }, https: { status: 'none', hints: [] },
      spf: { status: 'none', matches: [], unknown: [] }, failures: [{ what: 'mx', name: 'example.com', error: 'timeout' }]
    };
    const job = {
      label: parsed.label, blocks: parsed.blocks, domains: ['example.com', 'example.net'], checks: new Map([['example.com', check]]),
      errors: [{ domain: 'example.net', error: 'x' }], zoneOrigin: null, zoneRefs: [], status: 'cancelled',
      startedAt: new Date('2026-09-28T09:00:00Z'), finishedAt: new Date('2026-09-28T09:01:00Z')
    };
    const built = buildChanges({ blocks: parsed.blocks, checks: [check] });
    const facts = summaryFacts(job, built, { owners: 1, passive: false });
    assert.deepEqual({ ...facts, counts: undefined }, {
      label: '192.0.2.10', domains: ['example.com'], notChecked: ['example.net'], zone: null, passive: false, counts: undefined,
      top: [{ severity: 'live', name: 'example.com', type: 'A', value: '192.0.2.10' }], owners: 1, unverified: 0, failed: 2, stopped: true,
      at: new Date('2026-09-28T09:01:00Z')
    });
    setLang('en');
    const md = renderMarkdown(buildSummary('retire', facts, { t, lang: 'en', url: null, now: new Date('2026-09-28T10:00:00Z') }));
    assert.match(md, /^\*\*Retire an IP · `192\.0\.2\.10`\*\*\n- 1 record still point/);
    assert.match(md, /stopped early/);
    assert.match(md, /- Checked 1 domain over public DNS: `example\.com` · not checked: `example\.net`\n/, 'only the finished domain is called checked');
  });

  test('a check that could not settle everything: the gaps in words, the failed lookups of a domain, never "nothing" in the summary', () => {
    const parsed = parseRetireTargets('192.0.2.10');
    const failures = [
      { what: 'name', name: 'example.org', error: 'SERVFAIL' }, { what: 'mx', name: 'example.org', error: 'SERVFAIL' },
      { what: 'spf', name: 'example.org', error: 'SERVFAIL' }, ...['a', 'b', 'c', 'd'].map((x) => ({ what: 'name', name: `${x}.example.org`, error: 'SERVFAIL' }))
    ];
    const check = {
      domain: 'example.org', names: [], mx: { status: 'failed', hosts: [] }, ns: { status: 'none', hosts: [] }, https: { status: 'none', hints: [] },
      spf: { status: 'failed', matches: [], unknown: [{ path: ['example.org'], holder: 'example.org', record: null, term: '', mechanism: 'record', reason: 'lookup-failed', target: 'example.org' }] },
      failures
    };
    const job = {
      label: parsed.label, blocks: parsed.blocks, domains: ['example.org', 'example.net'], checks: new Map([['example.org', check]]), errors: [],
      zoneOrigin: null, zoneRefs: [], zoneVerified: false, status: 'cancelled', startedAt: new Date('2026-09-28T09:00:00Z'), finishedAt: new Date('2026-09-28T09:01:00Z')
    };
    const built = buildChanges({ blocks: parsed.blocks, checks: [check] });
    const gaps = jobGaps(job, built);
    assert.deepEqual([gaps.failed, gaps.unknown, gaps.notChecked, gaps.settled], [7, 1, ['example.net'], false]);
    setLang('en');
    assert.deepEqual(gapTexts(gaps), ['7 lookups failed', '1 SPF result cannot be told from here', '1 domain not checked']);
    assert.equal(failureList(check), 'MX, the SPF record, 5 host names (example.org, a.example.org, b.example.org …)');
    const row = built.changes[0];
    assert.deepEqual(changeText(row), { key: 'retire.act.check.record-failed', params: { domain: 'example.org' } });
    setLang('tr');
    assert.deepEqual(gapTexts(gaps), ['7 sorgu başarısız oldu', 'buradan anlaşılamayan 1 SPF sonucu', '1 alan adı kontrol edilmedi']);
    assert.equal(failureList(check), 'MX, SPF kaydı, 5 host adı (example.org, a.example.org, b.example.org …)');
    setLang('en');
    // Copy summary: nothing was found, but it never says nothing points at it.
    const done = { ...job, status: 'done', domains: ['example.org'] };
    const md = renderMarkdown(buildSummary('retire', summaryFacts(done, built, { owners: null }), { t, lang: 'en', url: null }));
    assert.match(md, /\n- Nothing found pointing at it, but not everything could be checked \(below\)\n/);
    assert.doesNotMatch(md, /Nothing in the checked domains/);
    assert.match(md, /Not settled:\*\* 1 SPF term that cannot be told from here · 7 failed lookups/);
  });
});
