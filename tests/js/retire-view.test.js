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
  shareParams, linkText, prefillDomains, hostsForDomains, zoneInternalNames, checkTooPlan, changeText, summaryFacts, jobGaps, gapTexts, failureList,
  LINK_MAX_CHARS
} from '../../assets/js/views/retire.js';
import { sessionZone, parseFiles } from '../../assets/js/views/zone.js';
import { buildChanges, parseRetireTargets, passiveNewNames, CHANGE_ACTIONS, UNKNOWN_REASONS, RETIRE_MAX_HOSTS, RETIRE_MAX_DOMAINS } from '../../assets/js/lib/retire.js';
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

  test('hostsForDomains: a name the zone marks internal is never sent, even with the hand-off toggle off', () => {
    const text = [
      '$ORIGIN example.com.',
      '@ 3600 IN SOA ns1.example.com. hostmaster.example.com. 1 7200 3600 1209600 300',
      '@ 3600 IN NS ns1.example.com.',
      'ns1 3600 IN A 192.0.2.53',
      'www 3600 IN A 192.0.2.10',
      'intranet 3600 IN A 192.0.2.10',
      'vpn.corp 3600 IN A 192.0.2.10',
      'db.internal 3600 IN A 192.0.2.10',
      'app 3600 IN A 10.0.0.5',
      ''
    ].join('\n');
    const zoneFile = parseFiles([{ name: 'example.com.zone', text }]);
    // "Leave out names that look internal" unchecked: the hand-off's names hold them, the session says which they are.
    const zone = sessionZone(zoneFile, { skipPrivate: false });
    const internal = ['app.example.com', 'db.internal.example.com', 'intranet.example.com', 'vpn.corp.example.com'];
    assert.ok(internal.every((n) => zone.names.includes(n)), `the scan hand-off holds them: ${zone.names}`);
    assert.deepEqual([...zoneInternalNames(zone)].filter((n) => internal.includes(n)).sort(), internal);
    // Whichever source brings them (the zone, the last scan, a passive hit), none is resolved.
    const { hosts } = hostsForDomains(['example.com'], {
      zone, scanHosts: { names: ['intranet.example.com', 'api.example.com'] }, passive: new Map([['example.com', ['vpn.corp.example.com.']]])
    });
    const names = hosts.get('example.com').map((x) => x.name);
    assert.ok(names.includes('www.example.com') && names.includes('api.example.com'), names.join(' '));
    assert.deepEqual(names.filter((n) => internal.includes(n)), [], 'no internal-looking name');
    // An older session zone without internalNames: its records' internal flags still count.
    assert.deepEqual([...zoneInternalNames({ records: [{ name: 'intranet.example.com', internal: true }, { name: 'www.example.com', internal: false }] })], ['intranet.example.com']);
    assert.equal(zoneInternalNames(null).size, 0);
  });

  test('checkTooPlan: the passive domains that fit in the list, the names checked then, and the ones that cannot be added', () => {
    const passive = [{ address: '192.0.2.10', names: ['blog.example.org', 'shop.example.net', 'cdn.example.com'] }];
    const fresh = passiveNewNames(passive, { checked: ['example.com'], resolved: [] });
    assert.deepEqual(checkTooPlan(fresh, ['example.com']), {
      add: ['example.net', 'example.org'], names: ['cdn.example.com', 'shop.example.net', 'blog.example.org'],
      checked: ['example.com', 'example.net', 'example.org'], left: []
    });
    // One place left: the first domain fits, the other is named as left out; its name is not offered for checking.
    const box = Array.from({ length: RETIRE_MAX_DOMAINS - 1 }, (_, i) => `d${i}.example.com`);
    const one = checkTooPlan(fresh, ['example.com', ...box.slice(1)]);
    assert.deepEqual([one.add, one.left], [['example.net'], ['example.org']]);
    assert.ok(!one.names.includes('blog.example.org'));
    // The box already over the cap (every domain counted, not only the first ones a check takes): nothing fits, a
    // name under a checked domain is still checked; a domain typed past the cap is no domain that gets checked.
    const full = checkTooPlan(fresh, ['example.com', ...Array.from({ length: RETIRE_MAX_DOMAINS }, (_, i) => `e${i}.example.com`), 'example.org']);
    assert.deepEqual([full.add, full.names, full.left], [[], ['cdn.example.com'], ['example.net', 'example.org']]);
    // Nothing that makes progress: no button (no name), only the note.
    const stuck = checkTooPlan(passiveNewNames([{ address: '192.0.2.10', names: ['blog.example.org'] }], { checked: ['example.com'] }),
      Array.from({ length: RETIRE_MAX_DOMAINS }, (_, i) => `e${i}.example.com`));
    assert.deepEqual([stuck.add, stuck.names, stuck.left], [[], [], ['example.org']]);
  });

  test('changeText: one text for each action and record type, every key in English and Turkish', () => {
    const cases = [
      [change({}), 'retire.act.remove.a'],
      [change({ type: 'HTTPS' }), 'retire.act.remove.https'],
      [change({ type: 'TXT', value: 'ip4:192.0.2.10', severity: 'mail', spf: { holder: 'example.com' } }), 'retire.act.remove.spf'],
      [change({ type: 'TXT', value: '-ip4:192.0.2.10', severity: 'stale', spf: { holder: 'example.com' } }), 'retire.act.remove.spfStale'],
      [change({ type: 'TXT', value: 'ip4:192.0.2.0/24', action: 'narrow', spf: { range: '192.0.2.0/24' } }), 'retire.act.narrow'],
      [change({ type: 'TXT', value: 'a/24', action: 'narrow', severity: 'mail', spf: { mechanism: 'a', host: 'example.com', hostAddress: '192.0.2.77', hostOn: false, range: '192.0.2.0/24' } }), 'retire.act.narrow.cidr'],
      [change({ type: 'TXT', value: 'a:mail.example.com/24', action: 'narrow', severity: 'mail', spf: { mechanism: 'a', host: 'mail.example.com', hostAddress: '192.0.2.10', hostOn: true, range: '192.0.2.0/24' } }), 'retire.act.narrow.cidrHost'],
      [change({ type: 'TXT', value: '-ip4:192.0.2.10', action: 'keep', severity: 'stale', spf: { shields: ['ip4:192.0.2.0/24'] } }), 'retire.act.keep.shield'],
      [change({ type: 'TXT', value: '~ip4:192.0.2.0/24', action: 'keep', severity: 'stale', spf: { shields: [] } }), 'retire.act.keep.range'],
      [change({ type: 'TXT', value: 'ip4:192.0.2.0/24', action: 'narrow', severity: 'stale', spf: { range: '192.0.2.0/24', shadowedBy: { term: '-ip4:192.0.2.10', qualifier: '-' } } }), 'retire.act.shadowed'],
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
        assert.doesNotMatch(t(key, { ...got.params, sources: 'HackerTarget' }), /(?:^|[^%])\{[A-Za-z]+\}/, `${key} [${lang}] fills every placeholder`);
      }
    }
    assert.deepEqual([...seen].sort(), [...CHANGE_ACTIONS].sort(), 'every action has a text');
    setLang('en');
    const text = (c) => { const x = changeText(c); return t(x.key, x.params); };
    assert.equal(text(change({ type: 'MX', value: '10 mail.example.com', action: 'repoint' })), 'Point the MX at a mail server that stays, or give mail.example.com its new address first. Senders queue mail for a few days, then bounce it.');
    // The a/24 term names the retiring address, never only its host's own one.
    assert.equal(text(cases.find(([, k]) => k === 'retire.act.narrow.cidr')[0]),
      'a/24 covers 192.0.2.10 only through its CIDR length: example.com is at 192.0.2.77, widened to 192.0.2.0/24. Give the term a narrower length (a larger number) so it no longer covers 192.0.2.10 — or keep it if the whole range stays yours.');
    assert.equal(text(cases.find(([, k]) => k === 'retire.act.keep.shield')[0]),
      'Keeps 192.0.2.10 out of ip4:192.0.2.0/24, which comes after it: leave it in place for as long as ip4:192.0.2.0/24 covers 192.0.2.10. Removed, it lets ip4:192.0.2.0/24 authorize the address.');
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
      top: [{ severity: 'live', name: 'example.com', type: 'A', value: '192.0.2.10' }], owners: 1, unverified: 0, failed: 2, missing: 0, stopped: true,
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

  test('a domain that does not exist: its card says so, the verdict is never "nothing", the summary names it', () => {
    const parsed = parseRetireTargets('192.0.2.10');
    const check = {
      domain: 'exmaple.example.org', missing: true,
      names: [{ name: 'exmaple.example.org', status: 'NXDOMAIN', cnames: [], ipv4: [], ipv6: [], roles: ['apex'], sources: [] }],
      mx: { status: 'none', hosts: [] }, ns: { status: 'none', hosts: [] }, https: { status: 'none', hints: [] },
      spf: { status: 'none', matches: [], unknown: [] }, failures: []
    };
    const job = {
      label: parsed.label, blocks: parsed.blocks, domains: ['exmaple.example.org'], checks: new Map([['exmaple.example.org', check]]), errors: [],
      zoneOrigin: null, zoneRefs: [], zoneVerified: false, status: 'done', startedAt: new Date('2026-09-28T09:00:00Z'), finishedAt: new Date('2026-09-28T09:01:00Z')
    };
    const built = buildChanges({ blocks: parsed.blocks, checks: [check] });
    const gaps = jobGaps(job, built);
    assert.deepEqual([gaps.missing, gaps.settled], [['exmaple.example.org'], false]);
    setLang('en');
    assert.deepEqual(gapTexts(gaps), ['1 domain does not exist']);
    assert.equal(t('retire.group.missing', { domain: 'exmaple.example.org' }),
      'exmaple.example.org does not exist: public DNS answers NXDOMAIN for it and it has no name servers. A typo? Correct it in the domain list and check again.');
    const md = renderMarkdown(buildSummary('retire', summaryFacts(job, built, { owners: null }), { t, lang: 'en', url: null }));
    assert.match(md, /\n- Nothing found pointing at it, but not everything could be checked \(below\)\n/);
    assert.match(md, /Not settled:\*\* 1 domain that does not exist \(a typo\?\)/);
    setLang('tr');
    assert.deepEqual(gapTexts(gaps), ['1 alan adı mevcut değil']);
    assert.match(renderMarkdown(buildSummary('retire', summaryFacts(job, built, { owners: null }), { t, lang: 'tr', url: null })), /mevcut olmayan 1 alan adı \(yazım hatası mı\?\)/);
    setLang('en');
  });
});
