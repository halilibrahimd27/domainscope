/**
 * views/portfolio.js — the pure parts of the Domain portfolio view: a link's list and the share
 * params, the table's filters over lib/portfolio.js facts (and the tiles they back), the calendar
 * events worded in English and Turkish with the .ics file they make (lib/ics.js), the line
 * above the policy matrix, and the Domain security tab's line and adoption bars
 * (ui/secscore-panel.js) in English and Turkish. The modules are DOM-free at import. Pure Node, no
 * network; documentation data only.
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { setLang, t } from '../../assets/js/i18n.js';
import {
  id, titleKey, icon, result, linkText, shareParams, matchesFilter, calendarEvents, matrixCountsText, rowChanges,
  PORTFOLIO_FILTERS, PORTFOLIO_TILES, RISK_BADGES, PORTFOLIO_TABS, MAX_LINK_DOMAINS
} from '../../assets/js/views/portfolio.js';
import { expiryUid } from '../../assets/js/lib/portfolio.js';
import { changedWords } from '../../assets/js/lib/portfoliosummary.js';
import { emptyRdapSeen, updateRdapSeen } from '../../assets/js/lib/regwatch.js';
import { buildCalendar } from '../../assets/js/lib/ics.js';
import { totalsText, barModel, generatedKeys, BAR_SEGMENTS } from '../../assets/js/ui/secscore-panel.js';
import { SECURITY_MEASURES } from '../../assets/js/lib/secscore.js';

after(() => setLang('en'));

const NOW = new Date('2026-10-02T12:00:00Z');
const day = (n) => new Date(NOW.getTime() + n * 86400000);

/** Facts as lib/portfolio.js portfolioFacts derives them: a healthy domain unless `over` says otherwise. */
function facts(domain, over = {}) {
  const reg = {
    state: 'ok', failure: null, registrar: 'Example Registrar, Inc.', expires: day(200), daysLeft: 200, expiry: 'ok',
    statuses: ['client transfer prohibited'], transferLock: true, critical: [], risk: 'ok', ...(over.registration || {})
  };
  return {
    domain,
    exists: true,
    dnssec: { state: 'validated', failure: null },
    caa: { state: 'present', failure: null, issuers: ['letsencrypt.org'], wildIssuers: [] },
    mx: { state: 'some', failure: null, hosts: [`mx.${domain}`] },
    spf: { state: 'ok', failure: null, all: '-', lookups: 3, lookupsState: 'ok', over: false },
    dmarc: { state: 'ok', failure: null, policy: 'reject' },
    dkim: { state: 'found', failure: null, selectors: ['google'] },
    mtaSts: { state: 'present', failure: null },
    tlsRpt: { state: 'present', failure: null },
    parked: { parked: false, complete: null },
    ...over,
    registration: reg,
    ns: over.ns || {
      state: 'ok', failure: null, hosts: ['ns1.example.net'], minDaysLeft: 300,
      domains: [{ domain: 'example.net', own: false, state: 'ok', expires: day(300), daysLeft: 300, expiry: 'ok', registrar: 'Example Registrar, Inc.', failure: null }]
    }
  };
}
const nsOn = (domains) => ({ state: 'ok', failure: null, hosts: domains.map((d) => `ns1.${d.domain}`), minDaysLeft: null, domains });
const nsDomain = (domain, daysLeft, extra = {}) => ({ domain, own: false, state: 'ok', expires: day(daysLeft), daysLeft, expiry: daysLeft < 30 ? 'error' : 'ok', registrar: 'Example Registrar, Inc.', failure: null, ...extra });
const failure = { kind: 'error', service: 'doh', status: null, retryAfterMs: null };

describe('Domain portfolio view helpers', () => {
  test('the view interface; nothing kept before a check; the tiles are filters, the risk badges risks', () => {
    assert.deepEqual([id, titleKey, icon], ['portfolio', 'nav.portfolio', 'box']);
    assert.equal(result(), null);
    assert.deepEqual(PORTFOLIO_TABS, ['domains', 'security', 'policy', 'ct']);
    for (const tile of PORTFOLIO_TILES) assert.ok(PORTFOLIO_FILTERS.includes(tile), tile);
    // every risk lib/portfolio.js rowRisk names but 'ok', worst first
    assert.deepEqual([...RISK_BADGES], ['critical', 'ns-unregistered', 'pending-transfer', 'expired', 'expiring', 'ns-expiring', 'hijack', 'warn']);
  });

  test('a link carries the list (one per line in the box), up to MAX_LINK_DOMAINS domains', () => {
    assert.equal(linkText('example.com, example.org;example.net  example-test.com.tr'), 'example.com\nexample.org\nexample.net\nexample-test.com.tr');
    assert.equal(linkText(''), '');
    assert.deepEqual(shareParams(['example.com', 'example.org']), { domains: 'example.com,example.org' });
    assert.deepEqual(shareParams([]), {});
    assert.deepEqual(shareParams(Array.from({ length: MAX_LINK_DOMAINS + 1 }, (_, i) => `d${i}.example.com`)), {}, 'a long list stays out of the URL');
  });

  test('the expiring tile says under 30 days, as it counts (the red band): a row showing "30 days left" is not in it', () => {
    const at = (n) => facts('example.org', { registration: { daysLeft: n, expiry: n < 30 ? 'error' : 'warn', expires: day(n + 0.5) } });
    assert.ok(matchesFilter(at(29), 'expiring') && !matchesFilter(at(30), 'expiring'));
    const nsAt = (n) => facts('example.com', { ns: nsOn([nsDomain('example.net', n)]) });
    assert.ok(matchesFilter(nsAt(29), 'ns') && !matchesFilter(nsAt(30), 'ns'), 'the name server domain tile has the same edge');
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      assert.match(t('pf.tile.expiring'), /^[^≤]*< 30\b/, `${lang}: ${t('pf.tile.expiring')}`);
    }
    setLang('en');
  });

  test('filters: expiring, critical, no transfer lock, name server domains (never the own one), no RDAP, failed lookups, the policy, what needs a look', () => {
    const fine = facts('example.com');
    const soon = facts('example.org', { registration: { daysLeft: 20, expiry: 'error', expires: day(20) } });
    const held = facts('example.net', { registration: { critical: ['serverHold'], risk: 'critical' } });
    const open = facts('example.com', { registration: { transferLock: false, risk: 'hijack' } });
    const nsSoon = facts('example.com', { ns: nsOn([nsDomain('example.net', 12)]) });
    const ownSoon = facts('example.org', { registration: { daysLeft: 200 }, ns: nsOn([nsDomain('example.org', 12, { own: true })]) });
    const noRdap = facts('example-test.com.tr', { registration: { state: 'unsupported', tld: 'tr', daysLeft: null, expires: null, risk: null } });
    const failed = facts('example.com', { caa: { state: null, failure } });
    const over = facts('example.com', { spf: { state: 'ok', failure: null, all: '-', lookups: 12, lookupsState: 'ok', over: true } });
    const parkedOpen = facts('example.org', { mx: { state: 'null', failure: null, hosts: [] }, parked: { parked: true, nullMx: true, spfFail: false, dmarcReject: true, complete: false } });
    const gone = facts('example.org', { registration: { state: 'not-found', daysLeft: null, expires: null, risk: null } });
    const pick = (filter, list, opts) => list.filter((f) => matchesFilter(f, filter, opts)).length;
    const all = [fine, soon, held, open, nsSoon, ownSoon, noRdap, failed, over, parkedOpen, gone];
    assert.equal(pick('all', all), all.length);
    assert.deepEqual([pick('expiring', all), pick('critical', all), pick('unlocked', all), pick('ns', all), pick('nordap', all), pick('failed', all)], [1, 1, 1, 1, 1, 1]);
    assert.ok(matchesFilter(nsSoon, 'ns') && !matchesFilter(ownSoon, 'ns'), 'the domain\'s own name servers expire with it');
    assert.equal(pick('policy', all), 0, 'no policy: nobody fails it');
    assert.equal(pick('policy', all, { policyFails: (d) => d === 'example.net' }), 1);
    assert.deepEqual(all.filter((f) => matchesFilter(f, 'attention')).length, all.length - 3, 'all but the fine one, the own name servers and the partial row');
    assert.ok(!matchesFilter(fine, 'attention') && !matchesFilter(noRdap, 'attention'), 'no RDAP alone needs no look: the row says it is partial');
    assert.ok(matchesFilter(fine, 'attention', { policyFails: () => true }), 'failing the policy needs a look');
    assert.equal(matchesFilter(null, 'all'), false);
    // A name server domain the registry does not know: anyone can register it and take over DNS.
    const nsGone = facts('example.com', { ns: nsOn([nsDomain('example.net', 300), { domain: 'example-gone.org', own: false, state: 'not-found', expires: null, daysLeft: null, expiry: null, registrar: null, failure: null }]) });
    assert.ok(matchesFilter(nsGone, 'ns'), 'the name server domain tile and filter count it');
    assert.ok(matchesFilter(nsGone, 'attention'), 'it needs a look');
    assert.ok(!matchesFilter(nsGone, 'failed'), 'an answer, not a failed lookup');
    assert.ok(RISK_BADGES.includes('ns-unregistered'));
    // A pending transfer needs a look.
    const moving = facts('example.com', { registration: { risk: 'pending-transfer', statuses: ['client transfer prohibited', 'pending transfer'] } });
    assert.ok(matchesFilter(moving, 'attention') && RISK_BADGES.includes('pending-transfer'));
  });

  test('changed since your last check: the registration against the workspace\'s baseline; the tile and filter; a bad change needs a look', () => {
    const at = '2026-09-25T12:00:00.000Z';
    // the workspace's last check of example.com: another registrar, its transfer lock, the DS of then
    const seen = updateRdapSeen(emptyRdapSeen(), [{
      domain: 'example.com',
      snapshot: { state: 'ok', registrar: 'Old Registrar LLC', ianaId: '1068', statuses: ['client transfer prohibited'], expires: '2027-05-20', nameservers: [], ds: null }
    }, {
      domain: 'example.org',
      snapshot: { state: 'ok', registrar: 'Example Registrar, Inc.', ianaId: '9999', statuses: ['client transfer prohibited'], expires: day(100).toISOString().slice(0, 10), nameservers: [], ds: null }
    }], { now: new Date(at) });
    const com = facts('example.com', { registration: { ianaId: '9999', statuses: [] } });
    const org = facts('example.org', { registration: { ianaId: '9999', expires: day(465) } });
    const net = facts('example.net', { registration: { ianaId: '9999' } });
    const changedCom = rowChanges(com, seen);
    assert.deepEqual([changedCom.at, changedCom.tone, changedCom.changes.map((c) => c.code)], [at, 'bad', ['registrar', 'lock-removed', 'expiry-earlier']]);
    assert.deepEqual(rowChanges(org, seen).changes.map((c) => c.code), ['expiry-later']);
    assert.equal(rowChanges(org, seen).tone, 'good');
    assert.equal(rowChanges(net, seen), null, 'checked for the first time in this workspace');
    assert.equal(rowChanges(facts('example.org', { registration: { state: 'failed', failure, ianaId: '1' } }), seen), null, 'the registry not read: nothing to say');
    assert.equal(rowChanges(com, null), null);
    const changedOf = (d) => rowChanges([com, org, net].find((f) => f.domain === d), seen);
    assert.deepEqual([com, org, net].filter((f) => matchesFilter(f, 'changed', { changedOf })).map((f) => f.domain), ['example.com', 'example.org']);
    assert.ok(matchesFilter(com, 'attention', { changedOf }), 'another registrar, a lock removed: a look');
    assert.ok(!matchesFilter(org, 'attention', { changedOf }), 'renewed: good news, no look');
    assert.ok(PORTFOLIO_TILES.includes('changed') && PORTFOLIO_FILTERS.includes('changed'));
    // what the badge and Copy summary say
    setLang('en');
    assert.equal(changedWords(changedCom.changes, t), 'registrar, lock removed, expiry moved earlier');
    assert.equal(changedWords([{ code: 'hold', item: 'client hold' }, { code: 'status', item: 'a' }, { code: 'status', item: 'b' }], t), 'client hold added, status changed');
    setLang('tr');
    assert.equal(changedWords(changedCom.changes, t), 'kayıt firması, kilit kaldırıldı, bitiş tarihi öne alındı');
    assert.equal(t('pf.chg.badge'), 'Son kontrolünüzden beri değişti');
    setLang('en');
  });

  test('calendar events: one per domain, the name servers\' domains too, worded in the language; the .ics they make', () => {
    setLang('en');
    const list = [
      facts('example.com', { ns: nsOn([nsDomain('example.net', 12)]) }),
      facts('example.org', { registration: { daysLeft: 20, expiry: 'error', expires: day(20), registrar: null }, ns: nsOn([nsDomain('example.net', 12)]) }),
      facts('example-test.com.tr', { registration: { state: 'unsupported', tld: 'tr', daysLeft: null, expires: null }, ns: nsOn([nsDomain('example.net', 12)]) })
    ];
    const events = calendarEvents(list, t);
    assert.deepEqual(events.map((e) => e.uid), [expiryUid('example.net'), expiryUid('example.org'), expiryUid('example.com')], 'soonest first; no date, no event');
    assert.deepEqual(events[0], {
      uid: 'expiry-example.net@domainscope', date: day(12),
      summary: 'example.net expires (name servers of example.com, example.org, example-test.com.tr)',
      description: 'Registrar: Example Registrar, Inc.\nRenew it before this date.\nThe name servers of example.com, example.org, example-test.com.tr are under this domain: if it lapses, whoever registers it answers for those zones.',
      alarm: `example.net expires on ${[day(12).getFullYear(), String(day(12).getMonth() + 1).padStart(2, '0'), String(day(12).getDate()).padStart(2, '0')].join('-')}`
    });
    assert.deepEqual([events[1].summary, events[1].description], ['example.org expires', 'Renew it before this date.'], 'no registrar, no line for it');
    const ics = buildCalendar(events, { now: NOW, name: t('pf.ics.name') });
    const unfolded = ics.replace(/\r\n /g, '');
    assert.match(unfolded, /\r\nX-WR-CALNAME:DomainScope: domain expiry\r\n/);
    assert.match(unfolded, /\r\nSUMMARY:example\.net expires \(name servers of example\.com\\, example\.org\\, example-test\.com\.tr\)\r\n/);
    assert.equal((ics.match(/BEGIN:VEVENT/g) || []).length, 3);
    // The alarm names the local day, as the event and the table do (22:30 UTC is the next day in Istanbul).
    const prevTz = process.env.TZ;
    process.env.TZ = 'Europe/Istanbul';
    const late = calendarEvents([facts('example.com', { registration: { expires: new Date('2026-10-14T22:30:00Z'), daysLeft: 12 } })], t);
    assert.equal(late[0].alarm, 'example.com expires on 2026-10-15');
    if (prevTz === undefined) delete process.env.TZ;
    else process.env.TZ = prevTz;
    // a name server domain serving one portfolio domain: that zone, said in the singular
    const one = [facts('example.com', { ns: nsOn([nsDomain('example.net', 12)]) })];
    assert.deepEqual([calendarEvents(one, t)[0].summary, calendarEvents(one, t)[0].description.split('\n').at(-1)], [
      'example.net expires (name servers of example.com)',
      'The name servers of example.com are under this domain: if it lapses, whoever registers it answers for that zone.'
    ]);
    setLang('tr');
    const tr = calendarEvents(list, t);
    assert.equal(tr[0].summary, 'example.net alan adının süresi doluyor (example.com, example.org, example-test.com.tr alan adlarının ad sunucuları)');
    assert.equal(tr[0].description.split('\n').at(-1), 'example.com, example.org, example-test.com.tr alan adlarının ad sunucuları bu alan adının altında: süresi dolarsa, onu yeniden kaydeden herkes bu zone’lar adına yanıt verebilir.');
    assert.deepEqual([calendarEvents(one, t)[0].summary, calendarEvents(one, t)[0].description.split('\n').at(-1)], [
      'example.net alan adının süresi doluyor (example.com alan adının ad sunucuları)',
      'example.com alan adının ad sunucuları bu alan adının altında: süresi dolarsa, onu yeniden kaydeden herkes bu zone adına yanıt verebilir.'
    ]);
    const local = (d) => `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    assert.equal(tr[1].alarm, `example.org alan adının süresi ${local(day(20))} tarihinde doluyor`);
    setLang('en');
  });

  test('the matrix line: the failing count always (none too), then what could not be checked and what meets every rule', () => {
    setLang('en');
    assert.equal(matrixCountsText({ domains: 3, failing: 2, unknown: 0, passing: 1 }, t), '2 of 3 domains fail the policy · 1 meets every rule');
    assert.equal(matrixCountsText({ domains: 3, failing: 1, unknown: 1, passing: 1 }, t), '1 of 3 domains fails the policy · 1 could not be checked in full · 1 meets every rule');
    assert.equal(matrixCountsText({ domains: 3, failing: 0, unknown: 3, passing: 0 }, t), 'None of the 3 domains fails the policy · 3 could not be checked in full');
    assert.equal(matrixCountsText({ domains: 3, failing: 0, unknown: 0, passing: 3 }, t), 'All 3 domains meet every rule');
    assert.equal(matrixCountsText({ domains: 1, failing: 0, unknown: 0, passing: 1 }, t), 'The domain meets every rule');
    setLang('tr');
    assert.equal(matrixCountsText({ domains: 3, failing: 1, unknown: 1, passing: 1 }, t), '3 alan adından 1 tanesi politikaya uymuyor · 1 tanesi tam kontrol edilemedi · 1 tanesi bütün kurallara uyuyor');
    assert.equal(matrixCountsText({ domains: 3, failing: 0, unknown: 2, passing: 1 }, t), '3 alan adından politikaya uymayan yok · 2 tanesi tam kontrol edilemedi · 1 tanesi bütün kurallara uyuyor');
    assert.equal(matrixCountsText({ domains: 4, failing: 0, unknown: 0, passing: 4 }, t), '4 alan adının tamamı bütün kurallara uyuyor');
    setLang('en');
  });
});

describe('Domain security tab (ui/secscore-panel.js)', () => {
  test('the line above the bars: the domains, the average, all eight, what could not be checked — in English and Turkish', () => {
    const totals = { domains: 3, average: 19 / 3, full: 1, unknownDomains: 2, unknownMeasures: 3 };
    setLang('en');
    assert.equal(totalsText(totals, t), '3 domains · average score 6.3 of 8 · 1 meets all eight · 3 measures could not be checked');
    assert.equal(totalsText({ domains: 1, average: 8, full: 1, unknownDomains: 0, unknownMeasures: 0 }, t), '1 domain · average score 8 of 8 · 1 meets all eight');
    assert.equal(totalsText({ domains: 2, average: 4.25, full: 0, unknownDomains: 1, unknownMeasures: 1 }, t), '2 domains · average score 4.3 of 8 · none meets all eight · 1 measure could not be checked');
    setLang('tr');
    assert.equal(totalsText(totals, t), '3 alan adı · ortalama puan 8 üzerinden 6,3 · 1 tanesi sekizini birden karşılıyor · 3 ölçüt kontrol edilemedi');
    assert.equal(totalsText({ domains: 2, average: 4, full: 0, unknownDomains: 0, unknownMeasures: 0 }, t), '2 alan adı · ortalama puan 8 üzerinden 4 · sekizini birden karşılayan yok');
    setLang('en');
  });

  test('a measure\'s bar: met, not met and not known as shares of the domains (an empty part left out), its text and its label', () => {
    setLang('en');
    const m = barModel({ id: 'registryLock', pass: 1, fail: 2, unknown: 1, total: 4, share: 0.25 }, t);
    assert.deepEqual(m.segments, [{ kind: 'pass', x: 0, width: 25, count: 1 }, { kind: 'fail', x: 25, width: 50, count: 2 }, { kind: 'unknown', x: 75, width: 25, count: 1 }]);
    assert.equal(m.text, '1 of 4 (25%) · 1 not known');
    assert.equal(m.label, 'Registry lock: 1 met, 2 not met, 1 not known');
    const all = barModel({ id: 'spf', pass: 3, fail: 0, unknown: 0, total: 3, share: 1 }, t);
    assert.deepEqual([all.segments.map((s) => s.kind), all.segments[0].width, all.text], [['pass'], 100, '3 of 3 (100%)']);
    assert.deepEqual(barModel({ id: 'caa', pass: 0, fail: 0, unknown: 0, total: 0, share: null }, t).segments, [], 'no domain: an empty track');
    setLang('tr');
    const tr = barModel({ id: 'registryLock', pass: 1, fail: 2, unknown: 1, total: 4, share: 0.25 }, t);
    assert.equal(tr.text, '4 alan adından 1 tanesi (%25) · 1 tanesi bilinmiyor');
    assert.equal(tr.label, 'Kayıt kuruluşu kilidi: 1 karşılanıyor, 2 karşılanmıyor, 1 bilinmiyor');
    setLang('en');
  });

  test('every key the tab builds from a code exists in both languages', () => {
    assert.deepEqual([...BAR_SEGMENTS], ['pass', 'fail', 'unknown']);
    for (const lang of ['en', 'tr']) {
      setLang(lang);
      for (const k of generatedKeys()) assert.notEqual(t(k), k, `${lang}: ${k}`);
    }
    setLang('en');
    assert.equal(generatedKeys().length, SECURITY_MEASURES.length * 2 + BAR_SEGMENTS.length);
  });
});
