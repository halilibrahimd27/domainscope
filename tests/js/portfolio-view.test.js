/**
 * views/portfolio.js — the pure parts of the Domain portfolio view: a link's list and the share
 * params, the table's filters over lib/portfolio.js facts (and the tiles they back), the calendar
 * events worded in English and Turkish with the .ics file they make (lib/ics.js), and the line
 * above the policy matrix. The module is DOM-free at import. Pure Node, no network; documentation
 * data only.
 */
import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import { setLang, t } from '../../assets/js/i18n.js';
import {
  id, titleKey, icon, result, linkText, shareParams, matchesFilter, calendarEvents, matrixCountsText,
  PORTFOLIO_FILTERS, PORTFOLIO_TILES, RISK_BADGES, PORTFOLIO_TABS, MAX_LINK_DOMAINS
} from '../../assets/js/views/portfolio.js';
import { expiryUid } from '../../assets/js/lib/portfolio.js';
import { buildCalendar } from '../../assets/js/lib/ics.js';

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
    assert.deepEqual(PORTFOLIO_TABS, ['domains', 'policy', 'ct']);
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
