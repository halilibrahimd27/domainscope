/**
 * tests/js/homedigest.test.js — lib/homedigest.js, Home's "Needs attention", fed with what the
 * real writers store: the CT watch's baseline (lib/ctseen.js updateSeen), the registration watch's
 * snapshot (lib/regwatch.js updateRdapSeen over registrationSnapshot), accepted risks
 * (lib/waivers.js addWaiver), rollout boards (lib/rollout.js setStep / setTotal), the Monitoring
 * digest (lib/digests.js) and a DMARC history's roll-up (lib/dmarchistory.js). Documentation
 * names only; no DOM, no network.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  SEVERITIES, ATTENTION_KINDS, STALE_DAYS, ROLLOUT_DAYS, NAMES_SHOWN, ATTENTION_SHOWN, ctAttention, regAttention, waiverAttention,
  rolloutAttention, monitorAttention, jobAttention, serversAttention, dmarcAttention, sortAttention, workspaceFacts, attention, namesShown
} from '../../assets/js/lib/homedigest.js';
import { emptySeen, updateSeen, seenText } from '../../assets/js/lib/ctseen.js';
import { emptyRdapSeen, updateRdapSeen, rdapSeenText, registrationSnapshot } from '../../assets/js/lib/regwatch.js';
import { addWaiver, waiversPartText, WAIVER_SOON_DAYS } from '../../assets/js/lib/waivers.js';
import { emptyRollout, setStep, setTotal, serializeRollout, boardId } from '../../assets/js/lib/rollout.js';
import { withDigest } from '../../assets/js/lib/digests.js';
import { readHistory, rollup } from '../../assets/js/lib/dmarchistory.js';
import { EXPIRY_BANDS } from '../../assets/js/lib/expiry.js';
// The tools with the details, which know the exact time (Home keeps the day): its days must be theirs on the last day.
import { analyzeCt } from '../../assets/js/lib/ctwatch.js';
import { portfolioFacts } from '../../assets/js/lib/portfolio.js';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const NOW = Date.parse('2026-10-09T12:00:00Z');
const DAY = 86400000;
const iso = (t) => new Date(t).toISOString();
const at = (daysAgo) => new Date(NOW - daysAgo * DAY);

/* --- what the writers store ------------------------------------------------------------- */

const cert = (id, names, notBefore, notAfter, extra = {}) => ({ id, names, notBefore: new Date(notBefore), notAfter: new Date(notAfter), ...extra });

/** The CT tab's check of three domains two days ago, and a domain checked before `due` existed. */
function ctText({ checkedDaysAgo = 2 } = {}) {
  const read = (domain, certs) => ({ domain, at: at(checkedDaysAgo), state: 'ok', certs });
  const seen = updateSeen(emptySeen(), [
    // ends 2026-10-12 (a due day counts in UTC calendar days: 3 days from today): error
    read('example.com', [cert('00000000000000a1', ['example.com', 'www.example.com'], '2026-07-14T00:00:00Z', '2026-10-12T12:00:00Z')]),
    // 16 days left: warn; the certificate its renewal replaced (2 days left) never counts
    read('example.org', [
      cert('00000000000000b1', ['example.org'], '2026-07-13T00:00:00Z', '2026-10-11T00:00:00Z'),
      cert('00000000000000b2', ['example.org'], '2026-09-26T00:00:00Z', '2026-10-25T00:00:00Z')
    ]),
    // expired and never renewed: still its current certificate
    read('example.net', [cert('00000000000000c1', ['example.net'], '2026-07-07T00:00:00Z', '2026-10-05T00:00:00Z')]),
    // far: nothing
    read('api.example.com', [cert('00000000000000d1', ['api.example.com'], '2026-09-01T00:00:00Z', '2026-12-01T00:00:00Z')])
  ], { now: at(checkedDaysAgo) });
  // A baseline written before `due`: its domain needs one more check.
  seen.domains['shop.example.net'] = { at: iso(at(3)), ids: { '00000000000000e1': '2026-10-10' } };
  return seenText(seen);
}

/** The Domain portfolio's last check of seven domains. */
function rdapText({ checkedDaysAgo = 1 } = {}) {
  const snap = (registration) => registrationSnapshot({ registration: { state: 'ok', registrar: 'Example Registrar', ianaId: '9999', nameservers: ['ns1.example.net'], ...registration } });
  const reads = [
    // 20 days left: error; locked
    { domain: 'example.com', snapshot: snap({ expires: '2026-10-29T10:00:00Z', statuses: ['client transfer prohibited'] }) },
    // 50 days left: warn; no transfer prohibition at all: warn
    { domain: 'example.org', snapshot: snap({ expires: '2026-11-28T10:00:00Z', statuses: ['client delete prohibited'] }) },
    // the registry does not know it
    { domain: 'example.net', snapshot: registrationSnapshot({ registration: { state: 'not-found' } }) },
    // on hold: critical
    { domain: 'shop.example.com', snapshot: snap({ expires: '2027-08-01T00:00:00Z', statuses: ['server hold', 'client transfer prohibited'] }) },
    // a transfer under way (EPP spelling, as some registries write it)
    { domain: 'mail.example.com', snapshot: snap({ expires: '2027-08-01T00:00:00Z', statuses: ['pendingTransfer', 'clientTransferProhibited'] }) },
    // a registry lock: server transfer, update and delete prohibited — never flagged
    { domain: 'lock.example.com', snapshot: snap({ expires: '2027-08-01T00:00:00Z', statuses: ['server transfer prohibited', 'server update prohibited', 'server delete prohibited'] }) },
    // ended on 2026-10-01: 8 days ago, in UTC calendar days
    { domain: 'old.example.com', snapshot: snap({ expires: '2026-10-01T00:00:00Z', statuses: ['client transfer prohibited'] }) }
  ];
  return rdapSeenText(updateRdapSeen(emptyRdapSeen(), reads, { now: at(checkedDaysAgo) }));
}

/** Two accepted risks: one ends in 5 days, one ended 3 days ago, one far away. */
function waiversText() {
  let list = [];
  list = addWaiver(list, { kind: 'finding', domain: 'example.com', ref: 'dmarc.policy-none', reason: 'migrating mail', expires: '2026-10-14' }, { now: NOW }).list;
  list = addWaiver(list, { kind: 'rule', domain: 'example.org', ref: 'transferLock', reason: 'registrar move', expires: '2026-10-06' }, { now: at(30) }).list;
  list = addWaiver(list, { kind: 'rule', domain: 'example.net', ref: 'dnssec', reason: 'next quarter', expires: '2027-01-31' }, { now: NOW }).list;
  return waiversPartText(list);
}

const FP = (c) => c.repeat(64);
const ROW = (key) => ({ key, name: key.slice(2) });

/* --- the kinds ---------------------------------------------------------------------------- */

describe('certificate expiry (the CT baseline\'s `due`)', () => {
  test('expired, under 7 days and under 30 days of the current certificates, by domain; a replaced one never counts', () => {
    const rows = ctAttention(ctText(), NOW);
    const by = (kind, severity) => rows.find((r) => r.kind === kind && r.severity === severity);
    assert.deepEqual(rows.map((r) => [r.kind, r.severity, r.params.count ?? null]),
      [['certExpired', 'error', 1], ['cert', 'error', 1], ['cert', 'warn', 1], ['ctFirst', 'info', null]]);
    assert.deepEqual(by('certExpired', 'error').names, ['example.net']);
    assert.equal(by('certExpired', 'error').soonest, -4, 'ended on 2026-10-05: 4 days ago');
    assert.deepEqual(by('cert', 'error').params, { count: 1, days: EXPIRY_BANDS.certificate.error });
    assert.deepEqual(by('cert', 'error').names, ['example.com']);
    assert.equal(by('cert', 'error').soonest, 3);
    assert.deepEqual(by('cert', 'warn').params, { count: 1, days: EXPIRY_BANDS.certificate.warn });
    assert.deepEqual(by('cert', 'warn').names, ['example.org'], 'its renewal (16 days) is due, the replaced certificate (2 days) is not');
    assert.deepEqual(by('ctFirst', 'info').names, ['shop.example.net'], 'a baseline from before `due`: check once');
    assert.deepEqual(by('cert', 'error').link, { view: 'portfolio', params: { domains: 'example.com', tab: 'ct', run: '0' } });
    assert.equal(by('cert', 'error').at, iso(at(2)));
    assert.ok(rows.every((r) => r.stale === false), 'checked 2 days ago: fresh');
  });

  test('a check older than 14 days keeps its count and severity, marked stale', () => {
    const rows = ctAttention(ctText({ checkedDaysAgo: STALE_DAYS.ct + 1 }), NOW - 0);
    const error = rows.find((r) => r.kind === 'cert' && r.severity === 'error');
    // 15 days ago the certificate of example.com was current too: still error (3 days left today)
    assert.equal(error.stale, true);
    assert.equal(error.params.count, 1);
  });

  test('nothing stored, or junk: no rows', () => {
    for (const text of ['', '{', null, '{"v":1,"domains":{}}']) assert.deepEqual(ctAttention(text, NOW), []);
  });
});

describe('registrations (the registration watch\'s snapshot)', () => {
  test('the bands, a domain the registry does not know, and the Domain portfolio\'s own risk rule', () => {
    const rows = regAttention(rdapText(), NOW);
    const by = (kind, severity) => rows.find((r) => r.kind === kind && r.severity === severity);
    assert.deepEqual(rows.map((r) => [r.kind, r.severity]).sort(), [
      ['reg', 'error'], ['reg', 'warn'], ['regExpired', 'error'], ['regGone', 'error'], ['regNoLock', 'warn'], ['regRisk', 'error'], ['regTransfer', 'error']
    ].sort());
    assert.deepEqual(by('regExpired', 'error'), {
      kind: 'regExpired', severity: 'error', key: 'home.regExpired', params: { count: 8, days: 8 }, nameParam: null, names: ['old.example.com'],
      soonest: -8, at: iso(at(1)), stale: false, link: { view: 'portfolio', params: { domains: 'old.example.com', run: '0' } }
    });
    assert.deepEqual([by('reg', 'error').key, by('reg', 'error').params, by('reg', 'error').names], ['home.reg', { count: 20, days: 20 }, ['example.com']]);
    assert.deepEqual([by('reg', 'warn').params, by('reg', 'warn').names], [{ count: 50, days: 50 }, ['example.org']]);
    assert.deepEqual(by('regGone', 'error').names, ['example.net']);
    assert.deepEqual([by('regRisk', 'error').params, by('regRisk', 'error').names], [{ status: 'server hold' }, ['shop.example.com']]);
    assert.deepEqual([by('regTransfer', 'error').nameParam, by('regTransfer', 'error').names], ['domain', ['mail.example.com']]);
    assert.deepEqual(by('regNoLock', 'warn').names, ['example.org'], 'no transfer prohibition of any kind');
    const all = rows.flatMap((r) => r.names);
    assert.ok(!all.includes('lock.example.com'), 'a registry lock (server prohibitions only) is no risk: the first draft would have flagged it');
  });

  test('a snapshot older than 7 days is stale', () => {
    const rows = regAttention(rdapText({ checkedDaysAgo: STALE_DAYS.registration + 1 }), NOW);
    assert.ok(rows.length && rows.every((r) => r.stale), 'every row');
  });
});

describe('the last day: a day that ends today is 0 days left, expired only from the day after', () => {
  // now 10:00 UTC; the CT baseline and the registration snapshot keep the day only, the CT tab and the Domain portfolio the time
  const T = Date.parse('2026-10-09T10:00:00Z');
  const hours = (n) => new Date(T + n * 3600000);

  test('a certificate valid until 20:00 today: "expires within 7 days" with 0 days left, as the CT tab says — not "has expired"', () => {
    const read = { domain: 'example.com', at: hours(-1), state: 'ok', certs: [cert('00000000000000a1', ['example.com'], '2026-07-11T20:00:00Z', iso(hours(10)))] };
    const text = seenText(updateSeen(emptySeen(), [read], { now: hours(-1) }));
    const tab = analyzeCt([read], { now: T }).rows[0];
    assert.deepEqual([tab.current, tab.daysLeft], [true, 0], 'the CT tab: its current certificate, 0 days left');
    const rows = ctAttention(text, T);
    assert.deepEqual(rows.map((r) => [r.kind, r.severity, r.params.count, r.soonest]), [['cert', 'error', 1, tab.daysLeft]]);
    // the day after (02:00): it has expired
    assert.deepEqual(ctAttention(text, T + 16 * 3600000).map((r) => [r.kind, r.soonest]), [['certExpired', -1]]);
  });

  test('a registration ending at 18:00 today expires in 0 days, one ending in 37 hours in 1 day, as the Domain portfolio counts them', () => {
    const rdap = (expires) => ({ ok: true, domain: 'example.com', expires, status: ['client transfer prohibited'], registrar: 'Example Registrar', registrarIanaId: '9999', nameservers: ['ns1.example.net'] });
    for (const [label, expires, days] of [['today, 18:00', iso(hours(8)), 0], ['today, 20:00', iso(hours(10)), 0], ['in 37 hours', iso(hours(37)), 1]]) {
      const facts = portfolioFacts({ domain: 'example.com', rdap: rdap(expires) }, { now: T });
      assert.equal(facts.registration.daysLeft, days, `${label}: the Domain portfolio`);
      const text = rdapSeenText(updateRdapSeen(emptyRdapSeen(), [{ domain: 'example.com', snapshot: registrationSnapshot(facts) }], { now: hours(-1) }));
      const rows = regAttention(text, T);
      assert.deepEqual(rows.map((r) => [r.kind, r.severity, r.params, r.soonest]), [['reg', 'error', { count: days, days }, days]], `${label}: Home`);
    }
    // the day after the 18:00 one: "expired 1 day ago"
    const facts = portfolioFacts({ domain: 'example.com', rdap: rdap(iso(hours(8))) }, { now: T });
    const text = rdapSeenText(updateRdapSeen(emptyRdapSeen(), [{ domain: 'example.com', snapshot: registrationSnapshot(facts) }], { now: hours(-1) }));
    assert.deepEqual(regAttention(text, T + 86400000).map((r) => [r.kind, r.params]), [['regExpired', { count: 1, days: 1 }]]);
  });
});

describe('accepted risks, rollouts, Monitoring, jobs, servers, DMARC', () => {
  test('accepted risks: ending within 14 days (warn), ended — counting again — (info); the link opens the Workspaces dialog', () => {
    const rows = waiverAttention(waiversText(), NOW);
    assert.deepEqual(rows.map((r) => [r.kind, r.severity, r.params, r.names]), [
      ['waivers', 'warn', { count: 1, days: WAIVER_SOON_DAYS }, ['example.com']],
      ['waiversEnded', 'info', { count: 1 }, ['example.org']]
    ]);
    assert.deepEqual(rows[0].link, { workspace: 'waivers' });
    assert.equal(rows[0].soonest, 5, 'its last day is 2026-10-14: 5 days from today');
  });

  test('rollout: "{done} of {total}" when every open board has its total, else what was ticked; finished and old boards are left out', () => {
    const rows = ['s:web01', 's:web02', 's:web03'].map(ROW);
    const clock = (t) => () => t;
    // board A: 3 rows shown, 1 verified, 1 installed
    let s = setStep(emptyRollout(), { id: FP('a'), label: '*.example.com' }, rows[0], 'verified', true, { now: clock(NOW - DAY) });
    s = setStep(s, { id: FP('a') }, rows[1], 'installed', true, { now: clock(NOW - DAY) });
    s = setTotal(s, boardId([FP('a')]), 3);
    assert.deepEqual(rolloutAttention(serializeRollout(s), NOW).map((r) => [r.key, r.params, r.names]),
      [['home.rollout', { done: 1, total: 3 }, ['*.example.com']]]);
    // board B: stored before `total` existed: what was ticked
    s = setStep(s, { id: FP('b'), label: 'shop.example.org' }, rows[0], 'reloaded', true, { now: clock(NOW - 2 * DAY) });
    const mixed = rolloutAttention(serializeRollout(s), NOW);
    assert.deepEqual(mixed.map((r) => [r.kind, r.key, r.params, r.nameParam]), [['rolloutTicked', 'home.rolloutTicked', { verified: 1, installed: 2 }, 'label']]);
    assert.deepEqual(mixed[0].names, ['*.example.com', 'shop.example.org']);
    assert.deepEqual(mixed[0].link, { view: 'scan' });
    // every row verified: closed
    let done = setStep(emptyRollout(), { id: FP('c'), label: 'example.net' }, rows[0], 'verified', true, { now: clock(NOW - DAY) });
    done = setTotal(done, boardId([FP('c')]), 1);
    assert.deepEqual(rolloutAttention(serializeRollout(done), NOW), []);
    // changed more than 30 days ago: left out
    const old = setStep(emptyRollout(), { id: FP('d') }, rows[0], 'installed', true, { now: clock(NOW - (ROLLOUT_DAYS + 1) * DAY) });
    assert.deepEqual(rolloutAttention(serializeRollout(old), NOW), []);
  });

  test('Monitoring: the digest as written — bad changes (error), expiring certificates and incomplete checks (warn); stale after 2 days', () => {
    const text = withDigest('', 'monitor', { at: at(1), imported: at(0.5), targets: 5, bad: 2, expiring: 1, incomplete: 0 });
    const rows = monitorAttention(text, NOW);
    assert.deepEqual(rows.map((r) => [r.kind, r.severity, r.params, r.stale]), [
      ['monitorBad', 'error', { count: 2, days: 7 }, false], ['monitorExpiring', 'warn', { count: 1, days: 21 }, false]
    ]);
    assert.deepEqual(rows[0].link, { view: 'monitor' });
    assert.deepEqual(rows[0].names, [], 'counts only: the digest names nothing');
    const old = withDigest('', 'monitor', { at: at(STALE_DAYS.monitor + 1), imported: at(2), targets: 5, bad: 0, expiring: 0, incomplete: 3 });
    assert.deepEqual(monitorAttention(old, NOW).map((r) => [r.kind, r.stale]), [['monitorIncomplete', true]]);
    assert.deepEqual(monitorAttention('', NOW), []);
  });

  test('jobs: one running row each, with the progress when it is known; the tool is named by the caller', () => {
    const rows = jobAttention([{ id: 4, view: 'subdomains', subject: 'example.net', fraction: 0.45 }, { id: 5, view: 'bulk', subject: null, fraction: null }, null]);
    assert.deepEqual(rows.map((r) => [r.severity, r.key, r.params, r.names, r.link]), [
      ['running', 'home.runningPercent', { tool: 'subdomains', percent: 0.45 }, ['example.net'], { view: 'subdomains' }],
      ['running', 'home.running', { tool: 'bulk', percent: null }, [], { view: 'bulk' }]
    ]);
    assert.deepEqual(rows[0].job, { id: 4, view: 'subdomains', fraction: 0.45 });
    assert.equal(jobAttention([{ id: 1, view: 'scan', fraction: 7 }])[0].params.percent, 1, 'kept between 0 and 1');
  });

  test('servers: lines of the server list that could not be read', () => {
    assert.deepEqual(serversAttention(2).map((r) => [r.kind, r.severity, r.params, r.link]), [['servers', 'warn', { count: 2 }, { view: 'inventory' }]]);
    assert.deepEqual(serversAttention(0), []);
    assert.deepEqual(serversAttention(-1), []);
  });

  test('DMARC: p=reject refusing known senders\' mail (error), known senders failing (warn), from the history\'s roll-up', () => {
    const day = '2026-10-05';
    const counts = (msgs, dmarcPass, knownFail) => ({ msgs, dmarcPass, spfAligned: dmarcPass, dkimAligned: dmarcPass, quarantine: 0, reject: msgs - dmarcPass, unknownMsgs: msgs - dmarcPass - knownFail, knownFail });
    const domain = (policy, c) => ({ days: { [day]: c }, sources: {}, recent: {}, policy: { p: policy, sp: policy, pct: 100, seenAt: `${day}T23:59:59Z` }, seen: {}, cut: null, checked: null });
    const history = readHistory(JSON.stringify({ v: 1, keep: true, updatedAt: `${day}T23:59:59Z`, domains: {
      'example.com': domain('reject', counts(100, 90, 4)),
      'example.org': domain('none', counts(50, 40, 6)),
      'example.net': domain('reject', counts(20, 20, 0))
    } }));
    const rows = dmarcAttention(rollup(history, { now: NOW, days: 30 }));
    assert.deepEqual(rows.map((r) => [r.kind, r.severity, r.names, r.nameParam]), [
      ['dmarcLosing', 'error', ['example.com'], 'domains'], ['dmarcFixFirst', 'warn', ['example.org'], 'domains']
    ]);
    assert.deepEqual(dmarcAttention(null), []);
  });
});

describe('together', () => {
  const parts = () => ({ ctSeen: ctText(), rdapSeen: rdapText(), waivers: waiversText(), rollout: '', digests: withDigest('', 'monitor', { at: at(1), imported: at(1), targets: 3, bad: 1, expiring: 0, incomplete: 0 }) });

  test('error → warn → running → info, then the soonest first; one row per kind and severity', () => {
    const { rows, facts, ok } = attention({ parts: parts(), jobs: [{ id: 1, view: 'scan', subject: 'example.com', fraction: null }], serverWarnings: 1, now: NOW });
    const sev = rows.map((r) => SEVERITIES.indexOf(r.severity));
    assert.deepEqual(sev, [...sev].sort((a, b) => a - b), 'by severity');
    assert.deepEqual(rows.filter((r) => r.severity === 'error').map((r) => r.kind),
      ['regExpired', 'certExpired', 'cert', 'reg', 'regGone', 'regRisk', 'regTransfer', 'monitorBad']);
    assert.equal(rows.find((r) => r.severity === 'running').kind, 'job');
    assert.deepEqual(rows.filter((r) => r.severity === 'info').map((r) => r.kind).sort(), ['ctFirst', 'waiversEnded']);
    const keys = rows.map((r) => `${r.kind}/${r.severity}`);
    assert.equal(new Set(keys).size, keys.length, 'one row per kind and severity');
    assert.ok(rows.every((r) => ATTENTION_KINDS.includes(r.kind)));
    assert.equal(ok, false);
    assert.deepEqual([facts.ctDomains, facts.regDomains, facts.waivers, facts.boards, facts.hasData], [5, 7, 3, 0, true]);
    assert.equal(facts.ctAt, iso(at(2)), 'the newest check');
    assert.equal(facts.monitorAt, iso(at(1)));
  });

  test('data but nothing due: one OK row; no data at all: nothing', () => {
    const quiet = updateSeen(emptySeen(), [{ domain: 'example.com', at: at(1), state: 'ok', certs: [cert('00000000000000f1', ['example.com'], '2026-09-01T00:00:00Z', '2026-12-01T00:00:00Z')] }], { now: at(1) });
    const calm = attention({ parts: { ctSeen: seenText(quiet) }, now: NOW });
    assert.deepEqual([calm.rows, calm.ok, calm.facts.ctAt], [[], true, iso(at(1))]);
    const empty = attention({ parts: {}, now: NOW });
    assert.deepEqual([empty.rows, empty.ok, empty.facts.hasData], [[], false, false]);
    // a running job alone is something to show, not an OK
    assert.equal(attention({ parts: {}, jobs: [{ id: 1, view: 'bulk' }], now: NOW }).rows.length, 1);
  });

  test('sortAttention keeps rows without a day after those with one; namesShown names three, then "+n more"', () => {
    const r = (kind, severity, soonest) => ({ kind, severity, soonest });
    assert.deepEqual(sortAttention([r('servers', 'warn', null), r('reg', 'warn', 40), r('job', 'running', null), r('cert', 'error', 2)]).map((x) => x.kind),
      ['cert', 'reg', 'servers', 'job']);
    assert.equal(NAMES_SHOWN, 3);
    assert.equal(ATTENTION_SHOWN, 6);
    assert.deepEqual(namesShown(['a.example', 'b.example', 'c.example', 'd.example', 'e.example']), { shown: ['a.example', 'b.example', 'c.example'], more: 2 });
    assert.deepEqual(namesShown([]), { shown: [], more: 0 });
    assert.deepEqual(workspaceFacts({}, NOW).hasData, false);
  });
});

describe('what it imports', () => {
  /** The static import graph of a module (relative paths), as tests/js/start-route.test.js walks it. */
  function graph(entry) {
    const seen = new Set();
    const queue = [entry];
    while (queue.length) {
      const file = queue.shift();
      if (seen.has(file)) continue;
      seen.add(file);
      const src = readFileSync(file, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
      for (const m of src.matchAll(/(?:^|[;\n])\s*(?:import|export)\s[^;'"]*?\bfrom\s*(['"])([^'"]+)\1/g)) queue.push(resolve(dirname(file), m[2]));
    }
    return [...seen].map((f) => f.slice(ROOT.length + 1).split('\\').join('/'));
  }

  test('the owners\' small readers only: never lib/ctwatch.js (x509), lib/policy.js, lib/portfolio.js, lib/monitor.js or the DMARC history', () => {
    const files = graph(join(ROOT, 'assets', 'js', 'lib', 'homedigest.js'));
    for (const heavy of ['ctwatch.js', 'x509.js', 'policy.js', 'portfolio.js', 'monitor.js', 'dmarchistory.js', 'passport.js']) {
      assert.ok(!files.includes(`assets/js/lib/${heavy}`), heavy);
    }
    assert.ok(files.every((f) => f.startsWith('assets/js/lib/')), 'DOM-free: no ui/ module');
    for (const reader of ['ctseen.js', 'regwatch.js', 'regstatus.js', 'waivers.js', 'rollout.js', 'digests.js', 'expiry.js']) {
      assert.ok(files.includes(`assets/js/lib/${reader}`), reader);
    }
  });
});
