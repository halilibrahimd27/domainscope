/**
 * The page template (docs/DESIGN.md §5, §8 phase 4) on the four tools of "Change & migrate DNS":
 * what each result header says, as data — the status items, the verdicts and their severities —
 * from the tools' own libraries: lib/fixes.js (a DNS change request), lib/changecheck.js (its "is
 * it live?" page), lib/propagation.js (Global DNS), lib/zonelint.js (Zone File), lib/retire.js
 * (Retire an IP) and lib/origincompare.js (the old and the new server). Each list goes through
 * lib/template.js statusItems as the views do. Pure Node.
 */
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { statusItems, STATUS_SEVERITIES } from '../../assets/js/lib/template.js';
import {
  buildChange, templateInput, requestSummaryFacts, changeStatus, changeHeadline, CHANGE_STATUS_OF, CHANGE_SIGNS, FIX_ACTIONS
} from '../../assets/js/lib/fixes.js';
import {
  CHECK_HEADLINES, CHECK_RESOLVERS, CHECK_HEADLINE_SEVERITY, CHECK_STATUS_KEYS, checkStatus, checkState, pairKey
} from '../../assets/js/lib/changecheck.js';
import {
  VERDICT_STATES, OUTCOME_SEVERITY, OUTCOME_STATUS_KEYS, propagationOutcome, propagationStatus, propagationStatusMatch, rowRcode
} from '../../assets/js/lib/propagation.js';
import { zoneStatus } from '../../assets/js/lib/zonelint.js';
import {
  RETIRE_STATUS, SEVERITIES, VERIFIED_STATES, retireStatus, retireStatusMatch, retireVerdict, retireFormMatches, breakingChanges,
  parseRetireTargets, parseDomainList
} from '../../assets/js/lib/retire.js';
import { COMPARE_VERDICTS, COMPARE_SEVERITY } from '../../assets/js/lib/origincompare.js';

const keys = (list) => list.map((x) => x.key);
const shown = (list, opts) => statusItems(list, opts).map((x) => `${x.key}:${x.count}`);
const TOKEN = 'gfj9Xq3Wr1Bm5zQXxZrW1zFeI6nY6cRgO0sIkWQfVbk';
const facts = (template, input) => requestSummaryFacts(buildChange(template, templateInput(template, input), {}), {});

describe('DNS change request (lib/fixes.js)', () => {
  test('every action but unchanged counts as added, changed or removed; "add or change" (an unread family edit) is a change', () => {
    assert.deepEqual(Object.keys(CHANGE_STATUS_OF).sort(), [...FIX_ACTIONS.filter((a) => a !== 'unchanged'), 'set'].sort());
    assert.deepEqual(new Set(Object.values(CHANGE_STATUS_OF)), new Set(['added', 'changed', 'removed']));
    assert.deepEqual(CHANGE_SIGNS, { added: '+', changed: '~', removed: '−' });
    assert.ok(Object.isFrozen(CHANGE_STATUS_OF) && Object.isFrozen(CHANGE_SIGNS));
  });

  test('an ACME TXT value: one set added; the title names it with its sign', () => {
    const f = facts('acme-txt', { name: '*.example.com', tokens: TOKEN });
    assert.deepEqual(changeStatus(f).map((x) => [x.key, x.severity, x.count]),
      [['error', 'error', 0], ['warn', 'warn', 0], ['added', 'neutral', 1], ['changed', 'neutral', 0], ['removed', 'neutral', 0]]);
    assert.deepEqual(shown(changeStatus(f)), ['added:1'], 'zero counts left out');
    assert.deepEqual(changeHeadline(f), { set: { sign: '+', kind: 'added', name: '_acme-challenge.example.com', type: 'TXT', family: null }, more: 0 });
  });

  test('a parked domain\'s lock-down changes four sets: the first is named, three more', () => {
    const f = facts('parked', { domain: 'example.com' });
    assert.deepEqual(shown(changeStatus(f)), ['changed:4']);
    const head = changeHeadline(f);
    assert.deepEqual([head.set.sign, head.set.type, head.set.name, head.more], ['~', 'MX', 'example.com', 3]);
  });

  test('a deletion is removed, with the minus sign; a set left as it is is neither counted nor named', () => {
    const f = facts('record', { name: 'old.example.com', type: 'A', action: 'delete', values: '192.0.2.10' });
    assert.deepEqual(shown(changeStatus(f)), ['removed:1']);
    assert.equal(changeHeadline(f).set.sign, '−');
    const same = { sets: [{ name: 'a.example.com', type: 'A', action: 'unchanged' }, { name: 'b.example.com', type: 'TXT', family: 'SPF', action: 'set' }] };
    assert.deepEqual(shown(changeStatus(same)), ['changed:1']);
    assert.deepEqual(changeHeadline(same), { set: { sign: '~', kind: 'changed', name: 'b.example.com', type: 'TXT', family: 'SPF' }, more: 0 });
    assert.deepEqual(changeHeadline({ sets: [{ name: 'a', type: 'A', action: 'unchanged' }] }), { set: null, more: 0 });
  });

  test('the errors and warnings shown with the change come first; nothing to say without facts', () => {
    const items = changeStatus({ sets: [{ action: 'add' }, { action: 'replace' }, { action: 'ttl' }], errors: 2, warnings: 1 });
    assert.deepEqual(shown(items), ['error:2', 'warn:1', 'added:1', 'changed:2']);
    assert.deepEqual(shown(changeStatus(null)), []);
    assert.deepEqual(changeHeadline(null), { set: null, more: 0 });
    assert.deepEqual(shown(changeStatus({ sets: 'nope', errors: -3, warnings: 'x' })), []);
  });
});

describe('the "is it live?" page (lib/changecheck.js)', () => {
  const check = { zone: 'example.com', sets: [{ name: 'www' }, { name: '_acme-challenge' }, { name: 'mail' }] };
  const latest = (verdicts) => new Map(Object.entries(verdicts).flatMap(([set, list]) => list.map((v, i) => [pairKey(Number(set), CHECK_RESOLVERS[i]), { verdict: v }])));

  test('every headline has its severity; still asking has none', () => {
    assert.deepEqual(Object.keys(CHECK_HEADLINE_SEVERITY).sort(), [...CHECK_HEADLINES].sort());
    for (const s of Object.values(CHECK_HEADLINE_SEVERITY)) assert.ok(s === null || STATUS_SEVERITIES.includes(s), String(s));
    assert.equal(CHECK_HEADLINE_SEVERITY.unknown, null);
    assert.equal(CHECK_HEADLINE_SEVERITY.wrong, 'error');
    assert.equal(CHECK_HEADLINE_SEVERITY.done, 'ok');
  });

  test('the sets by state: a wrong value, not live yet, live, no answer at all; the key metric is the sets done', () => {
    const map = latest({ 0: ['done', 'done', 'pending', 'done'], 1: ['done', 'wrong', 'done', 'done'], 2: ['error', 'error', 'error', 'error'] });
    const st = checkStatus(check, map);
    assert.deepEqual(keys(st.items), CHECK_STATUS_KEYS);
    assert.deepEqual([st.done, st.total], [0, 3]);
    assert.deepEqual(shown(st.items), ['wrong:1', 'pending:1', 'noanswer:1']);
    assert.equal(checkState(check, map).headline, 'wrong');
  });

  test('before any answer every set is still being asked; done everywhere is good news', () => {
    assert.deepEqual(shown(checkStatus(check, new Map()).items), ['waiting:3']);
    const all = latest({ 0: ['done', 'done', 'done', 'done'], 1: ['done', 'done', 'done', 'error'], 2: ['done', 'done', 'done', 'done'] });
    const st = checkStatus(check, all);
    assert.deepEqual([st.done, st.total], [3, 3]);
    assert.deepEqual(shown(st.items), ['done:3']);
  });
});

describe('Global DNS (lib/propagation.js)', () => {
  const row = (values, extra = {}) => ({ pending: false, values, ...extra });
  const rows = [
    row(['192.0.2.10']), row(['192.0.2.10']), row(['198.51.100.5']), row(['SERVFAIL']), row(['REFUSED']),
    row(['ERROR']), row(['ERROR'], { skipped: true }), row(['0.0.0.0'], { filtered: true }), row(null, { pending: true }),
    row(['NOT ASKED'], { notAsked: true })
  ];

  test('an outcome for every state the verdict has, and for running, stopped and failed', () => {
    for (const s of [...VERDICT_STATES, 'running', 'stopped', 'failed']) assert.ok(Object.hasOwn(OUTCOME_SEVERITY, s), s);
    assert.equal(OUTCOME_SEVERITY.running, null);
    assert.equal(OUTCOME_SEVERITY.agree, 'ok');
    assert.equal(OUTCOME_SEVERITY.differ, 'warn');
    assert.equal(OUTCOME_SEVERITY.unresolved, 'error');
    assert.equal(OUTCOME_SEVERITY['by-design'], 'info');
  });

  test('a DNS status is an rcode; an address, NXDOMAIN, an empty answer or a failed query is not', () => {
    assert.equal(rowRcode(row(['SERVFAIL'])), 'SERVFAIL');
    assert.equal(rowRcode(row(['REFUSED'])), 'REFUSED');
    for (const v of [['NXDOMAIN'], ['NODATA'], ['ERROR'], ['192.0.2.1'], ['"v=spf1 -all"'], ['10 mx.example.com.'], ['SERVFAIL', 'x']]) assert.equal(rowRcode(row(v)), null, v.join());
    assert.equal(rowRcode(row(['SERVFAIL'], { pending: true })), null);
    assert.equal(rowRcode(null), null);
  });

  test('the counts: answered of all asked, failed, unreadable, not asked, blocked, the rcodes and the distinct answers', () => {
    const o = propagationOutcome(rows, { state: 'differ' }, { done: true });
    assert.deepEqual(
      { state: o.state, severity: o.severity, total: o.total, answered: o.answered, failed: o.failed, unavailable: o.unavailable, notAsked: o.notAsked, blocked: o.blocked, rcodes: o.rcodes, rcodeRows: o.rcodeRows, groups: o.groups },
      { state: 'differ', severity: 'warn', total: 9, answered: 6, failed: 1, unavailable: 1, notAsked: 1, blocked: 1, rcodes: { REFUSED: 1, SERVFAIL: 1 }, rcodeRows: 2, groups: 4 });
    assert.deepEqual(shown(propagationStatus(o)), ['rcode:2', 'failed:1', 'differ:4', 'blocked:1', 'answered:6']);
    const answered = propagationStatus(o).find((x) => x.key === 'answered');
    assert.equal(answered.total, 9);
    assert.deepEqual(propagationStatus(o).find((x) => x.key === 'rcode').rcodes, ['REFUSED', 'SERVFAIL']);
  });

  test('the run\'s states: still asking, stopped or failed before any usable answer, nothing usable at all', () => {
    assert.equal(propagationOutcome(rows, { state: 'differ' }).state, 'running');
    const failedOnly = [row(['ERROR']), row(['ERROR']), row(null, { pending: true })];
    assert.equal(propagationOutcome(failedOnly, { state: 'none' }, { done: true }).state, 'failed');
    assert.equal(propagationOutcome(failedOnly, { state: 'none' }, { cancelled: true }).state, 'stopped');
    assert.equal(propagationOutcome([row(['0.0.0.0'], { filtered: true })], { state: 'none' }, { done: true }).state, 'none');
    assert.equal(propagationOutcome([row(['192.0.2.1'])], { state: 'nonsense' }, { done: true }).state, 'differ', 'an unknown verdict state reads as a difference');
  });

  test('differences by design are info, the others a warning; one answer is no difference; agree says only how many answered', () => {
    const two = [row(['192.0.2.1']), row(['192.0.2.2'])];
    assert.deepEqual(shown(propagationStatus(propagationOutcome(two, { state: 'by-design' }, { done: true }))), ['design:2', 'answered:2']);
    assert.deepEqual(shown(propagationStatus(propagationOutcome(two, { state: 'geo' }, { done: true }))), ['design:2', 'answered:2']);
    assert.deepEqual(shown(propagationStatus(propagationOutcome(two, { state: 'stale' }, { done: true }))), ['differ:2', 'answered:2']);
    const one = [row(['192.0.2.1']), row(['192.0.2.1'])];
    assert.deepEqual(shown(propagationStatus(propagationOutcome(one, { state: 'agree' }, { done: true }))), ['answered:2']);
    assert.deepEqual(keys(propagationStatus(null)), OUTCOME_STATUS_KEYS);
  });

  test('a status item filters the rows it counts: rcodes, failed queries, blocked answers; the others nothing', () => {
    const match = (key) => rows.map((r) => propagationStatusMatch(key, r));
    assert.deepEqual(match('rcode'), [false, false, false, true, true, false, false, false, false, false]);
    assert.deepEqual(match('failed'), [false, false, false, false, false, true, false, false, false, false]);
    assert.deepEqual(match('blocked'), [false, false, false, false, false, false, false, true, false, false]);
    assert.deepEqual(match('differ'), rows.map(() => false));
    assert.equal(propagationStatusMatch('rcode', null), false);
  });
});

describe('Zone File (lib/zonelint.js)', () => {
  test('errors and warnings first, then names and proxied records; "0 errors" said only as a verdict', () => {
    const items = zoneStatus({ errors: 0, warnings: 2, names: 26, proxied: 10, info: 4 });
    assert.deepEqual(items.map((x) => [x.key, x.severity]), [['error', 'error'], ['warn', 'warn'], ['names', 'neutral'], ['proxied', 'neutral']]);
    assert.deepEqual(shown(items, { verdict: true }), ['error:0', 'warn:2', 'names:26', 'proxied:10']);
    assert.deepEqual(shown(zoneStatus({ errors: 1, names: 3 })), ['error:1', 'names:3']);
    assert.deepEqual(shown(zoneStatus(null)), []);
    assert.deepEqual(zoneStatus({ errors: -1, warnings: 2.6 }).slice(0, 2).map((x) => x.count), [0, 2]);
  });
});

describe('Retire an IP (lib/retire.js)', () => {
  const counts = { total: 9, breaking: 5, passive: 2, bySeverity: { mail: 2, ns: 1, live: 1, chain: 1, file: 1, stale: 1, unknown: 1 }, byVerified: { live: 6, unverified: 2, file: 1 } };

  test('the items in their order with their severities; zeros left out', () => {
    assert.deepEqual(RETIRE_STATUS.map((s) => s.key), ['mail', 'ns', 'unknown', 'file', 'breaking', 'unverified']);
    assert.ok(Object.isFrozen(RETIRE_STATUS) && RETIRE_STATUS.every((s) => Object.isFrozen(s)));
    assert.ok(RETIRE_STATUS.every((s) => s.key === 'breaking' || s.key === 'unverified' || SEVERITIES.includes(s.key)));
    assert.deepEqual(shown(retireStatus(counts)), ['mail:2', 'ns:1', 'unknown:1', 'file:1', 'breaking:5'], 'five at most: the unverified names are the sixth');
    assert.deepEqual(shown(retireStatus({ breaking: 1, bySeverity: { live: 1 } })), ['breaking:1']);
    assert.deepEqual(shown(retireStatus(null)), []);
  });

  test('each item filters the change list to what it counts: "must change" is every record that breaks something', () => {
    const changes = SEVERITIES.map((severity, i) => ({ severity, verified: VERIFIED_STATES[i % VERIFIED_STATES.length] }));
    const breaking = new Set(breakingChanges(changes));
    assert.deepEqual(changes.filter((c) => retireStatusMatch('breaking', c)), [...breaking]);
    for (const key of ['mail', 'ns', 'unknown', 'file']) assert.deepEqual(changes.filter((c) => retireStatusMatch(key, c)).map((c) => c.severity), [key]);
    assert.deepEqual(changes.filter((c) => retireStatusMatch('unverified', c)), changes.filter((c) => c.verified === 'unverified'));
    assert.ok(changes.some((c) => c.verified === 'unverified'), 'the fixture has one');
    assert.equal(retireStatusMatch('live', { severity: 'live' }), false, 'not an item of its own');
    assert.equal(retireStatusMatch('mail', null), false);
  });

  test('the verdict: what breaks (an error when mail or DNS does), what to clean up, "not everything could be checked", nothing', () => {
    const settled = { settled: true };
    const open = { settled: false };
    assert.deepEqual(retireVerdict({ status: 'done', counts, gaps: settled }), { key: 'breaking', severity: 'error', count: 5, incomplete: false });
    assert.deepEqual(retireVerdict({ status: 'done', counts: { total: 2, breaking: 2, passive: 0, bySeverity: { live: 2 } }, gaps: open }),
      { key: 'breaking', severity: 'warn', count: 2, incomplete: true });
    assert.deepEqual(retireVerdict({ status: 'done', counts: { total: 3, breaking: 0, passive: 1, bySeverity: { file: 1, unknown: 1, stale: 1 } }, gaps: settled }),
      { key: 'cleanup', severity: 'info', count: 1, incomplete: false }, 'the passive hit and the "cannot tell" are not counted');
    assert.deepEqual(retireVerdict({ status: 'cancelled', counts: { total: 0, breaking: 0, bySeverity: {} }, gaps: open }), { key: 'open', severity: 'warn', count: 0, incomplete: true });
    assert.deepEqual(retireVerdict({ status: 'done', counts: { total: 0, breaking: 0, bySeverity: {} }, gaps: settled }), { key: 'none', severity: 'ok', count: 0, incomplete: false });
    assert.deepEqual(retireVerdict({ status: 'done', counts: { total: 0 } }), { key: 'open', severity: 'warn', count: 0, incomplete: true }, 'no gaps: never the green "nothing"');
    assert.equal(retireVerdict({ status: 'running' }).key, 'running');
    assert.deepEqual(retireVerdict({ status: 'error' }), { key: 'failed', severity: 'error', count: 0, incomplete: false });
  });

  test('the form asks for the check on screen: the same blocks and domains, in any order', () => {
    const job = { blocks: parseRetireTargets('192.0.2.10\n192.0.2.0/28').blocks, domains: ['example.com', 'example.net'] };
    const form = (ips, domains) => ({ blocks: parseRetireTargets(ips).blocks, domains: parseDomainList(domains).domains });
    assert.equal(retireFormMatches(form('192.0.2.0/28\n192.0.2.10', 'example.net\nexample.com'), job), true);
    assert.equal(retireFormMatches(form('192.0.2.10', 'example.com\nexample.net'), job), false, 'a block less');
    assert.equal(retireFormMatches(form('192.0.2.10\n192.0.2.0/28', 'example.com'), job), false, 'a domain less');
    assert.equal(retireFormMatches(form('', 'example.com\nexample.net'), { blocks: [], domains: ['example.com', 'example.net'] }), false, 'no address: no check');
    assert.equal(retireFormMatches(form('192.0.2.10', ''), null), false);
  });
});

describe('the old and the new server (lib/origincompare.js)', () => {
  test('every verdict has a severity', () => {
    assert.deepEqual(Object.keys(COMPARE_SEVERITY).sort(), [...COMPARE_VERDICTS].sort());
    assert.ok(Object.values(COMPARE_SEVERITY).every((s) => STATUS_SEVERITIES.includes(s)));
    assert.deepEqual([COMPARE_SEVERITY.same, COMPARE_SEVERITY.broken], ['ok', 'error']);
  });
});
