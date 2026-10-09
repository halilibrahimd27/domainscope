// Domain Health v2 (SPEC §5.78): lib/healthscore.js (the score and its letter, problems first),
// lib/healthweb.js (the Web category), lib/observatory.js (Mozilla's HTTP Observatory) and
// lib/healthadvice.js (advice for every problem without "Show the fix"). Fakes only, no network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import {
  scoreHealth, gradeFor, problemsFirst, countSeverities, groupWeight, whatIfHealth, HEALTH_SCORE_WEIGHTS, HEALTH_SCORE_GROUPS, SCORE_CAPS,
  DEFAULT_GROUP_WEIGHT, FATAL_CHECKS, HEALTH_GRADES
} from '../../assets/js/lib/healthscore.js';
import {
  wwwConsistency, httpsRecordChecks, observatoryCheck, observatorySeverity, withWebChecks, withObservatory, addWebChecks, webCheck,
  hstsPreloadUrl, WEB_CHECK_IDS, WEB_CATEGORIES, HEALTH_WEB_I18N
} from '../../assets/js/lib/healthweb.js';
import {
  observatoryScan, observatoryEligible, observatoryScanUrl, observatoryReportUrl, readObservatoryScan, OBSERVATORY_SCAN_URL,
  OBSERVATORY_GRADES, OBSERVATORY_SKIP_REASONS
} from '../../assets/js/lib/observatory.js';
import { HEALTH_ADVICE_I18N, HEALTH_ADVICE_IDS, adviceKey } from '../../assets/js/lib/healthadvice.js';
import { HEALTH_CATEGORIES, HEALTH_CHECK_IDS } from '../../assets/js/lib/health.js';
import { HEALTH_FIX_IDS } from '../../assets/js/lib/fixes.js';

const check = (id, severity, group) => ({ id, severity, group: group ?? HEALTH_CATEGORIES[id.split('.')[0]] ?? 'dns' });

describe('healthscore: the score and its letter', () => {
  test('a clean report is 100 and an A; info costs nothing', () => {
    const r = scoreHealth([check('ns.ok', 'ok'), check('mx.ok', 'ok'), check('caa.missing', 'info'), check('rdap.ok', 'ok')]);
    assert.equal(r.score, 100);
    assert.equal(r.grade, 'A');
    assert.equal(r.cap, null);
    assert.deepEqual(r.groups.map((g) => g.group), ['dns', 'email', 'security', 'registration']);
  });

  test('each group loses 40 per error and 15 per warning; the total is the weighted mean of the groups present', () => {
    // dns 100 (w30), email 100 − 2·15 = 70 (w25), security 100 (w20): (3000 + 1750 + 2000) / 75 = 90 → warning cap 89
    const r = scoreHealth([check('ns.ok', 'ok'), check('dmarc.policy-none', 'warn'), check('spf.ptr', 'warn'), check('caa.ok', 'ok')]);
    assert.equal(r.groups.find((g) => g.group === 'email').score, 70);
    assert.equal(r.raw, 90);
    assert.equal(r.score, 89);
    assert.equal(r.cap, 'warn');
    assert.equal(r.grade, 'B');
  });

  test('an error caps the score at 79; a group cannot go below 0; groups without checks are left out', () => {
    const one = scoreHealth([check('ns.ok', 'ok'), check('mx.unresolvable', 'error')]);
    // dns 100 (w30), email 60 (w25): (3000 + 1500) / 55 = 81.8 → 79
    assert.equal(Math.round(one.raw), 82);
    assert.deepEqual([one.score, one.grade, one.cap], [SCORE_CAPS.error, 'C', 'error']);
    const many = scoreHealth([check('ns.none', 'error'), check('ns.unresolvable', 'error'), check('ns.private-ip', 'error'), check('mx.ok', 'ok')]);
    assert.equal(many.groups[0].score, 0);
    // dns 0 (w30), email 100 (w25): 2500 / 55 = 45.5 → 45, under the cap
    assert.deepEqual([many.score, many.grade, many.cap], [45, 'F', null]);
  });

  test('the web group and an unknown group take their weights', () => {
    assert.equal(groupWeight('web'), HEALTH_SCORE_WEIGHTS.web);
    assert.equal(groupWeight('delegation'), DEFAULT_GROUP_WEIGHT);
    assert.equal(Object.values(HEALTH_SCORE_WEIGHTS).reduce((a, b) => a + b, 0), 100);
    const r = scoreHealth([check('ns.ok', 'ok'), check('www.missing', 'warn', 'web'), check('x.y', 'warn', 'delegation')]);
    // dns 100 (w30), web 85 (w15), delegation 85 (w10): (3000 + 1275 + 850) / 55 = 93.2 → 89
    assert.deepEqual(r.groups.map((g) => [g.group, g.weight, g.score]), [['dns', 30, 100], ['web', 15, 85], ['delegation', 10, 85]]);
    assert.equal(r.score, 89);
  });

  test('a name that does not exist scores 0 (F)', () => {
    for (const id of FATAL_CHECKS) {
      const r = scoreHealth([check(id, 'error'), check('rdap.ok', 'ok')]);
      assert.deepEqual([r.score, r.grade, r.cap], [0, 'F', 'fatal'], id);
    }
  });

  test('letters: A from 90, B 80, C 70, D 60, E 50, F below; empty input is 100', () => {
    assert.deepEqual([100, 90, 89, 80, 79, 70, 69, 60, 59, 50, 49, 0].map(gradeFor), ['A', 'A', 'B', 'B', 'C', 'C', 'D', 'D', 'E', 'E', 'F', 'F']);
    assert.equal(gradeFor(NaN), 'F');
    assert.deepEqual(HEALTH_GRADES.map((g) => g.grade), ['A', 'B', 'C', 'D', 'E', 'F']);
    assert.deepEqual([scoreHealth([]).score, scoreHealth(null).grade], [100, 'A']);
    assert.ok(Object.isFrozen(HEALTH_SCORE_WEIGHTS) && Object.isFrozen(HEALTH_SCORE_GROUPS));
  });

  test('problems first: errors, then warnings, each by group in display order, checks in report order', () => {
    const checks = [check('mx.cname', 'warn'), check('rdap.expiring', 'error'), check('ns.single', 'warn'), check('spf.syntax', 'error'),
      check('www.missing', 'warn', 'web'), check('ns.ok', 'ok'), check('spf.ptr', 'warn'), check('caa.missing', 'info')];
    const p = problemsFirst(checks);
    assert.equal(p.total, 6);
    assert.deepEqual(p.sections.map((s) => [s.severity, s.count]), [['error', 2], ['warn', 4]]);
    assert.deepEqual(p.sections[0].groups.map((g) => [g.group, g.checks.map((c) => c.id)]), [['email', ['spf.syntax']], ['registration', ['rdap.expiring']]]);
    assert.deepEqual(p.sections[1].groups.map((g) => [g.group, g.checks.map((c) => c.id)]),
      [['dns', ['ns.single']], ['email', ['mx.cname', 'spf.ptr']], ['web', ['www.missing']]]);
    assert.deepEqual(problemsFirst([check('ns.ok', 'ok')]), { total: 0, sections: [] });
    assert.deepEqual(countSeverities(checks), { ok: 1, info: 1, warn: 4, error: 2 });
  });
});

describe('healthscore with accepted risks (lib/waivers.js)', () => {
  // dns 100 (w30), email: one error, one warning → 45 (w25), security 100 (w20): (3000 + 1125 + 2000) / 75 = 81.7 → the error caps it at 79
  const checks = [check('ns.ok', 'ok'), check('mx.unresolvable', 'error'), check('dmarc.policy-none', 'warn'), check('caa.missing', 'info')];

  test('the same formula without the waived findings: they cost nothing and cap nothing, their group stays; `full` is the score with them', () => {
    const all = scoreHealth(checks);
    assert.deepEqual([all.score, all.grade, all.cap, all.waived, all.full], [79, 'C', 'error', 0, null]);
    const r = scoreHealth(checks, { waived: ['mx.unresolvable'] });
    // email 85 (one warning left): (3000 + 2125 + 2000) / 75 = 95 → the warning caps it at 89
    assert.equal(r.groups.find((g) => g.group === 'email').score, 85);
    assert.deepEqual([r.score, r.grade, r.cap, r.waived], [SCORE_CAPS.warn, 'B', 'warn', 1]);
    assert.deepEqual(r.full, { score: 79, grade: 'C', raw: all.raw, cap: 'error' });
    assert.deepEqual(r.groups.map((g) => [g.group, g.error, g.warn, g.waived]), [['dns', 0, 0, 0], ['email', 0, 1, 1], ['security', 0, 0, 0]]);
    // both accepted: every group at 100 → A, no cap
    const both = scoreHealth(checks, { waived: new Set(['mx.unresolvable', 'dmarc.policy-none']) });
    assert.deepEqual([both.score, both.grade, both.cap, both.waived, both.groups.find((g) => g.group === 'email').score], [100, 'A', null, 2, 100]);
    // a predicate works too; an info or ok check is never "waived"
    assert.equal(scoreHealth(checks, { waived: (c) => c.id === 'caa.missing' || c.id === 'ns.ok' }).waived, 0);
    assert.equal(scoreHealth(checks, { waived: 'mx.unresolvable' }).waived, 0, 'a string is not a list of ids');
  });

  test('a name that does not exist scores 0 whatever is accepted', () => {
    const gone = scoreHealth([check('domain.nxdomain', 'error'), check('rdap.ok', 'ok')], { waived: ['domain.nxdomain'] });
    assert.deepEqual([gone.score, gone.cap, gone.waived], [0, 'fatal', 0]);
  });

  test('problems first and the counts leave the accepted risks out', () => {
    const p = problemsFirst(checks, { waived: ['mx.unresolvable'] });
    assert.deepEqual(p.sections.map((s) => [s.severity, s.count]), [['warn', 1]]);
    assert.deepEqual(countSeverities(checks, { waived: ['mx.unresolvable'] }), { ok: 1, info: 1, warn: 1, error: 0 });
  });

  test('the what-if planner: the score now and with the ticked findings fixed, by the same formula', () => {
    const w = whatIfHealth(checks, ['dmarc.policy-none'], { waived: ['mx.unresolvable'] });
    assert.deepEqual([w.now.score, w.then.score, w.then.grade, w.gain, w.fixed], [89, 100, 'A', 11, 1]);
    const none = whatIfHealth(checks, []);
    assert.deepEqual([none.now.score, none.then.score, none.gain, none.fixed], [79, 79, 0, 0]);
    // fixing the error alone lifts the error cap: email 85 → (3000 + 2125 + 2000) / 75 = 95 → the warning's cap
    assert.deepEqual([whatIfHealth(checks, ['mx.unresolvable']).then.score, whatIfHealth(checks, ['mx.unresolvable']).then.grade], [89, 'B']);
    // an accepted risk ticked too counts once
    assert.equal(whatIfHealth(checks, ['mx.unresolvable'], { waived: ['mx.unresolvable'] }).fixed, 0);
  });
});

/** A fake DNS client: `zone[name][type]` answers (CNAME chains followed), `RCODE` per name. */
function fakeDns(zone) {
  const calls = [];
  return {
    calls,
    async query(name, type) {
      calls.push(`${name} ${type}`);
      const answers = [];
      let cur = name;
      for (let i = 0; i < 5; i += 1) {
        const z = zone[cur];
        if (!z) return { ok: true, rcode: answers.length || i ? 'NXDOMAIN' : 'NXDOMAIN', answers, authorities: [] };
        if (z.FAIL) return { ok: false, rcode: null, answers: [], authorities: [], error: 'timeout' };
        if (z.CNAME) {
          answers.push({ name: cur, type: 'CNAME', ttl: 300, data: z.CNAME });
          cur = z.CNAME;
          continue;
        }
        for (const data of z[type] || []) answers.push({ name: cur, type, ttl: 300, data });
        return { ok: true, rcode: 'NOERROR', answers, authorities: [] };
      }
      return { ok: true, rcode: 'NOERROR', answers, authorities: [] };
    }
  };
}

const report = (over = {}) => ({
  domain: 'example.com', apex: true, failedLookups: [],
  records: { a: ['192.0.2.10'], aaaa: [], https: [] },
  checks: [check('ns.ok', 'ok'), check('apex.ok', 'ok')],
  summary: { ok: 2, info: 0, warn: 0, error: 0 },
  ...over
});

describe('healthweb: www and the bare domain', () => {
  const ids = (r) => r.checks.map((c) => `${c.id}:${c.severity}`);

  test('www as an alias of the bare domain: ok, with how it resolves', async () => {
    const dns = fakeDns({ 'www.example.com': { CNAME: 'example.com' }, 'example.com': { A: ['192.0.2.10'] } });
    const r = await wwwConsistency(report(), { dns });
    assert.deepEqual(ids(r), ['www.ok:ok']);
    assert.equal(r.checks[0].params.how, 'CNAME → example.com');
    assert.equal(r.checks[0].group, 'web');
    assert.deepEqual(dns.calls.sort(), ['www.example.com A', 'www.example.com AAAA']);
  });

  test('own addresses: ok; none in common with the bare domain: also an info to check the redirect', async () => {
    const same = await wwwConsistency(report(), { dns: fakeDns({ 'www.example.com': { A: ['192.0.2.10'] } }) });
    assert.deepEqual(ids(same), ['www.ok:ok']);
    const other = await wwwConsistency(report(), { dns: fakeDns({ 'www.example.com': { A: ['198.51.100.7'] } }) });
    assert.deepEqual(ids(other), ['www.ok:ok', 'www.differs:info']);
    assert.equal(other.checks[1].params.wwwIps, '198.51.100.7');
  });

  test('only one of them resolves: a warning; neither: info (a mail-only domain)', async () => {
    assert.deepEqual(ids(await wwwConsistency(report(), { dns: fakeDns({}) })), ['www.missing:warn']);
    const noApex = report({ records: { a: [], aaaa: [], https: [] } });
    assert.deepEqual(ids(await wwwConsistency(noApex, { dns: fakeDns({ 'www.example.com': { A: ['192.0.2.20'] } }) })), ['www.apex-missing:warn']);
    assert.deepEqual(ids(await wwwConsistency(noApex, { dns: fakeDns({}) })), ['www.none:info']);
    // the bare domain's A lookup failed: whether it resolves is not known, so no verdict on it
    const apexFailed = report({ records: { a: [], aaaa: [], https: [] }, failedLookups: ['a'] });
    assert.deepEqual(ids(await wwwConsistency(apexFailed, { dns: fakeDns({ 'www.example.com': { A: ['192.0.2.20'] } }) })), []);
  });

  test('a CNAME to a name that does not exist is an error (takeover risk); private addresses a warning', async () => {
    const dangling = await wwwConsistency(report(), { dns: fakeDns({ 'www.example.com': { CNAME: 'gone.example.net' } }) });
    assert.deepEqual(ids(dangling), ['www.dangling:error']);
    assert.equal(dangling.checks[0].params.chain, 'www.example.com → gone.example.net');
    const priv = await wwwConsistency(report(), { dns: fakeDns({ 'www.example.com': { A: ['10.0.0.5'] } }) });
    assert.deepEqual(ids(priv), ['www.ok:ok', 'www.differs:info', 'www.private-ip:warn']);
  });

  test('a failed lookup is a status (info), never "does not resolve"', async () => {
    const r = await wwwConsistency(report(), { dns: fakeDns({ 'www.example.com': { FAIL: true } }) });
    assert.deepEqual(ids(r), ['www.error:info']);
    assert.equal(r.www.error, 'timeout');
  });

  test('skipped below a zone apex, for a www name and for a name that does not exist (no lookup)', async () => {
    const dns = fakeDns({});
    assert.equal((await wwwConsistency(report({ apex: false }), { dns })).www.skipped, 'not-apex');
    assert.equal((await wwwConsistency(report({ domain: 'www.example.com' }), { dns })).www.skipped, 'is-www');
    assert.equal((await wwwConsistency(report({ checks: [check('domain.nxdomain', 'error')] }), { dns })).www.skipped, 'no-domain');
    assert.deepEqual(dns.calls, []);
  });

  test('an abort rejects', async () => {
    const ctl = new AbortController();
    ctl.abort();
    await assert.rejects(wwwConsistency(report(), { dns: fakeDns({}), signal: ctl.signal }), { name: 'AbortError' });
  });
});

describe('healthweb: the HTTPS record, merging and the Observatory check', () => {
  test('no HTTPS record (with an address) is info; a failed lookup says so; lib/health files https-rr under Web', () => {
    assert.deepEqual(httpsRecordChecks(report()).map((c) => [c.id, c.severity]), [['https-rr.none', 'info']]);
    assert.deepEqual(httpsRecordChecks(report({ failedLookups: ['https'] })).map((c) => c.id), ['https-rr.error']);
    assert.deepEqual(httpsRecordChecks(report({ records: { a: ['192.0.2.10'], aaaa: [], https: [{ priority: 1, target: '.', params: { alpn: ['h2'] } }] } })), []);
    assert.deepEqual(httpsRecordChecks(report({ records: { a: [], aaaa: [], https: [] } })), []);
    for (const cat of WEB_CATEGORIES) assert.equal(HEALTH_CATEGORIES[cat], 'web', cat);
  });

  test('addWebChecks merges the Web checks and counts the summary again; a re-run keeps an Observatory grade', async () => {
    const dns = fakeDns({});
    const first = await addWebChecks(report(), { dns });
    assert.deepEqual(first.checks.map((c) => c.id), ['ns.ok', 'apex.ok', 'https-rr.none', 'www.missing']);
    assert.deepEqual(first.summary, { ok: 2, info: 1, warn: 1, error: 0 });
    assert.equal(first.web.www.name, 'www.example.com');
    const graded = withObservatory(first, { ok: true, host: 'example.com', grade: 'F', score: 10, testsFailed: 5, testsQuantity: 12 });
    assert.deepEqual(graded.checks.map((c) => `${c.id}:${c.severity}`).slice(-1), ['observatory.grade:warn']);
    assert.equal(graded.summary.warn, 2);
    const again = await addWebChecks(graded, { dns });
    assert.equal(again.checks.filter((c) => c.id === 'observatory.grade').length, 1);
    assert.equal(again.checks.filter((c) => c.id === 'www.missing').length, 1);
    // a failed scan removes the grade (a status, never a grade)
    const failed = withObservatory(graded, { ok: false, host: 'example.com', error: 'HTTP 503', errorKind: 'http' });
    assert.ok(!failed.checks.some((c) => c.id === 'observatory.grade'));
    assert.equal(failed.web.observatory.error, 'HTTP 503');
    assert.equal(report().checks.length, 2, 'the input report is not changed');
  });

  test('the Observatory grade: A ok, B and C info, D and F a warning; params say what failed', () => {
    assert.deepEqual(['A+', 'A', 'A-', 'B+', 'C-', 'D', 'F'].map(observatorySeverity), ['ok', 'ok', 'ok', 'info', 'info', 'warn', 'warn']);
    const c = observatoryCheck({ ok: true, host: 'example.com', grade: 'B+', score: 80, testsFailed: 2, testsQuantity: 10 });
    assert.deepEqual(c.params, { host: 'example.com', grade: 'B+', score: 80, failed: 2, total: 10 });
    assert.equal(observatoryCheck({ ok: false }), null);
    assert.equal(observatoryCheck({ ok: true, host: 'example.com', grade: 'A', score: null, testsFailed: null, testsQuantity: null }).params.total, '?');
    assert.deepEqual(withWebChecks({ checks: [webCheck('www.ok', 'ok')] }, []).summary, { ok: 0, info: 0, warn: 0, error: 0 });
    assert.equal(hstsPreloadUrl('example.com'), 'https://hstspreload.org/?domain=example.com');
  });

  test('every Web check has English and Turkish texts with the same placeholders; none clashes with lib/health', () => {
    for (const id of WEB_CHECK_IDS) {
      assert.ok(!HEALTH_CHECK_IDS.includes(id), `${id} is lib/health's`);
      assert.ok(WEB_CATEGORIES.includes(id.split('.')[0]), id);
      for (const part of ['title', 'detail']) {
        const key = `health.${id}.${part}`;
        assert.ok(HEALTH_WEB_I18N.en[key] && HEALTH_WEB_I18N.tr[key], key);
        const ph = (s) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort().join();
        assert.equal(ph(HEALTH_WEB_I18N.en[key]), ph(HEALTH_WEB_I18N.tr[key]), key);
      }
    }
    assert.deepEqual(Object.keys(HEALTH_WEB_I18N.en).sort(), Object.keys(HEALTH_WEB_I18N.tr).sort());
    assert.equal(HEALTH_WEB_I18N.en['health.group.web'], 'Web');
  });
});

/** A fake fetch: records calls and answers `respond(url, init)`. */
function fakeFetch(respond) {
  const calls = [];
  const fetchImpl = async (url, init = {}) => {
    calls.push({ url: String(url), method: init.method || 'GET' });
    if (init.signal && init.signal.aborted) throw new DOMException('The operation was aborted.', 'AbortError');
    return respond(String(url), init);
  };
  return { calls, fetchImpl };
}
const json = (status, body, headers = {}) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', ...headers } });
/** The /api/v2/scan answer's shape (fields as the live API names them; documentation values). */
const SCAN = {
  id: 1, details_url: 'https://developer.mozilla.org/en-US/observatory/analyze?host=example.com', algorithm_version: 6,
  scanned_at: '2026-10-08T10:00:00.000Z', error: null, grade: 'C+', score: 60, status_code: 200, tests_failed: 3, tests_passed: 7, tests_quantity: 10
};

describe('observatory: one POST per scan, only public names', () => {
  const at = () => Date.parse('2026-10-08T10:00:01Z');

  test('a scan is ONE POST to the scan URL with the host; the answer becomes a result with a report link built here', async () => {
    const f = fakeFetch(() => json(200, { ...SCAN, details_url: 'https://evil.example.net/' }));
    const r = await observatoryScan('Example.COM', { addresses: ['192.0.2.10'], fetchImpl: f.fetchImpl, now: at });
    assert.deepEqual(f.calls, [{ url: `${OBSERVATORY_SCAN_URL}?host=example.com`, method: 'POST' }]);
    assert.equal(observatoryScanUrl('example.com'), 'https://observatory-api.mdn.mozilla.net/api/v2/scan?host=example.com');
    assert.equal(r.ok, true);
    assert.deepEqual([r.grade, r.score, r.testsFailed, r.testsPassed, r.testsQuantity, r.statusCode], ['C+', 60, 3, 7, 10, 200]);
    assert.equal(r.reportUrl, observatoryReportUrl('example.com'));
    assert.equal(r.reportUrl, 'https://developer.mozilla.org/en-US/observatory/analyze?host=example.com');
    assert.equal(r.at.toISOString(), '2026-10-08T10:00:01.000Z');
  });

  test('never sent: an internal name, a single label, an IP, no address, only private or reserved addresses', async () => {
    const f = fakeFetch(() => json(200, SCAN));
    const cases = [
      ['intranet.local', ['192.0.2.10'], 'internal-name'], ['wiki.corp', ['192.0.2.10'], 'internal-name'],
      ['nas.home.arpa', ['192.0.2.10'], 'internal-name'], ['localhost', ['192.0.2.10'], 'invalid'],
      ['192.0.2.10', ['192.0.2.10'], 'invalid'], ['example.com', [], 'no-address'],
      ['example.com', ['10.0.0.5', 'fd00::5'], 'private-address'], ['example.com', ['127.0.0.1'], 'private-address']
    ];
    for (const [host, addresses, reason] of cases) {
      assert.deepEqual(observatoryEligible(host, { addresses }), { ok: false, reason }, host);
      const r = await observatoryScan(host, { addresses, fetchImpl: f.fetchImpl });
      assert.deepEqual([r.ok, r.skipped], [false, reason], host);
    }
    assert.equal(f.calls.length, 0, 'nothing was sent');
    assert.deepEqual(observatoryEligible('www.example-test.com.tr', { addresses: ['10.0.0.5', '198.51.100.9'] }), { ok: true, host: 'www.example-test.com.tr' });
    assert.ok(OBSERVATORY_SKIP_REASONS.includes('internal-name'));
  });

  test('failures are results: 429 with Retry-After, an HTTP error with the API’s reason, an error answer, a network error', async () => {
    const opts = (respond) => ({ addresses: ['192.0.2.10'], fetchImpl: fakeFetch(respond).fetchImpl, now: at });
    const limited = await observatoryScan('example.com', opts(() => json(429, { error: 'rate-limited' }, { 'retry-after': '60' })));
    assert.deepEqual([limited.ok, limited.errorKind, limited.httpStatus, limited.retryAfterMs], [false, 'rate-limit', 429, 60000]);
    const refused = await observatoryScan('example.com', opts(() => json(422, { error: 'invalid-hostname-lookup', message: 'cannot be resolved' })));
    assert.deepEqual([refused.ok, refused.errorKind, refused.httpStatus, refused.error], [false, 'http', 422, 'HTTP 422: invalid-hostname-lookup']);
    const down = await observatoryScan('example.com', opts(() => json(200, { ...SCAN, grade: null, error: 'site-down' })));
    assert.deepEqual([down.ok, down.errorKind, down.error], [false, 'unavailable', 'site-down']);
    const garbage = await observatoryScan('example.com', opts(() => new Response('<html>', { status: 200 })));
    assert.deepEqual([garbage.ok, garbage.errorKind], [false, 'parse']);
    const offline = await observatoryScan('example.com', opts(() => { throw new TypeError('Failed to fetch'); }));
    assert.deepEqual([offline.ok, offline.errorKind], [false, 'network']);
  });

  test('a timeout is a result; an abort rejects', async () => {
    const slow = fakeFetch((url, init) => new Promise((resolve, reject) => {
      init.signal.addEventListener('abort', () => reject(init.signal.reason || new DOMException('aborted', 'AbortError')));
    }));
    const r = await observatoryScan('example.com', { addresses: ['192.0.2.10'], fetchImpl: slow.fetchImpl, timeoutMs: 20 });
    assert.deepEqual([r.ok, r.errorKind], [false, 'timeout']);
    const ctl = new AbortController();
    const p = observatoryScan('example.com', { addresses: ['192.0.2.10'], fetchImpl: slow.fetchImpl, signal: ctl.signal, timeoutMs: 5000 });
    ctl.abort();
    await assert.rejects(p, { name: 'AbortError' });
  });

  test('readObservatoryScan takes only known grades', () => {
    assert.equal(readObservatoryScan('example.com', { ...SCAN, grade: 'a+' }).grade, 'A+');
    assert.equal(readObservatoryScan('example.com', { ...SCAN, grade: 'Z' }).ok, false);
    assert.equal(OBSERVATORY_GRADES.length, 13);
  });
});

describe('healthadvice: every problem has advice or "Show the fix"', () => {
  test('each error or warning lib/health and lib/healthweb can emit', async () => {
    const src = await readFile(new URL('../../assets/js/lib/health.js', import.meta.url), 'utf8');
    const literal = [...src.matchAll(/makeCheck\('([a-z0-9.-]+)', '(warn|error)'/g)].map((m) => m[1]);
    // computed severities: spf.broad / spf.missing (warn), "all" qualifiers (? warn, + error), DMARC p=none (warn)
    const computed = ['spf.broad', 'spf.missing', 'spf.all-neutral', 'spf.all-pass', 'dmarc.policy-none'];
    const web = ['www.missing', 'www.apex-missing', 'www.dangling', 'www.private-ip', 'observatory.grade'];
    const problems = [...new Set([...literal, ...computed, ...web])];
    assert.ok(literal.length > 60, `found ${literal.length} literal problem checks`);
    const missing = problems.filter((id) => !HEALTH_FIX_IDS.includes(id) && !adviceKey(id));
    assert.deepEqual(missing, []);
  });

  test('advice keys are real check ids, English and Turkish, never empty, no placeholders', () => {
    for (const id of HEALTH_ADVICE_IDS) {
      assert.ok(HEALTH_CHECK_IDS.includes(id) || WEB_CHECK_IDS.includes(id), id);
      for (const lang of ['en', 'tr']) {
        const s = HEALTH_ADVICE_I18N[lang][`hadv.${id}`];
        assert.ok(s && s.trim(), `${lang} ${id}`);
        assert.ok(!/\{\w+\}/.test(s), `${lang} ${id} has a placeholder`);
        assert.ok(!s.includes('...'), `${lang} ${id}: use …`);
      }
      assert.ok(!/'/.test(HEALTH_ADVICE_I18N.tr[`hadv.${id}`]), `tr ${id}: use ’`);
    }
    assert.equal(adviceKey('ns.ok'), null);
    assert.equal(new Set(HEALTH_ADVICE_IDS).size, HEALTH_ADVICE_IDS.length);
  });
});
